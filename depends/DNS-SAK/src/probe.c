// ======== dns_query_flooder.c ========
/*
    A DNS query flooding tool using the sender framework's burst strategy.
    This tool periodically sends DNS 'A' record queries for randomized
    subdomains of a specified base domain. It is intended for testing DNS
    resolver performance and security monitoring systems.
*/

#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include "util.h"
#include "network.h"
#include "dns.h"
#include "sender.h"
#include "strategy.h"
#include "common.h"

// Arguments for the packet creation function.
typedef struct {
    char* target_ip;
    char* base_domain;
    char* src_ip; // We need a source IP for the raw packet
    uint64_t request_counter; // To make each query unique
} make_query_args_t;


/**
 * @brief Frees the memory allocated for make_query_args_t.
 * This is used by the strategy framework for cleanup.
 */
static void free_make_query_args(void* args) {
    if (!args) return;
    make_query_args_t* q_args = (make_query_args_t*)args;
    free(q_args->target_ip);
    free(q_args->base_domain);
    free(q_args->src_ip);
    free(q_args);
}

/**
 * @brief Packet generation function called by the burst strategy timer.
 * It creates a single DNS query packet for a new, unique, randomized subdomain.
 */
bool make_repeater_query_packet(Arena* arena, packet_queue_t* queue, void* args) {
    make_query_args_t* q_args = (make_query_args_t*)args;
    q_args->request_counter++;

    // 1. Generate a unique domain name for this query.
    char random_subdomain[64];
    snprintf(random_subdomain, sizeof(random_subdomain), "q-%llu-%lx",
             (unsigned long long)q_args->request_counter, (unsigned long)time(NULL));

    char* full_domain = (char*)arena_alloc_memory(arena, strlen(q_args->base_domain) + strlen(random_subdomain) + 2);
    sprintf(full_domain, "%s.%s", random_subdomain, q_args->base_domain);

    printf("[Generator] Creating query for: %s\n", full_domain);

    // 2. Create the DNS query payload.
    struct dns_query* query[1];
    query[0] = new_dns_query_a(arena, full_domain);
    
    uint8_t* dns_payload = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    // Note: is_resp is FALSE for a query.
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, FALSE, get_tx_id(),
                                             query, 1, NULL, 0, NULL, 0, NULL, 0, FALSE);

    if (dns_payload_len == 0) {
        fprintf(stderr, "[-] Failed to create DNS payload.\n");
        return false;
    }

    // 3. Since the sender uses a raw socket (IP_HDRINCL), we must build the full IP/UDP packet.
    uint16_t src_port = 1024 + (rand() % (65535 - 1024)); // Random source port
    
    uint8_t* full_packet_data = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t full_packet_len = make_udp_packet(full_packet_data, DNS_PKT_MAX_LEN,
                                             inet_addr(q_args->src_ip),
                                             inet_addr(q_args->target_ip),
                                             src_port,
                                             53, // DNS standard port
                                             dns_payload, dns_payload_len);
    
    if (full_packet_len == 0) {
        fprintf(stderr, "[-] Failed to create full IP/UDP packet.\n");
        return false;
    }

    // 4. Create the packet_t structure and add it to the queue.
    packet_t* new_pkt = (packet_t*)arena_alloc_memory(arena, sizeof(packet_t));
    new_pkt->data = full_packet_data;
    new_pkt->size = full_packet_len;
    new_pkt->next = NULL;

    // The sender's raw socket will use this destination address.
    new_pkt->dest_addr.sin_family = AF_INET;
    new_pkt->dest_addr.sin_port = htons(53);
    new_pkt->dest_addr.sin_addr.s_addr = inet_addr(q_args->target_ip);
    
    // Add to the sender queue
    if (queue->head == NULL) {
        queue->head = new_pkt;
        queue->tail = new_pkt;
    } else {
        queue->tail->next = new_pkt;
        queue->tail = new_pkt;
    }

    return true;
}

/**
 * @brief Signal handler for graceful shutdown (Ctrl+C).
 */
static void on_signal(uv_signal_t* handle, int signum) {
    sender_t* sender = (sender_t*)handle->data;
    printf("\n[Signal] Caught signal %d. Shutting down gracefully...\n", signum);
    uv_async_send(sender->stop_async); // Signal the sender's event loop to stop
    uv_signal_stop(handle);
}

/**
 * @brief Prints the usage information for the program.
 */
static void print_usage(const char* prog_name) {
    fprintf(stderr, "DNS Query Flooder for Performance and Security Testing\n");
    fprintf(stderr, "Usage: %s -t <target_ip> -d <base_domain> -i <interval_ms>\n\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -t <ip>      IP address of the target DNS resolver (Required)\n");
    fprintf(stderr, "  -d <domain>  The base domain for queries (e.g., example.com) (Required)\n");
    fprintf(stderr, "  -i <ms>      Interval in milliseconds between queries (Required)\n");
    fprintf(stderr, "  -h           Print this help message\n\n");
    fprintf(stderr, "Example: %s -t 8.8.8.8 -d example.com -i 100\n", prog_name);
}

int main(int argc, char** argv) {
    char* target_ip = NULL;
    char* base_domain = NULL;
    uint64_t interval_ms = 0;
    int ch;

    while ((ch = getopt(argc, argv, "t:d:i:h")) != -1) {
        switch (ch) {
            case 't': target_ip = optarg; break;
            case 'd': base_domain = optarg; break;
            case 'i': interval_ms = atoll(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            case '?': default: print_usage(argv[0]); return 1;
        }
    }

    if (!target_ip || !base_domain || interval_ms == 0) {
        fprintf(stderr, "Error: All options (-t, -d, -i) are required.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    srand(time(NULL));
    dns_init();
    uv_loop_t* loop = uv_default_loop();

    sender_t my_sender;
    // The sender framework uses a raw socket, so IP/port are not critical here.
    if (sender_init(&my_sender, loop, "0.0.0.0", 0) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("[+] Sender framework initialized.\n");

    // Prepare arguments for the packet creation function
    make_query_args_t* q_args = (make_query_args_t*)alloc_memory(sizeof(make_query_args_t));
    q_args->target_ip = _strdup(target_ip);
    q_args->base_domain = _strdup(base_domain);
    q_args->src_ip = _strdup("10.0.0.5"); // Dummy source IP for the raw packet
    q_args->request_counter = 0;
    
    // Create the burst strategy
    sender_strategy_t* strategy = create_strategy_burst(
        make_repeater_query_packet, // The function to call periodically
        q_args,                     // Arguments for the function
        free_make_query_args,       // Function to free the arguments
        NULL,                       // Use default send logic
        NULL,
        NULL,
        0,                          // Start immediately (0ms delay)
        interval_ms                 // Repeat every 'interval_ms'
    );
    sender_set_strategy(&my_sender, strategy);
    printf("[+] Burst strategy configured to send one query every %llu ms.\n", (unsigned long long)interval_ms);
    
    // Set up signal handler for graceful exit
    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = &my_sender;
    uv_signal_start(&signal_handle, on_signal, SIGINT);
    
    // Start the sender's strategy
    sender_start(&my_sender);
    
    printf("[+] Starting event loop. Press Ctrl+C to stop.\n");
    uv_run(loop, UV_RUN_DEFAULT);
    
    printf("\n[+] Event loop stopped. Cleaning up...\n");

    sender_free(&my_sender);
    uv_run(loop, UV_RUN_ONCE); // Allow libuv to clean up closed handles
    uv_loop_close(loop);

    printf("[+] Finished.\n");
    return 0;
}