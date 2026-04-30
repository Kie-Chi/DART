/*
    Test for sendmmsg batch sending and multi-sender optimization
*/

#include "sender.h"
#include "strategy.h"
#include "dns.h"
#include <signal.h>

// Forward declarations
static void timer_stop_callback(uv_timer_t* handle);
static void timer_stop_multi_callback(uv_timer_t* handle);

static volatile bool g_running = true;

static void on_signal(uv_signal_t* handle, int signum) {
    (void)handle;
    printf("\n[Signal] Caught %d, stopping...\n", signum);
    g_running = false;
}

// Test 1: Simple sendmmsg batch send test
static void test_sendmmsg_basic() {
    printf("\n=== Test 1: Basic sendmmsg batch send ===\n");

    uv_loop_t* loop = uv_default_loop();
    sender_t sender;

    // Initialize sender
    if (sender_init(&sender, loop, "127.0.0.1", 53) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return;
    }

    printf("[*] Sender initialized, socket FD: %d\n", sender.sockfd);

    // Create a batch of packets using arena
    Arena arena;
    arena.begin = NULL;
    arena.end = NULL;

    packet_t packets[64];
    uint8_t* data_buffers[64];

    // Create packet template
    struct dns_query* query = new_dns_query_a(&arena, "test.com");
    struct dns_answer* answer = new_dns_answer_a(&arena, "test.com", inet_addr("8.8.8.8"), 3600);

    uint8_t dns_payload[512];
    size_t dns_len = make_dns_packet(dns_payload, sizeof(dns_payload), TRUE, 0, &query, 1, &answer, 1, NULL, 0, NULL, 0, FALSE);

    uint8_t pkt_template[1500];
    size_t pkt_len = make_udp_packet(pkt_template, sizeof(pkt_template),
                                     inet_addr("10.10.0.100"), inet_addr("127.0.0.1"),
                                     53, 12345, dns_payload, dns_len);

    // Create 64 packets with different TXIDs
    for (int i = 0; i < 64; i++) {
        packets[i].data = arena_alloc(&arena, pkt_len);
        memcpy(packets[i].data, pkt_template, pkt_len);
        packets[i].size = pkt_len;
        memset(&packets[i].dest_addr, 0, sizeof(packets[i].dest_addr));

        // Set unique TXID
        struct dnshdr* dnsh = (struct dnshdr*)(packets[i].data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons(i);
    }

    printf("[*] Created 64 packets, testing batch_send...\n");

    // Test batch_send (will fail without valid route, but tests the API)
    ssize_t sent = batch_send(&sender, packets, 64);
    printf("[*] batch_send result: %zd (expected: -1 without route)\n", sent);

    arena_free(&arena);
    sender_free(&sender);

    printf("[*] Test 1 completed\n");
}

// Test 2: Multi-sender initialization test
static void test_multi_sender_init() {
    printf("\n=== Test 2: Multi-sender initialization ===\n");

    uv_loop_t* loop = uv_default_loop();
    multi_sender_t ms;
    multi_sender_config_t config;

    // Configure 4 sender instances
    config.num_senders = 4;
    strncpy(config.dst_ip, "127.0.0.1", sizeof(config.dst_ip) - 1);
    config.dst_port = 53;

    // Set different source IPs for each sender
    for (int i = 0; i < config.num_senders; i++) {
        snprintf(config.src_ips[i], sizeof(config.src_ips[i]), "10.10.0.%d", 100 + i);
        config.src_ports[i] = 53;
    }

    printf("[*] Configuring %d senders, target: %s:%d\n",
           config.num_senders, config.dst_ip, config.dst_port);

    // Initialize multi-sender
    if (multi_sender_init(&ms, loop, &config) != 0) {
        fprintf(stderr, "Failed to initialize multi-sender\n");
        return;
    }

    printf("[*] Multi-sender initialized with %d active senders\n", ms.num_active);

    // Test start/stop
    multi_sender_start(&ms);
    printf("[*] Multi-sender started\n");

    multi_sender_stop(&ms);
    printf("[*] Multi-sender stopped\n");

    multi_sender_free(&ms);
    printf("[*] Multi-sender freed\n");

    printf("[*] Test 2 completed\n");
}

// Test 3: PPS sender with sendmmsg optimization
static void test_pps_with_sendmmsg() {
    printf("\n=== Test 3: PPS sender with sendmmsg ===\n");

    char* target_ip = "127.0.0.1";
    uint16_t target_port = 12345;
    uint16_t src_port = 53;
    char* domain_name = "example.com";
    char* src_ip = "10.10.0.100";

    uint32_t pps = 1000;              // Target packets per second
    size_t high_watermark = 100;
    size_t packets_per_burst = 100;

    printf("[*] Configuration:\n");
    printf("    Target: %s:%u\n", target_ip, target_port);
    printf("    Rate: %u pps\n", pps);
    printf("    Batch size: %zu packets\n", packets_per_burst);

    dns_init();
    uv_loop_t* loop = uv_default_loop();

    sender_t my_sender;
    if (sender_init(&my_sender, loop, target_ip, target_port) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return;
    }

    // Prepare PPS arguments
    default_make_args_t d_args = {
        .src_ip = src_ip,
        .dst_ip = target_ip,
        .src_port = src_port,
        .dst_port = target_port,
        .domain_name = domain_name
    };

    pps_make_args_t packet_args = {
        .default_args = d_args,
        .count = packets_per_burst
    };

    // Create PPS strategy
    sender_strategy_t* strategy = create_strategy_pps(
        pps_make,
        &packet_args,
        NULL,
        NULL,
        NULL,
        NULL,
        pps,
        high_watermark,
        4
    );

    if (!strategy) {
        fprintf(stderr, "Failed to create PPS strategy\n");
        sender_free(&my_sender);
        return;
    }

    sender_set_strategy(&my_sender, strategy);

    printf("[*] Starting sender for 2 seconds...\n");
    sender_start(&my_sender);

    // Run for 2 seconds using timer callback
    uv_timer_t stop_timer;
    uv_timer_init(loop, &stop_timer);
    stop_timer.data = &my_sender;
    uv_timer_start(&stop_timer, timer_stop_callback, 2000, 0);

    uv_run(loop, UV_RUN_DEFAULT);

    sender_free(&my_sender);
    printf("[*] Test 3 completed\n");
}

// Timer callback to stop sender
static void timer_stop_callback(uv_timer_t* handle) {
    sender_t* s = (sender_t*)handle->data;
    sender_stop(s);
    uv_stop(uv_default_loop());
}

// Timer callback to stop multi-sender
static void timer_stop_multi_callback(uv_timer_t* handle) {
    multi_sender_t* ms = (multi_sender_t*)handle->data;
    multi_sender_stop(ms);
    uv_stop(uv_default_loop());
}

// Test 4: Multi-sender parallel sending
static void test_multi_sender_parallel() {
    printf("\n=== Test 4: Multi-sender parallel sending ===\n");

    dns_init();
    uv_loop_t* loop = uv_default_loop();

    multi_sender_t ms;
    multi_sender_config_t config;

    // Configure 4 senders
    config.num_senders = 4;
    strncpy(config.dst_ip, "127.0.0.1", sizeof(config.dst_ip) - 1);
    config.dst_port = 12345;

    for (int i = 0; i < config.num_senders; i++) {
        snprintf(config.src_ips[i], sizeof(config.src_ips[i]), "10.10.0.%d", 100 + i);
        config.src_ports[i] = 53 + i;
    }

    if (multi_sender_init(&ms, loop, &config) != 0) {
        fprintf(stderr, "Failed to initialize multi-sender\n");
        return;
    }

    // Set up PPS strategy for each sender
    for (int i = 0; i < ms.num_active; i++) {
        default_make_args_t d_args = {
            .src_ip = config.src_ips[i],
            .dst_ip = config.dst_ip,
            .src_port = config.src_ports[i],
            .dst_port = config.dst_port,
            .domain_name = "test.com"
        };

        pps_make_args_t packet_args = {
            .default_args = d_args,
            .count = 50
        };

        sender_strategy_t* strategy = create_strategy_pps(
            pps_make,
            &packet_args,
            NULL,
            NULL,
            NULL,
            NULL,
            500,  // 500 pps per sender = 2000 pps total
            50,
            4
        );

        sender_set_strategy(&ms.senders[i], strategy);
    }

    printf("[*] Starting %d senders for 2 seconds...\n", ms.num_active);
    multi_sender_start(&ms);

    // Run for 2 seconds using timer callback
    uv_timer_t stop_timer;
    uv_timer_init(loop, &stop_timer);
    stop_timer.data = &ms;
    uv_timer_start(&stop_timer, timer_stop_multi_callback, 2000, 0);

    uv_run(loop, UV_RUN_DEFAULT);

    printf("[*] Total packets sent: %llu\n",
           (unsigned long long)multi_sender_get_packets_sent(&ms));

    multi_sender_free(&ms);
    printf("[*] Test 4 completed\n");
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    printf("=== sendmmsg and Multi-Sender Test Suite ===\n");
    printf("This test suite validates the sendmmsg optimization\n");
    printf("and multi-sender parallel sending features.\n\n");

    // Run tests based on command line argument
    int test_num = 0;
    if (argc > 1) {
        test_num = atoi(argv[1]);
    }

    if (test_num == 0 || test_num == 1) {
        test_sendmmsg_basic();
    }
    if (test_num == 0 || test_num == 2) {
        test_multi_sender_init();
    }
    if (test_num == 0 || test_num == 3) {
        test_pps_with_sendmmsg();
    }
    if (test_num == 0 || test_num == 4) {
        test_multi_sender_parallel();
    }

    printf("\n=== All tests completed ===\n");
    return 0;
}
