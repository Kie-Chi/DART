
#include "sender.h"
#include "strategy.h"
#include "common.h"
#include "dns.h"

typedef struct {
    int check_count;
    int max_checks;
} stop_state_t;

/**
 * @brief Stop condition check function (stop_func)
 *
 * @param state Pointer to stop_state_t structure
 * @return bool Returns true to trigger stop flow; false to continue running
 */
bool should_stop(void* state) {
    stop_state_t* s = (stop_state_t*)state;
    s->check_count++;

    printf("[Stop Check] Check #%d of %d...\n", s->check_count, s->max_checks);

    if (s->check_count >= s->max_checks) {
        printf("[Stop Check] Condition met! Requesting sender to stop.\n");
        return true; // Return true, triggers stop flow
    }

    return false; // Return false, continue running
}

/**
 * @brief State data free function (free_func)
 *
 * @param data Pointer to the state set by sender_set_stop_cond
 */
void free_stop_state(void* data) {
    if (data) {
        printf("[Cleanup] Stop condition state freed.\n");
        free(data);
    }
}

int main(int argc, char **argv) {
    // 1. Initialize libuv event loop and dns functionality
    uv_loop_t *loop = uv_default_loop();
    dns_init();

    // 2. Initialize sender
    sender_t sender;
    if (sender_init(&sender, loop, "127.0.0.1", 53) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("Sender initialized.\n");

    pps_make_args_t make_args = {
        .default_args = {
            .src_ip = "127.0.0.1",
            .dst_ip = "127.0.0.1",
            .src_port = 53,
            .dst_port = 12345,
            .domain_name = "example.com"
        },
        .count = 300 // Generate 1000 packets per background task
    };

    // 4. Create PPS strategy
    sender_strategy_t* pps_strategy = create_strategy_pps(
        pps_make,
        &make_args,
        NULL,
        default_send,
        NULL,
        NULL,
        100,      // Send rate: 100 pps
        10,      // Buffer high watermark
        4       // Max concurrent batches
    );
    if (!pps_strategy) {
        fprintf(stderr, "Failed to create PPS strategy\n");
        sender_free(&sender);
        return 1;
    }

    // 5. Set strategy for sender
    sender_set_strategy(&sender, pps_strategy);
    printf("PPS strategy set.\n");

    
    // Allocate and initialize state data
    stop_state_t* state = (stop_state_t*)malloc(sizeof(stop_state_t));
    state->check_count = 0;
    state->max_checks = 10; // Exit after 10 checks

    uint64_t check_interval_ms = 1000; // Check every 1000ms (1 second)

    if (sender_set_stop_cond(&sender, should_stop, state, free_stop_state, check_interval_ms) != NOERROR) {
        fprintf(stderr, "Failed to set stop condition\n");
        free(state); // Manual cleanup
        sender_free(&sender);
        return 1;
    }
    printf("Stop condition set: will stop after %d checks (approx. %d seconds).\n", state->max_checks, (int)(state->max_checks * check_interval_ms / 1000));


    // 7. Start sender
    sender_start(&sender);
    printf("Sender started.\n");

    // 8. Run event loop
    printf("Running event loop...\n");
    uv_run(loop, UV_RUN_DEFAULT);
    printf("Event loop finished.\n");

    // 9. Clean up resources
    // sender_free will stop timer, call free_stop_state, and release strategy
    sender_free(&sender);
    printf("Sender freed.\n");

    // Clean up libuv loop
    uv_loop_close(loop);
    
    printf("Test finished successfully.\n");
    return 0;
}