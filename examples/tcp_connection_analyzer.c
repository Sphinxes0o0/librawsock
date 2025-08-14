/**
 * @file tcp_connection_analyzer.c
 * @brief TCP Connection Analysis Tool
 * @author LibRawSock Team
 * 
 * This example demonstrates the TCP protocol analyzer capabilities,
 * including connection state tracking, RTT measurement, and performance analysis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <librawsock/rawsock.h>
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

/* Global variables for signal handling */
static volatile int g_running = 1;
static analyzer_context_t* g_analyzer_ctx = NULL;

/**
 * @brief Signal handler for graceful shutdown
 */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Connection event callback
 */
void connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                        analyzer_result_t result) {
    (void)ctx;

    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            printf("[NEW] Connection: %s\n", flow_str);
            break;

        case ANALYZER_RESULT_CONNECTION_CLOSE:
            printf("[CLOSE] Connection: %s\n", flow_str);

            /* Print connection summary */
            if (conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;

                printf("  Final State: %s\n", tcp_state_to_string(tcp_state->state));
                printf("  Packets: %lu forward, %lu reverse\n", 
                       conn->stats.packets_forward, conn->stats.packets_reverse);
                printf("  Bytes: %lu forward, %lu reverse\n",
                       conn->stats.bytes_forward, conn->stats.bytes_reverse);

                if (tcp_state->rtt_samples > 0) {
                    printf("  RTT: avg=%u us, min=%u us, max=%u us (%u samples)\n",
                           tcp_state->avg_rtt_us, tcp_state->min_rtt_us,
                           tcp_state->max_rtt_us, tcp_state->rtt_samples);
                }

                if (tcp_state->retransmit_count > 0) {
                    printf("  Retransmissions: %zu\n", tcp_state->retransmit_count);
                }

                printf("  Quality: OOO[%u,%u] DupACK[%u,%u] ZeroWin[%u,%u]\n",
                       tcp_state->out_of_order_packets[0], tcp_state->out_of_order_packets[1],
                       tcp_state->duplicate_acks[0], tcp_state->duplicate_acks[1],
                       tcp_state->zero_window_probes[0], tcp_state->zero_window_probes[1]);
            }
            printf("\n");
            break;

        default:
            break;
    }
}

/**
 * @brief Data ready callback
 */
void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t dir, const uint8_t* data, size_t size) {
    (void)ctx;

    char flow_str[64];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    printf("[DATA] %s [%s] %zu bytes\n", 
           flow_str, (dir == ANALYZER_DIR_FORWARD) ? "→" : "←", size);

    /* Show first 64 bytes of data */
    size_t show_bytes = (size > 64) ? 64 : size;
    printf("  Data: ");
    for (size_t i = 0; i < show_bytes; i++) {
        if (data[i] >= 32 && data[i] < 127) {
            printf("%c", data[i]);
        } else {
            printf(".");
        }
    }
    if (size > 64) {
        printf("...");
    }
    printf("\n\n");

    /* Consume the data */
    tcp_consume_reassembled_data(conn, dir, size);
}

/**
 * @brief Print connection state change
 */
void print_state_change(const analyzer_flow_id_t* flow_id, 
                       tcp_state_t old_state, tcp_state_t new_state) {
    if (old_state == new_state) {
        return;
    }

    char flow_str[64];
    analyzer_format_flow_id(flow_id, flow_str, sizeof(flow_str));

    printf("[STATE] %s: %s → %s\n", flow_str,
           tcp_state_to_string(old_state), tcp_state_to_string(new_state));
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -i interface     Network interface to capture from (default: any)\n");
    printf("  -f filter        BPF filter expression (default: tcp)\n");
    printf("  -c count         Number of packets to analyze (default: unlimited)\n");
    printf("  -v               Verbose output\n");
    printf("  -s               Show connection statistics periodically\n");
    printf("  -t timeout       Connection timeout in seconds (default: 300)\n");
    printf("  -h               Show this help\n");
    printf("\nExample:\n");
    printf("  %s -i eth0 -f \"tcp port 80\" -v\n", program_name);
    printf("\nNote: This program requires root privileges or CAP_NET_RAW capability.\n");
}

/**
 * @brief Print analyzer statistics
 */
void print_analyzer_stats(analyzer_context_t* ctx) {
    if (!ctx) {
        return;
    }

    printf("\n=== Analyzer Statistics ===\n");
    printf("Total packets processed: %lu\n", ctx->total_packets);
    printf("Total connections seen: %lu\n", ctx->total_connections);
    printf("Active connections: %lu\n", ctx->active_connections);
    printf("Dropped packets: %lu\n", ctx->dropped_packets);

    /* Get aggregated statistics */
    analyzer_stats_t stats;
    analyzer_get_stats(ctx, &stats);

    printf("Total packets: %lu forward, %lu reverse\n",
           stats.packets_forward, stats.packets_reverse);
    printf("Total bytes: %lu forward, %lu reverse\n",
           stats.bytes_forward, stats.bytes_reverse);

    if (stats.rtt_samples > 0) {
        printf("Average RTT: %u us (%u samples)\n",
               stats.avg_rtt_us, stats.rtt_samples);
    }

    printf("\n");
}

/**
 * @brief Main function
 */
int main(int argc, char* argv[]) {
    const char* interface = NULL;
    const char* filter = "tcp";
    int packet_count = 0;
    int verbose = 0;
    int show_stats = 0;
    int timeout = 300;
    int opt;

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "i:f:c:t:vsh")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 't':
                timeout = atoi(optarg);
                if (timeout < 1) timeout = 300;
                break;
            case 'v':
                verbose = 1;
                break;
            case 's':
                show_stats = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Check privileges */
    if (!rawsock_check_privileges()) {
        fprintf(stderr, "Error: This program requires root privileges or CAP_NET_RAW capability\n");
        return 1;
    }

    /* Initialize library */
    rawsock_error_t err = rawsock_init();
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize librawsock: %s\n", 
                rawsock_error_string(err));
        return 1;
    }

    /* Create analyzer context */
    analyzer_config_t config = {
        .max_connections = 1024,
        .max_reassembly_size = 65536,
        .connection_timeout = timeout,
        .enable_reassembly = 1,
        .enable_rtt_tracking = 1,
        .enable_statistics = 1
    };

    analyzer_context_t* ctx = analyzer_create_with_config(&config);
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create analyzer context\n");
        return 1;
    }

    g_analyzer_ctx = ctx;

    /* Create and register TCP analyzer */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    if (!tcp_handler) {
        fprintf(stderr, "Error: Failed to create TCP analyzer\n");
        analyzer_destroy(ctx);
        return 1;
    }

    err = analyzer_register_handler(ctx, tcp_handler);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to register TCP handler: %s\n",
                rawsock_error_string(err));
        tcp_analyzer_destroy(tcp_handler);
        analyzer_destroy(ctx);
        return 1;
    }

    /* Set callbacks */
    analyzer_set_connection_callback(ctx, connection_callback);
    analyzer_set_data_callback(ctx, data_callback);

    /* Create raw socket for packet capture */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_TCP);
    if (!sock) {
        fprintf(stderr, "Error: Failed to create raw socket\n");
        tcp_analyzer_destroy(tcp_handler);
        analyzer_destroy(ctx);
        return 1;
    }

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("TCP Connection Analyzer started\n");
    if (interface) {
        printf("Interface: %s\n", interface);
    }
    printf("Filter: %s\n", filter);
    printf("Connection timeout: %d seconds\n", timeout);
    if (packet_count > 0) {
        printf("Will analyze %d packets\n", packet_count);
    }
    printf("Press Ctrl+C to stop\n\n");

    /* Main analysis loop */
    uint8_t buffer[65536];
    int packets_processed = 0;

    while (g_running && (packet_count == 0 || packets_processed < packet_count)) {
        rawsock_packet_info_t packet_info;

        /* Receive packet */
        int received = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);

        if (received < 0) {
            rawsock_error_t error = -received;
            if (error == RAWSOCK_ERROR_TIMEOUT) {
                /* Cleanup expired connections */
                size_t cleaned = analyzer_cleanup_expired(ctx);
                if (verbose && cleaned > 0) {
                    printf("Cleaned up %zu expired connections\n", cleaned);
                }
                continue;
            } else {
                fprintf(stderr, "Error: Failed to receive packet: %s\n", 
                        rawsock_error_string(error));
                break;
            }
        }

        if (received == 0) {
            continue;
        }

        packets_processed++;

        /* Process packet through analyzer */
        struct timeval timestamp;
        gettimeofday(&timestamp, NULL);
        analyzer_result_t result = analyzer_process_packet(ctx, buffer, received, &timestamp);

        if (verbose) {
            printf("Packet %d: %d bytes, result=%d\n", packets_processed, received, result);
        }

        /* Show periodic statistics */
        if (show_stats && packets_processed % 1000 == 0) {
            print_analyzer_stats(ctx);
        }

        /* Small delay to avoid overwhelming the system */
        if (packets_processed % 100 == 0) {
            usleep(1000);  /* 1ms delay every 100 packets */
        }
    }

    printf("\nAnalysis completed\n");
    print_analyzer_stats(ctx);

    /* Cleanup */
    rawsock_destroy(sock);
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    rawsock_cleanup();

    return 0;
}
