/**
 * @file demo_tcp_analysis.c
 * @brief TCP Protocol Analyzer Demo Program
 * Demonstrates TCP connection state tracking, performance monitoring and data analysis
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <librawsock/rawsock.h>
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

/* Global control variables */
static volatile int g_running = 1;
static int g_verbose = 0;
static int g_packets_processed = 0;
static int g_connections_seen = 0;

/* Signal handler function */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\nStopping TCP analyzer...\n");
}

/* Connection event callback function */
void connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                        analyzer_result_t result) {
    (void)ctx;

    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            g_connections_seen++;
            printf("🔵 New connection: %s\n", flow_str);
            if (g_verbose && conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
                printf("   State: %s\n", tcp_state_to_string(tcp_state->state));
            }
            break;

        case ANALYZER_RESULT_CONNECTION_CLOSE:
            printf("🔴 Connection closed: %s\n", flow_str);
            if (g_verbose && conn->stats.packets_forward > 0) {
                printf("   Forward packets: %lu, Reverse packets: %lu\n", 
                       conn->stats.packets_forward,
                       conn->stats.packets_reverse);
                printf("   Forward bytes: %lu, Reverse bytes: %lu\n",
                       conn->stats.bytes_forward,
                       conn->stats.bytes_reverse);
                if (conn->stats.avg_rtt_us > 0) {
                    printf("   Average RTT: %.2f ms\n", conn->stats.avg_rtt_us / 1000.0);
                }
            }
            break;

        case ANALYZER_RESULT_DATA_READY:
            if (g_verbose) {
                printf("📊 Data ready: %s\n", flow_str);
            }
            break;

        default:
            break;
    }
}

/* Data flow callback function */
void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t direction, const uint8_t* data, size_t size) {
    (void)ctx;

    if (!g_verbose) return;

    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    printf("📦 Data: %s (%s) %zu bytes\n", 
           flow_str,
           (direction == ANALYZER_DIR_FORWARD) ? "→" : "←",
           size);

    /* If it's HTTP data, show first few bytes */
    if (size > 4 && (memcmp(data, "GET ", 4) == 0 || 
                     memcmp(data, "POST", 4) == 0 ||
                     memcmp(data, "HTTP", 4) == 0)) {
        printf("   HTTP data: ");
        for (size_t i = 0; i < (size < 40 ? size : 40); i++) {
            if (data[i] >= 32 && data[i] < 127) {
                printf("%c", data[i]);
            } else if (data[i] == '\r') {
                printf("\\r");
            } else if (data[i] == '\n') {
                printf("\\n");
                break;
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

/* Statistics display */
void print_statistics(analyzer_context_t* ctx) {
    printf("\n=== TCP Analysis Statistics ===\n");
    printf("Packets processed: %d\n", g_packets_processed);
    printf("Connections detected: %d\n", g_connections_seen);
    printf("Active connections: %lu\n", ctx->active_connections);
    printf("Total connections: %lu\n", ctx->total_connections);
    printf("Total packets: %lu\n", ctx->total_packets);
}

/* Create test TCP packet */
size_t create_test_packet(uint8_t* buffer, size_t buffer_size,
                         const char* src_ip, const char* dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         const char* payload) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(buffer_size);
    if (!builder) return 0;

    /* Add IP header */
    if (rawsock_packet_add_ipv4_header(builder, src_ip, dst_ip, IPPROTO_TCP, 64) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Add TCP header */
    if (rawsock_packet_add_tcp_header(builder, src_port, dst_port, seq, ack, flags, 8192) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Add payload */
    if (payload && strlen(payload) > 0) {
        if (rawsock_packet_add_payload(builder, payload, strlen(payload)) != RAWSOCK_SUCCESS) {
            rawsock_packet_builder_destroy(builder);
            return 0;
        }
    }

    /* Finalize construction */
    if (rawsock_packet_finalize(builder) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Get data */
    const void* packet_data;
    size_t packet_size;
    if (rawsock_packet_get_data(builder, &packet_data, &packet_size) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    if (packet_size <= buffer_size) {
        memcpy(buffer, packet_data, packet_size);
    }

    rawsock_packet_builder_destroy(builder);
    return packet_size;
}

/* Run demo mode */
void run_demo_mode(analyzer_context_t* ctx) {
    printf("🚀 Running TCP analysis demo mode...\n");
    printf("Will simulate a complete HTTP session process\n\n");

    uint8_t packet[1500];
    struct timeval timestamp;

    /* Simulate HTTP session: client 192.168.1.100:12345 -> server 93.184.216.34:80 */

    printf("1️⃣ Three-way handshake process\n");

    /* SYN */
    gettimeofday(&timestamp, NULL);
    size_t size = create_test_packet(packet, sizeof(packet),
                                   "192.168.1.100", "93.184.216.34",
                                   12345, 80, 1000, 0, TCP_FLAG_SYN, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(10000); /* 10ms RTT */

    /* SYN-ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000); /* 1ms */

    /* ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001, 2001, TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }

    sleep(1);
    printf("\n2️⃣ HTTP request and response\n");

    /* HTTP GET request */
    gettimeofday(&timestamp, NULL);
    const char* http_request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Demo/1.0\r\n\r\n";
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, http_request);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(50000); /* 50ms server processing time */

    /* HTTP response */
    gettimeofday(&timestamp, NULL);
    const char* http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1270\r\n\r\n<!DOCTYPE html><html>...";
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001, 1001 + strlen(http_request), 
                            TCP_FLAG_ACK | TCP_FLAG_PSH, http_response);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000); /* 1ms */

    /* ACK confirmation */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001 + strlen(http_request), 
                            2001 + strlen(http_response), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }

    sleep(1);
    printf("\n3️⃣ Connection closing process\n");

    /* FIN from client */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001 + strlen(http_request), 
                            2001 + strlen(http_response), TCP_FLAG_FIN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);

    /* ACK from server */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001 + strlen(http_response), 
                            1002 + strlen(http_request), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);

    /* FIN from server */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001 + strlen(http_response), 
                            1002 + strlen(http_request), TCP_FLAG_FIN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);

    /* Final ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1002 + strlen(http_request), 
                            2002 + strlen(http_response), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }

    printf("\n✅ HTTP session demo completed\n");
}

/* Help information */
void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -v, --verbose     Detailed output mode\n");
    printf("  -d, --demo        Run demo mode (simulate TCP session)\n");
    printf("  -h, --help        Show this help information\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -d -v        # Run detailed demo mode\n", program_name);
    printf("  sudo %s         # Monitor actual network traffic (requires root privileges)\n", program_name);
}

int main(int argc, char* argv[]) {
    int demo_mode = 0;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--demo") == 0) {
            demo_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("=== LibRawSock TCP Protocol Analyzer Demo ===\n");
    printf("Version: 1.0.0\n");
    printf("Time: %s", ctime(&(time_t){time(NULL)}));
    printf("Mode: %s\n", demo_mode ? "Demo mode" : "Real-time monitoring mode");
    printf("Verbose output: %s\n\n", g_verbose ? "Enabled" : "Disabled");

    /* Set signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Create analyzer */
    analyzer_context_t* ctx = analyzer_create();
    if (!ctx) {
        fprintf(stderr, "Error: Could not create analyzer context\n");
        return 1;
    }

    /* Create and register TCP processor */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    if (!tcp_handler) {
        fprintf(stderr, "Error: Could not create TCP analyzer\n");
        analyzer_destroy(ctx);
        return 1;
    }

    if (analyzer_register_handler(ctx, tcp_handler) != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Could not register TCP handler\n");
        tcp_analyzer_destroy(tcp_handler);
        analyzer_destroy(ctx);
        return 1;
    }

    /* Set callback functions */
    analyzer_set_connection_callback(ctx, connection_callback);
    analyzer_set_data_callback(ctx, data_callback);

    if (demo_mode) {
        /* Demo mode */
        run_demo_mode(ctx);
    } else {
        /* Real-time monitoring mode */
        printf("🔍 Starting TCP connection monitoring...\n");
        printf("Press Ctrl+C to stop monitoring\n\n");

        /* Check privileges */
        if (getuid() != 0) {
            printf("⚠️   Warning: Requires root privileges to monitor actual network traffic\n");
            printf("💡  Hint: Use 'sudo %s' or try the demo mode '%s -d'\n\n", argv[0], argv[0]);
        }

        /* Here you would add actual network packet capture code */
        /* For demonstration purposes, we just wait for user interruption */
        while (g_running) {
            sleep(1);
        }
    }

    /* Clean up expired connections */
    size_t cleaned = analyzer_cleanup_expired(ctx);
    if (cleaned > 0) {
        printf("Cleaned up %zu expired connections\n", cleaned);
    }

    /* Display statistics */
    print_statistics(ctx);

    /* Clean up resources */
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);

    printf("\n👋 TCP analyzer stopped\n");
    return 0;
}
