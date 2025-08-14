/**
 * @file simple_tcp_monitor.c
 * @brief Simple TCP Connection Monitor
 * @author LibRawSock Team
 * 
 * A simpler example showing basic TCP connection monitoring
 * with state tracking and basic statistics.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/time.h>

#include <librawsock/rawsock.h>
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

/* Global variables */
static volatile int g_running = 1;
static int g_connection_count = 0;

/**
 * @brief Signal handler
 */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Simple connection callback
 */
void simple_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                               analyzer_result_t result) {
    (void)ctx;

    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            g_connection_count++;
            printf("[%d] NEW: %s\n", g_connection_count, flow_str);
            break;

        case ANALYZER_RESULT_CONNECTION_CLOSE:
            if (conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
                printf("CLOSE: %s (State: %s, Packets: %lu/%lu)\n",
                       flow_str, tcp_state_to_string(tcp_state->state),
                       conn->stats.packets_forward, conn->stats.packets_reverse);
            } else {
                printf("CLOSE: %s\n", flow_str);
            }
            break;

        default:
            break;
    }
}

/**
 * @brief Print usage
 */
void print_usage(const char* program_name) {
    printf("Usage: %s [max_connections]\n", program_name);
    printf("Example: %s 100\n", program_name);
    printf("\nMonitors TCP connections and shows basic state information.\n");
    printf("Press Ctrl+C to stop.\n");
}

/**
 * @brief Main function
 */
int main(int argc, char* argv[]) {
    int max_connections = 50;

    if (argc > 1) {
        max_connections = atoi(argv[1]);
        if (max_connections <= 0) {
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Check privileges */
    if (!rawsock_check_privileges()) {
        fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    printf("Simple TCP Monitor (max %d connections)\n", max_connections);
    printf("Press Ctrl+C to stop\n\n");

    /* Initialize */
    rawsock_init();

    /* Create analyzer */
    analyzer_config_t config = {
        .max_connections = max_connections,
        .max_reassembly_size = 0,  /* Disable reassembly for simplicity */
        .connection_timeout = 300,
        .enable_reassembly = 0,
        .enable_rtt_tracking = 1,
        .enable_statistics = 1
    };

    analyzer_context_t* ctx = analyzer_create_with_config(&config);
    if (!ctx) {
        fprintf(stderr, "Failed to create analyzer\n");
        return 1;
    }

    /* Register TCP handler */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    analyzer_set_connection_callback(ctx, simple_connection_callback);

    /* Create socket */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_TCP);
    if (!sock) {
        fprintf(stderr, "Failed to create socket\n");
        analyzer_destroy(ctx);
        return 1;
    }

    /* Set signal handler */
    signal(SIGINT, signal_handler);

    /* Main loop */
    uint8_t buffer[1500];
    int packet_count = 0;

    while (g_running) {
        rawsock_packet_info_t packet_info;
        int received = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);

        if (received < 0) {
            if (-received == RAWSOCK_ERROR_TIMEOUT) {
                /* Cleanup expired connections every timeout */
                analyzer_cleanup_expired(ctx);
                continue;
            } else {
                break;
            }
        }

        if (received > 0) {
            packet_count++;
            struct timeval timestamp;
            gettimeofday(&timestamp, NULL);
            analyzer_process_packet(ctx, buffer, received, &timestamp);

            /* Show progress every 1000 packets */
            if (packet_count % 1000 == 0) {
                printf("Processed %d packets, %lu active connections\n", 
                       packet_count, ctx->active_connections);
            }
        }
    }

    printf("\nShutting down...\n");
    printf("Total packets processed: %d\n", packet_count);
    printf("Total connections seen: %lu\n", ctx->total_connections);

    /* Cleanup */
    rawsock_destroy(sock);
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    rawsock_cleanup();

    return 0;
}
