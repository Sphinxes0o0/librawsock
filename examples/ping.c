/**
 * @file ping.c
 * @brief Simple ping implementation using librawsock
 * @author LibRawSock Team
 * 
 * This example demonstrates how to create and send ICMP echo request packets
 * using the librawsock library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <getopt.h>
#include <netinet/in.h>

#include <librawsock/rawsock.h>
#include <librawsock/packet.h>

/* Global variables for signal handling */
static volatile int g_running = 1;
static int g_packets_sent = 0;
static int g_packets_received = 0;

/**
 * @brief Signal handler for graceful shutdown
 */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Get current time in microseconds
 */
uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    printf("Usage: %s <destination_ip> [options]\n", program_name);
    printf("Options:\n");
    printf("  -c count     Number of packets to send (default: continuous)\n");
    printf("  -i interval  Interval between packets in seconds (default: 1)\n");
    printf("  -t ttl       Time to live (default: 64)\n");
    printf("  -s size      Payload size (default: 56)\n");
    printf("  -h           Show this help\n");
    printf("\nExample:\n");
    printf("  %s 8.8.8.8 -c 4 -i 1\n", program_name);
    printf("\nNote: This program requires root privileges or CAP_NET_RAW capability.\n");
}

/**
 * @brief Main ping function
 */
int main(int argc, char* argv[]) {
    const char* dest_ip = NULL;
    int count = 0;              /* 0 = continuous */
    int interval = 1;           /* seconds */
    int ttl = 64;
    int payload_size = 56;
    int opt;

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "c:i:t:s:h")) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'i':
                interval = atoi(optarg);
                if (interval < 1) interval = 1;
                break;
            case 't':
                ttl = atoi(optarg);
                if (ttl < 1 || ttl > 255) {
                    fprintf(stderr, "TTL must be between 1 and 255\n");
                    return 1;
                }
                break;
            case 's':
                payload_size = atoi(optarg);
                if (payload_size < 0 || payload_size > 1400) {
                    fprintf(stderr, "Payload size must be between 0 and 1400\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Check for destination IP */
    if (optind >= argc) {
        fprintf(stderr, "Error: Destination IP address required\n");
        print_usage(argv[0]);
        return 1;
    }
    dest_ip = argv[optind];

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

    /* Create raw socket for ICMP */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        fprintf(stderr, "Error: Failed to create raw socket\n");
        return 1;
    }

    /* Create packet builder */
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    if (!builder) {
        fprintf(stderr, "Error: Failed to create packet builder\n");
        rawsock_destroy(sock);
        return 1;
    }

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("PING %s: %d data bytes\n", dest_ip, payload_size);

    uint16_t sequence = 1;
    uint16_t identifier = getpid() & 0xFFFF;

    /* Main ping loop */
    while (g_running && (count == 0 || g_packets_sent < count)) {
        /* Reset packet builder */
        rawsock_packet_builder_reset(builder);

        /* Get local IP (simplified - using 0.0.0.0) */
        const char* local_ip = "0.0.0.0";

        /* Add IP header */
        err = rawsock_packet_add_ipv4_header(builder, local_ip, dest_ip, 
                                            IPPROTO_ICMP, ttl);
        if (err != RAWSOCK_SUCCESS) {
            fprintf(stderr, "Error: Failed to add IP header: %s\n", 
                    rawsock_error_string(err));
            break;
        }

        /* Add ICMP header (Echo Request) */
        err = rawsock_packet_add_icmp_header(builder, 8, 0, identifier, sequence);
        if (err != RAWSOCK_SUCCESS) {
            fprintf(stderr, "Error: Failed to add ICMP header: %s\n", 
                    rawsock_error_string(err));
            break;
        }

        /* Add payload with timestamp */
        uint8_t payload[1400];
        memset(payload, 0, sizeof(payload));

        /* Include timestamp in payload */
        uint64_t timestamp = get_time_us();
        if (payload_size >= 8) {
            memcpy(payload, &timestamp, sizeof(timestamp));
        }

        /* Fill rest of payload with pattern */
        for (int i = 8; i < payload_size; i++) {
            payload[i] = 0x42 + (i % 26);  /* Pattern */
        }

        if (payload_size > 0) {
            err = rawsock_packet_add_payload(builder, payload, payload_size);
            if (err != RAWSOCK_SUCCESS) {
                fprintf(stderr, "Error: Failed to add payload: %s\n", 
                        rawsock_error_string(err));
                break;
            }
        }

        /* Finalize packet */
        err = rawsock_packet_finalize(builder);
        if (err != RAWSOCK_SUCCESS) {
            fprintf(stderr, "Error: Failed to finalize packet: %s\n", 
                    rawsock_error_string(err));
            break;
        }

        /* Get packet data */
        const void* packet_data;
        size_t packet_size;
        err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
        if (err != RAWSOCK_SUCCESS) {
            fprintf(stderr, "Error: Failed to get packet data: %s\n", 
                    rawsock_error_string(err));
            break;
        }

        /* Send packet */
        uint64_t send_time = get_time_us();
        int sent = rawsock_send(sock, packet_data, packet_size, dest_ip);
        if (sent < 0) {
            fprintf(stderr, "Error: Failed to send packet: %s\n", 
                    rawsock_error_string(-sent));
            break;
        }

        g_packets_sent++;
        printf("64 bytes to %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
               dest_ip, sequence, ttl, 0.0);  /* Simplified output */

        sequence++;

        /* Wait for next packet */
        if (g_running && (count == 0 || g_packets_sent < count)) {
            sleep(interval);
        }
    }

    /* Print statistics */
    printf("\n--- %s ping statistics ---\n", dest_ip);
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
           g_packets_sent, g_packets_received, 
           g_packets_sent > 0 ? 
           (100.0 * (g_packets_sent - g_packets_received) / g_packets_sent) : 0.0);

    /* Cleanup */
    rawsock_packet_builder_destroy(builder);
    rawsock_destroy(sock);
    rawsock_cleanup();

    return 0;
}

