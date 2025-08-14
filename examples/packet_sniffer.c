/**
 * @file packet_sniffer.c
 * @brief Simple packet sniffer using librawsock
 * @author Sphinxes0o0
 * 
 * This example demonstrates how to capture and parse network packets
 * using the librawsock library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/in.h>

#include <librawsock/rawsock.h>
#include <librawsock/packet.h>

/* Global variables for signal handling */
static volatile int g_running = 1;
static int g_packets_captured = 0;

/**
 * @brief Signal handler for graceful shutdown
 */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Convert timestamp to human readable format
 */
void format_timestamp(uint64_t timestamp_us, char* buffer, size_t buffer_size) {
    time_t seconds = timestamp_us / 1000000;
    int microseconds = timestamp_us % 1000000;

    struct tm* tm_info = localtime(&seconds);
    strftime(buffer, buffer_size, "%H:%M:%S", tm_info);

    /* Append microseconds */
    size_t len = strlen(buffer);
    snprintf(buffer + len, buffer_size - len, ".%06d", microseconds);
}

/**
 * @brief Print IP address from binary format
 */
void print_ip_address(const void* addr_bin, rawsock_family_t family) {
    char addr_str[46];
    if (rawsock_addr_bin_to_str(addr_bin, family, addr_str) == RAWSOCK_SUCCESS) {
        printf("%s", addr_str);
    } else {
        printf("unknown");
    }
}

/**
 * @brief Parse and display IPv4 packet
 */
void parse_ipv4_packet(const uint8_t* packet_data, size_t packet_size, 
                      uint64_t timestamp) {
    rawsock_ipv4_header_t ip_header;

    if (rawsock_parse_ipv4_header(packet_data, packet_size, &ip_header) != RAWSOCK_SUCCESS) {
        printf("Failed to parse IPv4 header\n");
        return;
    }

    /* Format timestamp */
    char time_str[32];
    format_timestamp(timestamp, time_str, sizeof(time_str));

    printf("[%s] IPv4: ", time_str);

    /* Convert addresses for display */
    uint32_t src_addr_net = htonl(ip_header.src_addr);
    uint32_t dst_addr_net = htonl(ip_header.dst_addr);

    print_ip_address(&src_addr_net, RAWSOCK_IPV4);
    printf(" -> ");
    print_ip_address(&dst_addr_net, RAWSOCK_IPV4);

    printf(" (proto=%d, len=%d, ttl=%d, id=0x%04x)",
           ip_header.protocol, ip_header.total_length, 
           ip_header.ttl, ip_header.id);

    /* Parse transport layer if enough data */
    size_t ip_header_len = (ip_header.version_ihl & 0x0F) * 4;
    if (packet_size > ip_header_len) {
        const uint8_t* transport_data = packet_data + ip_header_len;
        size_t transport_size = packet_size - ip_header_len;

        if (ip_header.protocol == IPPROTO_TCP && transport_size >= 20) {
            rawsock_tcp_header_t tcp_header;
            if (rawsock_parse_tcp_header(transport_data, transport_size, &tcp_header) == RAWSOCK_SUCCESS) {
                printf(" TCP %d->%d", tcp_header.src_port, tcp_header.dst_port);

                /* Display TCP flags */
                printf(" [");
                if (tcp_header.flags & 0x02) printf("SYN ");
                if (tcp_header.flags & 0x10) printf("ACK ");
                if (tcp_header.flags & 0x01) printf("FIN ");
                if (tcp_header.flags & 0x04) printf("RST ");
                if (tcp_header.flags & 0x08) printf("PSH ");
                if (tcp_header.flags & 0x20) printf("URG ");
                printf("]");

                printf(" seq=%u ack=%u win=%d",
                       tcp_header.seq_num, tcp_header.ack_num, tcp_header.window);
            }
        }
        else if (ip_header.protocol == IPPROTO_UDP && transport_size >= 8) {
            rawsock_udp_header_t udp_header;
            if (rawsock_parse_udp_header(transport_data, transport_size, &udp_header) == RAWSOCK_SUCCESS) {
                printf(" UDP %d->%d len=%d",
                       udp_header.src_port, udp_header.dst_port, udp_header.length);
            }
        }
        else if (ip_header.protocol == IPPROTO_ICMP && transport_size >= 8) {
            rawsock_icmp_header_t icmp_header;
            if (rawsock_parse_icmp_header(transport_data, transport_size, &icmp_header) == RAWSOCK_SUCCESS) {
                printf(" ICMP type=%d code=%d",
                       icmp_header.type, icmp_header.code);

                if (icmp_header.type == 8 || icmp_header.type == 0) {
                    printf(" id=%d seq=%d",
                           icmp_header.data.echo.id, icmp_header.data.echo.sequence);
                }
            }
        }
    }

    printf("\n");
}

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -c count     Number of packets to capture (default: continuous)\n");
    printf("  -p protocol  Protocol to capture (tcp, udp, icmp, all) (default: all)\n");
    printf("  -h           Show this help\n");
    printf("\nExample:\n");
    printf("  %s -c 100 -p tcp\n", program_name);
    printf("\nNote: This program requires root privileges or CAP_NET_RAW capability.\n");
}

/**
 * @brief Main function
 */
int main(int argc, char* argv[]) {
    int count = 0;              /* 0 = continuous */
    int protocol = 0;           /* 0 = all protocols */
    int opt;

    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "c:p:h")) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                break;
            case 'p':
                if (strcmp(optarg, "tcp") == 0) {
                    protocol = IPPROTO_TCP;
                } else if (strcmp(optarg, "udp") == 0) {
                    protocol = IPPROTO_UDP;
                } else if (strcmp(optarg, "icmp") == 0) {
                    protocol = IPPROTO_ICMP;
                } else if (strcmp(optarg, "all") == 0) {
                    protocol = 0;
                } else {
                    fprintf(stderr, "Error: Invalid protocol '%s'\n", optarg);
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

    /* Create configuration for promiscuous mode */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = protocol ? protocol : IPPROTO_RAW,
        .recv_timeout_ms = 1000,    /* 1 second timeout */
        .send_timeout_ms = 0,       /* Not used for receiving */
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 1
    };

    /* Create raw socket */
    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        fprintf(stderr, "Error: Failed to create raw socket\n");
        return 1;
    }

    /* Set up signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Starting packet capture...\n");
    if (protocol) {
        const char* proto_name = (protocol == IPPROTO_TCP) ? "TCP" :
                                (protocol == IPPROTO_UDP) ? "UDP" :
                                (protocol == IPPROTO_ICMP) ? "ICMP" : "Unknown";
        printf("Filtering for %s packets\n", proto_name);
    } else {
        printf("Capturing all packets\n");
    }

    if (count > 0) {
        printf("Will capture %d packets\n", count);
    } else {
        printf("Press Ctrl+C to stop\n");
    }
    printf("\n");

    /* Packet capture loop */
    uint8_t buffer[65536];
    while (g_running && (count == 0 || g_packets_captured < count)) {
        rawsock_packet_info_t packet_info;

        /* Receive packet */
        int received = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);

        if (received < 0) {
            rawsock_error_t error = -received;
            if (error == RAWSOCK_ERROR_TIMEOUT) {
                continue;  /* Timeout, try again */
            } else {
                fprintf(stderr, "Error: Failed to receive packet: %s\n", 
                        rawsock_error_string(error));
                break;
            }
        }

        if (received == 0) {
            continue;  /* No data received */
        }

        g_packets_captured++;

        /* Parse and display packet */
        if (received >= 20) {  /* Minimum IPv4 header size */
            uint8_t version = (buffer[0] >> 4) & 0x0F;

            if (version == 4) {
                parse_ipv4_packet(buffer, received, packet_info.timestamp_us);
            } else if (version == 6) {
                printf("IPv6 packet received (parsing not implemented)\n");
            } else {
                printf("Unknown IP version: %d\n", version);
            }
        } else {
            printf("Packet too small: %d bytes\n", received);
        }
    }

    /* Print statistics */
    printf("\n--- Capture Statistics ---\n");
    printf("Packets captured: %d\n", g_packets_captured);

    /* Cleanup */
    rawsock_destroy(sock);
    rawsock_cleanup();

    return 0;
}

