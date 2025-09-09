#include "../rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <strings.h>

static volatile int keep_running = 1;

void signal_handler(int sig) {
    keep_running = 0;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [protocol]\n", program_name);
    printf("  protocol: tcp, udp, icmp, or all (default)\n");
    printf("Example: %s tcp\n", program_name);
    printf("\nNote: This program must be run with root privileges (sudo)\n");
    printf("Example: sudo %s tcp\n", program_name);
}

void print_ip_header_info(const void* packet_data, size_t packet_size) {
    if (packet_size < RAWSOCK_IP4_HEADER_SIZE) {
        printf("  Packet too small to contain IP header\n");
        return;
    }

    rawsock_ipv4_header_t ip_header;
    rawsock_error_t err = rawsock_parse_ipv4_header(packet_data, packet_size, &ip_header);
    if (err != RAWSOCK_SUCCESS) {
        printf("  Failed to parse IP header: %s\n", rawsock_error_string(err));
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr = { .s_addr = htonl(ip_header.src_addr) };
    struct in_addr dst_addr = { .s_addr = htonl(ip_header.dst_addr) };
    
    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    printf("  IP Header:\n");
    printf("    Version: %d\n", (ip_header.version_ihl >> 4) & 0xF);
    printf("    Header Length: %d bytes\n", (ip_header.version_ihl & 0xF) * 4);
    printf("    Total Length: %d\n", ip_header.total_length);
    printf("    TTL: %d\n", ip_header.ttl);
    printf("    Protocol: %d\n", ip_header.protocol);
    printf("    Source IP: %s\n", src_ip);
    printf("    Destination IP: %s\n", dst_ip);
}

void print_tcp_header_info(const void* packet_data, size_t packet_size) {
    // Skip IP header to get to TCP header
    if (packet_size < RAWSOCK_IP4_HEADER_SIZE + RAWSOCK_TCP_HEADER_SIZE) {
        printf("  Packet too small to contain TCP header\n");
        return;
    }

    // Get IP header IHL to determine actual IP header size
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_header_len = (ip_data[0] & 0x0F) * 4;
    
    if (packet_size < ip_header_len + RAWSOCK_TCP_HEADER_SIZE) {
        printf("  Packet too small to contain TCP header\n");
        return;
    }

    rawsock_tcp_header_t tcp_header;
    rawsock_error_t err = rawsock_parse_tcp_header(ip_data + ip_header_len, 
                                                   packet_size - ip_header_len, 
                                                   &tcp_header);
    if (err != RAWSOCK_SUCCESS) {
        printf("  Failed to parse TCP header: %s\n", rawsock_error_string(err));
        return;
    }

    printf("  TCP Header:\n");
    printf("    Source Port: %d\n", tcp_header.src_port);
    printf("    Destination Port: %d\n", tcp_header.dst_port);
    printf("    Sequence Number: %u\n", tcp_header.seq_num);
    printf("    Acknowledgment Number: %u\n", tcp_header.ack_num);
    printf("    Flags: 0x%02x\n", tcp_header.flags);
    printf("    Window Size: %d\n", tcp_header.window);
}

void print_udp_header_info(const void* packet_data, size_t packet_size) {
    // Skip IP header to get to UDP header
    if (packet_size < RAWSOCK_IP4_HEADER_SIZE + RAWSOCK_UDP_HEADER_SIZE) {
        printf("  Packet too small to contain UDP header\n");
        return;
    }

    // Get IP header IHL to determine actual IP header size
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_header_len = (ip_data[0] & 0x0F) * 4;
    
    if (packet_size < ip_header_len + RAWSOCK_UDP_HEADER_SIZE) {
        printf("  Packet too small to contain UDP header\n");
        return;
    }

    rawsock_udp_header_t udp_header;
    rawsock_error_t err = rawsock_parse_udp_header(ip_data + ip_header_len, 
                                                   packet_size - ip_header_len, 
                                                   &udp_header);
    if (err != RAWSOCK_SUCCESS) {
        printf("  Failed to parse UDP header: %s\n", rawsock_error_string(err));
        return;
    }

    printf("  UDP Header:\n");
    printf("    Source Port: %d\n", udp_header.src_port);
    printf("    Destination Port: %d\n", udp_header.dst_port);
    printf("    Length: %d\n", udp_header.length);
}

void print_icmp_header_info(const void* packet_data, size_t packet_size) {
    // Skip IP header to get to ICMP header
    if (packet_size < RAWSOCK_IP4_HEADER_SIZE + RAWSOCK_ICMP_HEADER_SIZE) {
        printf("  Packet too small to contain ICMP header\n");
        return;
    }

    // Get IP header IHL to determine actual IP header size
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_header_len = (ip_data[0] & 0x0F) * 4;
    
    if (packet_size < ip_header_len + RAWSOCK_ICMP_HEADER_SIZE) {
        printf("  Packet too small to contain ICMP header\n");
        return;
    }

    rawsock_icmp_header_t icmp_header;
    rawsock_error_t err = rawsock_parse_icmp_header(ip_data + ip_header_len, 
                                                    packet_size - ip_header_len, 
                                                    &icmp_header);
    if (err != RAWSOCK_SUCCESS) {
        printf("  Failed to parse ICMP header: %s\n", rawsock_error_string(err));
        return;
    }

    printf("  ICMP Header:\n");
    printf("    Type: %d\n", icmp_header.type);
    printf("    Code: %d\n", icmp_header.code);
    if (icmp_header.type == 8 || icmp_header.type == 0) {
        printf("    Identifier: %d\n", icmp_header.data.echo.id);
        printf("    Sequence: %d\n", icmp_header.data.echo.sequence);
    }
}

void print_packet_details(const void* packet_data, size_t packet_size, uint8_t protocol) {
    print_ip_header_info(packet_data, packet_size);
    
    switch (protocol) {
        case IPPROTO_TCP:
            print_tcp_header_info(packet_data, packet_size);
            break;
        case IPPROTO_UDP:
            print_udp_header_info(packet_data, packet_size);
            break;
        case IPPROTO_ICMP:
            print_icmp_header_info(packet_data, packet_size);
            break;
        default:
            printf("  Unsupported protocol: %d\n", protocol);
            break;
    }
}

int main(int argc, char** argv) {
    if (argc > 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* protocol_str = (argc == 2) ? argv[1] : "all";
    int protocol;

    // Determine protocol
    if (strcasecmp(protocol_str, "tcp") == 0) {
        protocol = IPPROTO_TCP;
    } else if (strcasecmp(protocol_str, "udp") == 0) {
        protocol = IPPROTO_UDP;
    } else if (strcasecmp(protocol_str, "icmp") == 0) {
        protocol = IPPROTO_ICMP;
    } else if (strcasecmp(protocol_str, "all") == 0) {
        protocol = 0; // Raw socket to capture all IP packets
    } else {
        printf("Invalid protocol. Use tcp, udp, icmp, or all.\n");
        print_usage(argv[0]);
        return 1;
    }

    // Check for root privileges
    if (!rawsock_check_privileges()) {
        printf("Error: Root privileges required for raw socket operations\n");
        printf("Please run with sudo:\n");
        printf("  sudo %s %s\n", argv[0], protocol_str);
        return 1;
    }

    // Register signal handler for graceful shutdown
    signal(SIGINT, signal_handler);

    // Create raw socket configuration for IPv4
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = protocol,
        .recv_timeout_ms = 1000,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 1 // Enable promiscuous mode for packet capture
    };

    // Create raw socket
    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        printf("Error: Failed to create raw socket\n");
        printf("This might be due to insufficient privileges or system restrictions\n");
        return 1;
    }

    printf("Starting packet capture\n");
    printf("Protocol filter: %s\n", protocol_str);
    printf("Press Ctrl+C to stop...\n\n");

    // Buffer for receiving packets
    char buffer[RAWSOCK_MAX_PACKET_SIZE];
    rawsock_packet_info_t packet_info;

    // Capture packets
    int packet_count = 0;
    while (keep_running) {
        int result = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);
        if (result > 0) {
            packet_count++;
            printf("Packet #%d captured:\n", packet_count);
            printf("  Size: %zu bytes\n", packet_info.packet_size);
            printf("  Timestamp: %lu ms\n", (unsigned long)packet_info.timestamp_us);
            
            // Get protocol from IP header (byte 9 in IP header)
            if (packet_info.packet_size >= 9) {
                uint8_t ip_protocol = ((uint8_t*)buffer)[9];
                print_packet_details(buffer, packet_info.packet_size, ip_protocol);
            }
            
            printf("\n");
        } else if (result == -RAWSOCK_ERROR_TIMEOUT) {
            // Timeout, continue loop
            continue;
        } else if (result < 0) {
            rawsock_error_t error = rawsock_get_last_error(sock);
            if (error != RAWSOCK_ERROR_TIMEOUT) {
                printf("Error receiving packet: %s\n", rawsock_error_string(error));
                if (error == RAWSOCK_ERROR_PERMISSION) {
                    printf("Make sure you're running with sufficient privileges (sudo)\n");
                }
            }
        }
    }

    printf("\nShutting down packet capture...\n");
    printf("Total packets captured: %d\n", packet_count);

    // Clean up
    rawsock_destroy(sock);
    
    return 0;
}