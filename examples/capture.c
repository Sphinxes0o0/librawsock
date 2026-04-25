#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

static volatile int keep_running = 1;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

void print_usage(const char* program_name) {
    printf("Usage: %s [protocol]\n", program_name);
    printf("  protocol: tcp, udp, icmp, or all (default)\n");
    printf("Example: %s tcp\n", program_name);
    printf("\nNote: This program must be run with root privileges (sudo)\n");
}

void print_ip_info(const void* packet_data, size_t packet_size) {
    if (packet_size < RAWSOCK_IP4_HLEN) {
        printf("  Packet too small for IP header\n");
        return;
    }
    rawsock_ip4_t ip;
    if (rawsock_parse_ip4(packet_data, packet_size, &ip, NULL, NULL) != 0) {
        printf("  Failed to parse IP header\n");
        return;
    }
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src = { .s_addr = ip.src };
    struct in_addr dst = { .s_addr = ip.dst };
    inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

    printf("  IP Header:\n");
    printf("    Captured: %zu bytes\n", packet_size);
    printf("    Version: %d\n", ip.version);
    printf("    IHL: %d bytes\n", ip.ihl);
    printf("    Total Length: %d (from IP header)\n", ip.tot_len);
    printf("    TTL: %d\n", ip.ttl);
    printf("    Protocol: %d\n", ip.proto);
    printf("    Source IP: %s\n", src_ip);
    printf("    Destination IP: %s\n", dst_ip);
}

void print_tcp_info(const void* packet_data, size_t packet_size) {
    if (packet_size < RAWSOCK_IP4_HLEN + RAWSOCK_TCP_HLEN) {
        printf("  Packet too small for TCP header\n");
        return;
    }
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_hlen = (ip_data[0] & 0x0F) * 4;
    if (packet_size < ip_hlen + RAWSOCK_TCP_HLEN) {
        printf("  Packet too small for TCP header\n");
        return;
    }
    rawsock_tcp_t tcp;
    if (rawsock_parse_tcp(ip_data + ip_hlen, packet_size - ip_hlen, &tcp) != 0) {
        printf("  Failed to parse TCP header\n");
        return;
    }
    printf("  TCP Header:\n");
    printf("    Source Port: %d\n", tcp.src_port);
    printf("    Destination Port: %d\n", tcp.dst_port);
    printf("    Seq: %u  Ack: %u\n", tcp.seq, tcp.ack);
    printf("    Flags: 0x%02x\n", tcp.flags);
}

void print_udp_info(const void* packet_data, size_t packet_size) {
    if (packet_size < RAWSOCK_IP4_HLEN + RAWSOCK_UDP_HLEN) {
        printf("  Packet too small for UDP header\n");
        return;
    }
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_hlen = (ip_data[0] & 0x0F) * 4;
    if (packet_size < ip_hlen + RAWSOCK_UDP_HLEN) {
        printf("  Packet too small for UDP header\n");
        return;
    }
    rawsock_udp_t udp;
    if (rawsock_parse_udp(ip_data + ip_hlen, packet_size - ip_hlen, &udp) != 0) {
        printf("  Failed to parse UDP header\n");
        return;
    }
    printf("  UDP Header:\n");
    printf("    Source Port: %d\n", udp.src_port);
    printf("    Destination Port: %d\n", udp.dst_port);
    printf("    Length: %d\n", udp.len);
}

void print_icmp_info(const void* packet_data, size_t packet_size) {
    if (packet_size < RAWSOCK_IP4_HLEN + RAWSOCK_ICMP_HLEN) {
        printf("  Packet too small for ICMP header\n");
        return;
    }
    const uint8_t* ip_data = (const uint8_t*)packet_data;
    uint8_t ip_hlen = (ip_data[0] & 0x0F) * 4;
    if (packet_size < ip_hlen + RAWSOCK_ICMP_HLEN) {
        printf("  Packet too small for ICMP header\n");
        return;
    }
    rawsock_icmp_t icmp;
    if (rawsock_parse_icmp(ip_data + ip_hlen, packet_size - ip_hlen, &icmp) != 0) {
        printf("  Failed to parse ICMP header\n");
        return;
    }
    printf("  ICMP Header:\n");
    printf("    Type: %d  Code: %d\n", icmp.type, icmp.code);
    if (icmp.type == 8 || icmp.type == 0) {
        printf("    Identifier: %d  Sequence: %d\n", icmp.id, icmp.seq);
    }
}

void print_packet_details(const void* packet_data, size_t packet_size, uint8_t protocol) {
    print_ip_info(packet_data, packet_size);
    switch (protocol) {
        case IPPROTO_TCP:  print_tcp_info(packet_data, packet_size); break;
        case IPPROTO_UDP:  print_udp_info(packet_data, packet_size); break;
        case IPPROTO_ICMP: print_icmp_info(packet_data, packet_size); break;
        default:           printf("  Unsupported protocol: %d\n", protocol); break;
    }
}

int main(int argc, char** argv) {
    if (argc > 2) { print_usage(argv[0]); return 1; }

    const char* protocol_str = (argc == 2) ? argv[1] : "all";
    int protocol;
    if (strcmp(protocol_str, "tcp") == 0)       protocol = IPPROTO_TCP;
    else if (strcmp(protocol_str, "udp") == 0)  protocol = IPPROTO_UDP;
    else if (strcmp(protocol_str, "icmp") == 0) protocol = IPPROTO_ICMP;
    else if (strcmp(protocol_str, "all") == 0)  protocol = 0;
    else {
        printf("Invalid protocol. Use tcp, udp, icmp, or all.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (!rawsock_has_caps()) {
        printf("Error: Root privileges required\n");
        printf("Please run with sudo:\n  sudo %s %s\n", argv[0], protocol_str);
        return 1;
    }

    signal(SIGINT, signal_handler);

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = protocol;
    cfg.rcv_timeout_ms = 1000;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) {
        printf("Error: Failed to create raw socket: %s\n",
               rawsock_strerror(rawsock_last_err(NULL)));
        return 1;
    }

    printf("Starting packet capture (protocol: %s)\n", protocol_str);
    printf("Press Ctrl+C to stop...\n\n");

    char buffer[RAWSOCK_MAX_PACKET];
    rawsock_pkt_t info;
    int packet_count = 0;

    while (keep_running) {
        int result = rawsock_recv_auto(sock, buffer, sizeof(buffer), &info);
        if (result > 0) {
            packet_count++;
            printf("Packet #%d captured:\n", packet_count);
            printf("  Size: %zu bytes\n", info.pkt_len);
            printf("  Timestamp: %lu us\n", (unsigned long)info.timestamp_us);
            if (info.ip_ver) {
                if (info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) {
                    printf("  %s:%u -> %s:%u  proto=%d\n",
                           info.src_ip, info.src_port,
                           info.dst_ip, info.dst_port,
                           info.protocol);
                } else if (info.protocol == IPPROTO_ICMP) {
                    printf("  %s -> %s  ICMP id=%u\n",
                           info.src_ip, info.dst_ip, info.l4.icmp.id);
                } else {
                    printf("  %s -> %s  proto=%d\n",
                           info.src_ip, info.dst_ip, info.protocol);
                }
            }
            if (info.pkt_len >= 9) {
                uint8_t ip_proto = ((uint8_t*)buffer)[9];
                print_packet_details(buffer, info.pkt_len, ip_proto);
            }
            printf("\n");
        } else if (rawsock_last_err(sock) == RSE_TIMEOUT) {
            continue;
        } else {
            printf("Error: %s\n", rawsock_strerror(rawsock_last_err(sock)));
        }
    }

    printf("\nShutting down. Total packets: %d\n", packet_count);
    return 0;
}
