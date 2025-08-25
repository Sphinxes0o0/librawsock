/**
 * Test program for single-header rawsock library
 * Compile: gcc -o test_single_header test_single_header.c
 * Run: sudo ./test_single_header
 */

#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>

/* Simple ICMP ping test */
static void test_icmp_ping(void) {
    printf("\n=== Testing ICMP Ping ===\n");
    
    /* Check privileges first */
    if (!rawsock_check_privileges()) {
        printf("Error: Insufficient privileges for raw sockets (run with sudo)\n");
        return;
    }
    
    /* Create raw socket for ICMP */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        printf("Failed to create raw socket\n");
        return;
    }
    
    printf("Raw socket created successfully\n");
    
    /* Build a simple ICMP echo request packet */
    uint8_t packet[64];
    memset(packet, 0, sizeof(packet));
    
    struct icmp* icmp_hdr = (struct icmp*)packet;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(getpid());
    icmp_hdr->icmp_seq = htons(1);
    
    /* Add some data */
    const char* data = "Hello from rawsock!";
    memcpy(packet + 8, data, strlen(data));
    
    /* Calculate checksum */
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = rawsock_calculate_ip_checksum(packet, 8 + strlen(data));
    
    /* Send to localhost */
    printf("Sending ICMP echo request to 127.0.0.1...\n");
    int sent = rawsock_send(sock, packet, 8 + strlen(data), "127.0.0.1");
    if (sent > 0) {
        printf("Sent %d bytes\n", sent);
    } else {
        printf("Send failed: %s\n", rawsock_error_string(rawsock_get_last_error(sock)));
    }
    
    /* Try to receive reply */
    uint8_t recv_buffer[1024];
    rawsock_packet_info_t pkt_info;
    
    printf("Waiting for reply...\n");
    int received = rawsock_recv(sock, recv_buffer, sizeof(recv_buffer), &pkt_info);
    if (received > 0) {
        printf("Received %d bytes from %s\n", received, pkt_info.src_addr);
        
        /* Parse IP header to get to ICMP */
        if (received >= 20) {
            struct iphdr* ip = (struct iphdr*)recv_buffer;
            int ip_header_len = ip->ihl * 4;
            
            if (received >= ip_header_len + 8) {
                struct icmp* recv_icmp = (struct icmp*)(recv_buffer + ip_header_len);
                if (recv_icmp->icmp_type == ICMP_ECHOREPLY) {
                    printf("Got ICMP echo reply!\n");
                }
            }
        }
    } else {
        printf("Receive failed or timed out: %s\n", 
               rawsock_error_string(rawsock_get_last_error(sock)));
    }
    
    rawsock_destroy(sock);
    printf("Socket destroyed\n");
}

/* Test packet parsing functions */
static void test_packet_parsing(void) {
    printf("\n=== Testing Packet Parsing ===\n");
    
    /* Create a sample IPv4 packet */
    uint8_t ipv4_packet[] = {
        0x45, 0x00, 0x00, 0x3c,  /* Version/IHL, TOS, Total Length */
        0x1c, 0x46, 0x40, 0x00,  /* ID, Flags/Fragment */
        0x40, 0x06, 0xb1, 0xe6,  /* TTL, Protocol (TCP), Checksum */
        0xc0, 0xa8, 0x00, 0x01,  /* Source IP: 192.168.0.1 */
        0xc0, 0xa8, 0x00, 0x02   /* Dest IP: 192.168.0.2 */
    };
    
    rawsock_ipv4_header_t ipv4_hdr;
    if (rawsock_parse_ipv4_header(ipv4_packet, sizeof(ipv4_packet), &ipv4_hdr) == RAWSOCK_SUCCESS) {
        printf("IPv4 header parsed:\n");
        printf("  Version: %d\n", (ipv4_hdr.version_ihl >> 4) & 0xF);
        printf("  Header Length: %d bytes\n", (ipv4_hdr.version_ihl & 0xF) * 4);
        printf("  Protocol: %d\n", ipv4_hdr.protocol);
        printf("  Source: %d.%d.%d.%d\n",
               (ipv4_hdr.src_addr >> 24) & 0xFF,
               (ipv4_hdr.src_addr >> 16) & 0xFF,
               (ipv4_hdr.src_addr >> 8) & 0xFF,
               ipv4_hdr.src_addr & 0xFF);
        printf("  Dest: %d.%d.%d.%d\n",
               (ipv4_hdr.dst_addr >> 24) & 0xFF,
               (ipv4_hdr.dst_addr >> 16) & 0xFF,
               (ipv4_hdr.dst_addr >> 8) & 0xFF,
               ipv4_hdr.dst_addr & 0xFF);
    }
    
    /* Test TCP header parsing */
    uint8_t tcp_packet[] = {
        0x00, 0x50, 0x00, 0x50,  /* Source port: 80, Dest port: 80 */
        0x00, 0x00, 0x00, 0x01,  /* Sequence number */
        0x00, 0x00, 0x00, 0x02,  /* Acknowledgment number */
        0x50, 0x02, 0x20, 0x00,  /* Data offset, flags, window */
        0x00, 0x00, 0x00, 0x00   /* Checksum, urgent pointer */
    };
    
    rawsock_tcp_header_t tcp_hdr;
    if (rawsock_parse_tcp_header(tcp_packet, sizeof(tcp_packet), &tcp_hdr) == RAWSOCK_SUCCESS) {
        printf("\nTCP header parsed:\n");
        printf("  Source Port: %d\n", tcp_hdr.src_port);
        printf("  Dest Port: %d\n", tcp_hdr.dst_port);
        printf("  Seq Number: %u\n", tcp_hdr.seq_num);
        printf("  Ack Number: %u\n", tcp_hdr.ack_num);
    }
}

/* Test address conversion functions */
static void test_address_conversion(void) {
    printf("\n=== Testing Address Conversion ===\n");
    
    /* Test IPv4 */
    const char* ipv4_str = "192.168.1.1";
    uint32_t ipv4_bin;
    char ipv4_str_back[INET_ADDRSTRLEN];
    
    if (rawsock_addr_str_to_bin(ipv4_str, RAWSOCK_IPV4, &ipv4_bin) == RAWSOCK_SUCCESS) {
        printf("IPv4 string to binary: %s -> 0x%08x\n", ipv4_str, ntohl(ipv4_bin));
        
        if (rawsock_addr_bin_to_str(&ipv4_bin, RAWSOCK_IPV4, ipv4_str_back) == RAWSOCK_SUCCESS) {
            printf("IPv4 binary to string: 0x%08x -> %s\n", ntohl(ipv4_bin), ipv4_str_back);
        }
    }
    
    /* Test IPv6 */
    const char* ipv6_str = "2001:db8::1";
    uint8_t ipv6_bin[16];
    char ipv6_str_back[INET6_ADDRSTRLEN];
    
    if (rawsock_addr_str_to_bin(ipv6_str, RAWSOCK_IPV6, ipv6_bin) == RAWSOCK_SUCCESS) {
        printf("\nIPv6 string to binary: %s -> ", ipv6_str);
        for (int i = 0; i < 16; i++) {
            printf("%02x", ipv6_bin[i]);
            if (i % 2 == 1 && i < 15) printf(":");
        }
        printf("\n");
        
        if (rawsock_addr_bin_to_str(ipv6_bin, RAWSOCK_IPV6, ipv6_str_back) == RAWSOCK_SUCCESS) {
            printf("IPv6 binary to string: %s\n", ipv6_str_back);
        }
    }
}

/* Test checksum calculation */
static void test_checksum(void) {
    printf("\n=== Testing Checksum Calculation ===\n");
    
    /* Test IP checksum */
    uint8_t ip_header[] = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,  /* Checksum set to 0 */
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0x02
    };
    
    uint16_t checksum = rawsock_calculate_ip_checksum(ip_header, sizeof(ip_header));
    printf("IP header checksum: 0x%04x\n", checksum);
    
    /* Test transport checksum */
    uint32_t src_ip = htonl(0xc0a80001);  /* 192.168.0.1 */
    uint32_t dst_ip = htonl(0xc0a80002);  /* 192.168.0.2 */
    uint8_t tcp_segment[] = {
        0x00, 0x50, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    
    uint16_t tcp_checksum = rawsock_calculate_transport_checksum(
        &src_ip, &dst_ip, 4, IPPROTO_TCP, tcp_segment, sizeof(tcp_segment));
    printf("TCP checksum: 0x%04x\n", tcp_checksum);
}

int main(int argc, char* argv[]) {
    printf("=== Raw Socket Single Header Library Test ===\n");
    printf("Library version: %s\n", rawsock_get_version());
    
    /* Initialize library */
    if (rawsock_init() != RAWSOCK_SUCCESS) {
        printf("Failed to initialize library\n");
        return 1;
    }
    
    /* Check privileges */
    if (rawsock_check_privileges()) {
        printf("Raw socket privileges: OK\n");
    } else {
        printf("Raw socket privileges: NOT AVAILABLE\n");
        printf("Note: Some tests require root privileges\n");
    }
    
    /* Run tests */
    test_packet_parsing();
    test_address_conversion();
    test_checksum();
    
    /* Only run ICMP test if we have privileges */
    if (rawsock_check_privileges()) {
        test_icmp_ping();
    } else {
        printf("\nSkipping ICMP ping test (requires root privileges)\n");
    }
    
    /* Cleanup */
    rawsock_cleanup();
    printf("\n=== All tests completed ===\n");
    
    return 0;
}