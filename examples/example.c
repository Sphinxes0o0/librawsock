/**
 * Simple example of using the rawsock single-header library
 * 
 * Compile:
 *   gcc -o example example.c
 * 
 * Run:
 *   sudo ./example
 */

#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>

int main(void) {
    printf("Raw Socket Library Example - Version %s\n\n", rawsock_get_version());
    
    /* Check if we have the necessary privileges */
    if (!rawsock_check_privileges()) {
        printf("Error: This program requires root privileges.\n");
        printf("Please run with: sudo ./example\n");
        return 1;
    }
    
    /* Example 1: Create a simple raw socket */
    printf("Creating raw socket for ICMP...\n");
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        printf("Failed to create socket\n");
        return 1;
    }
    printf("Socket created successfully!\n");
    
    /* Example 2: Create socket with custom configuration */
    printf("\nCreating socket with custom config...\n");
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_TCP,
        .recv_timeout_ms = 3000,  /* 3 second timeout */
        .send_timeout_ms = 3000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    rawsock_t* tcp_sock = rawsock_create_with_config(&config);
    if (tcp_sock) {
        printf("TCP raw socket created with 3 second timeouts\n");
        rawsock_destroy(tcp_sock);
    }
    
    /* Example 3: Parse a packet header */
    printf("\nParsing example IPv4 header...\n");
    uint8_t sample_packet[] = {
        0x45, 0x00, 0x00, 0x3c,  /* Version/IHL, TOS, Total Length */
        0x1c, 0x46, 0x40, 0x00,  /* ID, Flags/Fragment */
        0x40, 0x01, 0x00, 0x00,  /* TTL, Protocol (ICMP), Checksum */
        0x0a, 0x00, 0x00, 0x01,  /* Source IP: 10.0.0.1 */
        0x0a, 0x00, 0x00, 0x02   /* Dest IP: 10.0.0.2 */
    };
    
    rawsock_ipv4_header_t ipv4_hdr;
    if (rawsock_parse_ipv4_header(sample_packet, sizeof(sample_packet), &ipv4_hdr) == RAWSOCK_SUCCESS) {
        printf("  Protocol: %d (ICMP)\n", ipv4_hdr.protocol);
        printf("  TTL: %d\n", ipv4_hdr.ttl);
    }
    
    /* Example 4: Address conversion */
    printf("\nConverting IP addresses...\n");
    const char* ip_str = "192.168.1.100";
    uint32_t ip_bin;
    
    if (rawsock_addr_str_to_bin(ip_str, RAWSOCK_IPV4, &ip_bin) == RAWSOCK_SUCCESS) {
        char converted_back[46];
        rawsock_addr_bin_to_str(&ip_bin, RAWSOCK_IPV4, converted_back);
        printf("  %s -> binary -> %s\n", ip_str, converted_back);
    }
    
    /* Clean up */
    rawsock_destroy(sock);
    printf("\nDone!\n");
    
    return 0;
}