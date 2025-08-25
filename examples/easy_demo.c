/**
 * @file easy_demo.c
 * @brief Comprehensive demo of easy API features
 * 
 * This demo shows how to use the simplified API for various network operations.
 * 
 * Compile: gcc -o easy_demo easy_demo.c
 * Run: sudo ./easy_demo
 */

#define RAWSOCK_EASY_IMPLEMENTATION
#include "../rawsock_easy.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void demo_list_interfaces() {
    printf("=== Listing Network Interfaces ===\n");
    
    char interfaces[10][32];
    int count = easy_list_interfaces(interfaces, 10);
    
    if (count > 0) {
        printf("Found %d interfaces:\n", count);
        for (int i = 0; i < count; i++) {
            printf("  %d. %s\n", i + 1, interfaces[i]);
        }
    } else {
        printf("No interfaces found or error occurred\n");
    }
    
    char default_iface[32];
    if (easy_get_default_interface(default_iface) == 0) {
        printf("Default interface: %s\n", default_iface);
    }
    
    printf("\n");
}

void demo_simple_capture() {
    printf("=== Simple Packet Capture Demo ===\n");
    printf("Capturing 5 packets on loopback interface...\n\n");
    
    /* Start capture on loopback */
    easy_capture_t* capture = easy_capture_start("lo", PROTO_ALL);
    if (!capture) {
        printf("Failed to start capture\n");
        return;
    }
    
    /* Generate some traffic on loopback */
    printf("Generating test traffic...\n");
    easy_send_icmp("lo", "127.0.0.1", "Test ping", 9);
    
    /* Capture packets */
    uint8_t buffer[65535];
    easy_packet_info_t info;
    int captured = 0;
    
    for (int i = 0; i < 5; i++) {
        int bytes = easy_capture_next_timeout(capture, buffer, sizeof(buffer), 1000, &info);
        
        if (bytes > 0) {
            captured++;
            printf("Packet %d: %s -> %s, Protocol %u, %zu bytes\n",
                   captured, info.src_ip, info.dst_ip, info.protocol, info.packet_size);
        } else if (bytes == EASY_ERROR_TIMEOUT) {
            printf("  (timeout waiting for packet)\n");
        }
    }
    
    easy_capture_stop(capture);
    printf("Captured %d packets\n\n", captured);
}

void demo_send_packets() {
    printf("=== Packet Sending Demo ===\n");
    
    /* Send UDP packet */
    printf("1. Sending UDP packet to 127.0.0.1:12345\n");
    const char* udp_data = "Hello from easy API!";
    int result = easy_send("lo", "127.0.0.1", 12345, udp_data, strlen(udp_data), PROTO_UDP);
    if (result > 0) {
        printf("   Sent %d bytes via UDP\n", result);
    } else {
        printf("   Failed: %s\n", easy_error_string(result));
    }
    
    /* Send TCP SYN packet */
    printf("2. Sending TCP SYN packet to 127.0.0.1:80\n");
    const char* tcp_data = "GET / HTTP/1.0\r\n\r\n";
    result = easy_send_from("lo", "127.0.0.1", 80, 54321, tcp_data, strlen(tcp_data), PROTO_TCP);
    if (result > 0) {
        printf("   Sent %d bytes via TCP (SYN)\n", result);
    } else {
        printf("   Failed: %s\n", easy_error_string(result));
    }
    
    /* Send ICMP ping */
    printf("3. Sending ICMP ping to 127.0.0.1\n");
    result = easy_send_icmp("lo", "127.0.0.1", NULL, 0);
    if (result > 0) {
        printf("   Sent %d bytes ICMP echo request\n", result);
    } else {
        printf("   Failed: %s\n", easy_error_string(result));
    }
    
    printf("\n");
}

void demo_protocol_filter() {
    printf("=== Protocol Filtering Demo ===\n");
    
    /* Create captures for different protocols */
    printf("Setting up protocol-specific captures...\n");
    
    easy_capture_t* tcp_capture = easy_capture_start("lo", PROTO_TCP);
    easy_capture_t* udp_capture = easy_capture_start("lo", PROTO_UDP);
    easy_capture_t* icmp_capture = easy_capture_start("lo", PROTO_ICMP);
    
    if (!tcp_capture || !udp_capture || !icmp_capture) {
        printf("Failed to create captures\n");
        goto cleanup;
    }
    
    /* Send different protocol packets */
    printf("Sending test packets...\n");
    easy_send("lo", "127.0.0.1", 9999, "UDP test", 8, PROTO_UDP);
    easy_send("lo", "127.0.0.1", 8888, "TCP test", 8, PROTO_TCP);
    easy_send_icmp("lo", "127.0.0.1", "ICMP test", 9);
    
    /* Try to capture from each filter */
    uint8_t buffer[65535];
    easy_packet_info_t info;
    
    printf("\nChecking TCP filter:\n");
    int bytes = easy_capture_next_timeout(tcp_capture, buffer, sizeof(buffer), 100, &info);
    if (bytes > 0) {
        printf("  Captured TCP packet: %s:%u -> %s:%u\n",
               info.src_ip, info.src_port, info.dst_ip, info.dst_port);
    } else {
        printf("  No TCP packet captured\n");
    }
    
    printf("Checking UDP filter:\n");
    bytes = easy_capture_next_timeout(udp_capture, buffer, sizeof(buffer), 100, &info);
    if (bytes > 0) {
        printf("  Captured UDP packet: %s:%u -> %s:%u\n",
               info.src_ip, info.src_port, info.dst_ip, info.dst_port);
    } else {
        printf("  No UDP packet captured\n");
    }
    
    printf("Checking ICMP filter:\n");
    bytes = easy_capture_next_timeout(icmp_capture, buffer, sizeof(buffer), 100, &info);
    if (bytes > 0) {
        printf("  Captured ICMP packet: %s -> %s\n", info.src_ip, info.dst_ip);
    } else {
        printf("  No ICMP packet captured\n");
    }
    
cleanup:
    if (tcp_capture) easy_capture_stop(tcp_capture);
    if (udp_capture) easy_capture_stop(udp_capture);
    if (icmp_capture) easy_capture_stop(icmp_capture);
    
    printf("\n");
}

void demo_raw_packet() {
    printf("=== Raw Packet Sending Demo ===\n");
    
    /* Build a custom IP packet */
    uint8_t packet[100];
    memset(packet, 0, sizeof(packet));
    
    /* IP header */
    struct iphdr* ip = (struct iphdr*)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + 8);  /* IP header + 8 bytes data */
    ip->id = htons(12345);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 253;  /* Custom protocol number */
    ip->saddr = inet_addr("10.0.0.1");
    ip->daddr = inet_addr("10.0.0.2");
    
    /* Custom payload */
    const char* payload = "RAW_DATA";
    memcpy(packet + sizeof(struct iphdr), payload, 8);
    
    /* Calculate checksum */
    ip->check = 0;
    uint16_t checksum = 0;
    uint16_t* ptr = (uint16_t*)ip;
    for (int i = 0; i < 10; i++) {
        checksum += ntohs(ptr[i]);
    }
    checksum = ~((checksum & 0xFFFF) + (checksum >> 16));
    ip->check = htons(checksum);
    
    printf("Sending custom raw packet:\n");
    printf("  Protocol: 253 (custom)\n");
    printf("  Source: 10.0.0.1\n");
    printf("  Destination: 10.0.0.2\n");
    printf("  Payload: RAW_DATA\n");
    
    int result = easy_send_raw("lo", packet, sizeof(struct iphdr) + 8);
    if (result > 0) {
        printf("  Sent %d bytes raw packet\n", result);
    } else {
        printf("  Failed: %s\n", easy_error_string(result));
    }
    
    printf("\n");
}

int main() {
    printf("========================================\n");
    printf("    Easy Raw Socket API Demo\n");
    printf("========================================\n\n");
    
    /* Check privileges */
    if (!easy_check_privileges()) {
        printf("Error: This demo requires root privileges.\n");
        printf("Please run with sudo.\n");
        return 1;
    }
    
    /* Run demos */
    demo_list_interfaces();
    demo_send_packets();
    demo_simple_capture();
    demo_protocol_filter();
    demo_raw_packet();
    
    printf("========================================\n");
    printf("    Demo completed successfully!\n");
    printf("========================================\n");
    
    return 0;
}