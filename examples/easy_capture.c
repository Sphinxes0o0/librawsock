/**
 * @file easy_capture.c
 * @brief Simple packet capture example using easy API
 * 
 * Compile: gcc -o easy_capture easy_capture.c
 * Run: sudo ./easy_capture [interface] [protocol]
 * 
 * Examples:
 *   sudo ./easy_capture                  # Capture all packets on default interface
 *   sudo ./easy_capture eth0             # Capture all packets on eth0
 *   sudo ./easy_capture eth0 tcp         # Capture only TCP packets on eth0
 *   sudo ./easy_capture lo udp           # Capture only UDP packets on loopback
 */

#define RAWSOCK_EASY_IMPLEMENTATION
#include "../rawsock_easy.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

static volatile int running = 1;

void signal_handler(int sig) {
    printf("\nStopping capture...\n");
    running = 0;
}

void print_packet_info(const easy_packet_info_t* info, const void* data, size_t size) {
    printf("\n=== Packet Captured ===\n");
    printf("Timestamp: %lu ms\n", info->timestamp_ms);
    printf("Size: %zu bytes\n", info->packet_size);
    printf("Protocol: ");
    
    switch (info->protocol) {
        case PROTO_TCP:
            printf("TCP\n");
            printf("  %s:%u -> %s:%u\n", 
                   info->src_ip, info->src_port,
                   info->dst_ip, info->dst_port);
            break;
        case PROTO_UDP:
            printf("UDP\n");
            printf("  %s:%u -> %s:%u\n",
                   info->src_ip, info->src_port,
                   info->dst_ip, info->dst_port);
            break;
        case PROTO_ICMP:
            printf("ICMP\n");
            printf("  %s -> %s\n", info->src_ip, info->dst_ip);
            break;
        default:
            printf("Protocol %u\n", info->protocol);
            printf("  %s -> %s\n", info->src_ip, info->dst_ip);
            break;
    }
    
    /* Print first 64 bytes of packet in hex */
    printf("Data (first 64 bytes):\n  ");
    size_t print_size = size < 64 ? size : 64;
    for (size_t i = 0; i < print_size; i++) {
        printf("%02x ", ((uint8_t*)data)[i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    const char* interface = NULL;
    uint8_t protocol = PROTO_ALL;
    
    /* Parse arguments */
    if (argc > 1) {
        interface = argv[1];
    }
    
    if (argc > 2) {
        if (strcmp(argv[2], "tcp") == 0) protocol = PROTO_TCP;
        else if (strcmp(argv[2], "udp") == 0) protocol = PROTO_UDP;
        else if (strcmp(argv[2], "icmp") == 0) protocol = PROTO_ICMP;
        else {
            printf("Unknown protocol: %s\n", argv[2]);
            printf("Supported: tcp, udp, icmp\n");
            return 1;
        }
    }
    
    /* Check privileges */
    if (!easy_check_privileges()) {
        printf("Error: This program requires root privileges.\n");
        printf("Please run with sudo.\n");
        return 1;
    }
    
    /* List available interfaces */
    printf("Available interfaces:\n");
    char interfaces[10][32];
    int count = easy_list_interfaces(interfaces, 10);
    for (int i = 0; i < count; i++) {
        printf("  - %s\n", interfaces[i]);
    }
    
    /* Get default interface if not specified */
    char default_iface[32];
    if (!interface) {
        if (easy_get_default_interface(default_iface) == 0) {
            interface = default_iface;
        }
    }
    
    printf("\nStarting capture on interface: %s\n", interface ? interface : "any");
    printf("Protocol filter: ");
    switch (protocol) {
        case PROTO_ALL: printf("all\n"); break;
        case PROTO_TCP: printf("TCP only\n"); break;
        case PROTO_UDP: printf("UDP only\n"); break;
        case PROTO_ICMP: printf("ICMP only\n"); break;
        default: printf("protocol %u\n", protocol); break;
    }
    printf("Press Ctrl+C to stop...\n\n");
    
    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Start capture */
    easy_capture_t* capture = easy_capture_start(interface, protocol);
    if (!capture) {
        printf("Failed to start capture\n");
        return 1;
    }
    
    /* Capture packets */
    uint8_t buffer[65535];
    easy_packet_info_t info;
    int packet_count = 0;
    
    while (running) {
        /* Capture with 1 second timeout to check running flag */
        int bytes = easy_capture_next_timeout(capture, buffer, sizeof(buffer), 1000, &info);
        
        if (bytes > 0) {
            packet_count++;
            printf("[Packet #%d]", packet_count);
            print_packet_info(&info, buffer, bytes);
        } else if (bytes == EASY_ERROR_TIMEOUT) {
            /* Timeout is normal, continue */
            continue;
        } else if (bytes < 0) {
            printf("Capture error: %s\n", easy_error_string(bytes));
            break;
        }
    }
    
    /* Stop capture */
    easy_capture_stop(capture);
    
    printf("\nCapture stopped. Total packets: %d\n", packet_count);
    return 0;
}