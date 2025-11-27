/**
 * @file capture_example.c
 * @brief C example for packet capture using rawsock library
 * 
 * This example demonstrates how to use the rawsock library to capture
 * network packets using the C interface.
 * 
 * Usage:
 *   sudo ./capture_example_c [interface] [protocol]
 */

#include <rawsock/rawsock_c.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <strings.h>

static volatile int running = 1;

void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

void print_usage(const char* prog) {
    printf("Usage: %s [interface] [protocol]\n", prog);
    printf("  interface: Network interface (default: any)\n");
    printf("  protocol: tcp, udp, icmp, or all (default: all)\n");
    printf("\nNote: Requires root privileges\n");
    printf("Example: sudo %s eth0 tcp\n", prog);
}

rawsock_protocol_t parse_protocol(const char* str) {
    if (strcasecmp(str, "tcp") == 0) return RAWSOCK_PROTO_TCP;
    if (strcasecmp(str, "udp") == 0) return RAWSOCK_PROTO_UDP;
    if (strcasecmp(str, "icmp") == 0) return RAWSOCK_PROTO_ICMP;
    return RAWSOCK_PROTO_ALL;
}

const char* protocol_name(uint8_t proto) {
    switch (proto) {
        case RAWSOCK_PROTO_TCP: return "TCP";
        case RAWSOCK_PROTO_UDP: return "UDP";
        case RAWSOCK_PROTO_ICMP: return "ICMP";
        default: return "Unknown";
    }
}

int main(int argc, char* argv[]) {
    const char* interface_name = "";
    rawsock_protocol_t filter_proto = RAWSOCK_PROTO_ALL;
    
    // Parse arguments
    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        interface_name = argv[1];
    }
    
    if (argc >= 3) {
        filter_proto = parse_protocol(argv[2]);
    }
    
    // Check privileges
    if (!rawsock_check_privileges()) {
        fprintf(stderr, "Error: Root privileges required\n");
        fprintf(stderr, "Please run with: sudo %s\n", argv[0]);
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    // Create capture
    rawsock_capture_t* cap = rawsock_capture_create();
    if (!cap) {
        fprintf(stderr, "Error: Failed to create capture\n");
        return 1;
    }
    
    // Configure capture
    rawsock_config_t config;
    rawsock_config_init(&config);
    strncpy(config.interface_name, interface_name, RAWSOCK_MAX_INTERFACE_NAME - 1);
    config.filter_protocol = filter_proto;
    config.recv_timeout_ms = 1000;
    config.promiscuous = 1;
    
    // Open capture
    rawsock_error_t err = rawsock_capture_open(cap, &config);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error opening capture: %s\n", rawsock_error_string(err));
        rawsock_capture_destroy(cap);
        return 1;
    }
    
    printf("Starting packet capture...\n");
    printf("Interface: %s\n", interface_name[0] ? interface_name : "any");
    printf("Protocol: %s\n", filter_proto == RAWSOCK_PROTO_ALL ? "all" : protocol_name(filter_proto));
    printf("Press Ctrl+C to stop\n\n");
    
    // Capture buffer
    uint8_t buffer[RAWSOCK_MAX_PACKET_SIZE];
    rawsock_packet_info_t info;
    int packet_count = 0;
    
    // Capture loop
    while (running) {
        int bytes = rawsock_capture_next(cap, buffer, sizeof(buffer), &info);
        
        if (bytes > 0) {
            ++packet_count;
            printf("Packet #%d: %s:%u -> %s:%u (%s, %zu bytes)\n",
                   packet_count,
                   info.src_addr, info.src_port,
                   info.dst_addr, info.dst_port,
                   protocol_name(info.protocol),
                   info.packet_size);
        } else if (bytes == -RAWSOCK_ERROR_TIMEOUT) {
            // Timeout - continue
            continue;
        } else {
            rawsock_error_t error = rawsock_capture_last_error(cap);
            if (error != RAWSOCK_ERROR_TIMEOUT) {
                fprintf(stderr, "Error: %s\n", rawsock_error_string(error));
            }
        }
    }
    
    // Print statistics
    printf("\n--- Capture Statistics ---\n");
    printf("Packets captured: %d\n", packet_count);
    
    uint64_t received, dropped;
    if (rawsock_capture_get_statistics(cap, &received, &dropped) == RAWSOCK_SUCCESS) {
        printf("Packets received (kernel): %lu\n", (unsigned long)received);
        printf("Packets dropped (kernel): %lu\n", (unsigned long)dropped);
    }
    
    rawsock_capture_destroy(cap);
    return 0;
}
