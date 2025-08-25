/**
 * @file quick_test.c
 * @brief Quick test of easy API
 */

#define RAWSOCK_EASY_IMPLEMENTATION
#include "../rawsock_easy.h"
#include <stdio.h>
#include <string.h>

int main() {
    printf("=== Quick Easy API Test ===\n\n");
    
    /* Check privileges */
    if (!easy_check_privileges()) {
        printf("Error: Need root privileges. Run with sudo.\n");
        return 1;
    }
    
    /* List interfaces */
    printf("Available network interfaces:\n");
    char interfaces[10][32];
    int count = easy_list_interfaces(interfaces, 10);
    for (int i = 0; i < count; i++) {
        printf("  - %s\n", interfaces[i]);
    }
    printf("\n");
    
    /* Test sending a simple ICMP ping to localhost */
    printf("Testing ICMP send to localhost...\n");
    int result = easy_send_icmp("lo", "127.0.0.1", "Test", 4);
    if (result > 0) {
        printf("  Success: Sent %d bytes\n", result);
    } else {
        printf("  Failed: %s\n", easy_error_string(result));
    }
    
    /* Test sending UDP packet to localhost */
    printf("\nTesting UDP send to localhost:12345...\n");
    const char* msg = "Hello UDP";
    result = easy_send("lo", "127.0.0.1", 12345, msg, strlen(msg), PROTO_UDP);
    if (result > 0) {
        printf("  Success: Sent %d bytes\n", result);
    } else {
        printf("  Failed: %s\n", easy_error_string(result));
    }
    
    /* Test packet capture (non-blocking) */
    printf("\nTesting packet capture on loopback...\n");
    easy_capture_t* cap = easy_capture_start("lo", PROTO_ALL);
    if (cap) {
        printf("  Capture started successfully\n");
        
        /* Generate a test packet */
        easy_send_icmp("lo", "127.0.0.1", NULL, 0);
        
        /* Try to capture it */
        uint8_t buffer[65535];
        easy_packet_info_t info;
        int bytes = easy_capture_next_timeout(cap, buffer, sizeof(buffer), 100, &info);
        
        if (bytes > 0) {
            printf("  Captured packet: %s -> %s, %zu bytes\n",
                   info.src_ip, info.dst_ip, info.packet_size);
        } else if (bytes == EASY_ERROR_TIMEOUT) {
            printf("  No packet captured (timeout)\n");
        } else {
            printf("  Capture error: %s\n", easy_error_string(bytes));
        }
        
        easy_capture_stop(cap);
        printf("  Capture stopped\n");
    } else {
        printf("  Failed to start capture\n");
    }
    
    printf("\n=== Test completed ===\n");
    return 0;
}