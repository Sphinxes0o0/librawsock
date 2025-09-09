#include "../rawsock.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("Testing rawsock library...\n");
    
    // Check privileges
    if (!rawsock_check_privileges()) {
        printf("Insufficient privileges for raw socket operations\n");
        return 1;
    }
    
    printf("Privileges OK\n");
    
    // Test basic socket creation with config
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = 0,
        .recv_timeout_ms = 1000,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        printf("Failed to create IPv4 raw socket with protocol 0\n");
        // We can't call rawsock_get_last_error because sock is NULL
        printf("Check system logs for more details (dmesg, /var/log/syslog)\n");
        return 1;
    }
    
    printf("Successfully created raw socket\n");
    rawsock_destroy(sock);
    
    // Test with ICMP
    config.protocol = IPPROTO_ICMP;
    sock = rawsock_create_with_config(&config);
    if (!sock) {
        printf("Failed to create IPv4 raw socket with ICMP protocol\n");
        printf("Check system logs for more details (dmesg, /var/log/syslog)\n");
        return 1;
    }
    
    printf("Successfully created ICMP raw socket\n");
    rawsock_destroy(sock);
    
    printf("All tests passed!\n");
    return 0;
}