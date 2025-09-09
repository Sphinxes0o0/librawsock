#include "../rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

int main() {
    printf("Testing raw socket permissions...\n");
    
    // Check effective user ID
    uid_t euid = geteuid();
    printf("Effective user ID: %d\n", euid);
    
    if (euid != 0) {
        printf("Not running as root. Trying to create raw socket directly...\n");
    } else {
        printf("Running as root.\n");
    }
    
    // Try to create a raw socket directly with system calls
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        printf("Failed to create raw socket directly\n");
        return 1;
    }
    
    printf("Successfully created raw socket directly (fd=%d)\n", sock);
    close(sock);
    
    // Now test with our library
    printf("Testing with rawsock library...\n");
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_ICMP,
        .recv_timeout_ms = 1000,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    rawsock_t* rawsock = rawsock_create_with_config(&config);
    if (!rawsock) {
        printf("Failed to create raw socket with rawsock library\n");
        return 1;
    }
    
    printf("Successfully created raw socket with rawsock library\n");
    rawsock_destroy(rawsock);
    
    printf("All tests passed!\n");
    return 0;
}