/**
 * @file easy_send.c
 * @brief Simple packet sending example using easy API
 * 
 * Compile: gcc -o easy_send easy_send.c
 * Run: sudo ./easy_send <command> [options]
 * 
 * Commands:
 *   tcp <dest_ip> <port> <message>     - Send TCP SYN packet with payload
 *   udp <dest_ip> <port> <message>     - Send UDP packet with payload
 *   icmp <dest_ip> [message]           - Send ICMP echo request (ping)
 *   
 * Options:
 *   -i <interface>  - Specify network interface (default: auto)
 *   -s <port>       - Specify source port (TCP/UDP only)
 * 
 * Examples:
 *   sudo ./easy_send udp 192.168.1.100 8080 "Hello, World!"
 *   sudo ./easy_send tcp 10.0.0.1 80 "GET / HTTP/1.0\r\n\r\n" -i eth0
 *   sudo ./easy_send icmp 8.8.8.8
 *   sudo ./easy_send icmp google.com "Custom ping payload"
 */

#define RAWSOCK_EASY_IMPLEMENTATION
#include "../rawsock_easy.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>

void print_usage(const char* program) {
    printf("Usage: %s <command> [options]\n", program);
    printf("\nCommands:\n");
    printf("  tcp <dest_ip> <port> <message>  - Send TCP SYN packet\n");
    printf("  udp <dest_ip> <port> <message>  - Send UDP packet\n");
    printf("  icmp <dest_ip> [message]        - Send ICMP echo request\n");
    printf("\nOptions:\n");
    printf("  -i <interface>  - Specify network interface\n");
    printf("  -s <port>       - Specify source port (TCP/UDP)\n");
    printf("\nExamples:\n");
    printf("  %s udp 192.168.1.100 8080 \"Hello!\"\n", program);
    printf("  %s tcp 10.0.0.1 80 \"GET /\" -i eth0\n", program);
    printf("  %s icmp 8.8.8.8\n", program);
}

/* Resolve hostname to IP address */
int resolve_hostname(const char* hostname, char* ip_str, size_t ip_str_size) {
    struct hostent* host = gethostbyname(hostname);
    if (!host) {
        return -1;
    }
    
    struct in_addr addr;
    memcpy(&addr, host->h_addr_list[0], sizeof(addr));
    strncpy(ip_str, inet_ntoa(addr), ip_str_size - 1);
    ip_str[ip_str_size - 1] = '\0';
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Check privileges */
    if (!easy_check_privileges()) {
        printf("Error: This program requires root privileges.\n");
        printf("Please run with sudo.\n");
        return 1;
    }
    
    const char* command = argv[1];
    const char* dest_host = argv[2];
    const char* interface = NULL;
    uint16_t src_port = 0;
    
    /* Resolve hostname to IP if needed */
    char dest_ip[46];
    if (strchr(dest_host, '.') && !strchr(dest_host, ':')) {
        /* Looks like an IP address */
        strncpy(dest_ip, dest_host, sizeof(dest_ip) - 1);
        dest_ip[sizeof(dest_ip) - 1] = '\0';
    } else {
        /* Try to resolve as hostname */
        printf("Resolving %s...\n", dest_host);
        if (resolve_hostname(dest_host, dest_ip, sizeof(dest_ip)) < 0) {
            printf("Failed to resolve hostname: %s\n", dest_host);
            return 1;
        }
        printf("Resolved to: %s\n", dest_ip);
    }
    
    /* Parse optional arguments */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            src_port = atoi(argv[++i]);
        }
    }
    
    /* Get default interface if not specified */
    char default_iface[32];
    if (!interface) {
        if (easy_get_default_interface(default_iface) == 0) {
            interface = default_iface;
        }
    }
    
    int result = 0;
    
    if (strcmp(command, "tcp") == 0) {
        /* TCP packet */
        if (argc < 5) {
            printf("Error: TCP requires <dest_ip> <port> <message>\n");
            return 1;
        }
        
        uint16_t dest_port = atoi(argv[3]);
        const char* message = argv[4];
        
        printf("Sending TCP SYN packet:\n");
        printf("  Interface: %s\n", interface ? interface : "default");
        printf("  Destination: %s:%u\n", dest_ip, dest_port);
        printf("  Source port: %u\n", src_port ? src_port : 0);
        printf("  Payload: %zu bytes\n", strlen(message));
        
        if (src_port) {
            result = easy_send_from(interface, dest_ip, dest_port, src_port,
                                   message, strlen(message), PROTO_TCP);
        } else {
            result = easy_send(interface, dest_ip, dest_port,
                              message, strlen(message), PROTO_TCP);
        }
        
    } else if (strcmp(command, "udp") == 0) {
        /* UDP packet */
        if (argc < 5) {
            printf("Error: UDP requires <dest_ip> <port> <message>\n");
            return 1;
        }
        
        uint16_t dest_port = atoi(argv[3]);
        const char* message = argv[4];
        
        printf("Sending UDP packet:\n");
        printf("  Interface: %s\n", interface ? interface : "default");
        printf("  Destination: %s:%u\n", dest_ip, dest_port);
        printf("  Source port: %u\n", src_port ? src_port : 0);
        printf("  Payload: %zu bytes\n", strlen(message));
        
        if (src_port) {
            result = easy_send_from(interface, dest_ip, dest_port, src_port,
                                   message, strlen(message), PROTO_UDP);
        } else {
            result = easy_send(interface, dest_ip, dest_port,
                              message, strlen(message), PROTO_UDP);
        }
        
    } else if (strcmp(command, "icmp") == 0) {
        /* ICMP packet */
        const char* message = (argc > 3) ? argv[3] : "Easy ICMP Ping";
        
        printf("Sending ICMP echo request:\n");
        printf("  Interface: %s\n", interface ? interface : "default");
        printf("  Destination: %s\n", dest_ip);
        printf("  Payload: %zu bytes\n", strlen(message));
        
        result = easy_send_icmp(interface, dest_ip, message, strlen(message));
        
    } else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    if (result > 0) {
        printf("Success! Sent %d bytes\n", result);
    } else {
        printf("Failed to send packet: %s\n", easy_error_string(result));
        return 1;
    }
    
    return 0;
}