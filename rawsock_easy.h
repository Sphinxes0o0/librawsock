/**
 * @file rawsock_easy.h
 * @brief Easy-to-use wrapper for rawsock library
 * @author Sphinxes0o0
 * @version 1.0.0
 * 
 * This header provides simplified interfaces for packet capture and sending.
 * It wraps the low-level rawsock.h API with easier-to-use functions.
 * 
 * Usage:
 * #define RAWSOCK_EASY_IMPLEMENTATION
 * #include "rawsock_easy.h"
 */

#ifndef RAWSOCK_EASY_H
#define RAWSOCK_EASY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/* ===== Protocol Constants ===== */
#define PROTO_ALL      0    /* Capture all protocols */
#define PROTO_ICMP     1    /* Internet Control Message Protocol */
#define PROTO_TCP      6    /* Transmission Control Protocol */
#define PROTO_UDP      17   /* User Datagram Protocol */
#define PROTO_ICMPV6   58   /* ICMPv6 */
#define PROTO_RAW      255  /* Raw IP */

/* ===== Error Codes ===== */
typedef enum {
    EASY_SUCCESS = 0,
    EASY_ERROR_INVALID_PARAM = -1,
    EASY_ERROR_PERMISSION = -2,
    EASY_ERROR_SOCKET = -3,
    EASY_ERROR_INTERFACE = -4,
    EASY_ERROR_TIMEOUT = -5,
    EASY_ERROR_BUFFER_TOO_SMALL = -6,
    EASY_ERROR_SEND_FAILED = -7,
    EASY_ERROR_RECV_FAILED = -8,
    EASY_ERROR_UNKNOWN = -9
} easy_error_t;

/* ===== Capture Context ===== */
typedef struct easy_capture easy_capture_t;

/* ===== Packet Information ===== */
typedef struct {
    char src_ip[46];        /* Source IP address string */
    char dst_ip[46];        /* Destination IP address string */
    uint16_t src_port;      /* Source port (0 for non-TCP/UDP) */
    uint16_t dst_port;      /* Destination port (0 for non-TCP/UDP) */
    uint8_t protocol;       /* Protocol number */
    size_t packet_size;     /* Total packet size */
    uint64_t timestamp_ms;  /* Timestamp in milliseconds */
} easy_packet_info_t;

/* ===== Simple Capture API ===== */

/**
 * Start packet capture on specified interface
 * 
 * @param interface Network interface name (e.g., "eth0", "lo", NULL for any)
 * @param protocol Protocol to capture (PROTO_ALL for all protocols)
 * @return Capture context on success, NULL on failure
 * 
 * Example:
 *   easy_capture_t* cap = easy_capture_start("eth0", PROTO_TCP);
 */
easy_capture_t* easy_capture_start(const char* interface, uint8_t protocol);

/**
 * Capture next packet
 * 
 * @param capture Capture context
 * @param buffer Buffer to store packet data
 * @param buffer_size Size of buffer
 * @param info Optional packet information (can be NULL)
 * @return Number of bytes captured, negative error code on failure
 * 
 * Example:
 *   uint8_t buffer[65535];
 *   easy_packet_info_t info;
 *   int bytes = easy_capture_next(cap, buffer, sizeof(buffer), &info);
 */
int easy_capture_next(easy_capture_t* capture, void* buffer, size_t buffer_size, 
                      easy_packet_info_t* info);

/**
 * Capture next packet with timeout
 * 
 * @param capture Capture context
 * @param buffer Buffer to store packet data
 * @param buffer_size Size of buffer
 * @param timeout_ms Timeout in milliseconds (0 for no timeout)
 * @param info Optional packet information (can be NULL)
 * @return Number of bytes captured, EASY_ERROR_TIMEOUT on timeout, negative error on failure
 */
int easy_capture_next_timeout(easy_capture_t* capture, void* buffer, size_t buffer_size,
                               int timeout_ms, easy_packet_info_t* info);

/**
 * Stop packet capture and free resources
 * 
 * @param capture Capture context to stop
 */
void easy_capture_stop(easy_capture_t* capture);

/* ===== Simple Send API ===== */

/**
 * Send raw packet
 * 
 * @param interface Network interface to send from (NULL for default)
 * @param dest_ip Destination IP address
 * @param dest_port Destination port (for TCP/UDP)
 * @param payload Payload data to send
 * @param payload_size Size of payload
 * @param protocol Protocol number (PROTO_TCP, PROTO_UDP, etc.)
 * @return Number of bytes sent on success, negative error code on failure
 * 
 * Example:
 *   const char* data = "Hello, World!";
 *   int sent = easy_send("eth0", "192.168.1.100", 8080, data, strlen(data), PROTO_UDP);
 */
int easy_send(const char* interface, const char* dest_ip, uint16_t dest_port,
              const void* payload, size_t payload_size, uint8_t protocol);

/**
 * Send raw packet with source port specification
 * 
 * @param interface Network interface to send from (NULL for default)
 * @param dest_ip Destination IP address
 * @param dest_port Destination port (for TCP/UDP)
 * @param src_port Source port (0 for automatic)
 * @param payload Payload data to send
 * @param payload_size Size of payload
 * @param protocol Protocol number
 * @return Number of bytes sent on success, negative error code on failure
 */
int easy_send_from(const char* interface, const char* dest_ip, uint16_t dest_port,
                   uint16_t src_port, const void* payload, size_t payload_size, 
                   uint8_t protocol);

/**
 * Send ICMP packet (ping)
 * 
 * @param interface Network interface to send from (NULL for default)
 * @param dest_ip Destination IP address
 * @param payload Optional payload data (can be NULL)
 * @param payload_size Size of payload (0 for no payload)
 * @return Number of bytes sent on success, negative error code on failure
 * 
 * Example:
 *   int sent = easy_send_icmp("eth0", "8.8.8.8", NULL, 0);
 */
int easy_send_icmp(const char* interface, const char* dest_ip,
                   const void* payload, size_t payload_size);

/**
 * Send raw IP packet (complete packet including headers)
 * 
 * @param interface Network interface to send from (NULL for default)
 * @param packet Complete packet data including IP header
 * @param packet_size Size of packet
 * @return Number of bytes sent on success, negative error code on failure
 */
int easy_send_raw(const char* interface, const void* packet, size_t packet_size);

/* ===== Utility Functions ===== */

/**
 * Get error description string
 * 
 * @param error Error code
 * @return Human-readable error description
 */
const char* easy_error_string(easy_error_t error);

/**
 * Check if running with sufficient privileges
 * 
 * @return 1 if has privileges, 0 otherwise
 */
int easy_check_privileges(void);

/**
 * List available network interfaces
 * 
 * @param interfaces Array to store interface names
 * @param max_interfaces Maximum number of interfaces to list
 * @return Number of interfaces found, negative error code on failure
 */
int easy_list_interfaces(char interfaces[][32], int max_interfaces);

/**
 * Get default network interface
 * 
 * @param interface Buffer to store interface name (at least 32 bytes)
 * @return 0 on success, negative error code on failure
 */
int easy_get_default_interface(char* interface);

/* ===== Implementation ===== */

#ifdef RAWSOCK_EASY_IMPLEMENTATION

#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif

/* Capture context structure */
struct easy_capture {
    rawsock_t* sock;
    uint8_t protocol;
    char interface[32];
    int timeout_ms;
};

/* Get current timestamp in milliseconds */
static uint64_t get_timestamp_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Convert rawsock error to easy error */
__attribute__((unused))
static easy_error_t convert_error(rawsock_error_t err) {
    switch (err) {
        case RAWSOCK_SUCCESS: return EASY_SUCCESS;
        case RAWSOCK_ERROR_INVALID_PARAM: return EASY_ERROR_INVALID_PARAM;
        case RAWSOCK_ERROR_PERMISSION: return EASY_ERROR_PERMISSION;
        case RAWSOCK_ERROR_SOCKET_CREATE:
        case RAWSOCK_ERROR_SOCKET_BIND: return EASY_ERROR_SOCKET;
        case RAWSOCK_ERROR_SEND: return EASY_ERROR_SEND_FAILED;
        case RAWSOCK_ERROR_RECV: return EASY_ERROR_RECV_FAILED;
        case RAWSOCK_ERROR_TIMEOUT: return EASY_ERROR_TIMEOUT;
        case RAWSOCK_ERROR_BUFFER_TOO_SMALL: return EASY_ERROR_BUFFER_TOO_SMALL;
        default: return EASY_ERROR_UNKNOWN;
    }
}

/* Extract packet info from raw packet */
static void extract_packet_info(const void* packet, size_t packet_size, 
                                easy_packet_info_t* info) {
    if (!info || !packet || packet_size < 20) return;
    
    memset(info, 0, sizeof(easy_packet_info_t));
    info->packet_size = packet_size;
    info->timestamp_ms = get_timestamp_ms();
    
    const struct iphdr* ip = (const struct iphdr*)packet;
    
    /* Extract IP addresses */
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->saddr;
    dst_addr.s_addr = ip->daddr;
    inet_ntop(AF_INET, &src_addr, info->src_ip, sizeof(info->src_ip));
    inet_ntop(AF_INET, &dst_addr, info->dst_ip, sizeof(info->dst_ip));
    
    info->protocol = ip->protocol;
    
    /* Extract ports for TCP/UDP */
    if (ip->protocol == IPPROTO_TCP && packet_size >= (ip->ihl * 4 + 8)) {
        const struct tcphdr* tcp = (const struct tcphdr*)((const uint8_t*)packet + ip->ihl * 4);
        info->src_port = ntohs(tcp->source);
        info->dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP && packet_size >= (ip->ihl * 4 + 8)) {
        const struct udphdr* udp = (const struct udphdr*)((const uint8_t*)packet + ip->ihl * 4);
        info->src_port = ntohs(udp->source);
        info->dst_port = ntohs(udp->dest);
    }
}

/* Start packet capture */
easy_capture_t* easy_capture_start(const char* interface, uint8_t protocol) {
    easy_capture_t* capture = (easy_capture_t*)calloc(1, sizeof(easy_capture_t));
    if (!capture) return NULL;
    
    /* Create raw socket configuration */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = (protocol == PROTO_ALL) ? IPPROTO_RAW : protocol,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 1
    };
    
    capture->sock = rawsock_create_with_config(&config);
    if (!capture->sock) {
        free(capture);
        return NULL;
    }
    
    capture->protocol = protocol;
    if (interface) {
        strncpy(capture->interface, interface, sizeof(capture->interface) - 1);
        
        /* Bind to interface if specified */
#ifdef SO_BINDTODEVICE
        if (setsockopt(*(int*)capture->sock, SOL_SOCKET, SO_BINDTODEVICE,
                      interface, strlen(interface)) < 0) {
            /* Non-fatal: continue without binding to specific interface */
        }
#endif
    }
    
    return capture;
}

/* Capture next packet */
int easy_capture_next(easy_capture_t* capture, void* buffer, size_t buffer_size,
                      easy_packet_info_t* info) {
    if (!capture || !buffer || buffer_size == 0) {
        return EASY_ERROR_INVALID_PARAM;
    }
    
    rawsock_packet_info_t raw_info;
    int bytes = rawsock_recv(capture->sock, buffer, buffer_size, &raw_info);
    
    if (bytes > 0) {
        /* Filter by protocol if specified */
        if (capture->protocol != PROTO_ALL) {
            const struct iphdr* ip = (const struct iphdr*)buffer;
            if (ip->protocol != capture->protocol) {
                /* Not the protocol we want, try again */
                return easy_capture_next(capture, buffer, buffer_size, info);
            }
        }
        
        if (info) {
            extract_packet_info(buffer, bytes, info);
        }
    }
    
    return bytes;
}

/* Capture next packet with timeout */
int easy_capture_next_timeout(easy_capture_t* capture, void* buffer, size_t buffer_size,
                               int timeout_ms, easy_packet_info_t* info) {
    if (!capture || !buffer || buffer_size == 0) {
        return EASY_ERROR_INVALID_PARAM;
    }
    
    /* Set timeout */
    rawsock_set_option(capture->sock, SO_RCVTIMEO, &timeout_ms, sizeof(timeout_ms));
    
    int result = easy_capture_next(capture, buffer, buffer_size, info);
    
    /* Reset timeout */
    int zero = 0;
    rawsock_set_option(capture->sock, SO_RCVTIMEO, &zero, sizeof(zero));
    
    if (result == -1 && errno == EAGAIN) {
        return EASY_ERROR_TIMEOUT;
    }
    
    return result;
}

/* Stop packet capture */
void easy_capture_stop(easy_capture_t* capture) {
    if (capture) {
        if (capture->sock) {
            rawsock_destroy(capture->sock);
        }
        free(capture);
    }
}

/* Build and send packet */
static int build_and_send_packet(const char* interface, const char* dest_ip,
                                 uint16_t dest_port, uint16_t src_port,
                                 const void* payload, size_t payload_size,
                                 uint8_t protocol) {
    uint8_t packet[RAWSOCK_MAX_PACKET_SIZE];
    size_t packet_size = 0;
    
    /* Build IP header */
    struct iphdr* ip = (struct iphdr*)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->id = htons(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->check = 0;
    
    /* Set destination IP */
    struct in_addr dst_addr;
    if (inet_pton(AF_INET, dest_ip, &dst_addr) != 1) {
        return EASY_ERROR_INVALID_PARAM;
    }
    ip->daddr = dst_addr.s_addr;
    
    /* Get source IP from interface or use INADDR_ANY */
    ip->saddr = INADDR_ANY;
    if (interface) {
        struct ifaddrs *ifap, *ifa;
        if (getifaddrs(&ifap) == 0) {
            for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
                    strcmp(ifa->ifa_name, interface) == 0) {
                    struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
                    ip->saddr = sa->sin_addr.s_addr;
                    break;
                }
            }
            freeifaddrs(ifap);
        }
    }
    
    packet_size = sizeof(struct iphdr);
    
    /* Build transport header based on protocol */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(packet + packet_size);
        tcp->source = htons(src_port ? src_port : (40000 + rand() % 20000));
        tcp->dest = htons(dest_port);
        tcp->seq = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->urg_ptr = 0;
        packet_size += sizeof(struct tcphdr);
        
        /* Add payload */
        if (payload && payload_size > 0) {
            memcpy(packet + packet_size, payload, payload_size);
            packet_size += payload_size;
        }
        
        /* Calculate TCP checksum */
        tcp->check = rawsock_calculate_transport_checksum(&ip->saddr, &ip->daddr,
                                                         sizeof(uint32_t), IPPROTO_TCP,
                                                         tcp, packet_size - sizeof(struct iphdr));
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(packet + packet_size);
        udp->source = htons(src_port ? src_port : (40000 + rand() % 20000));
        udp->dest = htons(dest_port);
        udp->len = htons(sizeof(struct udphdr) + payload_size);
        udp->check = 0;
        packet_size += sizeof(struct udphdr);
        
        /* Add payload */
        if (payload && payload_size > 0) {
            memcpy(packet + packet_size, payload, payload_size);
            packet_size += payload_size;
        }
        
        /* Calculate UDP checksum (optional but recommended) */
        udp->check = rawsock_calculate_transport_checksum(&ip->saddr, &ip->daddr,
                                                         sizeof(uint32_t), IPPROTO_UDP,
                                                         udp, packet_size - sizeof(struct iphdr));
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr* icmp = (struct icmphdr*)(packet + packet_size);
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->un.echo.id = htons(getpid());
        icmp->un.echo.sequence = htons(1);
        packet_size += sizeof(struct icmphdr);
        
        /* Add payload */
        if (payload && payload_size > 0) {
            memcpy(packet + packet_size, payload, payload_size);
            packet_size += payload_size;
        }
        
        /* Calculate ICMP checksum */
        icmp->checksum = rawsock_calculate_ip_checksum(icmp, 
                                                       packet_size - sizeof(struct iphdr));
    } else {
        /* Raw IP packet with custom protocol */
        if (payload && payload_size > 0) {
            memcpy(packet + packet_size, payload, payload_size);
            packet_size += payload_size;
        }
    }
    
    /* Update IP header */
    ip->tot_len = htons(packet_size);
    ip->check = rawsock_calculate_ip_checksum(ip, sizeof(struct iphdr));
    
    /* Create socket and send */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_RAW,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        return EASY_ERROR_SOCKET;
    }
    
    int result;
    if (interface) {
        result = rawsock_send_to_interface(sock, packet, packet_size, dest_ip, interface);
    } else {
        result = rawsock_send(sock, packet, packet_size, dest_ip);
    }
    
    rawsock_destroy(sock);
    
    return result > 0 ? result : EASY_ERROR_SEND_FAILED;
}

/* Send packet */
int easy_send(const char* interface, const char* dest_ip, uint16_t dest_port,
              const void* payload, size_t payload_size, uint8_t protocol) {
    return build_and_send_packet(interface, dest_ip, dest_port, 0,
                                 payload, payload_size, protocol);
}

/* Send packet with source port */
int easy_send_from(const char* interface, const char* dest_ip, uint16_t dest_port,
                   uint16_t src_port, const void* payload, size_t payload_size,
                   uint8_t protocol) {
    return build_and_send_packet(interface, dest_ip, dest_port, src_port,
                                 payload, payload_size, protocol);
}

/* Send ICMP packet */
int easy_send_icmp(const char* interface, const char* dest_ip,
                   const void* payload, size_t payload_size) {
    return build_and_send_packet(interface, dest_ip, 0, 0,
                                 payload, payload_size, IPPROTO_ICMP);
}

/* Send raw packet */
int easy_send_raw(const char* interface, const void* packet, size_t packet_size) {
    if (!packet || packet_size == 0) {
        return EASY_ERROR_INVALID_PARAM;
    }
    
    /* Extract destination IP from packet */
    const struct iphdr* ip = (const struct iphdr*)packet;
    struct in_addr dst_addr;
    dst_addr.s_addr = ip->daddr;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst_addr, dest_ip, sizeof(dest_ip));
    
    /* Create socket and send */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_RAW,
        .recv_timeout_ms = 0,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        return EASY_ERROR_SOCKET;
    }
    
    int result;
    if (interface) {
        result = rawsock_send_to_interface(sock, packet, packet_size, dest_ip, interface);
    } else {
        result = rawsock_send(sock, packet, packet_size, dest_ip);
    }
    
    rawsock_destroy(sock);
    
    return result > 0 ? result : EASY_ERROR_SEND_FAILED;
}

/* Get error string */
const char* easy_error_string(easy_error_t error) {
    switch (error) {
        case EASY_SUCCESS: return "Success";
        case EASY_ERROR_INVALID_PARAM: return "Invalid parameter";
        case EASY_ERROR_PERMISSION: return "Permission denied (need root/sudo)";
        case EASY_ERROR_SOCKET: return "Socket operation failed";
        case EASY_ERROR_INTERFACE: return "Interface error";
        case EASY_ERROR_TIMEOUT: return "Operation timed out";
        case EASY_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case EASY_ERROR_SEND_FAILED: return "Send failed";
        case EASY_ERROR_RECV_FAILED: return "Receive failed";
        case EASY_ERROR_UNKNOWN: return "Unknown error";
        default: return "Invalid error code";
    }
}

/* Check privileges */
int easy_check_privileges(void) {
    return rawsock_check_privileges();
}

/* List interfaces */
int easy_list_interfaces(char interfaces[][32], int max_interfaces) {
    struct ifaddrs *ifap, *ifa;
    int count = 0;
    
    if (getifaddrs(&ifap) != 0) {
        return EASY_ERROR_INTERFACE;
    }
    
    for (ifa = ifap; ifa != NULL && count < max_interfaces; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            /* Check if interface already in list */
            int found = 0;
            for (int i = 0; i < count; i++) {
                if (strcmp(interfaces[i], ifa->ifa_name) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                strncpy(interfaces[count], ifa->ifa_name, 31);
                interfaces[count][31] = '\0';
                count++;
            }
        }
    }
    
    freeifaddrs(ifap);
    return count;
}

/* Get default interface */
int easy_get_default_interface(char* interface) {
    if (!interface) {
        return EASY_ERROR_INVALID_PARAM;
    }
    
    /* Try to find the first non-loopback interface */
    char interfaces[10][32];
    int count = easy_list_interfaces(interfaces, 10);
    
    if (count <= 0) {
        return EASY_ERROR_INTERFACE;
    }
    
    for (int i = 0; i < count; i++) {
        if (strcmp(interfaces[i], "lo") != 0) {
            strcpy(interface, interfaces[i]);
            return EASY_SUCCESS;
        }
    }
    
    /* If only loopback found, use it */
    strcpy(interface, interfaces[0]);
    return EASY_SUCCESS;
}

#endif /* RAWSOCK_EASY_IMPLEMENTATION */

#ifdef __cplusplus
}
#endif

#endif /* RAWSOCK_EASY_H */