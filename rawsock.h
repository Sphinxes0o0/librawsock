/**
 * @file rawsock.h
 * @brief Raw Socket Network Library - Single Header Implementation
 * @author Sphinxes0o0
 * @version 1.0.0
 * 
 * This is a lightweight single-header raw socket library for Linux and macOS.
 * It provides a clean interface for raw socket programming with support for
 * IPv4/IPv6, various protocols, and packet construction/parsing utilities.
 * 
 * Usage:
 * #define RAWSOCK_IMPLEMENTATION
 * #include "rawsock.h"
 */

#ifndef RAWSOCK_H
#define RAWSOCK_H

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Standard Headers ===== */
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* ===== Library Version ===== */
#define RAWSOCK_VERSION_MAJOR 1
#define RAWSOCK_VERSION_MINOR 0
#define RAWSOCK_VERSION_PATCH 0
#define RAWSOCK_VERSION_STRING "1.0.0"

/* ===== Constants ===== */
#define RAWSOCK_MAX_PACKET_SIZE 65535
#define RAWSOCK_IP4_HEADER_SIZE 20
#define RAWSOCK_IP6_HEADER_SIZE 40
#define RAWSOCK_TCP_HEADER_SIZE 20
#define RAWSOCK_UDP_HEADER_SIZE 8
#define RAWSOCK_ICMP_HEADER_SIZE 8

/* ===== Type Definitions ===== */

typedef enum {
    RAWSOCK_IPV4 = 0,
    RAWSOCK_IPV6 = 1
} rawsock_family_t;

typedef enum {
    RAWSOCK_SUCCESS = 0,
    RAWSOCK_ERROR_INVALID_PARAM,
    RAWSOCK_ERROR_SOCKET_CREATE,
    RAWSOCK_ERROR_SOCKET_BIND,
    RAWSOCK_ERROR_SEND,
    RAWSOCK_ERROR_RECV,
    RAWSOCK_ERROR_PERMISSION,
    RAWSOCK_ERROR_TIMEOUT,
    RAWSOCK_ERROR_BUFFER_TOO_SMALL,
    RAWSOCK_ERROR_UNKNOWN
} rawsock_error_t;

typedef struct rawsock rawsock_t;

typedef struct {
    rawsock_family_t family;
    int protocol;
    int recv_timeout_ms;
    int send_timeout_ms;
    uint8_t include_ip_header;
    uint8_t broadcast;
    uint8_t promiscuous;
} rawsock_config_t;

typedef struct {
    char src_addr[46];
    char dst_addr[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    size_t packet_size;
    uint64_t timestamp_us;
} rawsock_packet_info_t;

/* ===== Packet Header Structures ===== */

typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed)) rawsock_ipv4_header_t;

typedef struct {
    uint32_t version_class_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
} __attribute__((packed)) rawsock_ipv6_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed)) rawsock_tcp_header_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) rawsock_udp_header_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;
    } data;
} __attribute__((packed)) rawsock_icmp_header_t;

/* ===== Core API Functions ===== */

rawsock_t* rawsock_create(rawsock_family_t family, int protocol);
rawsock_t* rawsock_create_with_config(const rawsock_config_t* config);
void rawsock_destroy(rawsock_t* sock);
int rawsock_send(rawsock_t* sock, const void* packet, size_t packet_size, const char* dest_addr);
int rawsock_send_to_interface(rawsock_t* sock, const void* packet, size_t packet_size, 
                             const char* dest_addr, const char* interface);
int rawsock_recv(rawsock_t* sock, void* buffer, size_t buffer_size, rawsock_packet_info_t* packet_info);
rawsock_error_t rawsock_set_option(rawsock_t* sock, int option, const void* value, size_t value_size);
rawsock_error_t rawsock_get_option(rawsock_t* sock, int option, void* value, size_t* value_size);
rawsock_error_t rawsock_get_last_error(rawsock_t* sock);
const char* rawsock_error_string(rawsock_error_t error);

/* ===== Utility Functions ===== */

const char* rawsock_get_version(void);
rawsock_error_t rawsock_init(void);
void rawsock_cleanup(void);
int rawsock_check_privileges(void);

/* ===== Packet Parsing Functions ===== */

rawsock_error_t rawsock_parse_ipv4_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv4_header_t* header);
rawsock_error_t rawsock_parse_ipv6_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv6_header_t* header);
rawsock_error_t rawsock_parse_tcp_header(const void* packet_data, size_t packet_size,
                                         rawsock_tcp_header_t* header);
rawsock_error_t rawsock_parse_udp_header(const void* packet_data, size_t packet_size,
                                         rawsock_udp_header_t* header);
rawsock_error_t rawsock_parse_icmp_header(const void* packet_data, size_t packet_size,
                                          rawsock_icmp_header_t* header);

/* ===== Checksum Functions ===== */

uint16_t rawsock_calculate_ip_checksum(const void* data, size_t length);
uint16_t rawsock_calculate_transport_checksum(const void* src_addr, const void* dst_addr,
                                             size_t addr_len, uint8_t protocol,
                                             const void* data, size_t length);

/* ===== Address Conversion Functions ===== */

rawsock_error_t rawsock_addr_str_to_bin(const char* addr_str, rawsock_family_t family, void* addr_bin);
rawsock_error_t rawsock_addr_bin_to_str(const void* addr_bin, rawsock_family_t family, char* addr_str);

/* ===== Implementation ===== */

#ifdef RAWSOCK_IMPLEMENTATION

/* Feature test macros for POSIX compliance */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <time.h>
#include <sys/ioctl.h>

/* Platform-specific headers */
#ifdef __linux__
#include <linux/if_packet.h>
#endif

/* For SO_BINDTODEVICE */
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

/* For missing constants */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* For SOCK_CLOEXEC (not available on all platforms) */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

/* For INET_ADDRSTRLEN and INET6_ADDRSTRLEN */
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* For CLOCK_MONOTONIC */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif



/* Internal raw socket structure */
struct rawsock {
    int sockfd;
    rawsock_family_t family;
    int protocol;
    rawsock_error_t last_error;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    
    /* Configuration */
    int recv_timeout_ms;
    int send_timeout_ms;
    uint8_t include_ip_header;
    uint8_t broadcast;
    uint8_t promiscuous;
};

/* Static variables */
static int g_rawsock_initialized = 0;

/* Internal function declarations */
static rawsock_error_t set_socket_options(rawsock_t* sock);
static rawsock_error_t addr_string_to_sockaddr(const char* addr_str, rawsock_family_t family,
                                               struct sockaddr_storage* addr, socklen_t* addr_len);
static uint64_t get_timestamp_us(void);

/* ===== Core API Implementation ===== */

rawsock_t* rawsock_create(rawsock_family_t family, int protocol) {
    rawsock_config_t config = {
        .family = family,
        .protocol = protocol,
        .recv_timeout_ms = 5000,
        .send_timeout_ms = 5000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };
    
    return rawsock_create_with_config(&config);
}

rawsock_t* rawsock_create_with_config(const rawsock_config_t* config) {
    if (!config) {
        return NULL;
    }
    
    /* Initialize library if needed */
    if (!g_rawsock_initialized) {
        rawsock_init();
    }
    
    /* Allocate socket structure */
    rawsock_t* sock = calloc(1, sizeof(rawsock_t));
    if (!sock) {
        return NULL;
    }
    
    /* Copy configuration */
    sock->family = config->family;
    sock->protocol = config->protocol;
    sock->recv_timeout_ms = config->recv_timeout_ms;
    sock->send_timeout_ms = config->send_timeout_ms;
    sock->include_ip_header = config->include_ip_header;
    sock->broadcast = config->broadcast;
    sock->promiscuous = config->promiscuous;
    sock->last_error = RAWSOCK_SUCCESS;
    
    /* Create socket */
    int domain = (config->family == RAWSOCK_IPV4) ? AF_INET : AF_INET6;
    sock->sockfd = socket(domain, SOCK_RAW | SOCK_CLOEXEC, config->protocol);
    
    if (sock->sockfd < 0) {
        /* Check for permission error */
        if (errno == EPERM || errno == EACCES) {
            sock->last_error = RAWSOCK_ERROR_PERMISSION;
        } else {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
        }
        free(sock);
        return NULL;
    }
    
    /* Set socket options */
    if (set_socket_options(sock) != RAWSOCK_SUCCESS) {
        close(sock->sockfd);
        free(sock);
        return NULL;
    }
    
    return sock;
}

void rawsock_destroy(rawsock_t* sock) {
    if (!sock) {
        return;
    }
    
    if (sock->sockfd >= 0) {
        close(sock->sockfd);
    }
    
    free(sock);
}

int rawsock_send(rawsock_t* sock, const void* packet, size_t packet_size, const char* dest_addr) {
    if (!sock || !packet || packet_size == 0 || !dest_addr) {
        if (sock) {
            sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        }
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Convert destination address */
    struct sockaddr_storage dest_sockaddr;
    socklen_t dest_addr_len;
    rawsock_error_t err = addr_string_to_sockaddr(dest_addr, sock->family,
                                                  &dest_sockaddr, &dest_addr_len);
    if (err != RAWSOCK_SUCCESS) {
        sock->last_error = err;
        return -err;
    }
    
    /* Send packet */
    ssize_t sent = sendto(sock->sockfd, packet, packet_size, 0,
                         (struct sockaddr*)&dest_sockaddr, dest_addr_len);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            sock->last_error = RAWSOCK_ERROR_TIMEOUT;
            return -RAWSOCK_ERROR_TIMEOUT;
        } else {
            sock->last_error = RAWSOCK_ERROR_SEND;
            return -RAWSOCK_ERROR_SEND;
        }
    }
    
    sock->last_error = RAWSOCK_SUCCESS;
    return (int)sent;
}

int rawsock_send_to_interface(rawsock_t* sock, const void* packet, size_t packet_size,
                             const char* dest_addr, const char* interface) {
    if (!sock || !packet || packet_size == 0 || !dest_addr || !interface) {
        if (sock) {
            sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        }
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
    
#ifdef SO_BINDTODEVICE
    /* Set socket to use specific interface (Linux) */
    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1) < 0) {
        sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
#else
    /* Platform doesn't support SO_BINDTODEVICE */
    (void)interface; /* Suppress unused parameter warning */
    /* Could implement alternative methods for other platforms here */
#endif
    
    /* Send using normal send function */
    return rawsock_send(sock, packet, packet_size, dest_addr);
}

int rawsock_recv(rawsock_t* sock, void* buffer, size_t buffer_size,
                rawsock_packet_info_t* packet_info) {
    if (!sock || !buffer || buffer_size == 0) {
        if (sock) {
            sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        }
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    
    /* Receive packet */
    ssize_t received = recvfrom(sock->sockfd, buffer, buffer_size, 0,
                               (struct sockaddr*)&src_addr, &src_addr_len);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            sock->last_error = RAWSOCK_ERROR_TIMEOUT;
            return -RAWSOCK_ERROR_TIMEOUT;
        } else {
            sock->last_error = RAWSOCK_ERROR_RECV;
            return -RAWSOCK_ERROR_RECV;
        }
    }
    
    /* Fill packet info if requested */
    if (packet_info) {
        memset(packet_info, 0, sizeof(*packet_info));
        
        /* Source address */
        if (src_addr.ss_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)&src_addr;
            inet_ntop(AF_INET, &sin->sin_addr, packet_info->src_addr,
                     sizeof(packet_info->src_addr));
            packet_info->src_port = ntohs(sin->sin_port);
        } else if (src_addr.ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&src_addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, packet_info->src_addr,
                     sizeof(packet_info->src_addr));
            packet_info->src_port = ntohs(sin6->sin6_port);
        }
        
        /* Destination (local) address via getsockname */
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        if (getsockname(sock->sockfd, (struct sockaddr*)&local_addr, &local_len) == 0) {
            if (local_addr.ss_family == AF_INET) {
                struct sockaddr_in* lin = (struct sockaddr_in*)&local_addr;
                inet_ntop(AF_INET, &lin->sin_addr, packet_info->dst_addr, sizeof(packet_info->dst_addr));
                packet_info->dst_port = ntohs(lin->sin_port);
            } else if (local_addr.ss_family == AF_INET6) {
                struct sockaddr_in6* lin6 = (struct sockaddr_in6*)&local_addr;
                inet_ntop(AF_INET6, &lin6->sin6_addr, packet_info->dst_addr, sizeof(packet_info->dst_addr));
                packet_info->dst_port = ntohs(lin6->sin6_port);
            }
        }
        
        packet_info->protocol = sock->protocol;
        packet_info->packet_size = received;
        packet_info->timestamp_us = get_timestamp_us();
    }
    
    sock->last_error = RAWSOCK_SUCCESS;
    return (int)received;
}

rawsock_error_t rawsock_set_option(rawsock_t* sock, int option, const void* value, size_t value_size) {
    if (!sock || !value) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    if (setsockopt(sock->sockfd, SOL_SOCKET, option, value, value_size) < 0) {
        sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    sock->last_error = RAWSOCK_SUCCESS;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_get_option(rawsock_t* sock, int option, void* value, size_t* value_size) {
    if (!sock || !value || !value_size) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    socklen_t len = *value_size;
    if (getsockopt(sock->sockfd, SOL_SOCKET, option, value, &len) < 0) {
        sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    *value_size = len;
    sock->last_error = RAWSOCK_SUCCESS;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_get_last_error(rawsock_t* sock) {
    return sock ? sock->last_error : RAWSOCK_ERROR_INVALID_PARAM;
}

const char* rawsock_error_string(rawsock_error_t error) {
    switch (error) {
        case RAWSOCK_SUCCESS:
            return "Success";
        case RAWSOCK_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case RAWSOCK_ERROR_SOCKET_CREATE:
            return "Socket creation failed";
        case RAWSOCK_ERROR_SOCKET_BIND:
            return "Socket bind failed";
        case RAWSOCK_ERROR_SEND:
            return "Send operation failed";
        case RAWSOCK_ERROR_RECV:
            return "Receive operation failed";
        case RAWSOCK_ERROR_PERMISSION:
            return "Insufficient permissions (root required for raw sockets)";
        case RAWSOCK_ERROR_TIMEOUT:
            return "Operation timed out";
        case RAWSOCK_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case RAWSOCK_ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}

/* ===== Utility Functions ===== */

const char* rawsock_get_version(void) {
    return RAWSOCK_VERSION_STRING;
}

rawsock_error_t rawsock_init(void) {
    if (g_rawsock_initialized) {
        return RAWSOCK_SUCCESS;
    }
    
    /* Check if we have necessary privileges */
    if (geteuid() != 0) {
        /* Not running as root - check if capabilities are available */
        /* This is a simplified check - in practice you might want to check
         * for CAP_NET_RAW capability */
    }
    
    g_rawsock_initialized = 1;
    return RAWSOCK_SUCCESS;
}

void rawsock_cleanup(void) {
    g_rawsock_initialized = 0;
}

int rawsock_check_privileges(void) {
    /* Simple check for root privileges */
    if (geteuid() == 0) {
        return 1;
    }
    
    /* Try to create a test raw socket */
    int test_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (test_sock >= 0) {
        close(test_sock);
        return 1;
    }
    
    return 0;
}

/* ===== Internal Helper Functions ===== */

static rawsock_error_t set_socket_options(rawsock_t* sock) {
    /* Set IP header include option */
    if (sock->include_ip_header) {
        int one = 1;
        if (sock->family == RAWSOCK_IPV4) {
            if (setsockopt(sock->sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
                sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
                return RAWSOCK_ERROR_SOCKET_CREATE;
            }
        }
    }
    
    /* Set broadcast option */
    if (sock->broadcast) {
        int one = 1;
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    /* Set receive timeout */
    if (sock->recv_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = sock->recv_timeout_ms / 1000;
        timeout.tv_usec = (sock->recv_timeout_ms % 1000) * 1000;
        
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    /* Set send timeout */
    if (sock->send_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = sock->send_timeout_ms / 1000;
        timeout.tv_usec = (sock->send_timeout_ms % 1000) * 1000;
        
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    return RAWSOCK_SUCCESS;
}

static rawsock_error_t addr_string_to_sockaddr(const char* addr_str, rawsock_family_t family,
                                               struct sockaddr_storage* addr, socklen_t* addr_len) {
    memset(addr, 0, sizeof(*addr));
    
    if (family == RAWSOCK_IPV4) {
        struct sockaddr_in* sin = (struct sockaddr_in*)addr;
        sin->sin_family = AF_INET;
        
        if (inet_pton(AF_INET, addr_str, &sin->sin_addr) != 1) {
            return RAWSOCK_ERROR_INVALID_PARAM;
        }
        
        *addr_len = sizeof(*sin);
    } else if (family == RAWSOCK_IPV6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)addr;
        sin6->sin6_family = AF_INET6;
        
        if (inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 1) {
            return RAWSOCK_ERROR_INVALID_PARAM;
        }
        
        *addr_len = sizeof(*sin6);
    } else {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    return RAWSOCK_SUCCESS;
}

static uint64_t get_timestamp_us(void) {
    /* Use gettimeofday for better compatibility */
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0) {
        return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
    }
    return 0;
}

/* ===== Packet Parsing Implementation ===== */

rawsock_error_t rawsock_parse_ipv4_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv4_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_IP4_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memcpy(header, packet_data, RAWSOCK_IP4_HEADER_SIZE);
    
    /* Convert from network byte order */
    header->total_length = ntohs(header->total_length);
    header->id = ntohs(header->id);
    header->flags_fragment = ntohs(header->flags_fragment);
    header->checksum = ntohs(header->checksum);
    header->src_addr = ntohl(header->src_addr);
    header->dst_addr = ntohl(header->dst_addr);
    
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_ipv6_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv6_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_IP6_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memcpy(header, packet_data, RAWSOCK_IP6_HEADER_SIZE);
    
    /* Convert from network byte order */
    header->version_class_label = ntohl(header->version_class_label);
    header->payload_length = ntohs(header->payload_length);
    
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_tcp_header(const void* packet_data, size_t packet_size,
                                         rawsock_tcp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_TCP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memcpy(header, packet_data, RAWSOCK_TCP_HEADER_SIZE);
    
    /* Convert from network byte order */
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->seq_num = ntohl(header->seq_num);
    header->ack_num = ntohl(header->ack_num);
    header->window = ntohs(header->window);
    header->checksum = ntohs(header->checksum);
    header->urgent_ptr = ntohs(header->urgent_ptr);
    
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_udp_header(const void* packet_data, size_t packet_size,
                                         rawsock_udp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_UDP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memcpy(header, packet_data, RAWSOCK_UDP_HEADER_SIZE);
    
    /* Convert from network byte order */
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->length = ntohs(header->length);
    header->checksum = ntohs(header->checksum);
    
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_icmp_header(const void* packet_data, size_t packet_size,
                                          rawsock_icmp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_ICMP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memcpy(header, packet_data, RAWSOCK_ICMP_HEADER_SIZE);
    
    /* Convert from network byte order */
    header->checksum = ntohs(header->checksum);
    
    if (header->type == 8 || header->type == 0) {  /* Echo Request/Reply */
        header->data.echo.id = ntohs(header->data.echo.id);
        header->data.echo.sequence = ntohs(header->data.echo.sequence);
    } else {
        header->data.gateway = ntohl(header->data.gateway);
    }
    
    return RAWSOCK_SUCCESS;
}

/* ===== Checksum Functions Implementation ===== */

uint16_t rawsock_calculate_ip_checksum(const void* data, size_t length) {
    uint32_t sum = 0;
    const uint16_t* ptr = (const uint16_t*)data;
    
    /* Sum all 16-bit words */
    for (size_t i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }
    
    /* Add odd byte if present */
    if (length % 2) {
        sum += ((const uint8_t*)data)[length - 1] << 8;
    }
    
    /* Fold carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint16_t rawsock_calculate_transport_checksum(const void* src_addr, const void* dst_addr,
                                             size_t addr_len, uint8_t protocol,
                                             const void* data, size_t length) {
    if (!src_addr || !dst_addr || !data || addr_len == 0) {
        return 0;
    }
    
    /* Create pseudo header */
    uint8_t pseudo_header[40];  /* Max size for IPv6 */
    size_t pseudo_size = 0;
    
    /* Copy addresses */
    memcpy(pseudo_header, src_addr, addr_len);
    memcpy(pseudo_header + addr_len, dst_addr, addr_len);
    pseudo_size = addr_len * 2;
    
    if (addr_len == 4) {  /* IPv4 */
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = protocol;
        uint16_t len = htons(length);
        memcpy(pseudo_header + pseudo_size, &len, 2);
        pseudo_size += 2;
    } else {  /* IPv6 */
        uint32_t len = htonl(length);
        memcpy(pseudo_header + pseudo_size, &len, 4);
        pseudo_size += 4;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = protocol;
    }
    
    /* Calculate checksum over pseudo header + data */
    uint32_t sum = 0;
    
    /* Pseudo header */
    const uint16_t* ptr = (const uint16_t*)pseudo_header;
    for (size_t i = 0; i < pseudo_size / 2; i++) {
        sum += ptr[i];
    }
    if (pseudo_size % 2) {
        sum += ((const uint8_t*)pseudo_header)[pseudo_size - 1] << 8;
    }
    
    /* Data */
    ptr = (const uint16_t*)data;
    for (size_t i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }
    if (length % 2) {
        sum += ((const uint8_t*)data)[length - 1] << 8;
    }
    
    /* Fold carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/* ===== Address Conversion Functions Implementation ===== */

rawsock_error_t rawsock_addr_str_to_bin(const char* addr_str, rawsock_family_t family, void* addr_bin) {
    if (!addr_str || !addr_bin) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    int af = (family == RAWSOCK_IPV4) ? AF_INET : AF_INET6;
    
    if (inet_pton(af, addr_str, addr_bin) != 1) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_addr_bin_to_str(const void* addr_bin, rawsock_family_t family, char* addr_str) {
    if (!addr_bin || !addr_str) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    int af = (family == RAWSOCK_IPV4) ? AF_INET : AF_INET6;
    
    if (!inet_ntop(af, addr_bin, addr_str,
                  (family == RAWSOCK_IPV4) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN)) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    return RAWSOCK_SUCCESS;
}

#endif /* RAWSOCK_IMPLEMENTATION */

#ifdef __cplusplus
}
#endif

#endif /* RAWSOCK_H */