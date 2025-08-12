/**
 * @file rawsock.c
 * @brief Raw Socket Network Library - Core Implementation
 * @author LibRawSock Team
 * @version 1.0.0
 */

#define _GNU_SOURCE
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
#include <linux/if_packet.h>
#include <sys/ioctl.h>

/* For SO_BINDTODEVICE */
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 25
#endif

/* For missing constants */
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#include "librawsock/rawsock.h"

/**
 * @brief Internal raw socket structure
 */
struct rawsock {
    int sockfd;                    /**< Socket file descriptor */
    rawsock_family_t family;       /**< Address family */
    int protocol;                  /**< Protocol number */
    rawsock_error_t last_error;    /**< Last error code */
    struct sockaddr_storage local_addr;  /**< Local address */
    socklen_t local_addr_len;      /**< Local address length */
    
    /* Configuration */
    int recv_timeout_ms;           /**< Receive timeout */
    int send_timeout_ms;           /**< Send timeout */
    uint8_t include_ip_header;     /**< Include IP header flag */
    uint8_t broadcast;             /**< Broadcast flag */
    uint8_t promiscuous;           /**< Promiscuous mode flag */
};

/* Static variables */
static int g_rawsock_initialized = 0;

/* Internal function declarations */
static rawsock_error_t set_socket_options(rawsock_t* sock);
static rawsock_error_t addr_string_to_sockaddr(const char* addr_str, 
                                               rawsock_family_t family,
                                               struct sockaddr_storage* addr,
                                               socklen_t* addr_len);
static uint64_t get_timestamp_us(void);

/* ===== Core API Implementation ===== */

rawsock_t* rawsock_create(rawsock_family_t family, int protocol) {
    rawsock_config_t config = {
        .family = family,
        .protocol = protocol,
        .recv_timeout_ms = 5000,    /* 5 seconds default */
        .send_timeout_ms = 5000,    /* 5 seconds default */
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

int rawsock_send(rawsock_t* sock, const void* packet, size_t packet_size, 
                const char* dest_addr) {
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

int rawsock_send_to_interface(rawsock_t* sock, const void* packet, 
                             size_t packet_size, const char* dest_addr,
                             const char* interface) {
    if (!sock || !packet || packet_size == 0 || !dest_addr || !interface) {
        if (sock) {
            sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        }
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Set socket to use specific interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (setsockopt(sock->sockfd, SOL_SOCKET, SO_BINDTODEVICE, 
                   &ifr, sizeof(ifr)) < 0) {
        sock->last_error = RAWSOCK_ERROR_INVALID_PARAM;
        return -RAWSOCK_ERROR_INVALID_PARAM;
    }
    
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

rawsock_error_t rawsock_set_option(rawsock_t* sock, int option, 
                                  const void* value, size_t value_size) {
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

rawsock_error_t rawsock_get_option(rawsock_t* sock, int option, 
                                  void* value, size_t* value_size) {
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
            if (setsockopt(sock->sockfd, IPPROTO_IP, IP_HDRINCL, 
                          &one, sizeof(one)) < 0) {
                sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
                return RAWSOCK_ERROR_SOCKET_CREATE;
            }
        }
    }
    
    /* Set broadcast option */
    if (sock->broadcast) {
        int one = 1;
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_BROADCAST, 
                      &one, sizeof(one)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    /* Set receive timeout */
    if (sock->recv_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = sock->recv_timeout_ms / 1000;
        timeout.tv_usec = (sock->recv_timeout_ms % 1000) * 1000;
        
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_RCVTIMEO, 
                      &timeout, sizeof(timeout)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    /* Set send timeout */
    if (sock->send_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = sock->send_timeout_ms / 1000;
        timeout.tv_usec = (sock->send_timeout_ms % 1000) * 1000;
        
        if (setsockopt(sock->sockfd, SOL_SOCKET, SO_SNDTIMEO, 
                      &timeout, sizeof(timeout)) < 0) {
            sock->last_error = RAWSOCK_ERROR_SOCKET_CREATE;
            return RAWSOCK_ERROR_SOCKET_CREATE;
        }
    }
    
    return RAWSOCK_SUCCESS;
}

static rawsock_error_t addr_string_to_sockaddr(const char* addr_str, 
                                               rawsock_family_t family,
                                               struct sockaddr_storage* addr,
                                               socklen_t* addr_len) {
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
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
    }
#endif
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
    }
    return 0;
}

