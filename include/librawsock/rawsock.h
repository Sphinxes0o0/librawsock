/**
 * @file rawsock.h
 * @brief Raw Socket Network Library - Main API
 * @author LibRawSock Team
 * @version 1.0.0
 * 
 * This library provides a clean, cross-platform interface for raw socket
 * programming. It supports IPv4/IPv6, various protocols, and includes
 * utilities for packet construction and parsing.
 */

#ifndef LIBRAWSOCK_RAWSOCK_H
#define LIBRAWSOCK_RAWSOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/**
 * @brief Library version information
 */
#define RAWSOCK_VERSION_MAJOR 1
#define RAWSOCK_VERSION_MINOR 0
#define RAWSOCK_VERSION_PATCH 0
#define RAWSOCK_VERSION_STRING "1.0.0"

/**
 * @brief Maximum packet size supported
 */
#define RAWSOCK_MAX_PACKET_SIZE 65535

/**
 * @brief Raw socket address family types
 */
typedef enum {
    RAWSOCK_IPV4 = 0,     /**< IPv4 address family */
    RAWSOCK_IPV6 = 1      /**< IPv6 address family */
} rawsock_family_t;

/**
 * @brief Raw socket error codes
 */
typedef enum {
    RAWSOCK_SUCCESS = 0,           /**< Operation successful */
    RAWSOCK_ERROR_INVALID_PARAM,   /**< Invalid parameter */
    RAWSOCK_ERROR_SOCKET_CREATE,   /**< Socket creation failed */
    RAWSOCK_ERROR_SOCKET_BIND,     /**< Socket bind failed */
    RAWSOCK_ERROR_SEND,            /**< Send operation failed */
    RAWSOCK_ERROR_RECV,            /**< Receive operation failed */
    RAWSOCK_ERROR_PERMISSION,      /**< Insufficient permissions */
    RAWSOCK_ERROR_TIMEOUT,         /**< Operation timed out */
    RAWSOCK_ERROR_BUFFER_TOO_SMALL,/**< Buffer too small */
    RAWSOCK_ERROR_UNKNOWN          /**< Unknown error */
} rawsock_error_t;

/**
 * @brief Raw socket handle (opaque structure)
 */
typedef struct rawsock rawsock_t;

/**
 * @brief Socket configuration structure
 */
typedef struct {
    rawsock_family_t family;       /**< Address family */
    int protocol;                  /**< Protocol number */
    int recv_timeout_ms;           /**< Receive timeout in milliseconds */
    int send_timeout_ms;           /**< Send timeout in milliseconds */
    uint8_t include_ip_header;     /**< Include IP header in packets */
    uint8_t broadcast;             /**< Enable broadcast */
    uint8_t promiscuous;           /**< Enable promiscuous mode */
} rawsock_config_t;

/**
 * @brief Packet information structure
 */
typedef struct {
    char src_addr[46];             /**< Source address string */
    char dst_addr[46];             /**< Destination address string */
    uint16_t src_port;             /**< Source port (if applicable) */
    uint16_t dst_port;             /**< Destination port (if applicable) */
    uint8_t protocol;              /**< Protocol number */
    size_t packet_size;            /**< Total packet size */
    uint64_t timestamp_us;         /**< Timestamp in microseconds */
} rawsock_packet_info_t;

/* ===== Core API Functions ===== */

/**
 * @brief Create a raw socket with default configuration
 * @param family Address family (IPv4 or IPv6)
 * @param protocol Protocol number (e.g., IPPROTO_ICMP, IPPROTO_TCP)
 * @return Raw socket handle on success, NULL on failure
 */
rawsock_t* rawsock_create(rawsock_family_t family, int protocol);

/**
 * @brief Create a raw socket with custom configuration
 * @param config Socket configuration
 * @return Raw socket handle on success, NULL on failure
 */
rawsock_t* rawsock_create_with_config(const rawsock_config_t* config);

/**
 * @brief Destroy a raw socket and free resources
 * @param sock Raw socket handle
 */
void rawsock_destroy(rawsock_t* sock);

/**
 * @brief Send a packet through the raw socket
 * @param sock Raw socket handle
 * @param packet Packet data
 * @param packet_size Size of packet data
 * @param dest_addr Destination address string
 * @return Number of bytes sent on success, negative error code on failure
 */
int rawsock_send(rawsock_t* sock, const void* packet, size_t packet_size, 
                const char* dest_addr);

/**
 * @brief Send a packet to a specific interface
 * @param sock Raw socket handle
 * @param packet Packet data
 * @param packet_size Size of packet data
 * @param dest_addr Destination address string
 * @param interface Interface name (e.g., "eth0")
 * @return Number of bytes sent on success, negative error code on failure
 */
int rawsock_send_to_interface(rawsock_t* sock, const void* packet, 
                             size_t packet_size, const char* dest_addr,
                             const char* interface);

/**
 * @brief Receive a packet from the raw socket
 * @param sock Raw socket handle
 * @param buffer Buffer to store received packet
 * @param buffer_size Size of the buffer
 * @param packet_info Pointer to store packet information (optional)
 * @return Number of bytes received on success, negative error code on failure
 */
int rawsock_recv(rawsock_t* sock, void* buffer, size_t buffer_size,
                rawsock_packet_info_t* packet_info);

/**
 * @brief Set socket option
 * @param sock Raw socket handle
 * @param option Option name
 * @param value Option value
 * @param value_size Size of option value
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_set_option(rawsock_t* sock, int option, 
                                  const void* value, size_t value_size);

/**
 * @brief Get socket option
 * @param sock Raw socket handle
 * @param option Option name
 * @param value Buffer to store option value
 * @param value_size Pointer to size of value buffer
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_get_option(rawsock_t* sock, int option, 
                                  void* value, size_t* value_size);

/**
 * @brief Get the last error code
 * @param sock Raw socket handle
 * @return Last error code
 */
rawsock_error_t rawsock_get_last_error(rawsock_t* sock);

/**
 * @brief Get error string description
 * @param error Error code
 * @return Error description string
 */
const char* rawsock_error_string(rawsock_error_t error);

/* ===== Utility Functions ===== */

/**
 * @brief Get library version string
 * @return Version string
 */
const char* rawsock_get_version(void);

/**
 * @brief Initialize the library (optional, called automatically)
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_init(void);

/**
 * @brief Cleanup library resources (optional)
 */
void rawsock_cleanup(void);

/**
 * @brief Check if the current user has sufficient privileges for raw sockets
 * @return 1 if privileges are sufficient, 0 otherwise
 */
int rawsock_check_privileges(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBRAWSOCK_RAWSOCK_H */

