/**
 * @file rawsock_c.h
 * @brief C interface for rawsock library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * This header provides a pure C interface for the rawsock library,
 * allowing C programs to use the library's functionality.
 *
 * Example usage:
 * @code
 * #include <rawsock/rawsock_c.h>
 * 
 * int main() {
 *     if (!rawsock_check_privileges()) {
 *         printf("Root privileges required\n");
 *         return 1;
 *     }
 *     
 *     rawsock_capture_t* cap = rawsock_capture_create();
 *     if (!cap) return 1;
 *     
 *     rawsock_config_t config;
 *     rawsock_config_init(&config);
 *     strcpy(config.interface_name, "eth0");
 *     config.filter_protocol = RAWSOCK_PROTO_TCP;
 *     
 *     if (rawsock_capture_open(cap, &config) == RAWSOCK_SUCCESS) {
 *         uint8_t buffer[65535];
 *         rawsock_packet_info_t info;
 *         
 *         int bytes = rawsock_capture_next(cap, buffer, sizeof(buffer), &info);
 *         if (bytes > 0) {
 *             printf("Captured: %s -> %s\n", info.src_addr, info.dst_addr);
 *         }
 *     }
 *     
 *     rawsock_capture_destroy(cap);
 *     return 0;
 * }
 * @endcode
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_C_H
#define RAWSOCK_C_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Export macros */
#if defined(RAWSOCK_SHARED_LIB)
    #if defined(_WIN32) || defined(_WIN64)
        #if defined(RAWSOCK_BUILDING_LIB)
            #define RAWSOCK_C_API __declspec(dllexport)
        #else
            #define RAWSOCK_C_API __declspec(dllimport)
        #endif
    #else
        #define RAWSOCK_C_API __attribute__((visibility("default")))
    #endif
#else
    #define RAWSOCK_C_API
#endif

/* Constants */
#define RAWSOCK_MAX_PACKET_SIZE 65535
#define RAWSOCK_MAX_INTERFACE_NAME 64
#define RAWSOCK_MAX_ADDR_STR 46

/* Protocol numbers */
typedef enum {
    RAWSOCK_PROTO_ALL = 0,
    RAWSOCK_PROTO_ICMP = 1,
    RAWSOCK_PROTO_TCP = 6,
    RAWSOCK_PROTO_UDP = 17,
    RAWSOCK_PROTO_ICMPV6 = 58,
    RAWSOCK_PROTO_RAW = 255
} rawsock_protocol_t;

/* Error codes */
typedef enum {
    RAWSOCK_SUCCESS = 0,
    RAWSOCK_ERROR_INVALID_ARGUMENT,
    RAWSOCK_ERROR_SOCKET_CREATE,
    RAWSOCK_ERROR_SOCKET_BIND,
    RAWSOCK_ERROR_SEND,
    RAWSOCK_ERROR_RECV,
    RAWSOCK_ERROR_PERMISSION,
    RAWSOCK_ERROR_TIMEOUT,
    RAWSOCK_ERROR_BUFFER_TOO_SMALL,
    RAWSOCK_ERROR_INTERFACE_NOT_FOUND,
    RAWSOCK_ERROR_NOT_SUPPORTED,
    RAWSOCK_ERROR_UNKNOWN
} rawsock_error_t;

/* Opaque capture handle */
typedef struct rawsock_capture rawsock_capture_t;

/* Configuration structure */
typedef struct {
    char interface_name[RAWSOCK_MAX_INTERFACE_NAME];
    rawsock_protocol_t filter_protocol;
    int recv_timeout_ms;
    int send_timeout_ms;
    int promiscuous;
    size_t buffer_size;
} rawsock_config_t;

/* Packet information structure */
typedef struct {
    char src_addr[RAWSOCK_MAX_ADDR_STR];
    char dst_addr[RAWSOCK_MAX_ADDR_STR];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    size_t packet_size;
    uint64_t timestamp_us;
    char interface_name[RAWSOCK_MAX_INTERFACE_NAME];
} rawsock_packet_info_t;

/* Ethernet header structure */
typedef struct {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} __attribute__((packed)) rawsock_ethernet_header_t;

/* IPv4 header structure */
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

/* TCP header structure */
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

/* UDP header structure */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) rawsock_udp_header_t;

/* ICMP header structure */
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
    } data;
} __attribute__((packed)) rawsock_icmp_header_t;

/* Packet callback function type */
typedef void (*rawsock_packet_handler_t)(const uint8_t* data, size_t size, 
                                         const rawsock_packet_info_t* info, 
                                         void* user_data);

/* ============= Library Functions ============= */

/**
 * @brief Get library version string
 * @return Version string
 */
RAWSOCK_C_API const char* rawsock_version(void);

/**
 * @brief Get library version as integer
 * @return Version number (major * 10000 + minor * 100 + patch)
 */
RAWSOCK_C_API int rawsock_version_number(void);

/**
 * @brief Check if running with required privileges
 * @return 1 if privileges are sufficient, 0 otherwise
 */
RAWSOCK_C_API int rawsock_check_privileges(void);

/**
 * @brief Get error string for error code
 * @param error Error code
 * @return Error string
 */
RAWSOCK_C_API const char* rawsock_error_string(rawsock_error_t error);

/* ============= Configuration Functions ============= */

/**
 * @brief Initialize configuration with defaults
 * @param config Configuration structure to initialize
 */
RAWSOCK_C_API void rawsock_config_init(rawsock_config_t* config);

/* ============= Capture Functions ============= */

/**
 * @brief Create a new capture instance
 * @return Capture handle, or NULL on error
 */
RAWSOCK_C_API rawsock_capture_t* rawsock_capture_create(void);

/**
 * @brief Destroy a capture instance
 * @param capture Capture handle
 */
RAWSOCK_C_API void rawsock_capture_destroy(rawsock_capture_t* capture);

/**
 * @brief Open capture with default configuration
 * @param capture Capture handle
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_capture_open_default(rawsock_capture_t* capture);

/**
 * @brief Open capture with configuration
 * @param capture Capture handle
 * @param config Configuration
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_capture_open(rawsock_capture_t* capture, 
                                                    const rawsock_config_t* config);

/**
 * @brief Close capture
 * @param capture Capture handle
 */
RAWSOCK_C_API void rawsock_capture_close(rawsock_capture_t* capture);

/**
 * @brief Check if capture is open
 * @param capture Capture handle
 * @return 1 if open, 0 otherwise
 */
RAWSOCK_C_API int rawsock_capture_is_open(const rawsock_capture_t* capture);

/**
 * @brief Capture next packet
 * @param capture Capture handle
 * @param buffer Buffer for packet data
 * @param buffer_size Size of buffer
 * @param info Optional packet info output
 * @return Number of bytes captured, or negative error code
 */
RAWSOCK_C_API int rawsock_capture_next(rawsock_capture_t* capture,
                                        void* buffer, size_t buffer_size,
                                        rawsock_packet_info_t* info);

/**
 * @brief Capture next packet with timeout
 * @param capture Capture handle
 * @param buffer Buffer for packet data
 * @param buffer_size Size of buffer
 * @param timeout_ms Timeout in milliseconds
 * @param info Optional packet info output
 * @return Number of bytes captured, or negative error code
 */
RAWSOCK_C_API int rawsock_capture_next_timeout(rawsock_capture_t* capture,
                                                void* buffer, size_t buffer_size,
                                                int timeout_ms,
                                                rawsock_packet_info_t* info);

/**
 * @brief Start continuous capture with callback
 * @param capture Capture handle
 * @param handler Packet handler callback
 * @param user_data User data passed to callback
 * @param count Number of packets to capture (0 for infinite)
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_capture_start(rawsock_capture_t* capture,
                                                     rawsock_packet_handler_t handler,
                                                     void* user_data,
                                                     size_t count);

/**
 * @brief Stop continuous capture
 * @param capture Capture handle
 */
RAWSOCK_C_API void rawsock_capture_stop(rawsock_capture_t* capture);

/**
 * @brief Send raw packet
 * @param capture Capture handle
 * @param data Packet data
 * @param size Size of packet data
 * @return Number of bytes sent, or negative error code
 */
RAWSOCK_C_API int rawsock_capture_send(rawsock_capture_t* capture,
                                        const void* data, size_t size);

/**
 * @brief Get last error code
 * @param capture Capture handle
 * @return Last error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_capture_last_error(const rawsock_capture_t* capture);

/**
 * @brief Get capture statistics
 * @param capture Capture handle
 * @param packets_received Output for received packets count
 * @param packets_dropped Output for dropped packets count
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_capture_get_statistics(const rawsock_capture_t* capture,
                                                              uint64_t* packets_received,
                                                              uint64_t* packets_dropped);

/* ============= Parsing Functions ============= */

/**
 * @brief Parse Ethernet header
 * @param data Packet data
 * @param size Size of data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_parse_ethernet(const void* data, size_t size,
                                                      rawsock_ethernet_header_t* header);

/**
 * @brief Parse IPv4 header
 * @param data Packet data
 * @param size Size of data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_parse_ipv4(const void* data, size_t size,
                                                  rawsock_ipv4_header_t* header);

/**
 * @brief Parse TCP header
 * @param data Packet data
 * @param size Size of data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_parse_tcp(const void* data, size_t size,
                                                 rawsock_tcp_header_t* header);

/**
 * @brief Parse UDP header
 * @param data Packet data
 * @param size Size of data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_parse_udp(const void* data, size_t size,
                                                 rawsock_udp_header_t* header);

/**
 * @brief Parse ICMP header
 * @param data Packet data
 * @param size Size of data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_C_API rawsock_error_t rawsock_parse_icmp(const void* data, size_t size,
                                                  rawsock_icmp_header_t* header);

/* ============= Utility Functions ============= */

/**
 * @brief Calculate IP checksum
 * @param data Data pointer
 * @param length Data length
 * @return Calculated checksum
 */
RAWSOCK_C_API uint16_t rawsock_calculate_checksum(const void* data, size_t length);

/**
 * @brief Get interface index by name
 * @param name Interface name
 * @return Interface index, or -1 on error
 */
RAWSOCK_C_API int rawsock_get_interface_index(const char* name);

#ifdef __cplusplus
}
#endif

#endif /* RAWSOCK_C_H */
