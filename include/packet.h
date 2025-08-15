/**
 * @file packet.h
 * @brief Basic packet header structures and utilities
 * @author Sphinxes0o0
 * @version 1.0.0
 * 
 * This module provides basic structures and utilities for network packet headers.
 */

#ifndef LIBRAWSOCK_PACKET_H
#define LIBRAWSOCK_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "rawsock.h"

/**
 * @brief Header sizes
 */
#define RAWSOCK_IP4_HEADER_SIZE 20
#define RAWSOCK_IP6_HEADER_SIZE 40
#define RAWSOCK_TCP_HEADER_SIZE 20
#define RAWSOCK_UDP_HEADER_SIZE 8
#define RAWSOCK_ICMP_HEADER_SIZE 8

/**
 * @brief IPv4 header structure
 */
typedef struct {
    uint8_t version_ihl;           /**< Version (4 bits) + IHL (4 bits) */
    uint8_t tos;                   /**< Type of Service */
    uint16_t total_length;         /**< Total Length */
    uint16_t id;                   /**< Identification */
    uint16_t flags_fragment;       /**< Flags (3 bits) + Fragment Offset (13 bits) */
    uint8_t ttl;                   /**< Time to Live */
    uint8_t protocol;              /**< Protocol */
    uint16_t checksum;             /**< Header Checksum */
    uint32_t src_addr;             /**< Source Address */
    uint32_t dst_addr;             /**< Destination Address */
} __attribute__((packed)) rawsock_ipv4_header_t;

/**
 * @brief IPv6 header structure
 */
typedef struct {
    uint32_t version_class_label;  /**< Version + Traffic Class + Flow Label */
    uint16_t payload_length;       /**< Payload Length */
    uint8_t next_header;           /**< Next Header */
    uint8_t hop_limit;             /**< Hop Limit */
    uint8_t src_addr[16];          /**< Source Address */
    uint8_t dst_addr[16];          /**< Destination Address */
} __attribute__((packed)) rawsock_ipv6_header_t;

/**
 * @brief TCP header structure
 */
typedef struct {
    uint16_t src_port;             /**< Source Port */
    uint16_t dst_port;             /**< Destination Port */
    uint32_t seq_num;              /**< Sequence Number */
    uint32_t ack_num;              /**< Acknowledgment Number */
    uint8_t data_offset_reserved;  /**< Data Offset + Reserved */
    uint8_t flags;                 /**< TCP Flags */
    uint16_t window;               /**< Window Size */
    uint16_t checksum;             /**< Checksum */
    uint16_t urgent_ptr;           /**< Urgent Pointer */
} __attribute__((packed)) rawsock_tcp_header_t;

/**
 * @brief UDP header structure
 */
typedef struct {
    uint16_t src_port;             /**< Source Port */
    uint16_t dst_port;             /**< Destination Port */
    uint16_t length;               /**< Length */
    uint16_t checksum;             /**< Checksum */
} __attribute__((packed)) rawsock_udp_header_t;

/**
 * @brief ICMP header structure
 */
typedef struct {
    uint8_t type;                  /**< ICMP Type */
    uint8_t code;                  /**< ICMP Code */
    uint16_t checksum;             /**< Checksum */
    union {
        struct {
            uint16_t id;           /**< Identifier */
            uint16_t sequence;     /**< Sequence Number */
        } echo;
        uint32_t gateway;          /**< Gateway Address */
        struct {
            uint16_t unused;       /**< Unused */
            uint16_t mtu;          /**< MTU */
        } frag;
    } data;
} __attribute__((packed)) rawsock_icmp_header_t;

/* ===== Packet Parsing Functions ===== */

/**
 * @brief Parse IPv4 header from packet data
 * @param packet_data Packet data
 * @param packet_size Packet size
 * @param header Pointer to store parsed header
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_parse_ipv4_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv4_header_t* header);

/**
 * @brief Parse IPv6 header from packet data
 * @param packet_data Packet data
 * @param packet_size Packet size
 * @param header Pointer to store parsed header
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_parse_ipv6_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv6_header_t* header);

/**
 * @brief Parse TCP header from packet data
 * @param packet_data Packet data (starting from TCP header)
 * @param packet_size Remaining packet size
 * @param header Pointer to store parsed header
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_parse_tcp_header(const void* packet_data, size_t packet_size,
                                         rawsock_tcp_header_t* header);

/**
 * @brief Parse UDP header from packet data
 * @param packet_data Packet data (starting from UDP header)
 * @param packet_size Remaining packet size
 * @param header Pointer to store parsed header
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_parse_udp_header(const void* packet_data, size_t packet_size,
                                         rawsock_udp_header_t* header);

/**
 * @brief Parse ICMP header from packet data
 * @param packet_data Packet data (starting from ICMP header)
 * @param packet_size Remaining packet size
 * @param header Pointer to store parsed header
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_parse_icmp_header(const void* packet_data, size_t packet_size,
                                          rawsock_icmp_header_t* header);

/* ===== Checksum Functions ===== */

/**
 * @brief Calculate IP checksum
 * @param data Data to calculate checksum for
 * @param length Data length
 * @return Calculated checksum
 */
uint16_t rawsock_calculate_ip_checksum(const void* data, size_t length);

/**
 * @brief Calculate TCP/UDP checksum with pseudo header
 * @param src_addr Source IP address (4 or 16 bytes)
 * @param dst_addr Destination IP address (4 or 16 bytes)
 * @param addr_len Address length (4 for IPv4, 16 for IPv6)
 * @param protocol Protocol number
 * @param data TCP/UDP header and data
 * @param length Data length
 * @return Calculated checksum
 */
uint16_t rawsock_calculate_transport_checksum(const void* src_addr, const void* dst_addr,
                                             size_t addr_len, uint8_t protocol,
                                             const void* data, size_t length);

/* ===== Utility Functions ===== */

/**
 * @brief Convert IP address string to binary format
 * @param addr_str IP address string
 * @param family Address family (RAWSOCK_IPV4 or RAWSOCK_IPV6)
 * @param addr_bin Buffer to store binary address
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_addr_str_to_bin(const char* addr_str, rawsock_family_t family,
                                        void* addr_bin);

/**
 * @brief Convert binary IP address to string format
 * @param addr_bin Binary IP address
 * @param family Address family (RAWSOCK_IPV4 or RAWSOCK_IPV6)
 * @param addr_str Buffer to store address string (at least 46 bytes)
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t rawsock_addr_bin_to_str(const void* addr_bin, rawsock_family_t family,
                                        char* addr_str);

#ifdef __cplusplus
}
#endif

#endif /* LIBRAWSOCK_PACKET_H */

