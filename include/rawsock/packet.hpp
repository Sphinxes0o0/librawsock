/**
 * @file packet.hpp
 * @brief Packet structures and parsing for rawsock library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_PACKET_HPP
#define RAWSOCK_PACKET_HPP

#include "config.hpp"
#include "error.hpp"
#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <arpa/inet.h>

RAWSOCK_NAMESPACE_BEGIN

/**
 * @brief Protocol numbers
 */
enum class protocol : std::uint8_t {
    all = 0,
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    raw = 255
};

/**
 * @brief Ethernet header structure
 */
struct ethernet_header {
    std::array<std::uint8_t, 6> dest_mac;
    std::array<std::uint8_t, 6> src_mac;
    std::uint16_t ether_type;
} __attribute__((packed));

/**
 * @brief IPv4 header structure
 */
struct ipv4_header {
    std::uint8_t version_ihl;
    std::uint8_t tos;
    std::uint16_t total_length;
    std::uint16_t id;
    std::uint16_t flags_fragment;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t checksum;
    std::uint32_t src_addr;
    std::uint32_t dst_addr;
    
    RAWSOCK_NODISCARD
    std::uint8_t version() const noexcept {
        return (version_ihl >> 4) & 0x0F;
    }
    
    RAWSOCK_NODISCARD
    std::uint8_t header_length() const noexcept {
        return (version_ihl & 0x0F) * 4;
    }
} __attribute__((packed));

/**
 * @brief IPv6 header structure
 */
struct ipv6_header {
    std::uint32_t version_class_label;
    std::uint16_t payload_length;
    std::uint8_t next_header;
    std::uint8_t hop_limit;
    std::array<std::uint8_t, 16> src_addr;
    std::array<std::uint8_t, 16> dst_addr;
    
    RAWSOCK_NODISCARD
    std::uint8_t version() const noexcept {
        return (ntohl(version_class_label) >> 28) & 0x0F;
    }
} __attribute__((packed));

/**
 * @brief TCP header structure
 */
struct tcp_header {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint32_t seq_num;
    std::uint32_t ack_num;
    std::uint8_t data_offset_reserved;
    std::uint8_t flags;
    std::uint16_t window;
    std::uint16_t checksum;
    std::uint16_t urgent_ptr;
    
    // TCP flags
    static constexpr std::uint8_t fin = 0x01;
    static constexpr std::uint8_t syn = 0x02;
    static constexpr std::uint8_t rst = 0x04;
    static constexpr std::uint8_t psh = 0x08;
    static constexpr std::uint8_t ack = 0x10;
    static constexpr std::uint8_t urg = 0x20;
    
    RAWSOCK_NODISCARD
    std::uint8_t data_offset() const noexcept {
        return (data_offset_reserved >> 4) * 4;
    }
} __attribute__((packed));

/**
 * @brief UDP header structure
 */
struct udp_header {
    std::uint16_t src_port;
    std::uint16_t dst_port;
    std::uint16_t length;
    std::uint16_t checksum;
} __attribute__((packed));

/**
 * @brief ICMP header structure
 */
struct icmp_header {
    std::uint8_t type;
    std::uint8_t code;
    std::uint16_t checksum;
    union {
        struct {
            std::uint16_t id;
            std::uint16_t sequence;
        } echo;
        std::uint32_t gateway;
        struct {
            std::uint16_t unused;
            std::uint16_t mtu;
        } frag;
    } data;
    
    // ICMP types
    static constexpr std::uint8_t echo_reply = 0;
    static constexpr std::uint8_t echo_request = 8;
} __attribute__((packed));

/**
 * @brief Captured packet information
 */
struct packet_info {
    std::string src_addr;
    std::string dst_addr;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    protocol proto = protocol::all;
    std::size_t packet_size = 0;
    std::uint64_t timestamp_us = 0;
    std::string interface_name;
};

/**
 * @brief Calculate IP checksum
 * @param data Pointer to data
 * @param length Length of data in bytes
 * @return Calculated checksum
 */
RAWSOCK_INLINE
std::uint16_t calculate_ip_checksum(const void* data, std::size_t length) noexcept {
    std::uint32_t sum = 0;
    const auto* ptr = static_cast<const std::uint16_t*>(data);
    
    for (std::size_t i = 0; i < length / 2; ++i) {
        sum += ptr[i];
    }
    
    if (length % 2) {
        sum += static_cast<const std::uint8_t*>(data)[length - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return static_cast<std::uint16_t>(~sum);
}

/**
 * @brief Parse Ethernet header from packet data
 * @param data Pointer to packet data
 * @param size Size of packet data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_INLINE
error_code parse_ethernet_header(const void* data, std::size_t size, ethernet_header& header) noexcept {
    if (!data || size < sizeof(ethernet_header)) {
        return error_code::invalid_argument;
    }
    
    std::memcpy(&header, data, sizeof(ethernet_header));
    header.ether_type = ntohs(header.ether_type);
    
    return error_code::success;
}

/**
 * @brief Parse IPv4 header from packet data
 * @param data Pointer to packet data
 * @param size Size of packet data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_INLINE
error_code parse_ipv4_header(const void* data, std::size_t size, ipv4_header& header) noexcept {
    if (!data || size < sizeof(ipv4_header)) {
        return error_code::invalid_argument;
    }
    
    std::memcpy(&header, data, sizeof(ipv4_header));
    header.total_length = ntohs(header.total_length);
    header.id = ntohs(header.id);
    header.flags_fragment = ntohs(header.flags_fragment);
    header.checksum = ntohs(header.checksum);
    header.src_addr = ntohl(header.src_addr);
    header.dst_addr = ntohl(header.dst_addr);
    
    return error_code::success;
}

/**
 * @brief Parse TCP header from packet data
 * @param data Pointer to packet data
 * @param size Size of packet data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_INLINE
error_code parse_tcp_header(const void* data, std::size_t size, tcp_header& header) noexcept {
    if (!data || size < sizeof(tcp_header)) {
        return error_code::invalid_argument;
    }
    
    std::memcpy(&header, data, sizeof(tcp_header));
    header.src_port = ntohs(header.src_port);
    header.dst_port = ntohs(header.dst_port);
    header.seq_num = ntohl(header.seq_num);
    header.ack_num = ntohl(header.ack_num);
    header.window = ntohs(header.window);
    header.checksum = ntohs(header.checksum);
    header.urgent_ptr = ntohs(header.urgent_ptr);
    
    return error_code::success;
}

/**
 * @brief Parse UDP header from packet data
 * @param data Pointer to packet data
 * @param size Size of packet data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_INLINE
error_code parse_udp_header(const void* data, std::size_t size, udp_header& header) noexcept {
    if (!data || size < sizeof(udp_header)) {
        return error_code::invalid_argument;
    }
    
    std::memcpy(&header, data, sizeof(udp_header));
    header.src_port = ntohs(header.src_port);
    header.dst_port = ntohs(header.dst_port);
    header.length = ntohs(header.length);
    header.checksum = ntohs(header.checksum);
    
    return error_code::success;
}

/**
 * @brief Parse ICMP header from packet data
 * @param data Pointer to packet data
 * @param size Size of packet data
 * @param header Output header structure
 * @return Error code
 */
RAWSOCK_INLINE
error_code parse_icmp_header(const void* data, std::size_t size, icmp_header& header) noexcept {
    if (!data || size < sizeof(icmp_header)) {
        return error_code::invalid_argument;
    }
    
    std::memcpy(&header, data, sizeof(icmp_header));
    header.checksum = ntohs(header.checksum);
    
    if (header.type == icmp_header::echo_reply || header.type == icmp_header::echo_request) {
        header.data.echo.id = ntohs(header.data.echo.id);
        header.data.echo.sequence = ntohs(header.data.echo.sequence);
    } else {
        header.data.gateway = ntohl(header.data.gateway);
    }
    
    return error_code::success;
}

RAWSOCK_NAMESPACE_END

#endif // RAWSOCK_PACKET_HPP
