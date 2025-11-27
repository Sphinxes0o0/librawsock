/**
 * @file test_packet.cpp
 * @brief Unit tests for packet parsing functions
 */

#include <rawsock/rawsock.hpp>
#include "test_common.hpp"

// Test IPv4 header parsing
TEST(parse_ipv4_header) {
    // Sample IPv4 header (20 bytes)
    uint8_t data[] = {
        0x45,                   // Version (4) + IHL (5)
        0x00,                   // TOS
        0x00, 0x3c,             // Total length (60)
        0x1c, 0x46,             // ID
        0x40, 0x00,             // Flags + Fragment offset
        0x40,                   // TTL (64)
        0x06,                   // Protocol (TCP)
        0x00, 0x00,             // Checksum
        0xc0, 0xa8, 0x01, 0x01, // Source (192.168.1.1)
        0xc0, 0xa8, 0x01, 0x02  // Dest (192.168.1.2)
    };
    
    rawsock::ipv4_header header;
    auto ec = rawsock::parse_ipv4_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), static_cast<int>(ec));
    ASSERT_EQ(4, header.version());
    ASSERT_EQ(20, header.header_length());
    ASSERT_EQ(64, header.ttl);
    ASSERT_EQ(6, header.protocol);  // TCP
}

// Test invalid IPv4 header
TEST(parse_ipv4_header_invalid) {
    uint8_t data[10] = {0};  // Too small
    
    rawsock::ipv4_header header;
    auto ec = rawsock::parse_ipv4_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::invalid_argument), static_cast<int>(ec));
}

// Test NULL data
TEST(parse_ipv4_header_null) {
    rawsock::ipv4_header header;
    auto ec = rawsock::parse_ipv4_header(nullptr, 100, header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::invalid_argument), static_cast<int>(ec));
}

// Test TCP header parsing
TEST(parse_tcp_header) {
    // Sample TCP header (20 bytes)
    uint8_t data[] = {
        0x00, 0x50,             // Source port (80)
        0x01, 0xbb,             // Dest port (443)
        0x00, 0x00, 0x00, 0x01, // Sequence number
        0x00, 0x00, 0x00, 0x02, // ACK number
        0x50,                   // Data offset (5) + reserved
        0x18,                   // Flags (PSH + ACK)
        0x00, 0x64,             // Window (100)
        0x00, 0x00,             // Checksum
        0x00, 0x00              // Urgent pointer
    };
    
    rawsock::tcp_header header;
    auto ec = rawsock::parse_tcp_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), static_cast<int>(ec));
    ASSERT_EQ(80, header.src_port);
    ASSERT_EQ(443, header.dst_port);
    ASSERT_EQ(1, header.seq_num);
    ASSERT_EQ(2, header.ack_num);
    ASSERT_TRUE((header.flags & rawsock::tcp_header::psh) != 0);
    ASSERT_TRUE((header.flags & rawsock::tcp_header::ack) != 0);
}

// Test UDP header parsing
TEST(parse_udp_header) {
    // Sample UDP header (8 bytes)
    uint8_t data[] = {
        0x00, 0x35,             // Source port (53)
        0x1f, 0x90,             // Dest port (8080)
        0x00, 0x20,             // Length (32)
        0x00, 0x00              // Checksum
    };
    
    rawsock::udp_header header;
    auto ec = rawsock::parse_udp_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), static_cast<int>(ec));
    ASSERT_EQ(53, header.src_port);
    ASSERT_EQ(8080, header.dst_port);
    ASSERT_EQ(32, header.length);
}

// Test ICMP header parsing
TEST(parse_icmp_header) {
    // Sample ICMP Echo Request header (8 bytes)
    uint8_t data[] = {
        0x08,                   // Type (Echo Request)
        0x00,                   // Code
        0x00, 0x00,             // Checksum
        0x00, 0x01,             // ID
        0x00, 0x01              // Sequence
    };
    
    rawsock::icmp_header header;
    auto ec = rawsock::parse_icmp_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), static_cast<int>(ec));
    ASSERT_EQ(8, header.type);  // Echo Request
    ASSERT_EQ(0, header.code);
    ASSERT_EQ(1, header.data.echo.id);
    ASSERT_EQ(1, header.data.echo.sequence);
}

// Test Ethernet header parsing
TEST(parse_ethernet_header) {
    // Sample Ethernet header (14 bytes)
    uint8_t data[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Dest MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Source MAC
        0x08, 0x00                            // EtherType (IPv4)
    };
    
    rawsock::ethernet_header header;
    auto ec = rawsock::parse_ethernet_header(data, sizeof(data), header);
    
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), static_cast<int>(ec));
    ASSERT_EQ(0x0800, header.ether_type);  // IPv4
}

// Test IP checksum calculation
TEST(calculate_ip_checksum) {
    // Sample IP header with zero checksum
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,  // Checksum = 0
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02
    };
    
    uint16_t checksum = rawsock::calculate_ip_checksum(data, sizeof(data));
    
    // Checksum should be non-zero
    ASSERT_TRUE(checksum != 0);
}

int main() {
    printf("=== Packet Parsing Tests ===\n\n");
    
    RUN_TEST(parse_ipv4_header);
    RUN_TEST(parse_ipv4_header_invalid);
    RUN_TEST(parse_ipv4_header_null);
    RUN_TEST(parse_tcp_header);
    RUN_TEST(parse_udp_header);
    RUN_TEST(parse_icmp_header);
    RUN_TEST(parse_ethernet_header);
    RUN_TEST(calculate_ip_checksum);
    
    printf("\n=== All Packet Tests Passed ===\n");
    return 0;
}
