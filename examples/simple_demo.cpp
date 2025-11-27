/**
 * @file simple_demo.cpp
 * @brief Simple demonstration of rawsock library features
 * 
 * This example shows basic usage of the library without requiring
 * root privileges for most operations.
 */

#include <rawsock/rawsock.hpp>
#include <iostream>
#include <cstring>

void demo_version() {
    std::cout << "=== Version Information ===\n";
    std::cout << "Library version: " << rawsock::version() << "\n";
    std::cout << "Version number: " << rawsock::version_number() << "\n\n";
}

void demo_constants() {
    std::cout << "=== Library Constants ===\n";
    std::cout << "Max packet size: " << rawsock::constants::max_packet_size << " bytes\n";
    std::cout << "Ethernet header: " << rawsock::constants::ethernet_header_size << " bytes\n";
    std::cout << "IPv4 header: " << rawsock::constants::ipv4_header_size << " bytes\n";
    std::cout << "IPv6 header: " << rawsock::constants::ipv6_header_size << " bytes\n";
    std::cout << "TCP header: " << rawsock::constants::tcp_header_size << " bytes\n";
    std::cout << "UDP header: " << rawsock::constants::udp_header_size << " bytes\n";
    std::cout << "ICMP header: " << rawsock::constants::icmp_header_size << " bytes\n\n";
}

void demo_parsing() {
    std::cout << "=== Packet Parsing Demo ===\n";
    
    // Sample IPv4 header
    uint8_t ip_data[] = {
        0x45, 0x00, 0x00, 0x3c,  // Version, IHL, TOS, Total Length
        0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment
        0x40, 0x06, 0x00, 0x00,  // TTL, Protocol (TCP=6), Checksum
        0xc0, 0xa8, 0x01, 0x01,  // Source: 192.168.1.1
        0xc0, 0xa8, 0x01, 0x02   // Dest: 192.168.1.2
    };
    
    rawsock::ipv4_header ipv4;
    auto ec = rawsock::parse_ipv4_header(ip_data, sizeof(ip_data), ipv4);
    
    if (ec == rawsock::error_code::success) {
        std::cout << "IPv4 Header:\n";
        std::cout << "  Version: " << (int)ipv4.version() << "\n";
        std::cout << "  Header length: " << (int)ipv4.header_length() << " bytes\n";
        std::cout << "  TTL: " << (int)ipv4.ttl << "\n";
        std::cout << "  Protocol: " << (int)ipv4.protocol << " (TCP)\n";
    }
    
    // Sample TCP header
    uint8_t tcp_data[] = {
        0x00, 0x50, 0x01, 0xbb,  // Src port: 80, Dst port: 443
        0x00, 0x00, 0x00, 0x01,  // Sequence number
        0x00, 0x00, 0x00, 0x02,  // ACK number
        0x50, 0x18, 0x00, 0x64,  // Offset, Flags (PSH|ACK), Window
        0x00, 0x00, 0x00, 0x00   // Checksum, Urgent pointer
    };
    
    rawsock::tcp_header tcp;
    ec = rawsock::parse_tcp_header(tcp_data, sizeof(tcp_data), tcp);
    
    if (ec == rawsock::error_code::success) {
        std::cout << "\nTCP Header:\n";
        std::cout << "  Source port: " << tcp.src_port << "\n";
        std::cout << "  Dest port: " << tcp.dst_port << "\n";
        std::cout << "  Flags: SYN=" << !!(tcp.flags & rawsock::tcp_header::syn)
                  << " ACK=" << !!(tcp.flags & rawsock::tcp_header::ack)
                  << " PSH=" << !!(tcp.flags & rawsock::tcp_header::psh)
                  << " FIN=" << !!(tcp.flags & rawsock::tcp_header::fin) << "\n";
    }
    
    std::cout << "\n";
}

void demo_checksum() {
    std::cout << "=== Checksum Calculation ===\n";
    
    // IP header with zero checksum
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,  // Checksum = 0
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02
    };
    
    uint16_t checksum = rawsock::calculate_ip_checksum(data, sizeof(data));
    std::cout << "Calculated checksum: 0x" << std::hex << checksum << std::dec << "\n\n";
}

void demo_interface() {
    std::cout << "=== Interface Lookup ===\n";
    
    // Try to get loopback interface
    int lo_index = rawsock::capture::get_interface_index("lo");
    if (lo_index >= 0) {
        std::cout << "Loopback (lo) interface index: " << lo_index << "\n";
    }
    
    // Try a non-existent interface
    int bad_index = rawsock::capture::get_interface_index("nonexistent_12345");
    std::cout << "Non-existent interface index: " << bad_index << " (expected -1)\n\n";
}

void demo_privilege_check() {
    std::cout << "=== Privilege Check ===\n";
    
    bool has_privileges = rawsock::capture::check_privileges();
    std::cout << "Has raw socket privileges: " << (has_privileges ? "YES" : "NO") << "\n";
    
    if (!has_privileges) {
        std::cout << "Note: Run with 'sudo' to enable packet capture\n";
    }
    std::cout << "\n";
}

void demo_error_handling() {
    std::cout << "=== Error Handling ===\n";
    
    // Create some error codes
    auto success = rawsock::make_error_code(rawsock::error_code::success);
    auto permission = rawsock::make_error_code(rawsock::error_code::permission_denied);
    auto timeout = rawsock::make_error_code(rawsock::error_code::timeout);
    
    std::cout << "Success: " << success.message() << "\n";
    std::cout << "Permission denied: " << permission.message() << "\n";
    std::cout << "Timeout: " << timeout.message() << "\n\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "     rawsock Library Demo\n";
    std::cout << "========================================\n\n";
    
    demo_version();
    demo_constants();
    demo_parsing();
    demo_checksum();
    demo_interface();
    demo_privilege_check();
    demo_error_handling();
    
    std::cout << "Demo complete!\n";
    return 0;
}
