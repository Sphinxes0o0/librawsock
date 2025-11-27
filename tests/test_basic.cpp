/**
 * @file test_basic.cpp
 * @brief Basic unit tests that don't require privileges
 */

#include <rawsock/rawsock.hpp>
#include <rawsock/rawsock_c.h>
#include <cstdio>
#include <cassert>
#include <cstring>

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("FAILED: Condition failed at line %d\n", __LINE__); \
            assert(false); \
        } \
    } while(0)

int main() {
    printf("=== Basic Library Tests ===\n\n");
    
    // Test version
    printf("Testing version...\n");
    const char* version = rawsock::version();
    ASSERT_TRUE(version != nullptr);
    ASSERT_TRUE(strlen(version) > 0);
    printf("  Version: %s\n", version);
    
    int version_num = rawsock::version_number();
    ASSERT_TRUE(version_num >= 20000);
    printf("  Version number: %d\n", version_num);
    
    // Test C version
    const char* c_version = rawsock_version();
    ASSERT_TRUE(c_version != nullptr);
    ASSERT_TRUE(strcmp(version, c_version) == 0);
    printf("  C API version matches\n");
    
    // Test constants
    printf("\nTesting constants...\n");
    ASSERT_TRUE(rawsock::constants::max_packet_size == 65535);
    ASSERT_TRUE(rawsock::constants::ethernet_header_size == 14);
    ASSERT_TRUE(rawsock::constants::ipv4_header_size == 20);
    ASSERT_TRUE(rawsock::constants::tcp_header_size == 20);
    ASSERT_TRUE(rawsock::constants::udp_header_size == 8);
    ASSERT_TRUE(rawsock::constants::icmp_header_size == 8);
    printf("  All constants correct\n");
    
    // Test error codes
    printf("\nTesting error codes...\n");
    auto ec = rawsock::make_error_code(rawsock::error_code::success);
    ASSERT_TRUE(!ec);  // success should be false
    
    ec = rawsock::make_error_code(rawsock::error_code::permission_denied);
    ASSERT_TRUE(ec);  // error should be true
    printf("  Error codes work correctly\n");
    
    // Test packet structures sizes
    printf("\nTesting structure sizes...\n");
    ASSERT_TRUE(sizeof(rawsock::ethernet_header) == 14);
    ASSERT_TRUE(sizeof(rawsock::ipv4_header) == 20);
    ASSERT_TRUE(sizeof(rawsock::tcp_header) == 20);
    ASSERT_TRUE(sizeof(rawsock::udp_header) == 8);
    ASSERT_TRUE(sizeof(rawsock::icmp_header) == 8);
    printf("  All structure sizes correct\n");
    
    // Test checksum
    printf("\nTesting checksum...\n");
    uint8_t data[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 
                      0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 
                      0xc0, 0xa8, 0x01, 0x02};
    uint16_t checksum = rawsock::calculate_ip_checksum(data, sizeof(data));
    ASSERT_TRUE(checksum != 0);
    printf("  Checksum: 0x%04x\n", checksum);
    
    // Test interface lookup
    printf("\nTesting interface lookup...\n");
    int lo_index = rawsock::capture::get_interface_index("lo");
    printf("  Loopback interface index: %d\n", lo_index);
    ASSERT_TRUE(lo_index >= 0);
    
    int bad_index = rawsock::capture::get_interface_index("nonexistent_123");
    ASSERT_TRUE(bad_index < 0);
    printf("  Non-existent interface correctly returns -1\n");
    
    // Test privilege check
    printf("\nTesting privilege check...\n");
    bool has_privileges = rawsock::capture::check_privileges();
    printf("  Has privileges: %s\n", has_privileges ? "yes" : "no");
    
    // Test capture config defaults
    printf("\nTesting capture config defaults...\n");
    rawsock::capture_config config;
    ASSERT_TRUE(config.interface_name.empty());
    ASSERT_TRUE(config.filter_protocol == rawsock::protocol::all);
    ASSERT_TRUE(config.recv_timeout_ms == rawsock::constants::default_recv_timeout_ms);
    ASSERT_TRUE(config.send_timeout_ms == rawsock::constants::default_send_timeout_ms);
    ASSERT_TRUE(!config.promiscuous);
    printf("  Defaults are correct\n");
    
    printf("\n=== All Basic Tests Passed ===\n");
    return 0;
}
