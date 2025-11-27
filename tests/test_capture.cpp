/**
 * @file test_capture.cpp
 * @brief Unit tests for capture functionality
 */

#include <rawsock/rawsock.hpp>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <vector>

// Test helper macros
#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    printf("Running %s...\n", #name); \
    test_##name(); \
    printf("PASSED: %s\n", #name); \
} while(0)

#define ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("FAILED: Expected %d, got %d at line %d\n", \
                   (int)(expected), (int)(actual), __LINE__); \
            assert(false); \
        } \
    } while(0)

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            printf("FAILED: Condition failed at line %d\n", __LINE__); \
            assert(false); \
        } \
    } while(0)

// Test capture default constructor
TEST(capture_default_constructor) {
    rawsock::capture cap;
    ASSERT_TRUE(!cap.is_open());
}

// Test capture with config constructor
TEST(capture_config_constructor) {
    rawsock::capture_config config;
    config.interface_name = "lo";
    config.filter_protocol = rawsock::protocol::tcp;
    config.recv_timeout_ms = 1000;
    config.promiscuous = false;
    
    rawsock::capture cap(config);
    ASSERT_TRUE(!cap.is_open());  // Not opened yet
}

// Test capture move semantics
TEST(capture_move) {
    rawsock::capture cap1;
    rawsock::capture cap2(std::move(cap1));
    
    ASSERT_TRUE(!cap2.is_open());
    
    rawsock::capture cap3;
    cap3 = std::move(cap2);
    ASSERT_TRUE(!cap3.is_open());
}

// Test capture operations without opening
TEST(capture_not_open) {
    rawsock::capture cap;
    
    std::vector<uint8_t> buffer(65535);
    int result = cap.capture_next(buffer.data(), buffer.size());
    ASSERT_TRUE(result < 0);  // Should fail because not open
}

// Test capture configuration
TEST(capture_config_defaults) {
    rawsock::capture_config config;
    
    // Check default values
    ASSERT_TRUE(config.interface_name.empty());
    ASSERT_EQ(static_cast<int>(rawsock::protocol::all), 
              static_cast<int>(config.filter_protocol));
    ASSERT_EQ(rawsock::constants::default_recv_timeout_ms, config.recv_timeout_ms);
    ASSERT_EQ(rawsock::constants::default_send_timeout_ms, config.send_timeout_ms);
    ASSERT_TRUE(!config.promiscuous);
    ASSERT_EQ(rawsock::constants::max_packet_size, config.buffer_size);
}

// Test interface index lookup (should work without privileges)
TEST(get_interface_index) {
    // "lo" (loopback) should always exist on Linux
    int index = rawsock::capture::get_interface_index("lo");
    ASSERT_TRUE(index >= 0);  // Should find loopback
    
    // Non-existent interface should return -1
    index = rawsock::capture::get_interface_index("nonexistent_interface_12345");
    ASSERT_EQ(-1, index);
}

// Test privilege check (informational, not assertion)
TEST(check_privileges) {
    bool has_privileges = rawsock::capture::check_privileges();
    printf("  Privilege check: %s\n", has_privileges ? "HAS PRIVILEGES" : "NO PRIVILEGES");
    // Don't assert - just informational
}

// Test open without privileges (expected to fail without root)
TEST(capture_open_permission) {
    if (rawsock::capture::check_privileges()) {
        printf("  Skipping (running as root)\n");
        return;
    }
    
    rawsock::capture cap;
    rawsock::error_code ec = cap.open();
    
    // Should fail with permission denied if not root
    ASSERT_EQ(static_cast<int>(rawsock::error_code::permission_denied), static_cast<int>(ec));
    ASSERT_TRUE(!cap.is_open());
}

// Test send without open
TEST(capture_send_not_open) {
    rawsock::capture cap;
    
    uint8_t data[] = {0x00, 0x01, 0x02, 0x03};
    int result = cap.send_packet(data, sizeof(data));
    
    ASSERT_TRUE(result < 0);  // Should fail
}

// Test last error
TEST(capture_last_error) {
    rawsock::capture cap;
    
    // Initially should be success
    ASSERT_EQ(static_cast<int>(rawsock::error_code::success), 
              static_cast<int>(cap.last_error()));
    
    // After failed operation
    std::vector<uint8_t> buffer(65535);
    cap.capture_next(buffer.data(), buffer.size());
    
    ASSERT_TRUE(cap.last_error() != rawsock::error_code::success);
}

// Test capture with loopback (if we have privileges)
TEST(capture_loopback) {
    if (!rawsock::capture::check_privileges()) {
        printf("  Skipping (no privileges)\n");
        return;
    }
    
    rawsock::capture_config config;
    config.interface_name = "lo";
    config.recv_timeout_ms = 100;  // Short timeout
    
    rawsock::capture cap;
    rawsock::error_code ec = cap.open(config);
    
    if (ec == rawsock::error_code::success) {
        ASSERT_TRUE(cap.is_open());
        
        std::vector<uint8_t> buffer(65535);
        rawsock::packet_info info;
        
        // Try to capture (will timeout, which is expected)
        int result = cap.capture_next(buffer.data(), buffer.size(), &info);
        
        // Either we got a packet or timed out (both are acceptable)
        if (result > 0) {
            ASSERT_TRUE(info.packet_size > 0);
        } else {
            ASSERT_EQ(-static_cast<int>(rawsock::error_code::timeout), result);
        }
        
        cap.close();
        ASSERT_TRUE(!cap.is_open());
    }
}

// Test packet_info structure
TEST(packet_info_defaults) {
    rawsock::packet_info info;
    
    ASSERT_TRUE(info.src_addr.empty());
    ASSERT_TRUE(info.dst_addr.empty());
    ASSERT_EQ(0, info.src_port);
    ASSERT_EQ(0, info.dst_port);
    ASSERT_EQ(static_cast<int>(rawsock::protocol::all), 
              static_cast<int>(info.proto));
    ASSERT_EQ(0, info.packet_size);
    ASSERT_EQ(0, info.timestamp_us);
    ASSERT_TRUE(info.interface_name.empty());
}

int main() {
    printf("=== Capture Tests ===\n\n");
    
    RUN_TEST(capture_default_constructor);
    RUN_TEST(capture_config_constructor);
    RUN_TEST(capture_move);
    RUN_TEST(capture_not_open);
    RUN_TEST(capture_config_defaults);
    RUN_TEST(get_interface_index);
    RUN_TEST(check_privileges);
    RUN_TEST(capture_open_permission);
    RUN_TEST(capture_send_not_open);
    RUN_TEST(capture_last_error);
    RUN_TEST(capture_loopback);
    RUN_TEST(packet_info_defaults);
    
    printf("\n=== All Capture Tests Passed ===\n");
    return 0;
}
