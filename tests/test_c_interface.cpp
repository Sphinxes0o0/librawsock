/**
 * @file test_c_interface.cpp
 * @brief Unit tests for C interface
 */

#include <rawsock/rawsock_c.h>
#include "test_common.hpp"

// Test version functions
TEST(version) {
    const char* version = rawsock_version();
    ASSERT_TRUE(version != NULL);
    ASSERT_TRUE(strlen(version) > 0);
    
    int version_num = rawsock_version_number();
    ASSERT_TRUE(version_num >= 20000);  // At least v2.0.0
}

// Test error string
TEST(error_string) {
    const char* msg;
    
    msg = rawsock_error_string(RAWSOCK_SUCCESS);
    ASSERT_TRUE(msg != NULL);
    ASSERT_TRUE(strlen(msg) > 0);
    
    msg = rawsock_error_string(RAWSOCK_ERROR_PERMISSION);
    ASSERT_TRUE(msg != NULL);
    ASSERT_TRUE(strlen(msg) > 0);
    
    msg = rawsock_error_string(RAWSOCK_ERROR_TIMEOUT);
    ASSERT_TRUE(msg != NULL);
    ASSERT_TRUE(strlen(msg) > 0);
}

// Test config initialization
TEST(config_init) {
    rawsock_config_t config;
    rawsock_config_init(&config);
    
    ASSERT_EQ(0, config.interface_name[0]);
    ASSERT_EQ(RAWSOCK_PROTO_ALL, config.filter_protocol);
    ASSERT_EQ(5000, config.recv_timeout_ms);
    ASSERT_EQ(5000, config.send_timeout_ms);
    ASSERT_EQ(0, config.promiscuous);
    ASSERT_EQ(RAWSOCK_MAX_PACKET_SIZE, config.buffer_size);
}

// Test capture create/destroy
TEST(capture_create_destroy) {
    rawsock_capture_t* cap = rawsock_capture_create();
    ASSERT_TRUE(cap != NULL);
    
    ASSERT_EQ(0, rawsock_capture_is_open(cap));
    
    rawsock_capture_destroy(cap);
}

// Test capture with NULL
TEST(capture_null_handling) {
    // Should not crash
    rawsock_capture_destroy(NULL);
    rawsock_capture_close(NULL);
    rawsock_capture_stop(NULL);
    
    ASSERT_EQ(0, rawsock_capture_is_open(NULL));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_capture_last_error(NULL));
    ASSERT_EQ(-RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_capture_next(NULL, NULL, 0, NULL));
}

// Test capture open without privileges
TEST(capture_open_no_privileges) {
    if (rawsock_check_privileges()) {
        printf("  Skipping (running as root)\n");
        return;
    }
    
    rawsock_capture_t* cap = rawsock_capture_create();
    ASSERT_TRUE(cap != NULL);
    
    rawsock_error_t err = rawsock_capture_open_default(cap);
    ASSERT_EQ(RAWSOCK_ERROR_PERMISSION, err);
    ASSERT_EQ(0, rawsock_capture_is_open(cap));
    
    rawsock_capture_destroy(cap);
}

// Test interface index
TEST(interface_index) {
    int index = rawsock_get_interface_index("lo");
    ASSERT_TRUE(index >= 0);
    
    index = rawsock_get_interface_index("nonexistent_12345");
    ASSERT_EQ(-1, index);
    
    index = rawsock_get_interface_index(NULL);
    ASSERT_EQ(-1, index);
}

// Test checksum calculation
TEST(checksum) {
    uint8_t data[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 
                      0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 
                      0xc0, 0xa8, 0x01, 0x02};
    
    uint16_t checksum = rawsock_calculate_checksum(data, sizeof(data));
    ASSERT_TRUE(checksum != 0);
}

// Test IPv4 parsing
TEST(parse_ipv4) {
    uint8_t data[] = {
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x01,
        0xc0, 0xa8, 0x01, 0x02
    };
    
    rawsock_ipv4_header_t header;
    rawsock_error_t err = rawsock_parse_ipv4(data, sizeof(data), &header);
    
    ASSERT_EQ(RAWSOCK_SUCCESS, err);
    ASSERT_EQ(64, header.ttl);
    ASSERT_EQ(6, header.protocol);  // TCP
}

// Test TCP parsing
TEST(parse_tcp) {
    uint8_t data[] = {
        0x00, 0x50, 0x01, 0xbb,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x50, 0x18, 0x00, 0x64,
        0x00, 0x00, 0x00, 0x00
    };
    
    rawsock_tcp_header_t header;
    rawsock_error_t err = rawsock_parse_tcp(data, sizeof(data), &header);
    
    ASSERT_EQ(RAWSOCK_SUCCESS, err);
    ASSERT_EQ(80, header.src_port);
    ASSERT_EQ(443, header.dst_port);
}

// Test UDP parsing
TEST(parse_udp) {
    uint8_t data[] = {
        0x00, 0x35, 0x1f, 0x90,
        0x00, 0x20, 0x00, 0x00
    };
    
    rawsock_udp_header_t header;
    rawsock_error_t err = rawsock_parse_udp(data, sizeof(data), &header);
    
    ASSERT_EQ(RAWSOCK_SUCCESS, err);
    ASSERT_EQ(53, header.src_port);
    ASSERT_EQ(8080, header.dst_port);
    ASSERT_EQ(32, header.length);
}

// Test ICMP parsing
TEST(parse_icmp) {
    uint8_t data[] = {
        0x08, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    
    rawsock_icmp_header_t header;
    rawsock_error_t err = rawsock_parse_icmp(data, sizeof(data), &header);
    
    ASSERT_EQ(RAWSOCK_SUCCESS, err);
    ASSERT_EQ(8, header.type);  // Echo Request
    ASSERT_EQ(1, header.data.echo.id);
    ASSERT_EQ(1, header.data.echo.sequence);
}

// Test Ethernet parsing
TEST(parse_ethernet) {
    uint8_t data[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00
    };
    
    rawsock_ethernet_header_t header;
    rawsock_error_t err = rawsock_parse_ethernet(data, sizeof(data), &header);
    
    ASSERT_EQ(RAWSOCK_SUCCESS, err);
    ASSERT_EQ(0x0800, header.ether_type);  // IPv4
}

// Test parsing with NULL
TEST(parse_null_handling) {
    rawsock_ipv4_header_t ipv4;
    rawsock_tcp_header_t tcp;
    rawsock_udp_header_t udp;
    rawsock_icmp_header_t icmp;
    rawsock_ethernet_header_t eth;
    
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ipv4(NULL, 20, &ipv4));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_tcp(NULL, 20, &tcp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_udp(NULL, 8, &udp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_icmp(NULL, 8, &icmp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ethernet(NULL, 14, &eth));
    
    uint8_t data[32] = {0};
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ipv4(data, 20, NULL));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_tcp(data, 20, NULL));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_udp(data, 8, NULL));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_icmp(data, 8, NULL));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ethernet(data, 14, NULL));
}

// Test parsing with small buffer
TEST(parse_buffer_too_small) {
    uint8_t data[4] = {0};
    
    rawsock_ipv4_header_t ipv4;
    rawsock_tcp_header_t tcp;
    rawsock_udp_header_t udp;
    rawsock_icmp_header_t icmp;
    rawsock_ethernet_header_t eth;
    
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ipv4(data, 4, &ipv4));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_tcp(data, 4, &tcp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_udp(data, 4, &udp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_icmp(data, 4, &icmp));
    ASSERT_EQ(RAWSOCK_ERROR_INVALID_ARGUMENT, rawsock_parse_ethernet(data, 4, &eth));
}

int main() {
    printf("=== C Interface Tests ===\n\n");
    
    RUN_TEST(version);
    RUN_TEST(error_string);
    RUN_TEST(config_init);
    RUN_TEST(capture_create_destroy);
    RUN_TEST(capture_null_handling);
    RUN_TEST(capture_open_no_privileges);
    RUN_TEST(interface_index);
    RUN_TEST(checksum);
    RUN_TEST(parse_ipv4);
    RUN_TEST(parse_tcp);
    RUN_TEST(parse_udp);
    RUN_TEST(parse_icmp);
    RUN_TEST(parse_ethernet);
    RUN_TEST(parse_null_handling);
    RUN_TEST(parse_buffer_too_small);
    
    printf("\n=== All C Interface Tests Passed ===\n");
    return 0;
}
