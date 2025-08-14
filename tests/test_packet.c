/**
 * @file test_packet.c
 * @brief Unit tests for packet construction and parsing
 * @author LibRawSock Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <librawsock/packet.h>
#include <librawsock/rawsock.h>

/* Test helper macros */
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 0; \
        } \
    } while(0)

#define TEST_PASS(message) \
    do { \
        printf("PASS: %s\n", message); \
        return 1; \
    } while(0)

/**
 * @brief Test packet builder creation and destruction
 */
int test_packet_builder_creation(void) {
    /* Test valid creation */
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    TEST_ASSERT(builder != NULL, "Packet builder creation should succeed");

    rawsock_packet_builder_destroy(builder);

    /* Test invalid parameters */
    builder = rawsock_packet_builder_create(0);
    TEST_ASSERT(builder == NULL, "Packet builder creation with size 0 should fail");

    builder = rawsock_packet_builder_create(RAWSOCK_MAX_PACKET_SIZE + 1);
    TEST_ASSERT(builder == NULL, "Packet builder creation with oversized buffer should fail");

    /* Test NULL destruction */
    rawsock_packet_builder_destroy(NULL);  /* Should not crash */

    TEST_PASS("Packet builder creation and destruction");
}

/**
 * @brief Test IPv4 header construction
 */
int test_ipv4_header_construction(void) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    TEST_ASSERT(builder != NULL, "Packet builder creation should succeed");

    /* Add IPv4 header */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(builder,
                                                        "192.168.1.1",
                                                        "192.168.1.100",
                                                        IPPROTO_ICMP, 64);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header addition should succeed");

    /* Finalize packet */
    err = rawsock_packet_finalize(builder);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Packet finalization should succeed");

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Getting packet data should succeed");
    TEST_ASSERT(packet_size >= RAWSOCK_IP4_HEADER_SIZE, "Packet size should be at least IPv4 header size");

    /* Parse the header back */
    rawsock_ipv4_header_t header;
    err = rawsock_parse_ipv4_header(packet_data, packet_size, &header);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header parsing should succeed");

    /* Verify header fields */
    TEST_ASSERT((header.version_ihl >> 4) == 4, "IP version should be 4");
    TEST_ASSERT((header.version_ihl & 0x0F) == 5, "IHL should be 5");
    TEST_ASSERT(header.protocol == IPPROTO_ICMP, "Protocol should be ICMP");
    TEST_ASSERT(header.ttl == 64, "TTL should be 64");

    /* Verify addresses */
    uint32_t expected_src = ntohl(inet_addr("192.168.1.1"));
    uint32_t expected_dst = ntohl(inet_addr("192.168.1.100"));
    TEST_ASSERT(header.src_addr == expected_src, "Source address should match");
    TEST_ASSERT(header.dst_addr == expected_dst, "Destination address should match");

    rawsock_packet_builder_destroy(builder);
    TEST_PASS("IPv4 header construction");
}

/**
 * @brief Test TCP header construction
 */
int test_tcp_header_construction(void) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    TEST_ASSERT(builder != NULL, "Packet builder creation should succeed");

    /* Add IPv4 header first */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(builder,
                                                        "10.0.0.1",
                                                        "10.0.0.2",
                                                        IPPROTO_TCP, 64);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header addition should succeed");

    /* Add TCP header */
    err = rawsock_packet_add_tcp_header(builder, 12345, 80, 1000, 0, 0x02, 8192);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "TCP header addition should succeed");

    /* Finalize packet */
    err = rawsock_packet_finalize(builder);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Packet finalization should succeed");

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Getting packet data should succeed");

    /* Parse TCP header (skip IP header) */
    const uint8_t* tcp_data = (const uint8_t*)packet_data + RAWSOCK_IP4_HEADER_SIZE;
    size_t tcp_size = packet_size - RAWSOCK_IP4_HEADER_SIZE;

    rawsock_tcp_header_t header;
    err = rawsock_parse_tcp_header(tcp_data, tcp_size, &header);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "TCP header parsing should succeed");

    /* Verify header fields */
    TEST_ASSERT(header.src_port == 12345, "Source port should match");
    TEST_ASSERT(header.dst_port == 80, "Destination port should match");
    TEST_ASSERT(header.seq_num == 1000, "Sequence number should match");
    TEST_ASSERT(header.ack_num == 0, "Acknowledgment number should match");
    TEST_ASSERT(header.flags == 0x02, "Flags should match (SYN)");
    TEST_ASSERT(header.window == 8192, "Window size should match");

    rawsock_packet_builder_destroy(builder);
    TEST_PASS("TCP header construction");
}

/**
 * @brief Test UDP header construction
 */
int test_udp_header_construction(void) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    TEST_ASSERT(builder != NULL, "Packet builder creation should succeed");

    /* Add IPv4 header first */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(builder,
                                                        "172.16.0.1",
                                                        "172.16.0.2",
                                                        IPPROTO_UDP, 64);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header addition should succeed");

    /* Add UDP header */
    err = rawsock_packet_add_udp_header(builder, 53, 12345);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "UDP header addition should succeed");

    /* Add some payload */
    const char* payload = "Hello, UDP!";
    err = rawsock_packet_add_payload(builder, payload, strlen(payload));
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Payload addition should succeed");

    /* Finalize packet */
    err = rawsock_packet_finalize(builder);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Packet finalization should succeed");

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Getting packet data should succeed");

    /* Parse UDP header (skip IP header) */
    const uint8_t* udp_data = (const uint8_t*)packet_data + RAWSOCK_IP4_HEADER_SIZE;
    size_t udp_size = packet_size - RAWSOCK_IP4_HEADER_SIZE;

    rawsock_udp_header_t header;
    err = rawsock_parse_udp_header(udp_data, udp_size, &header);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "UDP header parsing should succeed");

    /* Verify header fields */
    TEST_ASSERT(header.src_port == 53, "Source port should match");
    TEST_ASSERT(header.dst_port == 12345, "Destination port should match");
    TEST_ASSERT(header.length == RAWSOCK_UDP_HEADER_SIZE + strlen(payload), 
                "UDP length should include header and payload");

    rawsock_packet_builder_destroy(builder);
    TEST_PASS("UDP header construction");
}

/**
 * @brief Test ICMP header construction
 */
int test_icmp_header_construction(void) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    TEST_ASSERT(builder != NULL, "Packet builder creation should succeed");

    /* Add IPv4 header first */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(builder,
                                                        "8.8.8.8",
                                                        "8.8.4.4",
                                                        IPPROTO_ICMP, 64);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header addition should succeed");

    /* Add ICMP header (Echo Request) */
    err = rawsock_packet_add_icmp_header(builder, 8, 0, 1234, 5678);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "ICMP header addition should succeed");

    /* Finalize packet */
    err = rawsock_packet_finalize(builder);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Packet finalization should succeed");

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Getting packet data should succeed");

    /* Parse ICMP header (skip IP header) */
    const uint8_t* icmp_data = (const uint8_t*)packet_data + RAWSOCK_IP4_HEADER_SIZE;
    size_t icmp_size = packet_size - RAWSOCK_IP4_HEADER_SIZE;

    rawsock_icmp_header_t header;
    err = rawsock_parse_icmp_header(icmp_data, icmp_size, &header);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "ICMP header parsing should succeed");

    /* Verify header fields */
    TEST_ASSERT(header.type == 8, "ICMP type should be 8 (Echo Request)");
    TEST_ASSERT(header.code == 0, "ICMP code should be 0");
    TEST_ASSERT(header.data.echo.id == 1234, "ICMP ID should match");
    TEST_ASSERT(header.data.echo.sequence == 5678, "ICMP sequence should match");

    rawsock_packet_builder_destroy(builder);
    TEST_PASS("ICMP header construction");
}

/**
 * @brief Test address utility functions
 */
int test_address_utilities(void) {
    /* Test IPv4 address conversion */
    const char* ipv4_str = "192.168.1.1";
    uint32_t ipv4_bin;

    rawsock_error_t err = rawsock_addr_str_to_bin(ipv4_str, RAWSOCK_IPV4, &ipv4_bin);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 string to binary conversion should succeed");

    char ipv4_str_result[46];
    err = rawsock_addr_bin_to_str(&ipv4_bin, RAWSOCK_IPV4, ipv4_str_result);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 binary to string conversion should succeed");
    TEST_ASSERT(strcmp(ipv4_str, ipv4_str_result) == 0, "IPv4 round-trip conversion should match");

    /* Test IPv6 address conversion */
    const char* ipv6_str = "2001:db8::1";
    uint8_t ipv6_bin[16];

    err = rawsock_addr_str_to_bin(ipv6_str, RAWSOCK_IPV6, ipv6_bin);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv6 string to binary conversion should succeed");

    char ipv6_str_result[46];
    err = rawsock_addr_bin_to_str(ipv6_bin, RAWSOCK_IPV6, ipv6_str_result);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv6 binary to string conversion should succeed");

    /* Test invalid parameters */
    err = rawsock_addr_str_to_bin(NULL, RAWSOCK_IPV4, &ipv4_bin);
    TEST_ASSERT(err == RAWSOCK_ERROR_INVALID_PARAM, "NULL address string should fail");

    err = rawsock_addr_str_to_bin("invalid.ip", RAWSOCK_IPV4, &ipv4_bin);
    TEST_ASSERT(err == RAWSOCK_ERROR_INVALID_PARAM, "Invalid IP address should fail");

    TEST_PASS("Address utility functions");
}

/**
 * @brief Test checksum calculation functions
 */
int test_checksum_functions(void) {
    /* Test IP checksum with known data */
    uint8_t test_data[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                          0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
                          0xac, 0x10, 0x0a, 0x0c};

    uint16_t checksum = rawsock_calculate_ip_checksum(test_data, sizeof(test_data));
    TEST_ASSERT(checksum != 0, "IP checksum should be calculated");

    /* Test transport checksum */
    uint32_t src_addr = inet_addr("192.168.1.1");
    uint32_t dst_addr = inet_addr("192.168.1.2");
    uint8_t tcp_data[] = {0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
                         0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
                         0x00, 0x00, 0x00, 0x00};

    checksum = rawsock_calculate_transport_checksum(&src_addr, &dst_addr, 4,
                                                   IPPROTO_TCP, tcp_data, sizeof(tcp_data));
    TEST_ASSERT(checksum != 0, "Transport checksum should be calculated");

    TEST_PASS("Checksum calculation functions");
}

/**
 * @brief Test error handling
 */
int test_error_handling(void) {
    /* Test invalid packet builder operations */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(NULL, "1.1.1.1", "2.2.2.2", 
                                                        IPPROTO_TCP, 64);
    TEST_ASSERT(err == RAWSOCK_ERROR_INVALID_PARAM, "NULL builder should fail");

    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(50);  /* Small buffer */
    TEST_ASSERT(builder != NULL, "Small packet builder creation should succeed");

    /* Try to add headers that won't fit */
    err = rawsock_packet_add_ipv4_header(builder, "1.1.1.1", "2.2.2.2", IPPROTO_TCP, 64);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "IPv4 header should fit");

    err = rawsock_packet_add_tcp_header(builder, 1234, 80, 1000, 0, 0x02, 8192);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "TCP header should fit");

    /* Try to add payload that won't fit */
    char large_payload[100];
    memset(large_payload, 'A', sizeof(large_payload));

    err = rawsock_packet_add_payload(builder, large_payload, sizeof(large_payload));
    TEST_ASSERT(err == RAWSOCK_ERROR_BUFFER_TOO_SMALL, "Large payload should not fit");

    rawsock_packet_builder_destroy(builder);
    TEST_PASS("Error handling");
}

/**
 * @brief Run all packet tests
 */
int run_packet_tests(void) {
    int tests_passed = 0;
    int total_tests = 0;

    printf("Running packet construction and parsing tests...\n\n");

    total_tests++; if (test_packet_builder_creation()) tests_passed++;
    total_tests++; if (test_ipv4_header_construction()) tests_passed++;
    total_tests++; if (test_tcp_header_construction()) tests_passed++;
    total_tests++; if (test_udp_header_construction()) tests_passed++;
    total_tests++; if (test_icmp_header_construction()) tests_passed++;
    total_tests++; if (test_address_utilities()) tests_passed++;
    total_tests++; if (test_checksum_functions()) tests_passed++;
    total_tests++; if (test_error_handling()) tests_passed++;

    printf("\n=== Packet Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, total_tests);

    return (tests_passed == total_tests) ? 0 : 1;
}

/**
 * @brief Main function
 */
int main(void) {
    return run_packet_tests();
}

