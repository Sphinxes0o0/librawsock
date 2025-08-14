/**
 * @file test_analyzer.c
 * @brief Unit tests for protocol analyzer framework
 * @author LibRawSock Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>
#include <librawsock/packet.h>

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

/* Global test variables */
static int g_connection_new_called = 0;
static int g_connection_close_called = 0;
static int g_data_ready_called = 0;

/**
 * @brief Test connection callback
 */
void test_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                             analyzer_result_t result) {
    (void)ctx;
    (void)conn;

    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            g_connection_new_called++;
            break;
        case ANALYZER_RESULT_CONNECTION_CLOSE:
            g_connection_close_called++;
            break;
        default:
            break;
    }
}

/**
 * @brief Test data callback
 */
void test_data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                       analyzer_direction_t dir, const uint8_t* data, size_t size) {
    (void)ctx;
    (void)conn;
    (void)dir;
    (void)data;
    (void)size;

    g_data_ready_called++;
}

/**
 * @brief Create test TCP packet
 */
size_t create_test_tcp_packet(uint8_t* buffer, size_t buffer_size,
                             const char* src_ip, const char* dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint32_t seq, uint32_t ack, uint8_t flags,
                             const char* payload) {
    if (!buffer || buffer_size < 100) {
        return 0;
    }

    /* Create packet builder */
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(buffer_size);
    if (!builder) {
        return 0;
    }

    /* Add IP header */
    if (rawsock_packet_add_ipv4_header(builder, src_ip, dst_ip, IPPROTO_TCP, 64) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Add TCP header */
    if (rawsock_packet_add_tcp_header(builder, src_port, dst_port, seq, ack, flags, 8192) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Add payload if provided */
    if (payload && strlen(payload) > 0) {
        if (rawsock_packet_add_payload(builder, payload, strlen(payload)) != RAWSOCK_SUCCESS) {
            rawsock_packet_builder_destroy(builder);
            return 0;
        }
    }

    /* Finalize packet */
    if (rawsock_packet_finalize(builder) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    if (rawsock_packet_get_data(builder, &packet_data, &packet_size) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }

    /* Copy to buffer */
    if (packet_size <= buffer_size) {
        memcpy(buffer, packet_data, packet_size);
    }

    rawsock_packet_builder_destroy(builder);
    return packet_size;
}

/**
 * @brief Test analyzer creation and destruction
 */
int test_analyzer_creation(void) {
    /* Test default creation */
    analyzer_context_t* ctx = analyzer_create();
    TEST_ASSERT(ctx != NULL, "Analyzer creation should succeed");

    analyzer_destroy(ctx);

    /* Test creation with config */
    analyzer_config_t config = {
        .max_connections = 100,
        .max_reassembly_size = 32768,
        .connection_timeout = 60,
        .enable_reassembly = 1,
        .enable_rtt_tracking = 1,
        .enable_statistics = 1
    };

    ctx = analyzer_create_with_config(&config);
    TEST_ASSERT(ctx != NULL, "Analyzer creation with config should succeed");
    TEST_ASSERT(ctx->config.max_connections == 100, "Config should be applied");

    analyzer_destroy(ctx);

    /* Test NULL destruction */
    analyzer_destroy(NULL);  /* Should not crash */

    TEST_PASS("Analyzer creation and destruction");
}

/**
 * @brief Test TCP analyzer handler
 */
int test_tcp_analyzer_handler(void) {
    /* Create TCP handler */
    analyzer_protocol_handler_t* handler = tcp_analyzer_create();
    TEST_ASSERT(handler != NULL, "TCP analyzer creation should succeed");
    TEST_ASSERT(handler->protocol == ANALYZER_PROTO_TCP, "Protocol should be TCP");
    TEST_ASSERT(handler->packet_handler != NULL, "Packet handler should be set");

    /* Create analyzer context */
    analyzer_context_t* ctx = analyzer_create();
    TEST_ASSERT(ctx != NULL, "Analyzer context creation should succeed");

    /* Register handler */
    rawsock_error_t err = analyzer_register_handler(ctx, handler);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Handler registration should succeed");

    /* Verify handler is registered */
    TEST_ASSERT(ctx->handlers[ANALYZER_PROTO_TCP] == handler, "Handler should be registered");

    /* Cleanup */
    analyzer_destroy(ctx);
    tcp_analyzer_destroy(handler);

    TEST_PASS("TCP analyzer handler");
}

/**
 * @brief Test flow ID utilities
 */
int test_flow_id_utilities(void) {
    analyzer_flow_id_t flow1, flow2, reverse_flow;

    /* Create flow ID */
    analyzer_create_flow_id(inet_addr("192.168.1.1"), inet_addr("192.168.1.2"),
                           1234, 80, IPPROTO_TCP, &flow1);

    TEST_ASSERT(flow1.src_ip == inet_addr("192.168.1.1"), "Source IP should match");
    TEST_ASSERT(flow1.dst_ip == inet_addr("192.168.1.2"), "Destination IP should match");
    TEST_ASSERT(flow1.src_port == 1234, "Source port should match");
    TEST_ASSERT(flow1.dst_port == 80, "Destination port should match");
    TEST_ASSERT(flow1.protocol == IPPROTO_TCP, "Protocol should match");

    /* Test flow comparison */
    flow2 = flow1;
    TEST_ASSERT(analyzer_flow_compare(&flow1, &flow2) == 1, "Identical flows should compare equal");

    flow2.src_port = 1235;
    TEST_ASSERT(analyzer_flow_compare(&flow1, &flow2) == 0, "Different flows should not compare equal");

    /* Test reverse flow */
    analyzer_get_reverse_flow_id(&flow1, &reverse_flow);
    TEST_ASSERT(reverse_flow.src_ip == flow1.dst_ip, "Reverse flow should swap IPs");
    TEST_ASSERT(reverse_flow.dst_ip == flow1.src_ip, "Reverse flow should swap IPs");
    TEST_ASSERT(reverse_flow.src_port == flow1.dst_port, "Reverse flow should swap ports");
    TEST_ASSERT(reverse_flow.dst_port == flow1.src_port, "Reverse flow should swap ports");

    /* Test hash function */
    uint32_t hash1 = analyzer_flow_hash(&flow1);
    uint32_t hash2 = analyzer_flow_hash(&flow1);
    TEST_ASSERT(hash1 == hash2, "Hash should be consistent");

    /* Test format function */
    char flow_str[128];
    analyzer_format_flow_id(&flow1, flow_str, sizeof(flow_str));
    TEST_ASSERT(strlen(flow_str) > 0, "Flow format should produce output");

    TEST_PASS("Flow ID utilities");
}

/**
 * @brief Test TCP state machine
 */
int test_tcp_state_machine(void) {
    /* Create TCP state */
    tcp_connection_state_t tcp_state;
    memset(&tcp_state, 0, sizeof(tcp_state));
    tcp_state.state = TCP_STATE_CLOSED;

    /* Test state transitions */
    rawsock_tcp_header_t tcp_header;
    memset(&tcp_header, 0, sizeof(tcp_header));

    /* SYN packet should transition to SYN_SENT */
    tcp_header.flags = TCP_FLAG_SYN;
    tcp_state_t new_state = tcp_update_state(&tcp_state, &tcp_header, ANALYZER_DIR_FORWARD);
    TEST_ASSERT(new_state == TCP_STATE_SYN_SENT, "SYN should transition to SYN_SENT");

    tcp_state.state = new_state;

    /* SYN-ACK should transition to SYN_RECEIVED */
    tcp_header.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    new_state = tcp_update_state(&tcp_state, &tcp_header, ANALYZER_DIR_REVERSE);
    TEST_ASSERT(new_state == TCP_STATE_SYN_RECEIVED, "SYN-ACK should transition to SYN_RECEIVED");

    tcp_state.state = new_state;

    /* ACK should transition to ESTABLISHED */
    tcp_header.flags = TCP_FLAG_ACK;
    new_state = tcp_update_state(&tcp_state, &tcp_header, ANALYZER_DIR_FORWARD);
    TEST_ASSERT(new_state == TCP_STATE_ESTABLISHED, "ACK should transition to ESTABLISHED");

    /* Test state to string conversion */
    const char* state_str = tcp_state_to_string(TCP_STATE_ESTABLISHED);
    TEST_ASSERT(strcmp(state_str, "ESTABLISHED") == 0, "State string should be correct");

    TEST_PASS("TCP state machine");
}

/**
 * @brief Test TCP options parsing
 */
int test_tcp_options_parsing(void) {
    /* Create a TCP header with options */
    uint8_t tcp_packet[64];
    memset(tcp_packet, 0, sizeof(tcp_packet));

    rawsock_tcp_header_t* header = (rawsock_tcp_header_t*)tcp_packet;
    header->src_port = htons(1234);
    header->dst_port = htons(80);
    header->seq_num = htonl(12345);
    header->ack_num = htonl(67890);
    header->data_offset_reserved = 0x80;  /* 8 * 4 = 32 bytes header (12 bytes options) */
    header->flags = TCP_FLAG_SYN;
    header->window = htons(8192);

    /* Add MSS option */
    uint8_t* options = tcp_packet + 20;
    options[0] = TCP_OPT_MSS;
    options[1] = 4;
    *(uint16_t*)(options + 2) = htons(1460);

    /* Add window scale option */
    options[4] = TCP_OPT_WINDOW_SCALE;
    options[5] = 3;
    options[6] = 7;

    /* Add SACK permitted option */
    options[7] = TCP_OPT_SACK_PERMITTED;
    options[8] = 2;

    /* End option */
    options[9] = TCP_OPT_END;

    /* Parse options */
    tcp_options_t parsed_options;
    rawsock_error_t err = tcp_parse_options(header, &parsed_options);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Options parsing should succeed");
    TEST_ASSERT(parsed_options.count >= 3, "Should find at least 3 options");
    TEST_ASSERT(parsed_options.mss == 1460, "MSS should be parsed correctly");
    TEST_ASSERT(parsed_options.window_scale == 7, "Window scale should be parsed correctly");
    TEST_ASSERT(parsed_options.sack_permitted == 1, "SACK permitted should be set");

    /* Test option lookup */
    const tcp_option_t* mss_opt = tcp_find_option(&parsed_options, TCP_OPT_MSS);
    TEST_ASSERT(mss_opt != NULL, "MSS option should be found");
    TEST_ASSERT(mss_opt->type == TCP_OPT_MSS, "Option type should match");
    TEST_ASSERT(mss_opt->length == 4, "Option length should match");

    TEST_PASS("TCP options parsing");
}

/**
 * @brief Test packet processing
 */
int test_packet_processing(void) {
    /* Reset global counters */
    g_connection_new_called = 0;
    g_connection_close_called = 0;
    g_data_ready_called = 0;

    /* Create analyzer */
    analyzer_context_t* ctx = analyzer_create();
    TEST_ASSERT(ctx != NULL, "Analyzer creation should succeed");

    /* Register TCP handler */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    /* Set callbacks */
    analyzer_set_connection_callback(ctx, test_connection_callback);
    analyzer_set_data_callback(ctx, test_data_callback);

    /* Create test packets */
    uint8_t packet1[100], packet2[100], packet3[100];
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    /* SYN packet */
    size_t size1 = create_test_tcp_packet(packet1, sizeof(packet1),
                                         "192.168.1.1", "192.168.1.2",
                                         1234, 80, 1000, 0, TCP_FLAG_SYN, NULL);
    TEST_ASSERT(size1 > 0, "SYN packet creation should succeed");

    /* SYN-ACK packet */
    size_t size2 = create_test_tcp_packet(packet2, sizeof(packet2),
                                         "192.168.1.2", "192.168.1.1",
                                         80, 1234, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL);
    TEST_ASSERT(size2 > 0, "SYN-ACK packet creation should succeed");

    /* ACK packet with data */
    size_t size3 = create_test_tcp_packet(packet3, sizeof(packet3),
                                         "192.168.1.1", "192.168.1.2",
                                         1234, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, "GET / HTTP/1.1\r\n");
    TEST_ASSERT(size3 > 0, "Data packet creation should succeed");

    /* Process packets */
    analyzer_result_t result;

    result = analyzer_process_packet(ctx, packet1, size1, &timestamp);
    TEST_ASSERT(result == ANALYZER_RESULT_CONNECTION_NEW, "First packet should create new connection");
    TEST_ASSERT(g_connection_new_called == 1, "New connection callback should be called");

    result = analyzer_process_packet(ctx, packet2, size2, &timestamp);
    TEST_ASSERT(result == ANALYZER_RESULT_OK, "SYN-ACK should be processed successfully");

    result = analyzer_process_packet(ctx, packet3, size3, &timestamp);
    /* Data packet may or may not trigger data ready depending on reassembly */
    TEST_ASSERT(result == ANALYZER_RESULT_OK || result == ANALYZER_RESULT_DATA_READY, 
                "Data packet should be processed successfully");

    /* Verify statistics */
    TEST_ASSERT(ctx->total_packets == 3, "Should have processed 3 packets");
    TEST_ASSERT(ctx->total_connections == 1, "Should have seen 1 connection");
    TEST_ASSERT(ctx->active_connections == 1, "Should have 1 active connection");

    /* Cleanup */
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);

    TEST_PASS("Packet processing");
}

/**
 * @brief Test connection cleanup
 */
int test_connection_cleanup(void) {
    /* Create analyzer with short timeout */
    analyzer_config_t config = {
        .max_connections = 10,
        .max_reassembly_size = 1024,
        .connection_timeout = 1,  /* 1 second timeout */
        .enable_reassembly = 0,
        .enable_rtt_tracking = 1,
        .enable_statistics = 1
    };

    analyzer_context_t* ctx = analyzer_create_with_config(&config);
    TEST_ASSERT(ctx != NULL, "Analyzer creation should succeed");

    /* Register TCP handler */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    /* Create test packet */
    uint8_t packet[100];
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    size_t size = create_test_tcp_packet(packet, sizeof(packet),
                                        "10.0.0.1", "10.0.0.2",
                                        5000, 80, 1000, 0, TCP_FLAG_SYN, NULL);
    TEST_ASSERT(size > 0, "Packet creation should succeed");

    /* Process packet to create connection */
    analyzer_result_t result = analyzer_process_packet(ctx, packet, size, &timestamp);
    TEST_ASSERT(result == ANALYZER_RESULT_CONNECTION_NEW, "Should create new connection");
    TEST_ASSERT(ctx->active_connections == 1, "Should have 1 active connection");

    /* Wait for timeout */
    sleep(2);

    /* Cleanup expired connections */
    size_t cleaned = analyzer_cleanup_expired(ctx);
    TEST_ASSERT(cleaned == 1, "Should clean up 1 expired connection");
    TEST_ASSERT(ctx->active_connections == 0, "Should have 0 active connections");

    /* Cleanup */
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);

    TEST_PASS("Connection cleanup");
}

/**
 * @brief Run all analyzer tests
 */
int run_analyzer_tests(void) {
    int tests_passed = 0;
    int total_tests = 0;

    printf("Running protocol analyzer tests...\n\n");

    total_tests++; if (test_analyzer_creation()) tests_passed++;
    total_tests++; if (test_tcp_analyzer_handler()) tests_passed++;
    total_tests++; if (test_flow_id_utilities()) tests_passed++;
    total_tests++; if (test_tcp_state_machine()) tests_passed++;
    total_tests++; if (test_tcp_options_parsing()) tests_passed++;
    total_tests++; if (test_packet_processing()) tests_passed++;
    total_tests++; if (test_connection_cleanup()) tests_passed++;

    printf("\n=== Analyzer Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, total_tests);

    return (tests_passed == total_tests) ? 0 : 1;
}

/**
 * @brief Main function
 */
int main(void) {
    return run_analyzer_tests();
}
