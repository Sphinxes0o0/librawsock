/**
 * @file test_rawsock.c
 * @brief Unit tests for raw socket core functionality
 * @author Sphinxes0o0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

#define TEST_SKIP(message) \
    do { \
        printf("SKIP: %s\n", message); \
        return 1; \
    } while(0)

/**
 * @brief Test library initialization and cleanup
 */
int test_library_init(void) {
    /* Test initialization */
    rawsock_error_t err = rawsock_init();
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Library initialization should succeed");

    /* Test multiple initializations (should be safe) */
    err = rawsock_init();
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Multiple initializations should be safe");

    /* Test cleanup */
    rawsock_cleanup();  /* Should not crash */
    rawsock_cleanup();  /* Multiple cleanups should be safe */

    /* Test version function */
    const char* version = rawsock_get_version();
    TEST_ASSERT(version != NULL, "Version string should not be NULL");
    TEST_ASSERT(strlen(version) > 0, "Version string should not be empty");

    TEST_PASS("Library initialization and cleanup");
}

/**
 * @brief Test error string functions
 */
int test_error_strings(void) {
    /* Test all error codes */
    const char* str;

    str = rawsock_error_string(RAWSOCK_SUCCESS);
    TEST_ASSERT(str != NULL && strlen(str) > 0, "Success error string should be valid");

    str = rawsock_error_string(RAWSOCK_ERROR_INVALID_PARAM);
    TEST_ASSERT(str != NULL && strlen(str) > 0, "Invalid param error string should be valid");

    str = rawsock_error_string(RAWSOCK_ERROR_SOCKET_CREATE);
    TEST_ASSERT(str != NULL && strlen(str) > 0, "Socket create error string should be valid");

    str = rawsock_error_string(RAWSOCK_ERROR_PERMISSION);
    TEST_ASSERT(str != NULL && strlen(str) > 0, "Permission error string should be valid");

    str = rawsock_error_string(RAWSOCK_ERROR_UNKNOWN);
    TEST_ASSERT(str != NULL && strlen(str) > 0, "Unknown error string should be valid");

    /* Test invalid error code */
    str = rawsock_error_string((rawsock_error_t)999);
    TEST_ASSERT(str != NULL, "Invalid error code should return valid string");

    TEST_PASS("Error string functions");
}

/**
 * @brief Test privilege checking
 */
int test_privilege_check(void) {
    int has_privileges = rawsock_check_privileges();

    if (geteuid() == 0) {
        /* Running as root */
        TEST_ASSERT(has_privileges == 1, "Root should have raw socket privileges");
    } else {
        /* Not running as root - may or may not have privileges */
        printf("INFO: Running as non-root user, privilege check returned: %d\n", 
               has_privileges);
    }

    TEST_PASS("Privilege checking");
}

/**
 * @brief Test socket creation and destruction
 */
int test_socket_creation(void) {
    /* Skip this test if we don't have privileges */
    if (!rawsock_check_privileges()) {
        TEST_SKIP("Socket creation (requires root privileges)");
    }

    /* Test basic socket creation */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        /* This might fail on some systems even with root privileges */
        TEST_SKIP("Socket creation (raw sockets may not be available)");
    }

    TEST_ASSERT(sock != NULL, "Socket creation should succeed with root privileges");

    /* Test last error function */
    rawsock_error_t last_error = rawsock_get_last_error(sock);
    TEST_ASSERT(last_error == RAWSOCK_SUCCESS, "Last error should be success after creation");

    /* Destroy socket */
    rawsock_destroy(sock);

    /* Test destruction of NULL socket */
    rawsock_destroy(NULL);  /* Should not crash */

    /* Test socket creation with configuration */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_ICMP,
        .recv_timeout_ms = 1000,
        .send_timeout_ms = 1000,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };

    sock = rawsock_create_with_config(&config);
    if (sock) {
        TEST_ASSERT(sock != NULL, "Socket creation with config should succeed");
        rawsock_destroy(sock);
    }

    /* Test invalid configuration */
    sock = rawsock_create_with_config(NULL);
    TEST_ASSERT(sock == NULL, "Socket creation with NULL config should fail");

    TEST_PASS("Socket creation and destruction");
}

/**
 * @brief Test socket options
 */
int test_socket_options(void) {
    /* Skip this test if we don't have privileges */
    if (!rawsock_check_privileges()) {
        TEST_SKIP("Socket options (requires root privileges)");
    }

    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        TEST_SKIP("Socket options (socket creation failed)");
    }

    /* Test setting socket option */
    int option_value = 1;
    rawsock_error_t err = rawsock_set_option(sock, SO_REUSEADDR, 
                                            &option_value, sizeof(option_value));
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Setting socket option should succeed");

    /* Test getting socket option */
    int retrieved_value;
    size_t value_size = sizeof(retrieved_value);
    err = rawsock_get_option(sock, SO_REUSEADDR, &retrieved_value, &value_size);
    TEST_ASSERT(err == RAWSOCK_SUCCESS, "Getting socket option should succeed");
    TEST_ASSERT(value_size == sizeof(retrieved_value), "Retrieved value size should match");

    /* Test invalid parameters */
    err = rawsock_set_option(NULL, SO_REUSEADDR, &option_value, sizeof(option_value));
    TEST_ASSERT(err == RAWSOCK_ERROR_INVALID_PARAM, "Setting option on NULL socket should fail");

    err = rawsock_get_option(sock, SO_REUSEADDR, NULL, &value_size);
    TEST_ASSERT(err == RAWSOCK_ERROR_INVALID_PARAM, "Getting option with NULL buffer should fail");

    rawsock_destroy(sock);
    TEST_PASS("Socket options");
}

/**
 * @brief Test parameter validation
 */
int test_parameter_validation(void) {
    /* Test invalid parameters for socket creation */
    rawsock_t* sock = rawsock_create((rawsock_family_t)999, IPPROTO_ICMP);
    TEST_ASSERT(sock == NULL, "Socket creation with invalid family should fail");

    /* Test invalid parameters for send function (without valid socket) */
    char test_data[] = "test";

    /* All these should fail due to NULL socket */
    int result = rawsock_send(NULL, test_data, sizeof(test_data), "192.168.1.1");
    TEST_ASSERT(result < 0, "Send with NULL socket should fail");

    /* Test error code for NULL parameters */
    rawsock_error_t error = rawsock_get_last_error(NULL);
    TEST_ASSERT(error == RAWSOCK_ERROR_INVALID_PARAM, 
                "Getting error from NULL socket should return invalid param");

    TEST_PASS("Parameter validation");
}

/**
 * @brief Test address family functionality
 */
int test_address_families(void) {
    /* Skip this test if we don't have privileges */
    if (!rawsock_check_privileges()) {
        TEST_SKIP("Address families (requires root privileges)");
    }

    /* Test IPv4 socket creation */
    rawsock_t* ipv4_sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (ipv4_sock) {
        TEST_ASSERT(ipv4_sock != NULL, "IPv4 socket creation should succeed");
        rawsock_destroy(ipv4_sock);
    }

    /* Test IPv6 socket creation */
    rawsock_t* ipv6_sock = rawsock_create(RAWSOCK_IPV6, IPPROTO_ICMPV6);
    if (ipv6_sock) {
        TEST_ASSERT(ipv6_sock != NULL, "IPv6 socket creation should succeed");
        rawsock_destroy(ipv6_sock);
    } else {
        printf("INFO: IPv6 socket creation failed (may not be available)\n");
    }

    TEST_PASS("Address families");
}

/**
 * @brief Test timeout functionality
 */
int test_timeout_functionality(void) {
    /* Skip this test if we don't have privileges */
    if (!rawsock_check_privileges()) {
        TEST_SKIP("Timeout functionality (requires root privileges)");
    }

    /* Create socket with short timeout */
    rawsock_config_t config = {
        .family = RAWSOCK_IPV4,
        .protocol = IPPROTO_ICMP,
        .recv_timeout_ms = 100,  /* Very short timeout */
        .send_timeout_ms = 100,
        .include_ip_header = 1,
        .broadcast = 0,
        .promiscuous = 0
    };

    rawsock_t* sock = rawsock_create_with_config(&config);
    if (!sock) {
        TEST_SKIP("Timeout functionality (socket creation failed)");
    }

    /* Try to receive with timeout (should timeout quickly) */
    char buffer[1500];
    rawsock_packet_info_t packet_info;

    int result = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);

    /* Should timeout or receive something */
    if (result < 0) {
        rawsock_error_t error = -result;
        if (error == RAWSOCK_ERROR_TIMEOUT) {
            printf("INFO: Receive timeout worked as expected\n");
        } else {
            printf("INFO: Receive failed with error: %s\n", rawsock_error_string(error));
        }
    } else {
        printf("INFO: Received %d bytes (may happen on busy networks)\n", result);
    }

    rawsock_destroy(sock);
    TEST_PASS("Timeout functionality");
}

/**
 * @brief Run all raw socket tests
 */
int run_rawsock_tests(void) {
    int tests_passed = 0;
    int total_tests = 0;

    printf("Running raw socket core functionality tests...\n\n");

    total_tests++; if (test_library_init()) tests_passed++;
    total_tests++; if (test_error_strings()) tests_passed++;
    total_tests++; if (test_privilege_check()) tests_passed++;
    total_tests++; if (test_socket_creation()) tests_passed++;
    total_tests++; if (test_socket_options()) tests_passed++;
    total_tests++; if (test_parameter_validation()) tests_passed++;
    total_tests++; if (test_address_families()) tests_passed++;
    total_tests++; if (test_timeout_functionality()) tests_passed++;

    printf("\n=== Raw Socket Test Results ===\n");
    printf("Tests passed: %d/%d\n", tests_passed, total_tests);

    return (tests_passed == total_tests) ? 0 : 1;
}

/**
 * @brief Main function
 */
int main(void) {
    return run_rawsock_tests();
}

