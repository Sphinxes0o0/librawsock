/**
 * @file test_error.cpp
 * @brief Unit tests for error handling
 */

#include <rawsock/rawsock.hpp>
#include <cstdio>
#include <cassert>
#include <cstring>

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

#define ASSERT_STREQ(expected, actual) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            printf("FAILED: Expected '%s', got '%s' at line %d\n", \
                   (expected), (actual), __LINE__); \
            assert(false); \
        } \
    } while(0)

// Test error code to string conversion
TEST(error_to_string) {
    std::error_code ec = rawsock::make_error_code(rawsock::error_code::success);
    ASSERT_TRUE(ec.message().find("Success") != std::string::npos);
    
    ec = rawsock::make_error_code(rawsock::error_code::permission_denied);
    ASSERT_TRUE(ec.message().find("Permission") != std::string::npos || 
                ec.message().find("permission") != std::string::npos);
    
    ec = rawsock::make_error_code(rawsock::error_code::timeout);
    ASSERT_TRUE(ec.message().find("timed") != std::string::npos || 
                ec.message().find("Timeout") != std::string::npos ||
                ec.message().find("timeout") != std::string::npos);
}

// Test error category
TEST(error_category) {
    const auto& cat = rawsock::error_category();
    ASSERT_STREQ("rawsock", cat.name());
    
    // Test message for each error code
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::success)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::invalid_argument)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::socket_create_failed)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::socket_bind_failed)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::send_failed)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::recv_failed)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::permission_denied)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::timeout)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::buffer_too_small)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::interface_not_found)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::not_supported)).length() > 0);
    ASSERT_TRUE(cat.message(static_cast<int>(rawsock::error_code::unknown_error)).length() > 0);
}

// Test exception
TEST(exception) {
    try {
        throw rawsock::exception(rawsock::error_code::permission_denied);
    } catch (const rawsock::exception& e) {
        ASSERT_TRUE(e.code().value() == static_cast<int>(rawsock::error_code::permission_denied));
        ASSERT_TRUE(strlen(e.what()) > 0);
    }
    
    try {
        throw rawsock::exception(rawsock::error_code::timeout, "Custom message");
    } catch (const rawsock::exception& e) {
        ASSERT_TRUE(e.code().value() == static_cast<int>(rawsock::error_code::timeout));
        ASSERT_TRUE(strlen(e.what()) > 0);
    }
}

// Test make_error_code
TEST(make_error_code) {
    auto ec = rawsock::make_error_code(rawsock::error_code::success);
    ASSERT_EQ(0, ec.value());
    ASSERT_TRUE(!ec);  // Success should evaluate to false in boolean context
    
    ec = rawsock::make_error_code(rawsock::error_code::permission_denied);
    ASSERT_EQ(static_cast<int>(rawsock::error_code::permission_denied), ec.value());
    ASSERT_TRUE(ec);  // Error should evaluate to true in boolean context
}

// Test error code comparison
TEST(error_code_comparison) {
    auto ec1 = rawsock::make_error_code(rawsock::error_code::timeout);
    auto ec2 = rawsock::make_error_code(rawsock::error_code::timeout);
    auto ec3 = rawsock::make_error_code(rawsock::error_code::permission_denied);
    
    ASSERT_TRUE(ec1 == ec2);
    ASSERT_TRUE(ec1 != ec3);
}

int main() {
    printf("=== Error Handling Tests ===\n\n");
    
    RUN_TEST(error_to_string);
    RUN_TEST(error_category);
    RUN_TEST(exception);
    RUN_TEST(make_error_code);
    RUN_TEST(error_code_comparison);
    
    printf("\n=== All Error Tests Passed ===\n");
    return 0;
}
