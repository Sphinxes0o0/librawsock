/**
 * @file test_common.hpp
 * @brief Common test macros and utilities
 */

#ifndef RAWSOCK_TEST_COMMON_HPP
#define RAWSOCK_TEST_COMMON_HPP

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

#define ASSERT_FALSE(condition) \
    do { \
        if ((condition)) { \
            printf("FAILED: Condition should be false at line %d\n", __LINE__); \
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

#endif // RAWSOCK_TEST_COMMON_HPP
