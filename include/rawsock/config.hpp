/**
 * @file config.hpp
 * @brief Configuration and platform detection for rawsock library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_CONFIG_HPP
#define RAWSOCK_CONFIG_HPP

#include <cstddef>

// Platform detection
#if defined(__linux__)
    #define RAWSOCK_PLATFORM_LINUX 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define RAWSOCK_PLATFORM_MACOS 1
#elif defined(_WIN32) || defined(_WIN64)
    #define RAWSOCK_PLATFORM_WINDOWS 1
#else
    #error "Unsupported platform"
#endif

// C++ version detection
#if __cplusplus >= 201703L
    #define RAWSOCK_CXX17 1
#elif __cplusplus >= 201402L
    #define RAWSOCK_CXX14 1
#elif __cplusplus >= 201103L
    #define RAWSOCK_CXX11 1
#endif

// Namespace configuration
#define RAWSOCK_NAMESPACE_BEGIN namespace rawsock {
#define RAWSOCK_NAMESPACE_END }

// Export macros for shared library
#if defined(RAWSOCK_SHARED_LIB)
    #if defined(_WIN32) || defined(_WIN64)
        #if defined(RAWSOCK_BUILDING_LIB)
            #define RAWSOCK_API __declspec(dllexport)
        #else
            #define RAWSOCK_API __declspec(dllimport)
        #endif
    #else
        #define RAWSOCK_API __attribute__((visibility("default")))
    #endif
#else
    #define RAWSOCK_API
#endif

// Inline hints
#define RAWSOCK_INLINE inline
#if defined(__GNUC__) || defined(__clang__)
    #define RAWSOCK_FORCE_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define RAWSOCK_FORCE_INLINE __forceinline
#else
    #define RAWSOCK_FORCE_INLINE inline
#endif

// Packed structure attribute
#if defined(__GNUC__) || defined(__clang__)
    #define RAWSOCK_PACKED __attribute__((packed))
#elif defined(_MSC_VER)
    #define RAWSOCK_PACKED
    #define RAWSOCK_PRAGMA_PACK_PUSH _Pragma("pack(push, 1)")
    #define RAWSOCK_PRAGMA_PACK_POP _Pragma("pack(pop)")
#else
    #define RAWSOCK_PACKED
#endif

#ifndef RAWSOCK_PRAGMA_PACK_PUSH
    #define RAWSOCK_PRAGMA_PACK_PUSH
    #define RAWSOCK_PRAGMA_PACK_POP
#endif

// Nodiscard attribute
#if defined(RAWSOCK_CXX17)
    #define RAWSOCK_NODISCARD [[nodiscard]]
#else
    #define RAWSOCK_NODISCARD
#endif

// Constants
namespace rawsock {
namespace constants {

constexpr std::size_t max_packet_size = 65535;
constexpr std::size_t ethernet_header_size = 14;
constexpr std::size_t ipv4_header_size = 20;
constexpr std::size_t ipv6_header_size = 40;
constexpr std::size_t tcp_header_size = 20;
constexpr std::size_t udp_header_size = 8;
constexpr std::size_t icmp_header_size = 8;

constexpr int default_recv_timeout_ms = 5000;
constexpr int default_send_timeout_ms = 5000;

} // namespace constants
} // namespace rawsock

#endif // RAWSOCK_CONFIG_HPP
