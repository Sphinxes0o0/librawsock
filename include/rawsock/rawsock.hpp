/**
 * @file rawsock.hpp
 * @brief Main header for rawsock C++ library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * @brief rawsock - A lightweight AF_PACKET based network capture library
 *
 * This library provides a clean, modern C++ interface for network packet
 * capture using Linux's AF_PACKET interface. It follows Boost coding
 * conventions and requires no external dependencies.
 *
 * Features:
 * - Header-only library design
 * - Modern C++11/14/17 compatible
 * - AF_PACKET based capture (Linux)
 * - Protocol filtering
 * - Packet parsing utilities
 * - Both C and C++ interfaces
 *
 * Example usage:
 * @code
 * #include <rawsock/rawsock.hpp>
 * 
 * int main() {
 *     rawsock::capture cap;
 *     rawsock::capture_config config;
 *     config.interface_name = "eth0";
 *     config.filter_protocol = rawsock::protocol::tcp;
 *     
 *     if (cap.open(config) == rawsock::error_code::success) {
 *         std::vector<uint8_t> buffer(65535);
 *         rawsock::packet_info info;
 *         
 *         int bytes = cap.capture_next(buffer.data(), buffer.size(), &info);
 *         if (bytes > 0) {
 *             std::cout << "Captured: " << info.src_addr << " -> " 
 *                       << info.dst_addr << std::endl;
 *         }
 *     }
 *     return 0;
 * }
 * @endcode
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_HPP
#define RAWSOCK_HPP

// Include all components
#include "config.hpp"
#include "error.hpp"
#include "packet.hpp"
#include "capture.hpp"

RAWSOCK_NAMESPACE_BEGIN

/**
 * @brief Get library version string
 * @return Version string in format "major.minor.patch"
 */
RAWSOCK_INLINE
const char* version() noexcept {
    return "2.0.0";
}

/**
 * @brief Get library version as integer
 * @return Version as integer (major * 10000 + minor * 100 + patch)
 */
RAWSOCK_INLINE
int version_number() noexcept {
    return 20000;
}

RAWSOCK_NAMESPACE_END

#endif // RAWSOCK_HPP
