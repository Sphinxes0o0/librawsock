/**
 * @file error.hpp
 * @brief Error handling for rawsock library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_ERROR_HPP
#define RAWSOCK_ERROR_HPP

#include "config.hpp"
#include <system_error>
#include <string>

RAWSOCK_NAMESPACE_BEGIN

/**
 * @brief Error codes for rawsock operations
 */
enum class error_code {
    success = 0,
    invalid_argument,
    socket_create_failed,
    socket_bind_failed,
    send_failed,
    recv_failed,
    permission_denied,
    timeout,
    buffer_too_small,
    interface_not_found,
    not_supported,
    unknown_error
};

/**
 * @brief Error category for rawsock errors
 */
class error_category_impl : public std::error_category {
public:
    RAWSOCK_NODISCARD
    const char* name() const noexcept override {
        return "rawsock";
    }

    RAWSOCK_NODISCARD
    std::string message(int ev) const override {
        switch (static_cast<error_code>(ev)) {
            case error_code::success:
                return "Success";
            case error_code::invalid_argument:
                return "Invalid argument";
            case error_code::socket_create_failed:
                return "Socket creation failed";
            case error_code::socket_bind_failed:
                return "Socket bind failed";
            case error_code::send_failed:
                return "Send operation failed";
            case error_code::recv_failed:
                return "Receive operation failed";
            case error_code::permission_denied:
                return "Permission denied (root privileges required)";
            case error_code::timeout:
                return "Operation timed out";
            case error_code::buffer_too_small:
                return "Buffer too small";
            case error_code::interface_not_found:
                return "Network interface not found";
            case error_code::not_supported:
                return "Operation not supported on this platform";
            case error_code::unknown_error:
            default:
                return "Unknown error";
        }
    }
};

/**
 * @brief Get the rawsock error category
 * @return Reference to the error category singleton
 */
RAWSOCK_INLINE
const std::error_category& error_category() noexcept {
    static error_category_impl instance;
    return instance;
}

/**
 * @brief Create a std::error_code from a rawsock error_code
 * @param e The rawsock error code
 * @return A std::error_code representing the error
 */
RAWSOCK_INLINE
std::error_code make_error_code(error_code e) noexcept {
    return {static_cast<int>(e), error_category()};
}

/**
 * @brief Exception class for rawsock errors
 */
class exception : public std::system_error {
public:
    explicit exception(error_code ec)
        : std::system_error(make_error_code(ec)) {}
    
    explicit exception(error_code ec, const std::string& what_arg)
        : std::system_error(make_error_code(ec), what_arg) {}
};

RAWSOCK_NAMESPACE_END

// Register rawsock::error_code as a std::error_code compatible type
namespace std {
template <>
struct is_error_code_enum<rawsock::error_code> : true_type {};
}

#endif // RAWSOCK_ERROR_HPP
