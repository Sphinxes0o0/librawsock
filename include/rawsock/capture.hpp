/**
 * @file capture.hpp
 * @brief AF_PACKET based network capture interface
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#ifndef RAWSOCK_CAPTURE_HPP
#define RAWSOCK_CAPTURE_HPP

#include "config.hpp"
#include "error.hpp"
#include "packet.hpp"

#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <cstdint>
#include <atomic>

#ifdef RAWSOCK_PLATFORM_LINUX
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

RAWSOCK_NAMESPACE_BEGIN

/**
 * @brief Configuration options for packet capture
 */
struct capture_config {
    std::string interface_name;     ///< Network interface name (empty for any)
    protocol filter_protocol = protocol::all;  ///< Protocol to filter
    int recv_timeout_ms = constants::default_recv_timeout_ms;
    int send_timeout_ms = constants::default_send_timeout_ms;
    bool promiscuous = false;       ///< Enable promiscuous mode
    std::size_t buffer_size = constants::max_packet_size;
};

/**
 * @brief Packet callback function type
 */
using packet_handler = std::function<void(const std::uint8_t*, std::size_t, const packet_info&)>;

/**
 * @brief AF_PACKET based network capture class
 *
 * This class provides a clean C++ interface for capturing network packets
 * using Linux's AF_PACKET socket interface.
 */
class RAWSOCK_API capture {
public:
    /**
     * @brief Default constructor
     */
    capture() noexcept;
    
    /**
     * @brief Constructor with configuration
     * @param config Capture configuration
     */
    explicit capture(const capture_config& config);
    
    /**
     * @brief Destructor
     */
    ~capture() noexcept;
    
    // Non-copyable
    capture(const capture&) = delete;
    capture& operator=(const capture&) = delete;
    
    // Movable
    capture(capture&& other) noexcept;
    capture& operator=(capture&& other) noexcept;
    
    /**
     * @brief Open the capture socket
     * @return Error code
     */
    RAWSOCK_NODISCARD
    error_code open() noexcept;
    
    /**
     * @brief Open the capture socket with configuration
     * @param config Capture configuration
     * @return Error code
     */
    RAWSOCK_NODISCARD
    error_code open(const capture_config& config) noexcept;
    
    /**
     * @brief Close the capture socket
     */
    void close() noexcept;
    
    /**
     * @brief Check if capture is open
     * @return true if capture is open
     */
    RAWSOCK_NODISCARD
    bool is_open() const noexcept;
    
    /**
     * @brief Capture next packet
     * @param buffer Buffer to store packet data
     * @param buffer_size Size of buffer
     * @param info Optional packet info output
     * @return Number of bytes captured, or negative error code
     */
    RAWSOCK_NODISCARD
    int capture_next(void* buffer, std::size_t buffer_size, packet_info* info = nullptr) noexcept;
    
    /**
     * @brief Capture next packet with timeout
     * @param buffer Buffer to store packet data
     * @param buffer_size Size of buffer
     * @param timeout_ms Timeout in milliseconds
     * @param info Optional packet info output
     * @return Number of bytes captured, or negative error code
     */
    RAWSOCK_NODISCARD
    int capture_next_timeout(void* buffer, std::size_t buffer_size, 
                            int timeout_ms, packet_info* info = nullptr) noexcept;
    
    /**
     * @brief Start continuous capture with callback
     * @param handler Packet handler callback
     * @param count Number of packets to capture (0 for infinite)
     * @return Error code
     */
    error_code start_capture(const packet_handler& handler, std::size_t count = 0);
    
    /**
     * @brief Stop continuous capture
     */
    void stop_capture() noexcept;
    
    /**
     * @brief Send raw packet
     * @param data Packet data
     * @param size Size of packet data
     * @return Number of bytes sent, or negative error code
     */
    RAWSOCK_NODISCARD
    int send_packet(const void* data, std::size_t size) noexcept;
    
    /**
     * @brief Get last error code
     * @return Last error code
     */
    RAWSOCK_NODISCARD
    error_code last_error() const noexcept;
    
    /**
     * @brief Get capture statistics
     * @param packets_received Output for received packets count
     * @param packets_dropped Output for dropped packets count
     * @return Error code
     */
    RAWSOCK_NODISCARD
    error_code get_statistics(std::uint64_t& packets_received, 
                              std::uint64_t& packets_dropped) const noexcept;
    
    /**
     * @brief Set socket option
     * @param level Option level
     * @param optname Option name
     * @param optval Option value
     * @param optlen Option value length
     * @return Error code
     */
    error_code set_option(int level, int optname, 
                          const void* optval, std::size_t optlen) noexcept;
    
    /**
     * @brief Get interface index by name
     * @param name Interface name
     * @return Interface index or -1 on error
     */
    static int get_interface_index(const std::string& name) noexcept;
    
    /**
     * @brief Check if running with required privileges
     * @return true if privileges are sufficient
     */
    static bool check_privileges() noexcept;

private:
    int socket_fd_ = -1;
    capture_config config_;
    error_code last_error_ = error_code::success;
    std::atomic<bool> running_{false};
    
    void extract_packet_info(const void* packet, std::size_t size, 
                            packet_info& info) const noexcept;
    bool should_filter_packet(const void* packet, std::size_t size) const noexcept;
};

// Implementation

RAWSOCK_INLINE
capture::capture() noexcept = default;

RAWSOCK_INLINE
capture::capture(const capture_config& config) 
    : config_(config) {
}

RAWSOCK_INLINE
capture::~capture() noexcept {
    close();
}

RAWSOCK_INLINE
capture::capture(capture&& other) noexcept
    : socket_fd_(other.socket_fd_)
    , config_(std::move(other.config_))
    , last_error_(other.last_error_)
    , running_(other.running_.load()) {
    other.socket_fd_ = -1;
    other.running_ = false;
}

RAWSOCK_INLINE
capture& capture::operator=(capture&& other) noexcept {
    if (this != &other) {
        close();
        socket_fd_ = other.socket_fd_;
        config_ = std::move(other.config_);
        last_error_ = other.last_error_;
        running_ = other.running_.load();
        other.socket_fd_ = -1;
        other.running_ = false;
    }
    return *this;
}

RAWSOCK_INLINE
error_code capture::open() noexcept {
    return open(config_);
}

RAWSOCK_INLINE
error_code capture::open(const capture_config& config) noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    config_ = config;
    
    // Create AF_PACKET socket
    socket_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd_ < 0) {
        if (errno == EPERM || errno == EACCES) {
            last_error_ = error_code::permission_denied;
        } else {
            last_error_ = error_code::socket_create_failed;
        }
        return last_error_;
    }
    
    // Bind to interface if specified
    if (!config_.interface_name.empty()) {
        struct sockaddr_ll sll;
        std::memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = get_interface_index(config_.interface_name);
        
        if (sll.sll_ifindex < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            last_error_ = error_code::interface_not_found;
            return last_error_;
        }
        
        if (bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
            ::close(socket_fd_);
            socket_fd_ = -1;
            last_error_ = error_code::socket_bind_failed;
            return last_error_;
        }
    }
    
    // Set promiscuous mode if requested
    if (config_.promiscuous && !config_.interface_name.empty()) {
        struct packet_mreq mreq;
        std::memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = get_interface_index(config_.interface_name);
        mreq.mr_type = PACKET_MR_PROMISC;
        
        if (setsockopt(socket_fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, 
                      &mreq, sizeof(mreq)) < 0) {
            // Non-fatal, continue without promiscuous mode
        }
    }
    
    // Set receive timeout
    if (config_.recv_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = config_.recv_timeout_ms / 1000;
        timeout.tv_usec = (config_.recv_timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
    
    // Set send timeout
    if (config_.send_timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = config_.send_timeout_ms / 1000;
        timeout.tv_usec = (config_.send_timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    
    last_error_ = error_code::success;
    return last_error_;
#else
    last_error_ = error_code::not_supported;
    return last_error_;
#endif
}

RAWSOCK_INLINE
void capture::close() noexcept {
    stop_capture();
    if (socket_fd_ >= 0) {
#ifdef RAWSOCK_PLATFORM_LINUX
        ::close(socket_fd_);
#endif
        socket_fd_ = -1;
    }
}

RAWSOCK_INLINE
bool capture::is_open() const noexcept {
    return socket_fd_ >= 0;
}

RAWSOCK_INLINE
int capture::capture_next(void* buffer, std::size_t buffer_size, packet_info* info) noexcept {
    return capture_next_timeout(buffer, buffer_size, config_.recv_timeout_ms, info);
}

RAWSOCK_INLINE
int capture::capture_next_timeout(void* buffer, std::size_t buffer_size, 
                                  int timeout_ms, packet_info* info) noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    if (!is_open() || !buffer || buffer_size == 0) {
        last_error_ = error_code::invalid_argument;
        return -static_cast<int>(last_error_);
    }
    
    // Set timeout for this operation
    if (timeout_ms > 0) {
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
    
    // Use iterative approach for packet filtering to avoid stack overflow
    while (true) {
        struct sockaddr_ll src_addr;
        socklen_t addr_len = sizeof(src_addr);
        
        ssize_t received = recvfrom(socket_fd_, buffer, buffer_size, 0,
                                    reinterpret_cast<struct sockaddr*>(&src_addr), &addr_len);
        
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                last_error_ = error_code::timeout;
            } else {
                last_error_ = error_code::recv_failed;
            }
            return -static_cast<int>(last_error_);
        }
        
        // Check protocol filter
        if (config_.filter_protocol != protocol::all) {
            if (should_filter_packet(buffer, static_cast<std::size_t>(received))) {
                // Packet doesn't match filter, continue loop to try again
                continue;
            }
        }
        
        // Fill packet info if requested
        if (info) {
            extract_packet_info(buffer, static_cast<std::size_t>(received), *info);
            info->packet_size = static_cast<std::size_t>(received);
            
            // Get timestamp
            struct timeval tv;
            gettimeofday(&tv, nullptr);
            info->timestamp_us = static_cast<std::uint64_t>(tv.tv_sec) * 1000000ULL + 
                                static_cast<std::uint64_t>(tv.tv_usec);
            
            if (!config_.interface_name.empty()) {
                info->interface_name = config_.interface_name;
            }
        }
        
        last_error_ = error_code::success;
        return static_cast<int>(received);
    }
#else
    (void)buffer;
    (void)buffer_size;
    (void)timeout_ms;
    (void)info;
    last_error_ = error_code::not_supported;
    return -static_cast<int>(last_error_);
#endif
}

RAWSOCK_INLINE
error_code capture::start_capture(const packet_handler& handler, std::size_t count) {
    if (!is_open()) {
        last_error_ = error_code::invalid_argument;
        return last_error_;
    }
    
    running_ = true;
    std::vector<std::uint8_t> buffer(config_.buffer_size);
    std::size_t captured = 0;
    
    while (running_ && (count == 0 || captured < count)) {
        packet_info info;
        int result = capture_next(buffer.data(), buffer.size(), &info);
        
        if (result > 0) {
            handler(buffer.data(), static_cast<std::size_t>(result), info);
            ++captured;
        } else if (result == -static_cast<int>(error_code::timeout)) {
            // Timeout, continue loop
            continue;
        } else {
            break;
        }
    }
    
    running_ = false;
    return last_error_;
}

RAWSOCK_INLINE
void capture::stop_capture() noexcept {
    running_ = false;
}

RAWSOCK_INLINE
int capture::send_packet(const void* data, std::size_t size) noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    if (!is_open() || !data || size == 0) {
        last_error_ = error_code::invalid_argument;
        return -static_cast<int>(last_error_);
    }
    
    ssize_t sent = send(socket_fd_, data, size, 0);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            last_error_ = error_code::timeout;
        } else {
            last_error_ = error_code::send_failed;
        }
        return -static_cast<int>(last_error_);
    }
    
    last_error_ = error_code::success;
    return static_cast<int>(sent);
#else
    (void)data;
    (void)size;
    last_error_ = error_code::not_supported;
    return -static_cast<int>(last_error_);
#endif
}

RAWSOCK_INLINE
error_code capture::last_error() const noexcept {
    return last_error_;
}

RAWSOCK_INLINE
error_code capture::get_statistics(std::uint64_t& packets_received, 
                                   std::uint64_t& packets_dropped) const noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    if (!is_open()) {
        return error_code::invalid_argument;
    }
    
    struct tpacket_stats stats;
    socklen_t len = sizeof(stats);
    
    if (getsockopt(socket_fd_, SOL_PACKET, PACKET_STATISTICS, &stats, &len) < 0) {
        return error_code::unknown_error;
    }
    
    packets_received = stats.tp_packets;
    packets_dropped = stats.tp_drops;
    
    return error_code::success;
#else
    (void)packets_received;
    (void)packets_dropped;
    return error_code::not_supported;
#endif
}

RAWSOCK_INLINE
error_code capture::set_option(int level, int optname, 
                               const void* optval, std::size_t optlen) noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    if (!is_open() || !optval) {
        last_error_ = error_code::invalid_argument;
        return last_error_;
    }
    
    if (setsockopt(socket_fd_, level, optname, optval, static_cast<socklen_t>(optlen)) < 0) {
        last_error_ = error_code::unknown_error;
        return last_error_;
    }
    
    last_error_ = error_code::success;
    return last_error_;
#else
    (void)level;
    (void)optname;
    (void)optval;
    (void)optlen;
    last_error_ = error_code::not_supported;
    return last_error_;
#endif
}

RAWSOCK_INLINE
int capture::get_interface_index(const std::string& name) noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    
    int result = -1;
    if (ioctl(sock, SIOCGIFINDEX, &ifr) >= 0) {
        result = ifr.ifr_ifindex;
    }
    
    ::close(sock);
    return result;
#else
    (void)name;
    return -1;
#endif
}

RAWSOCK_INLINE
bool capture::check_privileges() noexcept {
#ifdef RAWSOCK_PLATFORM_LINUX
    if (geteuid() == 0) {
        return true;
    }
    
    // Try to create a test socket
    int test_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (test_sock >= 0) {
        ::close(test_sock);
        return true;
    }
    
    return false;
#else
    return false;
#endif
}

RAWSOCK_INLINE
void capture::extract_packet_info(const void* packet, std::size_t size, 
                                  packet_info& info) const noexcept {
    info = packet_info{};
    
    if (size < constants::ethernet_header_size + constants::ipv4_header_size) {
        return;
    }
    
    const auto* eth = static_cast<const std::uint8_t*>(packet);
    const auto* ip = eth + constants::ethernet_header_size;
    
    // Check for IPv4
    if ((ip[0] >> 4) == 4) {
        ipv4_header ipv4;
        if (parse_ipv4_header(ip, size - constants::ethernet_header_size, ipv4) == error_code::success) {
            // Convert addresses to strings
            struct in_addr src, dst;
            src.s_addr = htonl(ipv4.src_addr);
            dst.s_addr = htonl(ipv4.dst_addr);
            
            char src_str[INET_ADDRSTRLEN];
            char dst_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src, src_str, sizeof(src_str));
            inet_ntop(AF_INET, &dst, dst_str, sizeof(dst_str));
            
            info.src_addr = src_str;
            info.dst_addr = dst_str;
            info.proto = static_cast<protocol>(ipv4.protocol);
            
            // Parse transport layer
            std::size_t ip_header_len = ipv4.header_length();
            const auto* transport = ip + ip_header_len;
            std::size_t transport_size = size - constants::ethernet_header_size - ip_header_len;
            
            if (ipv4.protocol == static_cast<std::uint8_t>(protocol::tcp) && 
                transport_size >= constants::tcp_header_size) {
                tcp_header tcp;
                if (parse_tcp_header(transport, transport_size, tcp) == error_code::success) {
                    info.src_port = tcp.src_port;
                    info.dst_port = tcp.dst_port;
                }
            } else if (ipv4.protocol == static_cast<std::uint8_t>(protocol::udp) && 
                       transport_size >= constants::udp_header_size) {
                udp_header udp;
                if (parse_udp_header(transport, transport_size, udp) == error_code::success) {
                    info.src_port = udp.src_port;
                    info.dst_port = udp.dst_port;
                }
            }
        }
    }
}

RAWSOCK_INLINE
bool capture::should_filter_packet(const void* packet, std::size_t size) const noexcept {
    if (config_.filter_protocol == protocol::all) {
        return false;  // No filtering
    }
    
    if (size < constants::ethernet_header_size + constants::ipv4_header_size) {
        return true;  // Filter out: too small
    }
    
    const auto* eth = static_cast<const std::uint8_t*>(packet);
    const auto* ip = eth + constants::ethernet_header_size;
    
    // Check for IPv4
    if ((ip[0] >> 4) == 4) {
        std::uint8_t proto = ip[9];  // Protocol field in IP header
        return proto != static_cast<std::uint8_t>(config_.filter_protocol);
    }
    
    return true;  // Filter out non-IPv4 packets when filtering
}

RAWSOCK_NAMESPACE_END

#endif // RAWSOCK_CAPTURE_HPP
