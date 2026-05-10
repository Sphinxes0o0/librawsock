/**
 * @file rawsock.hpp
 * @brief C++ Header-Only Wrapper for RawSock
 *
 * Usage:
 *   #include "rawsock.hpp"
 *   // No need to define RAWSOCK_IMPLEMENTATION — the .c file that has it
 *
 * Compile:
 *   g++ -std=c++11 -o myprogram myprogram.cpp
 *   sudo ./myprogram   # raw socket requires root/CAP_NET_RAW
 */

#ifndef RAWSOCK_HPP
#define RAWSOCK_HPP

#include "rawsock.h"

#include <stdexcept>
#include <string>
#include <cstring>

// INET6_ADDRSTRLEN may be in different headers across platforms
#ifdef __linux__
#include <arpa/inet.h>
#elif defined(__APPLE__)
#include <netinet/in.h>
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

namespace rawsock {

// ─── Exception ───────────────────────────────────────────────────────────────

class error : public std::runtime_error {
public:
    error(rawsock_err_t code, int sys_errno, const char* msg = nullptr)
        : std::runtime_error(msg ? msg : rawsock_strerror(code))
        , code_(code), sys_errno_(sys_errno) {}

    error(rawsock_err_t code, int sys_errno, const std::string& msg)
        : std::runtime_error(msg.empty() ? rawsock_strerror(code) : msg)
        , code_(code), sys_errno_(sys_errno) {}

    rawsock_err_t code() const noexcept { return code_; }
    int sys_errno() const noexcept { return sys_errno_; }

private:
    rawsock_err_t code_;
    int sys_errno_;
};

// ─── RAII Socket ─────────────────────────────────────────────────────────────

class socket {
public:
    /// Default construct — no socket, call open() later
    socket() noexcept : s_(nullptr) {}

    /// Open with config (throws on failure)
    explicit socket(const rawsock_cfg_t& cfg) : s_(rawsock_open(&cfg)) {
        if (!s_) throw error(last_err(), last_errno());
    }

    /// Open with default config (IPv4, all protocols)
    static socket open() { return socket(RAWSOCK_CFG_DEFAULT); }

    /// Open IPv4 socket for specific protocol
    static socket open_ip4(int protocol) {
        rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
        cfg.af = AF_INET;
        cfg.protocol = protocol;
        return socket(cfg);
    }

    /// Open IPv6 socket for specific protocol
    static socket open_ip6(int protocol) {
        rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
        cfg.af = AF_INET6;
        cfg.protocol = protocol;
        return socket(cfg);
    }

    /// Move constructor
    socket(socket&& other) noexcept : s_(other.s_) { other.s_ = nullptr; }

    /// Move assignment
    socket& operator=(socket&& other) noexcept {
        if (this != &other) { close(); s_ = other.s_; other.s_ = nullptr; }
        return *this;
    }

    /// Destructor — closes socket if open
    ~socket() { close(); }

    // No copy
    socket(const socket&) = delete;
    socket& operator=(const socket&) = delete;

    /// Check if socket is open
    explicit operator bool() const noexcept { return s_ != nullptr; }

    /// Get underlying handle (for advanced use)
    rawsock_t* get() noexcept { return s_; }
    const rawsock_t* get() const noexcept { return s_; }

    /// Close socket
    void close() noexcept {
        if (s_) { rawsock_close(s_); s_ = nullptr; }
    }

    /// Send packet (throws on failure)
    ssize_t send(const void* pkt, size_t len, const char* dst_addr) {
        ssize_t n = rawsock_send(s_, pkt, len, dst_addr);
        if (n < 0) throw error(last_err(), last_errno());
        return n;
    }

    /// Receive into buffer (throws on failure)
    ssize_t recv(void* buf, size_t len) {
        ssize_t n = rawsock_recv(s_, buf, len);
        if (n < 0) throw error(last_err(), last_errno());
        return n;
    }

    /// Receive with auto-parsing (throws on failure)
    ssize_t recv_auto(void* buf, size_t len, rawsock_pkt_t* info) {
        ssize_t n = rawsock_recv_auto(s_, buf, len, info);
        if (n < 0) throw error(last_err(), last_errno());
        return n;
    }

    /// Bind to interface (throws on failure)
    void bind_iface(const char* ifname) {
        if (rawsock_bind_iface(s_, ifname) < 0)
            throw error(last_err(), last_errno());
    }

    /// Set timeout (throws on failure)
    void set_timeout(int rcv_ms, int snd_ms) {
        if (rawsock_set_timeout(s_, rcv_ms, snd_ms) < 0)
            throw error(last_err(), last_errno());
    }

    rawsock_err_t last_err() const { return rawsock_last_err(s_); }
    int last_errno() const { return rawsock_last_errno(s_); }

private:
    rawsock_t* s_;
};

// ─── Utility ─────────────────────────────────────────────────────────────────

inline bool has_caps() noexcept { return rawsock_has_caps(); }

/// Parse IPv4 header (throws on failure)
inline void parse_ip4(const void* data, size_t len, rawsock_ip4_t& out,
                       const void** payload = nullptr, size_t* payload_len = nullptr) {
    if (rawsock_parse_ip4(data, len, &out, payload, payload_len) < 0)
        throw error(RSE_PROTO, 0, "IPv4 parse failed");
}

/// Parse IPv6 header (throws on failure)
inline void parse_ip6(const void* data, size_t len, rawsock_ip6_t& out,
                       const void** payload = nullptr, size_t* payload_len = nullptr) {
    if (rawsock_parse_ip6(data, len, &out, payload, payload_len) < 0)
        throw error(RSE_PROTO, 0, "IPv6 parse failed");
}

/// Parse TCP header (throws on failure)
inline void parse_tcp(const void* data, size_t len, rawsock_tcp_t& out) {
    if (rawsock_parse_tcp(data, len, &out) < 0)
        throw error(RSE_PROTO, 0, "TCP parse failed");
}

/// Parse UDP header (throws on failure)
inline void parse_udp(const void* data, size_t len, rawsock_udp_t& out) {
    if (rawsock_parse_udp(data, len, &out) < 0)
        throw error(RSE_PROTO, 0, "UDP parse failed");
}

/// Parse ICMP header (throws on failure)
inline void parse_icmp(const void* data, size_t len, rawsock_icmp_t& out) {
    if (rawsock_parse_icmp(data, len, &out) < 0)
        throw error(RSE_PROTO, 0, "ICMP parse failed");
}

/// Convert IP string to binary
inline void pton(const char* str, int af, void* bin, size_t bin_len) {
    if (rawsock_pton(str, af, bin, bin_len) < 0)
        throw error(RSE_INVAL, 0, "pton failed");
}

/// Convert binary IP to string
inline std::string ntop(const void* bin, int af) {
    char buf[INET6_ADDRSTRLEN];
    if (rawsock_ntop(bin, af, buf, sizeof(buf)) < 0)
        throw error(RSE_INVAL, 0, "ntop failed");
    return buf;
}

} // namespace rawsock

#endif // RAWSOCK_HPP
