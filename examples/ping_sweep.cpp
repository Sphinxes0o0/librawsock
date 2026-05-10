/**
 * @example ping_sweep.cpp
 * @brief ICMP ping sweep - discover live hosts using ICMP echo requests
 *
 * Sends ICMP echo requests to a range of IPs and reports which hosts reply.
 * Requires root privileges (sudo).
 *
 * Usage:
 *   sudo ./ping_sweep 192.168.1.0/24
 *   sudo ./ping_sweep 10.0.0.1-254
 */

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <chrono>
#include <thread>

static uint16_t calc_cksum(const void* data, size_t len) {
    return rawsock_cksum(data, len);
}

struct icmp_echo {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
    uint8_t  payload[56];  // 64 bytes ICMP header area
};

static void build_icmp_echo_request(uint8_t* packet, uint16_t id, uint16_t seq) {
    icmp_echo* icmp = (icmp_echo*)packet;
    memset(icmp, 0, sizeof(icmp_echo));
    icmp->type = 8;  // Echo request
    icmp->code = 0;
    icmp->id = id;
    icmp->seq = seq;
    // Fill payload with pattern
    for (int i = 0; i < 56; i++) {
        icmp->payload[i] = (uint8_t)(i & 0xFF);
    }
    icmp->checksum = calc_cksum(icmp, sizeof(icmp_echo));
}

struct scan_result {
    uint8_t ip[4];
    bool replied;
    int64_t rtt_us;
};

static bool parse_ip(const char* str, uint8_t* ip) {
    return sscanf(str, "%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]) == 4;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <target> [timeout_ms]\n", argv[0]);
        std::fprintf(stderr, "  target:     IP range like 192.168.1.0/24 or 192.168.1.1-254\n");
        std::fprintf(stderr, "  timeout_ms: per-host timeout in ms (default: 2000)\n");
        return 1;
    }

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    const char* target = argv[1];
    int timeout_ms = (argc > 2) ? atoi(argv[2]) : 2000;

    // Parse target range
    uint8_t start_ip[4], end_ip[4];

    if (strchr(target, '/')) {
        uint8_t mask;
        uint8_t base_ip[4];
        if (sscanf(target, "%hhu.%hhu.%hhu.%hhu/%hhu",
                   &base_ip[0], &base_ip[1], &base_ip[2], &base_ip[3], &mask) != 5) {
            std::fprintf(stderr, "Invalid CIDR: %s\n", target);
            return 1;
        }
        memcpy(start_ip, base_ip, 4);
        memcpy(end_ip, base_ip, 4);
        if (mask == 24) {
            start_ip[3] = 1; end_ip[3] = 254;
        } else if (mask < 24) {
            start_ip[3] = 0; end_ip[3] = 255;
        } else {
            std::fprintf(stderr, "Unsupported CIDR mask: %d (only /24 supported)\n", mask);
            return 1;
        }
    } else if (strchr(target, '-')) {
        char* dash = strchr(const_cast<char*>(target), '-');
        *dash = '\0';
        if (!parse_ip(target, start_ip) || !parse_ip(dash + 1, end_ip)) {
            std::fprintf(stderr, "Invalid range: %s\n", target);
            return 1;
        }
    } else {
        std::fprintf(stderr, "Use CIDR (192.168.1.0/24) or range (192.168.1.1-254)\n");
        return 1;
    }

    try {
        rawsock::socket sock = rawsock::socket::open_ip4(IPPROTO_ICMP);
        sock.set_timeout(timeout_ms, timeout_ms);

        std::printf("ICMP Ping Sweep: %d.%d.%d.%d - %d.%d.%d.%d\n",
                    start_ip[0], start_ip[1], start_ip[2], start_ip[3],
                    end_ip[0], end_ip[1], end_ip[2], end_ip[3]);
        std::printf("Timeout: %d ms\n\n", timeout_ms);

        std::vector<scan_result> results;
        uint8_t current[4];
        memcpy(current, start_ip, 4);
        uint16_t seq = 1;

        while (memcmp(current, end_ip, 4) <= 0) {
            char ip_str[32];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     current[0], current[1], current[2], current[3]);

            uint8_t packet[sizeof(icmp_echo)];
            build_icmp_echo_request(packet, 0x1234, seq++);

            auto t0 = std::chrono::steady_clock::now();

            ssize_t sent = sock.send(packet, sizeof(packet), ip_str);
            if (sent < 0) {
                std::fprintf(stderr, "Send to %s failed\n", ip_str);
            }

            // Wait for reply
            uint8_t reply_buf[128];
            bool got_reply = false;

            for (int attempts = 0; attempts < 3; attempts++) {
                try {
                    ssize_t n = sock.recv(reply_buf, sizeof(reply_buf));
                    if (n > 0) {
                        // Check if it's an ICMP echo reply
                        if (n >= 28) {  // IP(20) + ICMP(8)
                            uint8_t* ip_data = reply_buf;
                            uint8_t ihl = (ip_data[0] & 0x0F) * 4;
                            icmp_echo* icmp = (icmp_echo*)(ip_data + ihl);
                            if (icmp->type == 0 && icmp->id == 0x1234) {
                                got_reply = true;
                                break;
                            }
                        }
                    }
                } catch (const rawsock::error& e) {
                    if (e.code() == RSE_TIMEOUT) break;
                }
            }

            auto t1 = std::chrono::steady_clock::now();
            int64_t rtt = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

            scan_result r;
            memcpy(r.ip, current, 4);
            r.replied = got_reply;
            r.rtt_us = rtt;
            results.push_back(r);

            if (got_reply) {
                std::printf("  [LIVE] %s  rtt=%lld us\n", ip_str, (long long)rtt);
            }

            // Increment IP
            current[3]++;
            if (current[3] == 0) { current[2]++; }
            if (current[2] == 0) { current[1]++; }
            if (current[1] == 0) { current[0]++; }

            if (memcmp(current, end_ip, 4) > 0) break;
        }

        int live_count = 0;
        for (const auto& r : results) {
            if (r.replied) live_count++;
        }

        std::printf("\n=== Summary ===\n");
        std::printf("Hosts scanned: %zu\n", results.size());
        std::printf("Hosts alive:   %d\n", live_count);

    } catch (const rawsock::error& e) {
        std::fprintf(stderr, "Error: %s (code=%d)\n", e.what(), e.code());
        return 1;
    }

    return 0;
}
