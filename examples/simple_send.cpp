/**
 * @example simple_send.cpp
 * @brief C++ raw socket send example using rawsock.hpp
 */

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static uint16_t calc_cksum(const void* data, size_t len) {
    return rawsock_cksum(data, len);
}

static void build_udp_header(uint8_t* buf, uint16_t src_port, uint16_t dst_port,
                             size_t payload_len) {
    std::memset(buf, 0, RAWSOCK_UDP_HLEN);
    buf[0] = (src_port >> 8) & 0xFF; buf[1] = src_port & 0xFF;
    buf[2] = (dst_port >> 8) & 0xFF; buf[3] = dst_port & 0xFF;
    size_t udp_len = RAWSOCK_UDP_HLEN + payload_len;
    buf[4] = (udp_len >> 8) & 0xFF;  buf[5] = udp_len & 0xFF;
}

static void build_icmp_header(uint8_t* buf, uint8_t type, uint8_t code,
                              uint16_t id, uint16_t seq) {
    std::memset(buf, 0, RAWSOCK_ICMP_HLEN);
    buf[0] = type; buf[1] = code;
    buf[4] = (id >> 8) & 0xFF; buf[5] = id & 0xFF;
    buf[6] = (seq >> 8) & 0xFF; buf[7] = seq & 0xFF;
    uint16_t cksum = calc_cksum(buf, RAWSOCK_ICMP_HLEN);
    buf[2] = (cksum >> 8) & 0xFF; buf[3] = cksum & 0xFF;
}

int main(int argc, char** argv) {
    int protocol = 0; // UDP
    const char* dst_ip = "127.0.0.1";
    if (argc >= 2) {
        if (std::strcmp(argv[1], "udp") == 0) protocol = 0;
        else if (std::strcmp(argv[1], "icmp") == 0) protocol = 1;
        else {
            std::fprintf(stderr, "Usage: %s [udp|icmp] [dst_ip]\n", argv[0]);
            return 1;
        }
    }
    if (argc >= 3) dst_ip = argv[2];

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    std::printf("=== C++ Send Test (%s) ===\n", protocol == 0 ? "UDP" : "ICMP");

    try {
        rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
        cfg.protocol = (protocol == 0) ? IPPROTO_UDP : IPPROTO_ICMP;
        cfg.hdr_incl = false;

        rawsock::socket sock(cfg);
        std::printf("Socket opened (fd=%d)\n", sock.get()->fd);

        uint8_t packet[128] = {0};

        if (protocol == 0) {
            const char* payload = "Hello from rawsock C++!";
            size_t payload_len = std::strlen(payload);
            build_udp_header(packet, 12345, 54321, payload_len);
            std::memcpy(packet + RAWSOCK_UDP_HLEN, payload, payload_len);

            ssize_t sent = sock.send(packet, RAWSOCK_UDP_HLEN + payload_len, dst_ip);
            std::printf("UDP sent: %zd bytes\n", sent);
        } else {
            const char* payload = "ICMP test";
            size_t payload_len = std::strlen(payload);
            build_icmp_header(packet, 8, 0, 0x1234, 99);
            std::memcpy(packet + RAWSOCK_ICMP_HLEN, payload, payload_len);

            ssize_t sent = sock.send(packet, RAWSOCK_ICMP_HLEN + payload_len, dst_ip);
            std::printf("ICMP sent: %zd bytes\n", sent);
        }

        std::printf("=== PASS ===\n");
    } catch (const rawsock::error& e) {
        std::fprintf(stderr, "Error: %s (code=%d, errno=%d)\n",
                     e.what(), e.code(), e.sys_errno());
        return 1;
    }

    return 0;
}
