/**
 * @example simple_capture.cpp
 * @brief C++ packet capture example using rawsock.hpp
 */

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.hpp"
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>

static volatile int keep_running = 1;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(int argc, char** argv) {
    const char* protocol_str = (argc > 1) ? argv[1] : "all";

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    std::signal(SIGINT, signal_handler);

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    if (std::strcmp(protocol_str, "tcp") == 0)       cfg.protocol = IPPROTO_TCP;
    else if (std::strcmp(protocol_str, "udp") == 0)  cfg.protocol = IPPROTO_UDP;
    else if (std::strcmp(protocol_str, "icmp") == 0) cfg.protocol = IPPROTO_ICMP;
    else                                             cfg.protocol = 0; // all

    cfg.rcv_timeout_ms = 1000;

    try {
        rawsock::socket sock(cfg);
        std::printf("Started capture (protocol: %s)\nPress Ctrl+C to stop...\n\n", protocol_str);

        uint8_t buf[RAWSOCK_MAX_PACKET];
        rawsock_pkt_t info;

        while (keep_running) {
            ssize_t n = sock.recv_auto(buf, sizeof(buf), &info);
            if (n > 0) {
                std::printf("Packet: %zu bytes from %s:%u -> %s:%u\n",
                            info.pkt_len,
                            info.src_ip, info.src_port,
                            info.dst_ip, info.dst_port);

                if (info.protocol == IPPROTO_TCP) {
                    std::printf("  TCP  sport=%u dport=%u\n",
                                info.l4.tcp.src_port, info.l4.tcp.dst_port);
                } else if (info.protocol == IPPROTO_UDP) {
                    std::printf("  UDP  sport=%u dport=%u\n",
                                info.l4.udp.src_port, info.l4.udp.dst_port);
                } else if (info.protocol == IPPROTO_ICMP) {
                    std::printf("  ICMP type=%u code=%u\n",
                                info.l4.icmp.type, info.l4.icmp.code);
                }
            }
        }
    } catch (const rawsock::error& e) {
        std::fprintf(stderr, "Error: %s (code=%d, errno=%d)\n",
                     e.what(), e.code(), e.sys_errno());
        return 1;
    }

    std::printf("\nDone.\n");
    return 0;
}
