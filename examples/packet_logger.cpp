/**
 * @example packet_logger.cpp
 * @brief Packet logger - capture packets and write to PCAP-like log file
 *
 * Captures network packets and writes them to a simple binary log format
 * that can be later analyzed.
 * Requires root privileges (sudo).
 *
 * Usage:
 *   sudo ./packet_logger output.log
 *   sudo ./packet_logger output.log tcp    # only TCP
 *   sudo ./packet_logger output.log udp    # only UDP
 */

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <ctime>
#include <vector>

// Simple packet log format:
//   uint32_t magic = 0x504B4C47 ('PLOG')
//   uint16_t version = 1
//   Each packet:
//     uint32_t timestamp_us
//     uint32_t cap_len
//     uint32_t orig_len
//     uint8_t  data[cap_len]
#define PLOG_MAGIC    0x504B4C47
#define PLOG_VERSION  1

static void write_pkt(FILE* f, const void* data, size_t len, uint64_t ts_us) {
    uint32_t cap_len = (uint32_t)len;
    uint32_t orig_len = (uint32_t)len;
    fwrite(&ts_us, sizeof(ts_us), 1, f);
    fwrite(&cap_len, sizeof(cap_len), 1, f);
    fwrite(&orig_len, sizeof(orig_len), 1, f);
    fwrite(data, 1, len, f);
}

static const char* proto_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_ICMPV6: return "ICMPv6";
        default:           return "UNK";
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <output.log> [proto] [count]\n", argv[0]);
        std::fprintf(stderr, "  proto:  tcp, udp, icmp, all (default: all)\n");
        std::fprintf(stderr, "  count:  number of packets to capture (default: unlimited)\n");
        return 1;
    }

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    const char* output_file = argv[1];
    const char* proto_str = (argc > 2) ? argv[2] : "all";
    int max_count = (argc > 3) ? atoi(argv[3]) : 0;

    int filter_proto = 0;
    if (strcmp(proto_str, "tcp") == 0)      filter_proto = IPPROTO_TCP;
    else if (strcmp(proto_str, "udp") == 0) filter_proto = IPPROTO_UDP;
    else if (strcmp(proto_str, "icmp") == 0) filter_proto = IPPROTO_ICMP;

    FILE* log = fopen(output_file, "wb");
    if (!log) {
        std::fprintf(stderr, "Cannot open %s: %s\n", output_file, strerror(errno));
        return 1;
    }

    // Write log header
    uint32_t magic = PLOG_MAGIC;
    uint16_t version = PLOG_VERSION;
    fwrite(&magic, sizeof(magic), 1, log);
    fwrite(&version, sizeof(version), 1, log);

    try {
        rawsock::socket sock = rawsock::socket::open();  // capture all
        sock.set_timeout(1000, 0);

        std::printf("Logging packets to: %s\n", output_file);
        std::printf("Filter: %s\n", proto_str);
        if (max_count > 0) std::printf("Max packets: %d\n", max_count);
        std::printf("Press Ctrl+C to stop...\n\n");

        uint8_t buf[RAWSOCK_MAX_PACKET];
        rawsock_pkt_t info;
        int count = 0;
        time_t start = time(nullptr);

        while (true) {
            try {
                ssize_t n = sock.recv_auto(buf, sizeof(buf), &info);
                if (n > 0) {
                    // Apply protocol filter
                    if (filter_proto && info.protocol != filter_proto) continue;

                    // Write to log
                    write_pkt(log, buf, (size_t)n, info.timestamp_us);
                    fflush(log);

                    count++;

                    // Print summary
                    char time_str[32];
                    time_t t = time(nullptr);
                    strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&t));

                    std::printf("[%s] #%d  %d bytes  %s:%u -> %s:%u  %s\n",
                                time_str, count, (int)info.pkt_len,
                                info.src_ip, info.src_port,
                                info.dst_ip, info.dst_port,
                                proto_name(info.protocol));

                    if (max_count > 0 && count >= max_count) break;
                }
            } catch (const rawsock::error& e) {
                if (e.code() == RSE_TIMEOUT) continue;
                std::fprintf(stderr, "Error: %s\n", e.what());
                break;
            }
        }

        fclose(log);

        time_t elapsed = time(nullptr) - start;
        std::printf("\n=== Summary ===\n");
        std::printf("Packets captured: %d\n", count);
        std::printf("Duration: %ld seconds\n", elapsed);
        std::printf("Log file: %s\n", output_file);

    } catch (const rawsock::error& e) {
        fclose(log);
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }

    return 0;
}
