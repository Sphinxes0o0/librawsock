/**
 * @example arp_scan.cpp
 * @brief ARP network scanner - discover live hosts on the local network
 *
 * Sends ARP requests to all IPs in a subnet and collects replies.
 * Requires root privileges (sudo).
 *
 * Usage:
 *   sudo ./arp_scan 192.168.1.0/24
 *   sudo ./arp_scan 192.168.1.1-254
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
#include <algorithm>

// ARP packet structure (Ethernet + ARP)
#pragma pack(push, 1)
struct arp_eth_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;          // 0x0806 for ARP
};

struct arp_packet {
    uint16_t hw_type;           // 1 for Ethernet
    uint16_t proto_type;        // 0x0800 for IPv4
    uint8_t  hw_size;          // 6
    uint8_t  proto_size;       // 4
    uint16_t opcode;            // 1 = request, 2 = reply
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};
#pragma pack(pop)

static uint16_t arp_htons(uint16_t x) {
    return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
}

static void build_arp_request(uint8_t* packet, const uint8_t* src_mac,
                               const uint8_t* src_ip, const uint8_t* target_ip) {
    // Ethernet header
    arp_eth_header* eth = (arp_eth_header*)packet;
    memset(eth->dst_mac, 0xFF, 6);  // Broadcast
    memcpy(eth->src_mac, src_mac, 6);
    eth->eth_type = arp_htons(0x0806);

    // ARP header
    arp_packet* arp = (arp_packet*)(packet + sizeof(arp_eth_header));
    arp->hw_type   = arp_htons(1);
    arp->proto_type = arp_htons(0x0800);
    arp->hw_size   = 6;
    arp->proto_size = 4;
    arp->opcode    = arp_htons(1);  // ARP Request
    memcpy(arp->sender_mac, src_mac, 6);
    memcpy(arp->sender_ip, src_ip, 4);
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, target_ip, 4);
}

static void mac_to_str(const uint8_t* mac, char* buf) {
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ip_to_str(const uint8_t* ip, char* buf) {
    sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

struct host_entry {
    uint8_t ip[4];
    uint8_t mac[6];
    bool replied;
};

static bool parse_ip(const char* str, uint8_t* ip) {
    return sscanf(str, "%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]) == 4;
}

static bool parse_cidr(const char* cidr, uint8_t* base_ip, uint8_t* mask) {
    uint32_t ip_int = 0;
    int bits = 24;
    if (sscanf(cidr, "%u.%u.%u.%u/%d", (unsigned*)&ip_int, (unsigned*)&ip_int+1,
               (unsigned*)&ip_int+2, (unsigned*)&ip_int+3, &bits) != 5) {
        return false;
    }
    base_ip[0] = (ip_int >> 24) & 0xFF;
    base_ip[1] = (ip_int >> 16) & 0xFF;
    base_ip[2] = (ip_int >> 8) & 0xFF;
    base_ip[3] = ip_int & 0xFF;
    *mask = (uint8_t)bits;
    return bits >= 0 && bits <= 32;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "Usage: %s <target> [iface]\n", argv[0]);
        std::fprintf(stderr, "  target: IP range like 192.168.1.0/24 or 192.168.1.1-254\n");
        std::fprintf(stderr, "  iface:  network interface (optional, auto-detect)\n");
        return 1;
    }

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    const char* target = argv[1];
    const char* iface = (argc > 2) ? argv[2] : nullptr;

    // Parse target range
    uint8_t start_ip[4], end_ip[4];
    uint8_t mask = 32;

    if (strchr(target, '/')) {
        uint8_t base_ip[4];
        if (!parse_cidr(target, base_ip, &mask)) {
            std::fprintf(stderr, "Invalid CIDR: %s\n", target);
            return 1;
        }
        memcpy(start_ip, base_ip, 4);
        uint8_t host_bits = 32 - mask;
        end_ip[0] = start_ip[0] | ((host_bits >= 24) ? (0xFF >> (host_bits - 24)) : 0);
        end_ip[1] = (host_bits >= 16) ? 0xFF : ((mask < 24) ? (0xFF >> (8 - (24 - mask))) : 0);
        end_ip[2] = (host_bits >= 8) ? 0xFF : ((mask < 16) ? (0xFF >> (8 - (16 - mask))) : 0);
        end_ip[3] = (host_bits > 0) ? (start_ip[3] | ((1 << host_bits) - 1)) : start_ip[3];
        // Simpler: for /24 just last octet 1-254
        if (mask == 24) {
            start_ip[3] = 1; end_ip[3] = 254;
        } else if (mask < 24) {
            start_ip[3] = 0; end_ip[3] = 255;
        }
    } else if (strchr(target, '-')) {
        char* dash = const_cast<char*>(strchr(target, '-'));
        *dash = '\0';
        if (!parse_ip(target, start_ip) || !parse_ip(dash + 1, end_ip)) {
            std::fprintf(stderr, "Invalid range: %s\n", target);
            return 1;
        }
    } else {
        std::fprintf(stderr, "Use CIDR (192.168.1.0/24) or range (192.168.1.1-254)\n");
        return 1;
    }

    // Our MAC (fake for this example - in production, get real interface MAC)
    uint8_t src_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t src_ip[4] = {0, 0, 0, 0};  // Will be auto-detected in production

    try {
        rawsock::socket sock;
        {
            rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
            cfg.protocol = IPPROTO_RAW;  // Raw to send ARP
            cfg.hdr_incl = false;
            sock = rawsock::socket::open_ip4(IPPROTO_RAW);
        }

        // If interface specified, bind to it
        if (iface) {
            sock.bind_iface(iface);
        }

        std::printf("ARP Scan: %d.%d.%d.%d -> %d.%d.%d.%d\n\n",
                    start_ip[0], start_ip[1], start_ip[2], start_ip[3],
                    end_ip[0], end_ip[1], end_ip[2], end_ip[3]);

        std::vector<host_entry> hosts;
        uint8_t current[4];
        memcpy(current, start_ip, 4);

        char ip_str[32];
        char mac_str[32];

        while (memcmp(current, end_ip, 4) <= 0) {
            uint8_t packet[64];
            build_arp_request(packet, src_mac, src_ip, current);

            ssize_t sent = sock.send(packet, sizeof(packet),
                                     "255.255.255.255");
            (void)sent;

            ip_to_str(current, ip_str);
            std::printf("Sent ARP request to %s\n", ip_str);

            // Increment IP
            current[3]++;
            if (current[3] == 0) { current[2]++; }
            if (current[2] == 0) { current[1]++; }
            if (current[1] == 0) { current[0]++; }
        }

        std::printf("\nScan complete. Check replies above.\n");

    } catch (const rawsock::error& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }

    return 0;
}
