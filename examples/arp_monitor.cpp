/**
 * @example arp_monitor.cpp
 * @brief ARP poison detector - monitors for ARP spoofing/poisoning attacks
 *
 * Builds a table of IP->MAC mappings and alerts when duplicates are detected
 * (same IP with different MAC), which indicates ARP poisoning.
 * Requires root privileges (sudo).
 *
 * Usage:
 *   sudo ./arp_monitor
 *   sudo ./arp_monitor eth0
 */

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <ctime>

// ARP Ethernet frame
#pragma pack(push, 1)
struct arp_eth_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type;
};

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_size;
    uint8_t  proto_size;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};
#pragma pack(pop)

static uint16_t arp_htons(uint16_t x) {
    return ((x & 0x00FF) << 8) | ((x & 0xFF00) >> 8);
}

static void mac_to_str(const uint8_t* mac, char* buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ip_to_str(const uint8_t* ip, char* buf) {
    snprintf(buf, 16, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

struct arp_entry {
    uint8_t mac[6];
    uint8_t ip[4];
    time_t  first_seen;
    time_t  last_seen;
    int     count;
};

struct mac_key {
    uint8_t mac[6];
    bool operator<(const mac_key& other) const {
        return memcmp(mac, other.mac, 6) < 0;
    }
};

int main(int argc, char** argv) {
    const char* iface = (argc > 1) ? argv[1] : nullptr;

    if (!rawsock::has_caps()) {
        std::fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    if (iface) {
        std::printf("Monitoring interface: %s\n", iface);
    } else {
        std::printf("Monitoring all interfaces\n");
    }
    std::printf("Press Ctrl+C to stop...\n\n");

    // IP -> ARP entry
    std::map<uint32_t, arp_entry> arp_table;
    // MAC -> set of IPs (for detecting multiple IPs per MAC)
    std::map<mac_key, std::set<uint32_t>> mac_to_ips;

    try {
        rawsock::socket sock = rawsock::socket::open();  // capture all
        sock.set_timeout(1000, 0);

        uint8_t buf[RAWSOCK_MAX_PACKET];
        int pkt_count = 0;
        int alerts = 0;

        while (true) {
            try {
                ssize_t n = sock.recv(buf, sizeof(buf));
                if (n > 0) {
                    pkt_count++;

                    // Check if it's an ARP packet (Ethernet type 0x0806)
                    if (n < 28) continue;  // Min: Eth(14) + ARP(28)

                    arp_eth_header* eth = (arp_eth_header*)buf;
                    if (eth->eth_type != arp_htons(0x0806)) continue;

                    arp_header* arp = (arp_header*)(buf + sizeof(arp_eth_header));
                    if (arp->hw_type != arp_htons(1)) continue;  // Ethernet
                    if (arp->proto_type != arp_htons(0x0800)) continue;  // IPv4
                    if (arp->hw_size != 6 || arp->proto_size != 4) continue;

                    uint16_t opcode = arp_htons(arp->opcode);
                    const char* op_str = (opcode == 1) ? "REQUEST" : (opcode == 2) ? "REPLY" : "UNKNOWN";

                    // Build keys
                    uint32_t sender_ip = *(uint32_t*)arp->sender_ip;
                    uint32_t target_ip = *(uint32_t*)arp->target_ip;

                    char sender_mac_str[18], sender_ip_str[16];
                    char target_mac_str[18], target_ip_str[16];
                    mac_to_str(arp->sender_mac, sender_mac_str);
                    ip_to_str(arp->sender_ip, sender_ip_str);
                    mac_to_str(arp->target_mac, target_mac_str);
                    ip_to_str(arp->target_ip, target_ip_str);

                    time_t now = time(nullptr);

                    // Update ARP table
                    arp_entry& entry = arp_table[sender_ip];
                    bool ip_new = (entry.count == 0);

                    // Check for MAC change (ARP spoofing indicator)
                    if (!ip_new && memcmp(entry.mac, arp->sender_mac, 6) != 0) {
                        char old_mac_str[18];
                        mac_to_str(entry.mac, old_mac_str);
                        std::printf("[ALERT!] ARP SPOOF DETECTED\n");
                        std::printf("  IP:       %s\n", sender_ip_str);
                        std::printf("  Old MAC:  %s\n", old_mac_str);
                        std::printf("  New MAC:  %s\n", sender_mac_str);
                        std::printf("  Opcode:   %s\n", op_str);
                        std::printf("  Time:     %s", ctime(&now));
                        alerts++;
                    }

                    // Update entry
                    memcpy(entry.mac, arp->sender_mac, 6);
                    memcpy(entry.ip, arp->sender_ip, 4);
                    entry.count++;
                    if (ip_new) entry.first_seen = now;
                    entry.last_seen = now;

                    // Update MAC -> IPs mapping
                    mac_key mk;
                    memcpy(mk.mac, arp->sender_mac, 6);
                    mac_to_ips[mk].insert(sender_ip);

                    // Check for multiple IPs on same MAC (possible router impersonation)
                    if (mac_to_ips[mk].size() > 2) {
                        std::printf("[WARNING] MAC %s seen with %zu different IPs\n",
                                   sender_mac_str, mac_to_ips[mk].size());
                    }

                    // Print ARP info (only first few to avoid spam)
                    if (pkt_count <= 10 || pkt_count % 100 == 0) {
                        std::printf("[%d] ARP %s: %s (%s) -> %s (%s)\n",
                                   pkt_count, op_str,
                                   sender_ip_str, sender_mac_str,
                                   target_ip_str, target_mac_str);
                    }

                }
            } catch (const rawsock::error& e) {
                if (e.code() == RSE_TIMEOUT) continue;
                std::fprintf(stderr, "Error: %s\n", e.what());
                break;
            }
        }

    } catch (const rawsock::error& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }

    return 0;
}
