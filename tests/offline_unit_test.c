#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.h"

static void test_invalid_open_sets_global_error(void) {
    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.af = -1;

    rawsock_t* sock = rawsock_open(&cfg);
    assert(sock == NULL);
    assert(rawsock_last_err(NULL) == RSE_INVAL);
    assert(rawsock_last_errno(NULL) == EINVAL);
}

static void test_addr_helpers(void) {
    uint8_t v4[4];
    uint8_t v6[16];
    uint8_t v6_roundtrip[16];
    char out4[46];
    char out6[46];

    assert(rawsock_pton("127.0.0.1", AF_INET, v4, sizeof(v4)) == 0);
    assert(rawsock_ntop(v4, AF_INET, out4, sizeof(out4)) == 0);
    assert(strcmp(out4, "127.0.0.1") == 0);

    assert(rawsock_pton("2001:db8::1", AF_INET6, v6, sizeof(v6)) == 0);
    assert(rawsock_ntop(v6, AF_INET6, out6, sizeof(out6)) == 0);
    assert(rawsock_pton(out6, AF_INET6, v6_roundtrip, sizeof(v6_roundtrip)) == 0);
    assert(memcmp(v6, v6_roundtrip, sizeof(v6)) == 0);
}

static void test_parse_ip4_and_l4(void) {
    static const uint8_t pkt[40] = {
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 192, 168, 1, 10,
        8, 8, 8, 8,
        0x30, 0x39, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    static const uint8_t udp[8] = {0x1f, 0x90, 0x00, 0x35, 0x00, 0x08, 0x12, 0x34};
    static const uint8_t icmp[8] = {8, 0, 0xaa, 0x55, 0x12, 0x34, 0x00, 0x01};

    rawsock_ip4_t ip4;
    rawsock_tcp_t tcp;
    rawsock_udp_t udph;
    rawsock_icmp_t icmph;
    const void* payload = NULL;
    size_t payload_len = 0;

    assert(rawsock_parse_ip4(pkt, sizeof(pkt), &ip4, &payload, &payload_len) == 0);
    assert(ip4.version == 4);
    assert(ip4.ihl == 20);
    assert(ip4.tot_len == 40);
    assert(ip4.proto == IPPROTO_TCP);
    assert(payload_len == 20);

    assert(rawsock_parse_tcp(payload, payload_len, &tcp) == 0);
    assert(tcp.src_port == 12345);
    assert(tcp.dst_port == 443);
    assert(tcp.seq == 1);
    assert(tcp.doff == 20);

    assert(rawsock_parse_udp(udp, sizeof(udp), &udph) == 0);
    assert(udph.src_port == 8080);
    assert(udph.dst_port == 53);
    assert(udph.len == 8);

    assert(rawsock_parse_icmp(icmp, sizeof(icmp), &icmph) == 0);
    assert(icmph.type == 8);
    assert(icmph.code == 0);
    assert(icmph.id == 0x1234);
    assert(icmph.seq == 1);
}

static void test_checksums(void) {
    static const uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    uint16_t csum = rawsock_cksum(data, sizeof(data));
    assert(csum == 0x220d);

    uint8_t src[4] = {192, 168, 1, 10};
    uint8_t dst[4] = {8, 8, 8, 8};
    uint16_t pseudo = rawsock_cksum_pseudo(src, dst, 4, IPPROTO_UDP, data, sizeof(data));
    assert(pseudo != 0);
}

static void test_parse_ip6(void) {
    // IPv6 packet: 2001:db8::1 -> 2001:db8::2, next header = TCP (6)
    static const uint8_t pkt[] = {
        0x60, 0x00, 0x00, 0x00,  // version(6) + traffic class + flow label
        0x00, 0x28,               // payload length = 40
        0x06,                     // next header = TCP
        0x40,                     // hop limit = 64
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // src: 2001:db8::1
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02   // dst: 2001:db8::2
    };

    rawsock_ip6_t ip6;
    const void* l4 = NULL;
    size_t l4_len = 0;

    assert(rawsock_parse_ip6(pkt, sizeof(pkt), &ip6, &l4, &l4_len) == 0);
    assert(ip6.payload_len == 40);
    assert(ip6.next_header == 6);  // TCP
    assert(ip6.hop_limit == 64);
    assert(memcmp(ip6.src, "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) == 0);
    assert(memcmp(ip6.dst, "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02", 16) == 0);
    (void)l4; (void)l4_len;
}

static void test_parse_truncated_headers(void) {
    static const uint8_t short_ip4[] = {0x45, 0x00, 0x00, 0x14};  // only 4 bytes
    rawsock_ip4_t ip4;
    assert(rawsock_parse_ip4(short_ip4, sizeof(short_ip4), &ip4, NULL, NULL) < 0);

    static const uint8_t short_tcp[] = {0x30, 0x39, 0x01};  // only 3 bytes
    rawsock_tcp_t tcp;
    assert(rawsock_parse_tcp(short_tcp, sizeof(short_tcp), &tcp) < 0);

    static const uint8_t short_udp[] = {0x1f, 0x90, 0x00};  // only 3 bytes
    rawsock_udp_t udp;
    assert(rawsock_parse_udp(short_udp, sizeof(short_udp), &udp) < 0);

    static const uint8_t short_icmp[] = {0x08, 0x00};  // only 2 bytes
    rawsock_icmp_t icmp;
    assert(rawsock_parse_icmp(short_icmp, sizeof(short_icmp), &icmp) < 0);
}

static void test_parse_ip6_truncated(void) {
    static const uint8_t short_ip6[] = {0x60, 0x00, 0x00};  // only 3 bytes
    rawsock_ip6_t ip6;
    assert(rawsock_parse_ip6(short_ip6, sizeof(short_ip6), &ip6, NULL, NULL) < 0);
}

static void test_cksum_edge_cases(void) {
    // Empty data
    uint16_t csum_empty = rawsock_cksum(NULL, 0);
    (void)csum_empty;  // just ensure it doesn't crash

    // Single byte
    static const uint8_t single[] = {0x01};
    uint16_t csum_single = rawsock_cksum(single, sizeof(single));
    assert(csum_single != 0);  // should be non-zero

    // Odd length (3 bytes)
    static const uint8_t triple[] = {0x01, 0x02, 0x03};
    uint16_t csum_triple = rawsock_cksum(triple, sizeof(triple));
    assert(csum_triple != 0);

    // Pseudo header with IPv6 addresses
    static const uint8_t src6[16] = {0};
    static const uint8_t dst6[16] = {0};
    uint16_t pseudo6 = rawsock_cksum_pseudo(src6, dst6, 16, IPPROTO_TCP, src6, 16);
    assert(pseudo6 != 0);
}

static void test_pton_invalid(void) {
    uint8_t v4[4];
    // Invalid IPv4
    assert(rawsock_pton("not.an.ip.address", AF_INET, v4, sizeof(v4)) < 0);
    // Buffer too small
    assert(rawsock_pton("127.0.0.1", AF_INET, v4, 2) < 0);
    // Invalid family
    assert(rawsock_pton("127.0.0.1", AF_UNSPEC, v4, sizeof(v4)) < 0);
}

int main(void) {
    test_invalid_open_sets_global_error();
    test_addr_helpers();
    test_parse_ip4_and_l4();
    test_checksums();
    test_parse_ip6();
    test_parse_truncated_headers();
    test_parse_ip6_truncated();
    test_cksum_edge_cases();
    test_pton_invalid();

    puts("offline_unit_test: all checks passed");
    return 0;
}
