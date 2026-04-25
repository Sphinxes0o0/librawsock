#define RAWSOCK_IMPLEMENTATION
#include "../rawsock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile int keep_running = 1;

void signal_handler(int sig) {
    (void)sig;
    keep_running = 0;
}

static uint16_t calc_cksum(const void* data, size_t len) {
    return rawsock_cksum(data, len);
}

static void build_udp_header(uint8_t* buf,
                             uint16_t src_port, uint16_t dst_port,
                             size_t payload_len) {
    memset(buf, 0, RAWSOCK_UDP_HLEN);
    buf[0] = (src_port >> 8) & 0xFF;
    buf[1] = src_port & 0xFF;
    buf[2] = (dst_port >> 8) & 0xFF;
    buf[3] = dst_port & 0xFF;
    size_t udp_len = RAWSOCK_UDP_HLEN + payload_len;
    buf[4] = (udp_len >> 8) & 0xFF;
    buf[5] = udp_len & 0xFF;
}

static void build_icmp_header(uint8_t* buf, uint8_t type, uint8_t code,
                              uint16_t id, uint16_t seq) {
    memset(buf, 0, RAWSOCK_ICMP_HLEN);
    buf[0] = type;
    buf[1] = code;
    buf[4] = (id >> 8) & 0xFF;
    buf[5] = id & 0xFF;
    buf[6] = (seq >> 8) & 0xFF;
    buf[7] = seq & 0xFF;
    uint16_t cksum = calc_cksum(buf, RAWSOCK_ICMP_HLEN);
    buf[2] = (cksum >> 8) & 0xFF;
    buf[3] = cksum & 0xFF;
}

static void print_hex(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", p[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16) printf("\n");
}

int main(int argc, char** argv) {
    int protocol = 0;
    if (argc >= 2) {
        if (strcmp(argv[1], "udp") == 0) protocol = 0;
        else if (strcmp(argv[1], "icmp") == 0) protocol = 1;
        else { fprintf(stderr, "Usage: %s [udp|icmp]\n", argv[0]); return 1; }
    }

    if (!rawsock_has_caps()) {
        fprintf(stderr, "Error: Root privileges required\n");
        return 1;
    }

    printf("=== Raw Socket Send Test ===\n");
    printf("Protocol: %s\n\n", protocol == 0 ? "UDP" : "ICMP");

    signal(SIGINT, signal_handler);

    rawsock_cfg_t cfg = RAWSOCK_CFG_DEFAULT;
    cfg.protocol = (protocol == 0) ? IPPROTO_UDP : IPPROTO_ICMP;
    cfg.hdr_incl = false;

    RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(&cfg);
    if (!sock) {
        fprintf(stderr, "[sender] open failed: %s (errno=%d)\n",
                rawsock_strerror(rawsock_last_err(NULL)),
                rawsock_last_errno(NULL));
        return 1;
    }
    printf("[sender] Socket opened (fd=%d, af=%d, proto=%d, hdr_incl=%d)\n",
           sock->fd, sock->af, sock->proto, cfg.hdr_incl);

    uint8_t packet[128];
    memset(packet, 0, sizeof(packet));

    if (protocol == 0) {
        const char* payload = "Hello from rawsock send!";
        size_t payload_len = strlen(payload);

        build_udp_header(packet, 12345, 54321, payload_len);
        memcpy(packet + RAWSOCK_UDP_HLEN, payload, payload_len);

        ssize_t sent = rawsock_send(sock, packet,
                                    RAWSOCK_UDP_HLEN + payload_len,
                                    "127.0.0.1");
        if (sent < 0) {
            fprintf(stderr, "[sender] send failed: %s (errno=%d, %s)\n",
                    rawsock_strerror(rawsock_last_err(sock)),
                    rawsock_last_errno(sock),
                    strerror(rawsock_last_errno(sock)));
            return 1;
        }
        printf("[sender] UDP packet sent: %zd bytes (payload %zu bytes)\n",
               sent, payload_len);
        printf("  Packet hex:\n  ");
        print_hex(packet, (size_t)sent);

    } else {
        const char* payload = "ICMP test payload";
        size_t payload_len = strlen(payload);

        build_icmp_header(packet, 8, 0, 0x1234, 99);
        memcpy(packet + RAWSOCK_ICMP_HLEN, payload, payload_len);

        ssize_t sent = rawsock_send(sock, packet,
                                    RAWSOCK_ICMP_HLEN + payload_len,
                                    "127.0.0.1");
        if (sent < 0) {
            fprintf(stderr, "[sender] send failed: %s (errno=%d, %s)\n",
                    rawsock_strerror(rawsock_last_err(sock)),
                    rawsock_last_errno(sock),
                    strerror(rawsock_last_errno(sock)));
            return 1;
        }
        printf("[sender] ICMP packet sent: %zd bytes (payload %zu bytes)\n",
               sent, payload_len);
        printf("  ID: 0x1234  Seq: 99  Payload: \"%s\"\n", payload);
        printf("  Packet hex:\n  ");
        print_hex(packet, (size_t)sent);
    }

    printf("\n=== Send Test: PASS ===\n");
    return 0;
}
