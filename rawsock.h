/**
 * @file rawsock.h
 * @brief Raw Socket Library — Single Header, Refactored v2.0
 * @author Sphinxes0o0
 *
 * Usage:
 *   In ONE .c file:
 *     #define RAWSOCK_IMPLEMENTATION
 *     #include "rawsock.h"
 *
 *   In other files:
 *     #include "rawsock.h"
 */

#ifndef RAWSOCK_H
#define RAWSOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

/* ───────────────  Constants  ─────────────── */
#define RAWSOCK_MAX_PACKET  65535
#define RAWSOCK_IP4_HLEN    20
#define RAWSOCK_IP6_HLEN    40
#define RAWSOCK_TCP_HLEN    20
#define RAWSOCK_UDP_HLEN    8
#define RAWSOCK_ICMP_HLEN   8

/* ───────────────  Error codes  ─────────────── */
typedef enum {
    RSE_OK = 0,
    RSE_INVAL,      /* invalid argument */
    RSE_PERM,       /* permission denied (root / CAP_NET_RAW) */
    RSE_SOCKET,     /* socket() failed */
    RSE_BIND,       /* bind / setsockopt failed */
    RSE_SEND,       /* sendto() failed */
    RSE_RECV,       /* recvfrom() failed */
    RSE_TIMEOUT,    /* operation timed out */
    RSE_NOBUFS,     /* buffer too small */
    RSE_PROTO,      /* protocol / parse error */
    RSE_SYS,        /* other system error */
} rawsock_err_t;

/* ───────────────  Handle (opaque but struct visible for inline close)  ─────────────── */
typedef struct rawsock_ctx {
    int           fd;
    int           af;          /* AF_INET or AF_INET6 */
    int           proto;
    rawsock_err_t last_err;
    int           last_errno;
} rawsock_t;

/* ───────────────  Configuration  ─────────────── */
typedef struct {
    int af;            /* AF_INET or AF_INET6 */
    int protocol;      /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, 0=all */
    int rcv_timeout_ms;
    int snd_timeout_ms;
    bool hdr_incl;     /* build IP header in userland (IPv4) */
    bool broadcast;
} rawsock_cfg_t;

#define RAWSOCK_CFG_DEFAULT  \
    ((rawsock_cfg_t){ .af = AF_INET, .protocol = 0, \
       .rcv_timeout_ms = 5000, .snd_timeout_ms = 5000, \
       .hdr_incl = true, .broadcast = false })

/* ───────────────  Layer-0: Core API  ─────────────── */
rawsock_t* rawsock_open(const rawsock_cfg_t* cfg);
ssize_t    rawsock_send(rawsock_t* s, const void* pkt, size_t len, const char* dst_addr);
ssize_t    rawsock_recv(rawsock_t* s, void* buf, size_t len);

rawsock_err_t rawsock_last_err(const rawsock_t* s);
int           rawsock_last_errno(const rawsock_t* s);
const char*   rawsock_strerror(rawsock_err_t e);
bool          rawsock_has_caps(void);

/* rawsock_close is inline so RAII works in every TU */
static inline void rawsock_close(rawsock_t* s)
{
    if (s) {
        if (s->fd >= 0) close(s->fd);
        free(s);
    }
}

/* RAII: `RAWSOCK_AUTO_CLOSE rawsock_t* sock = rawsock_open(...);` */
static inline void rawsock_auto_cleanup(rawsock_t** p)
{
    if (p && *p) { rawsock_close(*p); *p = NULL; }
}

#ifdef __GNUC__
#define RAWSOCK_AUTO_CLOSE __attribute__((cleanup(rawsock_auto_cleanup)))
#else
#define RAWSOCK_AUTO_CLOSE
#endif

/* ───────────────  Layer-1: Helpers  ─────────────── */
int rawsock_bind_iface(rawsock_t* s, const char* ifname);
int rawsock_set_timeout(rawsock_t* s, int rcv_ms, int snd_ms);
int rawsock_pton(const char* str, int af, void* bin, size_t bin_len);
int rawsock_ntop(const void* bin, int af, char* str, size_t str_len);

/* ───────────────  Layer-2: Header structs & parsers  ─────────────── */
typedef struct {
    uint8_t  version;
    uint8_t  ihl;          /* header len in bytes */
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t src;          /* network byte order */
    uint32_t dst;          /* network byte order */
} rawsock_ip4_t;

typedef struct {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} rawsock_ip6_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  doff;         /* data offset in bytes */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg;
} rawsock_tcp_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t check;
} rawsock_udp_t;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
} rawsock_icmp_t;

int rawsock_parse_ip4(const void* data, size_t len, rawsock_ip4_t* out,
                      const void** payload, size_t* payload_len);
int rawsock_parse_ip6(const void* data, size_t len, rawsock_ip6_t* out,
                      const void** payload, size_t* payload_len);
int rawsock_parse_tcp (const void* data, size_t len, rawsock_tcp_t* out);
int rawsock_parse_udp (const void* data, size_t len, rawsock_udp_t* out);
int rawsock_parse_icmp(const void* data, size_t len, rawsock_icmp_t* out);

uint16_t rawsock_cksum(const void* data, size_t len);
uint16_t rawsock_cksum_pseudo(const void* src, const void* dst,
                               size_t addr_len, uint8_t proto,
                               const void* data, size_t len);

/* ───────────────  Layer-3: High-level convenience  ─────────────── */
typedef struct {
    uint64_t timestamp_us;
    size_t   pkt_len;
    char     src_ip[46];
    char     dst_ip[46];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  ip_ver;
    uint8_t  protocol;
    uint8_t  l4_parsed;
    union {
        rawsock_tcp_t  tcp;
        rawsock_udp_t  udp;
        rawsock_icmp_t icmp;
    } l4;
} rawsock_pkt_t;

ssize_t rawsock_recv_auto(rawsock_t* s, void* buf, size_t len, rawsock_pkt_t* info);

#ifdef __cplusplus
}
#endif

#endif /* RAWSOCK_H */

/* ═══════════════════════════════════════════════════════════════════════
 *                        IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════════ */

#ifdef RAWSOCK_IMPLEMENTATION

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#if defined(__linux__)
#  include <sys/ioctl.h>
#endif

static rawsock_err_t rawsock_global_err = RSE_OK;
static int rawsock_global_errno = 0;

/* ─── helpers ─── */
static inline void set_err(rawsock_t* s, rawsock_err_t e, int en)
{
    if (s) {
        s->last_err = e;
        s->last_errno = en;
    } else {
        rawsock_global_err = e;
        rawsock_global_errno = en;
    }
}
static inline void clear_err(rawsock_t* s) { set_err(s, RSE_OK, 0); }

static inline struct timeval tv_from_ms(int ms)
{
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    return tv;
}

static inline uint64_t now_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
        return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0)
        return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
    return 0;
}

/* ─── Layer-0 ─── */
rawsock_t* rawsock_open(const rawsock_cfg_t* cfg)
{
    rawsock_cfg_t def = RAWSOCK_CFG_DEFAULT;
    if (!cfg) cfg = &def;

    if (cfg->af != AF_INET && cfg->af != AF_INET6) {
        set_err(NULL, RSE_INVAL, EINVAL);
        return NULL;
    }

    int type = SOCK_RAW;
#ifdef SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif
    int proto = cfg->protocol;
    if (cfg->hdr_incl && cfg->af == AF_INET && proto == 0)
        proto = IPPROTO_RAW;
    int fd = socket(cfg->af, type, proto);
    if (fd < 0) {
        int e = errno;
        set_err(NULL, (e == EPERM || e == EACCES) ? RSE_PERM : RSE_SOCKET, e);
        return NULL;
    }

    rawsock_t* s = (rawsock_t*)calloc(1, sizeof(*s));
    if (!s) { set_err(NULL, RSE_SYS, errno); close(fd); return NULL; }

    s->fd = fd; s->af = cfg->af; s->proto = cfg->protocol;
    clear_err(s);

    if (cfg->hdr_incl && cfg->af == AF_INET) {
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) goto fail;
    }
    if (cfg->broadcast) {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) goto fail;
    }
    if (cfg->rcv_timeout_ms > 0) {
        struct timeval tv = tv_from_ms(cfg->rcv_timeout_ms);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) goto fail;
    }
    if (cfg->snd_timeout_ms > 0) {
        struct timeval tv = tv_from_ms(cfg->snd_timeout_ms);
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) goto fail;
    }
    return s;

fail:
    set_err(s, RSE_BIND, errno);
    rawsock_close(s);
    return NULL;
}

ssize_t rawsock_send(rawsock_t* s, const void* pkt, size_t len, const char* dst_addr)
{
    if (!s || !pkt || !len || !dst_addr) { set_err(s, RSE_INVAL, EINVAL); return -1; }

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    socklen_t sslen;

    if (s->af == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)&ss;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, dst_addr, &sin->sin_addr) != 1) {
            set_err(s, RSE_INVAL, EINVAL); return -1;
        }
        sslen = sizeof(*sin);
    } else if (s->af == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&ss;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, dst_addr, &sin6->sin6_addr) != 1) {
            set_err(s, RSE_INVAL, EINVAL); return -1;
        }
        sslen = sizeof(*sin6);
    } else {
        set_err(s, RSE_INVAL, EINVAL);
        return -1;
    }

    ssize_t n = sendto(s->fd, pkt, len, 0, (struct sockaddr*)&ss, sslen);
    if (n < 0) {
        int e = errno;
        set_err(s, (e == EAGAIN || e == EWOULDBLOCK) ? RSE_TIMEOUT : RSE_SEND, e);
        return -1;
    }
    clear_err(s);
    return n;
}

ssize_t rawsock_recv(rawsock_t* s, void* buf, size_t len)
{
    if (!s || !buf || !len) { set_err(s, RSE_INVAL, EINVAL); return -1; }
    ssize_t n = recvfrom(s->fd, buf, len, 0, NULL, NULL);
    if (n < 0) {
        int e = errno;
        set_err(s, (e == EAGAIN || e == EWOULDBLOCK) ? RSE_TIMEOUT : RSE_RECV, e);
        return -1;
    }
    clear_err(s);
    return n;
}

rawsock_err_t rawsock_last_err(const rawsock_t* s)
{
    return s ? s->last_err : rawsock_global_err;
}

int rawsock_last_errno(const rawsock_t* s)
{
    return s ? s->last_errno : rawsock_global_errno;
}

const char* rawsock_strerror(rawsock_err_t e)
{
    switch (e) {
        case RSE_OK:      return "Success";
        case RSE_INVAL:   return "Invalid argument";
        case RSE_PERM:    return "Permission denied (need root or CAP_NET_RAW)";
        case RSE_SOCKET:  return "Socket creation failed";
        case RSE_BIND:    return "Socket option/bind failed";
        case RSE_SEND:    return "Send failed";
        case RSE_RECV:    return "Receive failed";
        case RSE_TIMEOUT: return "Timeout";
        case RSE_NOBUFS:  return "Buffer too small";
        case RSE_PROTO:   return "Protocol / parse error";
        case RSE_SYS:     return "System error";
        default:          return "Unknown error";
    }
}

bool rawsock_has_caps(void)
{
    if (geteuid() == 0) return true;
    int t = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (t >= 0) { close(t); return true; }
    return false;
}

/* ─── Layer-1 ─── */
int rawsock_bind_iface(rawsock_t* s, const char* ifname)
{
    if (!s || !ifname) { set_err(s, RSE_INVAL, EINVAL); return -1; }
#ifdef SO_BINDTODEVICE
    if (setsockopt(s->fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)(strlen(ifname) + 1)) < 0)
        { set_err(s, RSE_BIND, errno); return -1; }
#elif defined(IP_BOUND_IF)
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { set_err(s, RSE_BIND, errno); return -1; }
    if (setsockopt(s->fd, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex)) < 0)
        { set_err(s, RSE_BIND, errno); return -1; }
#else
    (void)ifname; set_err(s, RSE_BIND, ENOTSUP); return -1;
#endif
    clear_err(s); return 0;
}

int rawsock_set_timeout(rawsock_t* s, int rcv_ms, int snd_ms)
{
    if (!s) { set_err(s, RSE_INVAL, EINVAL); return -1; }
    if (rcv_ms > 0) {
        struct timeval tv = tv_from_ms(rcv_ms);
        if (setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) goto fail;
    }
    if (snd_ms > 0) {
        struct timeval tv = tv_from_ms(snd_ms);
        if (setsockopt(s->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) goto fail;
    }
    clear_err(s); return 0;
fail:
    set_err(s, RSE_BIND, errno); return -1;
}

int rawsock_pton(const char* str, int af, void* bin, size_t bin_len)
{
    if (!str || !bin) return -1;
    size_t need = (af == AF_INET6) ? 16 : 4;
    if (bin_len < need) return -1;
    if (af == AF_INET) {
        struct in_addr addr;
        if (inet_pton(AF_INET, str, &addr) != 1) return -1;
        memcpy(bin, &addr, 4);
    } else if (af == AF_INET6) {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, str, &addr) != 1) return -1;
        memcpy(bin, &addr, 16);
    } else return -1;
    return 0;
}

int rawsock_ntop(const void* bin, int af, char* str, size_t str_len)
{
    if (!bin || !str || !str_len) return -1;
    return inet_ntop(af, bin, str, str_len) ? 0 : -1;
}

/* ─── Layer-2: Parsing ─── */
int rawsock_parse_ip4(const void* data, size_t len, rawsock_ip4_t* out,
                                    const void** payload, size_t* payload_len)
{
    if (!data || len < RAWSOCK_IP4_HLEN || !out) return -1;
    const uint8_t* p = (const uint8_t*)data;
    out->version = (p[0] >> 4) & 0x0F;
    out->ihl     = (p[0] & 0x0F) * 4;
    if (out->version != 4 || out->ihl < RAWSOCK_IP4_HLEN || out->ihl > len) return -1;
    out->tos      = p[1];
    out->tot_len  = (p[2] << 8) | p[3];
    out->id       = (p[4] << 8) | p[5];
    out->frag_off = (p[6] << 8) | p[7];
    out->ttl      = p[8];
    out->proto    = p[9];
    out->check    = (p[10] << 8) | p[11];
    memcpy(&out->src, p + 12, 4);
    memcpy(&out->dst, p + 16, 4);
    if (payload) {
        *payload = p + out->ihl;
        *payload_len = (len > out->ihl) ? (len - out->ihl) : 0;
    }
    return 0;
}

int rawsock_parse_ip6(const void* data, size_t len, rawsock_ip6_t* out,
                                    const void** payload, size_t* payload_len)
{
    if (!data || len < RAWSOCK_IP6_HLEN || !out) return -1;
    const uint8_t* p = (const uint8_t*)data;
    out->ver_tc_fl   = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
                     | ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
    out->payload_len = (p[4] << 8) | p[5];
    out->next_header = p[6];
    out->hop_limit   = p[7];
    memcpy(out->src, p + 8,  16);
    memcpy(out->dst, p + 24, 16);
    if (payload) {
        *payload = p + RAWSOCK_IP6_HLEN;
        *payload_len = (len > RAWSOCK_IP6_HLEN) ? (len - RAWSOCK_IP6_HLEN) : 0;
    }
    return 0;
}

int rawsock_parse_tcp(const void* data, size_t len, rawsock_tcp_t* out)
{
    if (!data || len < RAWSOCK_TCP_HLEN || !out) return -1;
    const uint8_t* p = (const uint8_t*)data;
    out->src_port = (p[0] << 8) | p[1];
    out->dst_port = (p[2] << 8) | p[3];
    out->seq = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16)
             | ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
    out->ack = ((uint32_t)p[8]  << 24) | ((uint32_t)p[9]  << 16)
             | ((uint32_t)p[10] << 8)  | (uint32_t)p[11];
    out->doff  = ((p[12] >> 4) & 0x0F) * 4;
    out->flags = p[13];
    out->window = (p[14] << 8) | p[15];
    out->check  = (p[16] << 8) | p[17];
    out->urg    = (p[18] << 8) | p[19];
    return 0;
}

int rawsock_parse_udp(const void* data, size_t len, rawsock_udp_t* out)
{
    if (!data || len < RAWSOCK_UDP_HLEN || !out) return -1;
    const uint8_t* p = (const uint8_t*)data;
    out->src_port = (p[0] << 8) | p[1];
    out->dst_port = (p[2] << 8) | p[3];
    out->len      = (p[4] << 8) | p[5];
    out->check    = (p[6] << 8) | p[7];
    return 0;
}

int rawsock_parse_icmp(const void* data, size_t len, rawsock_icmp_t* out)
{
    if (!data || len < RAWSOCK_ICMP_HLEN || !out) return -1;
    const uint8_t* p = (const uint8_t*)data;
    out->type = p[0]; out->code = p[1];
    out->check = (p[2] << 8) | p[3];
    out->id    = (p[4] << 8) | p[5];
    out->seq   = (p[6] << 8) | p[7];
    return 0;
}

/* ─── Checksums ─── */
uint16_t rawsock_cksum(const void* data, size_t len)
{
    const uint8_t* buf = (const uint8_t*)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint16_t)buf[0] << 8) | buf[1];
        buf += 2; len -= 2;
    }
    if (len) sum += (uint16_t)buf[0] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t rawsock_cksum_pseudo(const void* src, const void* dst,
                                             size_t addr_len, uint8_t proto,
                                             const void* data, size_t len)
{
    if (!src || !dst || !data || addr_len == 0) return 0;
    uint8_t ph[40]; size_t ph_len = 0;
    memcpy(ph + ph_len, src, addr_len); ph_len += addr_len;
    memcpy(ph + ph_len, dst, addr_len); ph_len += addr_len;
    if (addr_len == 4) {
        ph[ph_len++] = 0; ph[ph_len++] = proto;
        ph[ph_len++] = (uint8_t)(len >> 8); ph[ph_len++] = (uint8_t)len;
    } else {
        ph[ph_len++] = (uint8_t)(len >> 24); ph[ph_len++] = (uint8_t)(len >> 16);
        ph[ph_len++] = (uint8_t)(len >> 8);  ph[ph_len++] = (uint8_t)len;
        ph[ph_len++] = 0; ph[ph_len++] = 0; ph[ph_len++] = 0; ph[ph_len++] = proto;
    }
    uint32_t sum = 0;
    const uint8_t* p; size_t i;
    for (p = ph, i = 0; i + 1 < ph_len; i += 2)
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    if (i < ph_len) sum += (uint16_t)p[i] << 8;
    for (p = data, i = 0; i + 1 < len; i += 2)
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    if (i < len) sum += (uint16_t)p[i] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ─── Layer-3: Auto-parse ─── */
ssize_t rawsock_recv_auto(rawsock_t* s, void* buf, size_t len,
                                         rawsock_pkt_t* info)
{
    if (!s || !buf || !len) { set_err(s, RSE_INVAL, EINVAL); return -1; }

    struct sockaddr_storage ss;
    socklen_t sslen = sizeof(ss);
    ssize_t n = recvfrom(s->fd, buf, len, 0, (struct sockaddr*)&ss, &sslen);
    if (n < 0) {
        int e = errno;
        set_err(s, (e == EAGAIN || e == EWOULDBLOCK) ? RSE_TIMEOUT : RSE_RECV, e);
        return -1;
    }
    clear_err(s);

    if (info) {
        memset(info, 0, sizeof(*info));
        info->pkt_len = (size_t)n;
        info->timestamp_us = now_us();

        if (ss.ss_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, info->src_ip, sizeof(info->src_ip));
            info->protocol = s->proto; info->ip_ver = 4;
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, info->src_ip, sizeof(info->src_ip));
            info->protocol = s->proto; info->ip_ver = 6;
        }

        if (n >= 1) {
            uint8_t ver = ((uint8_t*)buf)[0] >> 4;
            if (ver == 4 && (size_t)n >= RAWSOCK_IP4_HLEN) {
                rawsock_ip4_t ip4; const void* l4; size_t l4_len;
                if (rawsock_parse_ip4(buf, n, &ip4, &l4, &l4_len) == 0) {
                    info->ip_ver = 4; info->protocol = ip4.proto;
                    inet_ntop(AF_INET, &ip4.src, info->src_ip, sizeof(info->src_ip));
                    inet_ntop(AF_INET, &ip4.dst, info->dst_ip, sizeof(info->dst_ip));
                    if (ip4.proto == IPPROTO_TCP && l4_len >= RAWSOCK_TCP_HLEN) {
                        if (rawsock_parse_tcp(l4, l4_len, &info->l4.tcp) == 0) {
                            info->l4_parsed = 1;
                            info->src_port = info->l4.tcp.src_port;
                            info->dst_port = info->l4.tcp.dst_port;
                        }
                    } else if (ip4.proto == IPPROTO_UDP && l4_len >= RAWSOCK_UDP_HLEN) {
                        if (rawsock_parse_udp(l4, l4_len, &info->l4.udp) == 0) {
                            info->l4_parsed = 1;
                            info->src_port = info->l4.udp.src_port;
                            info->dst_port = info->l4.udp.dst_port;
                        }
                    } else if (ip4.proto == IPPROTO_ICMP && l4_len >= RAWSOCK_ICMP_HLEN) {
                        if (rawsock_parse_icmp(l4, l4_len, &info->l4.icmp) == 0)
                            info->l4_parsed = 1;
                    }
                }
            } else if (ver == 6 && (size_t)n >= RAWSOCK_IP6_HLEN) {
                rawsock_ip6_t ip6; const void* l4; size_t l4_len;
                if (rawsock_parse_ip6(buf, n, &ip6, &l4, &l4_len) == 0) {
                    info->ip_ver = 6; info->protocol = ip6.next_header;
                    inet_ntop(AF_INET6, ip6.src, info->src_ip, sizeof(info->src_ip));
                    inet_ntop(AF_INET6, ip6.dst, info->dst_ip, sizeof(info->dst_ip));
                    if (ip6.next_header == IPPROTO_TCP && l4_len >= RAWSOCK_TCP_HLEN) {
                        if (rawsock_parse_tcp(l4, l4_len, &info->l4.tcp) == 0) {
                            info->l4_parsed = 1;
                            info->src_port = info->l4.tcp.src_port;
                            info->dst_port = info->l4.tcp.dst_port;
                        }
                    } else if (ip6.next_header == IPPROTO_UDP && l4_len >= RAWSOCK_UDP_HLEN) {
                        if (rawsock_parse_udp(l4, l4_len, &info->l4.udp) == 0) {
                            info->l4_parsed = 1;
                            info->src_port = info->l4.udp.src_port;
                            info->dst_port = info->l4.udp.dst_port;
                        }
                    } else if (ip6.next_header == IPPROTO_ICMPV6 && l4_len >= RAWSOCK_ICMP_HLEN) {
                        if (rawsock_parse_icmp(l4, l4_len, &info->l4.icmp) == 0)
                            info->l4_parsed = 1;
                    }
                }
            }
        }
    }
    return n;
}

#endif /* RAWSOCK_IMPLEMENTATION */
