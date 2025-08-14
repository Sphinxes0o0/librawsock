/**
 * @file packet.c
 * @brief Packet construction and parsing utilities implementation
 * @author Sphinxes0o0
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "librawsock/packet.h"
#include "librawsock/rawsock.h"

/**
 * @brief Packet builder internal structure
 */
struct rawsock_packet_builder {
    uint8_t* buffer;               /**< Packet buffer */
    size_t buffer_size;            /**< Buffer size */
    size_t current_size;           /**< Current packet size */
    size_t max_size;               /**< Maximum packet size */

    /* Header positions for checksum calculation */
    size_t ip_header_offset;       /**< IP header offset */
    size_t transport_header_offset;/**< Transport header offset */
    rawsock_family_t family;       /**< Address family */
    uint8_t transport_protocol;    /**< Transport protocol */
};

/* Internal function declarations */
static uint16_t calculate_checksum(const void* data, size_t length);
static rawsock_error_t finalize_ip_header(rawsock_packet_builder_t* builder);
static rawsock_error_t finalize_transport_header(rawsock_packet_builder_t* builder);

/* ===== Packet Construction Functions ===== */

rawsock_packet_builder_t* rawsock_packet_builder_create(size_t max_size) {
    if (max_size == 0 || max_size > RAWSOCK_MAX_PACKET_SIZE) {
        return NULL;
    }

    rawsock_packet_builder_t* builder = calloc(1, sizeof(rawsock_packet_builder_t));
    if (!builder) {
        return NULL;
    }

    builder->buffer = malloc(max_size);
    if (!builder->buffer) {
        free(builder);
        return NULL;
    }

    builder->buffer_size = max_size;
    builder->max_size = max_size;
    builder->current_size = 0;
    builder->ip_header_offset = SIZE_MAX;
    builder->transport_header_offset = SIZE_MAX;

    return builder;
}

void rawsock_packet_builder_destroy(rawsock_packet_builder_t* builder) {
    if (!builder) {
        return;
    }

    if (builder->buffer) {
        free(builder->buffer);
    }

    free(builder);
}

void rawsock_packet_builder_reset(rawsock_packet_builder_t* builder) {
    if (!builder) {
        return;
    }

    builder->current_size = 0;
    builder->ip_header_offset = SIZE_MAX;
    builder->transport_header_offset = SIZE_MAX;
    builder->family = RAWSOCK_IPV4;
    builder->transport_protocol = 0;

    if (builder->buffer) {
        memset(builder->buffer, 0, builder->buffer_size);
    }
}

rawsock_error_t rawsock_packet_add_ipv4_header(rawsock_packet_builder_t* builder,
                                               const char* src_addr,
                                               const char* dst_addr,
                                               uint8_t protocol, uint8_t ttl) {
    if (!builder || !src_addr || !dst_addr) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + RAWSOCK_IP4_HEADER_SIZE > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Store header position */
    builder->ip_header_offset = builder->current_size;
    builder->family = RAWSOCK_IPV4;
    builder->transport_protocol = protocol;

    /* Create IPv4 header */
    rawsock_ipv4_header_t* header = (rawsock_ipv4_header_t*)(builder->buffer + builder->current_size);
    memset(header, 0, sizeof(*header));

    header->version_ihl = 0x45;        /* Version 4, IHL 5 */
    header->tos = 0;
    header->total_length = 0;          /* Will be filled in finalize */
    header->id = htons(getpid() & 0xFFFF);
    header->flags_fragment = 0;
    header->ttl = ttl ? ttl : 64;
    header->protocol = protocol;
    header->checksum = 0;              /* Will be calculated in finalize */

    /* Convert addresses */
    if (inet_pton(AF_INET, src_addr, &header->src_addr) != 1 ||
        inet_pton(AF_INET, dst_addr, &header->dst_addr) != 1) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    builder->current_size += RAWSOCK_IP4_HEADER_SIZE;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_add_ipv6_header(rawsock_packet_builder_t* builder,
                                               const char* src_addr,
                                               const char* dst_addr,
                                               uint8_t next_header, uint8_t hop_limit) {
    if (!builder || !src_addr || !dst_addr) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + RAWSOCK_IP6_HEADER_SIZE > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Store header position */
    builder->ip_header_offset = builder->current_size;
    builder->family = RAWSOCK_IPV6;
    builder->transport_protocol = next_header;

    /* Create IPv6 header */
    rawsock_ipv6_header_t* header = (rawsock_ipv6_header_t*)(builder->buffer + builder->current_size);
    memset(header, 0, sizeof(*header));

    header->version_class_label = htonl(0x60000000);  /* Version 6 */
    header->payload_length = 0;        /* Will be filled in finalize */
    header->next_header = next_header;
    header->hop_limit = hop_limit ? hop_limit : 64;

    /* Convert addresses */
    if (inet_pton(AF_INET6, src_addr, header->src_addr) != 1 ||
        inet_pton(AF_INET6, dst_addr, header->dst_addr) != 1) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    builder->current_size += RAWSOCK_IP6_HEADER_SIZE;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_add_tcp_header(rawsock_packet_builder_t* builder,
                                              uint16_t src_port, uint16_t dst_port,
                                              uint32_t seq_num, uint32_t ack_num,
                                              uint8_t flags, uint16_t window) {
    if (!builder) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + RAWSOCK_TCP_HEADER_SIZE > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Store header position */
    builder->transport_header_offset = builder->current_size;

    /* Create TCP header */
    rawsock_tcp_header_t* header = (rawsock_tcp_header_t*)(builder->buffer + builder->current_size);
    memset(header, 0, sizeof(*header));

    header->src_port = htons(src_port);
    header->dst_port = htons(dst_port);
    header->seq_num = htonl(seq_num);
    header->ack_num = htonl(ack_num);
    header->data_offset_reserved = 0x50;  /* Data offset 5 (20 bytes) */
    header->flags = flags;
    header->window = htons(window ? window : 8192);
    header->checksum = 0;              /* Will be calculated in finalize */
    header->urgent_ptr = 0;

    builder->current_size += RAWSOCK_TCP_HEADER_SIZE;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_add_udp_header(rawsock_packet_builder_t* builder,
                                              uint16_t src_port, uint16_t dst_port) {
    if (!builder) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + RAWSOCK_UDP_HEADER_SIZE > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Store header position */
    builder->transport_header_offset = builder->current_size;

    /* Create UDP header */
    rawsock_udp_header_t* header = (rawsock_udp_header_t*)(builder->buffer + builder->current_size);
    memset(header, 0, sizeof(*header));

    header->src_port = htons(src_port);
    header->dst_port = htons(dst_port);
    header->length = 0;                /* Will be filled in finalize */
    header->checksum = 0;              /* Will be calculated in finalize */

    builder->current_size += RAWSOCK_UDP_HEADER_SIZE;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_add_icmp_header(rawsock_packet_builder_t* builder,
                                               uint8_t type, uint8_t code,
                                               uint16_t id, uint16_t sequence) {
    if (!builder) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + RAWSOCK_ICMP_HEADER_SIZE > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    /* Store header position */
    builder->transport_header_offset = builder->current_size;

    /* Create ICMP header */
    rawsock_icmp_header_t* header = (rawsock_icmp_header_t*)(builder->buffer + builder->current_size);
    memset(header, 0, sizeof(*header));

    header->type = type;
    header->code = code;
    header->checksum = 0;              /* Will be calculated in finalize */

    /* Set data based on ICMP type */
    if (type == 8 || type == 0) {      /* Echo Request/Reply */
        header->data.echo.id = htons(id);
        header->data.echo.sequence = htons(sequence);
    }

    builder->current_size += RAWSOCK_ICMP_HEADER_SIZE;
    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_add_payload(rawsock_packet_builder_t* builder,
                                           const void* data, size_t data_size) {
    if (!builder || !data || data_size == 0) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    if (builder->current_size + data_size > builder->max_size) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(builder->buffer + builder->current_size, data, data_size);
    builder->current_size += data_size;

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_finalize(rawsock_packet_builder_t* builder) {
    if (!builder) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    /* Finalize IP header */
    rawsock_error_t err = finalize_ip_header(builder);
    if (err != RAWSOCK_SUCCESS) {
        return err;
    }

    /* Finalize transport header */
    err = finalize_transport_header(builder);
    if (err != RAWSOCK_SUCCESS) {
        return err;
    }

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_packet_get_data(rawsock_packet_builder_t* builder,
                                        const void** packet_data, size_t* packet_size) {
    if (!builder || !packet_data || !packet_size) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    *packet_data = builder->buffer;
    *packet_size = builder->current_size;

    return RAWSOCK_SUCCESS;
}

/* ===== Packet Parsing Functions ===== */

rawsock_error_t rawsock_parse_ipv4_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv4_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_IP4_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    memcpy(header, packet_data, RAWSOCK_IP4_HEADER_SIZE);

    /* Convert from network byte order */
    header->total_length = ntohs(header->total_length);
    header->id = ntohs(header->id);
    header->flags_fragment = ntohs(header->flags_fragment);
    header->checksum = ntohs(header->checksum);
    header->src_addr = ntohl(header->src_addr);
    header->dst_addr = ntohl(header->dst_addr);

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_ipv6_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv6_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_IP6_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    memcpy(header, packet_data, RAWSOCK_IP6_HEADER_SIZE);

    /* Convert from network byte order */
    header->version_class_label = ntohl(header->version_class_label);
    header->payload_length = ntohs(header->payload_length);

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_tcp_header(const void* packet_data, size_t packet_size,
                                         rawsock_tcp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_TCP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    memcpy(header, packet_data, RAWSOCK_TCP_HEADER_SIZE);

    /* Convert from network byte order */
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->seq_num = ntohl(header->seq_num);
    header->ack_num = ntohl(header->ack_num);
    header->window = ntohs(header->window);
    header->checksum = ntohs(header->checksum);
    header->urgent_ptr = ntohs(header->urgent_ptr);

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_udp_header(const void* packet_data, size_t packet_size,
                                         rawsock_udp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_UDP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    memcpy(header, packet_data, RAWSOCK_UDP_HEADER_SIZE);

    /* Convert from network byte order */
    header->src_port = ntohs(header->src_port);
    header->dst_port = ntohs(header->dst_port);
    header->length = ntohs(header->length);
    header->checksum = ntohs(header->checksum);

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_parse_icmp_header(const void* packet_data, size_t packet_size,
                                          rawsock_icmp_header_t* header) {
    if (!packet_data || packet_size < RAWSOCK_ICMP_HEADER_SIZE || !header) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    memcpy(header, packet_data, RAWSOCK_ICMP_HEADER_SIZE);

    /* Convert from network byte order */
    header->checksum = ntohs(header->checksum);

    if (header->type == 8 || header->type == 0) {  /* Echo Request/Reply */
        header->data.echo.id = ntohs(header->data.echo.id);
        header->data.echo.sequence = ntohs(header->data.echo.sequence);
    } else {
        header->data.gateway = ntohl(header->data.gateway);
    }

    return RAWSOCK_SUCCESS;
}

/* ===== Checksum Functions ===== */

uint16_t rawsock_calculate_ip_checksum(const void* data, size_t length) {
    return calculate_checksum(data, length);
}

uint16_t rawsock_calculate_transport_checksum(const void* src_addr, const void* dst_addr,
                                             size_t addr_len, uint8_t protocol,
                                             const void* data, size_t length) {
    if (!src_addr || !dst_addr || !data || addr_len == 0) {
        return 0;
    }

    /* Create pseudo header */
    uint8_t pseudo_header[40];  /* Max size for IPv6 */
    size_t pseudo_size = 0;

    /* Copy addresses */
    memcpy(pseudo_header, src_addr, addr_len);
    memcpy(pseudo_header + addr_len, dst_addr, addr_len);
    pseudo_size = addr_len * 2;

    if (addr_len == 4) {  /* IPv4 */
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = protocol;
        uint16_t len = htons(length);
        memcpy(pseudo_header + pseudo_size, &len, 2);
        pseudo_size += 2;
    } else {  /* IPv6 */
        uint32_t len = htonl(length);
        memcpy(pseudo_header + pseudo_size, &len, 4);
        pseudo_size += 4;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = 0;
        pseudo_header[pseudo_size++] = protocol;
    }

    /* Calculate checksum over pseudo header + data */
    uint32_t sum = 0;

    /* Pseudo header */
    const uint16_t* ptr = (const uint16_t*)pseudo_header;
    for (size_t i = 0; i < pseudo_size / 2; i++) {
        sum += ptr[i];
    }
    if (pseudo_size % 2) {
        sum += ((const uint8_t*)pseudo_header)[pseudo_size - 1] << 8;
    }

    /* Data */
    ptr = (const uint16_t*)data;
    for (size_t i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }
    if (length % 2) {
        sum += ((const uint8_t*)data)[length - 1] << 8;
    }

    /* Fold carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/* ===== Utility Functions ===== */

rawsock_error_t rawsock_addr_str_to_bin(const char* addr_str, rawsock_family_t family,
                                        void* addr_bin) {
    if (!addr_str || !addr_bin) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    int af = (family == RAWSOCK_IPV4) ? AF_INET : AF_INET6;

    if (inet_pton(af, addr_str, addr_bin) != 1) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    return RAWSOCK_SUCCESS;
}

rawsock_error_t rawsock_addr_bin_to_str(const void* addr_bin, rawsock_family_t family,
                                        char* addr_str) {
    if (!addr_bin || !addr_str) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    int af = (family == RAWSOCK_IPV4) ? AF_INET : AF_INET6;

    if (!inet_ntop(af, addr_bin, addr_str, 
                  (family == RAWSOCK_IPV4) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN)) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }

    return RAWSOCK_SUCCESS;
}

/* ===== Internal Helper Functions ===== */

static uint16_t calculate_checksum(const void* data, size_t length) {
    uint32_t sum = 0;
    const uint16_t* ptr = (const uint16_t*)data;

    /* Sum all 16-bit words */
    for (size_t i = 0; i < length / 2; i++) {
        sum += ptr[i];
    }

    /* Add odd byte if present */
    if (length % 2) {
        sum += ((const uint8_t*)data)[length - 1] << 8;
    }

    /* Fold carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

static rawsock_error_t finalize_ip_header(rawsock_packet_builder_t* builder) {
    if (builder->ip_header_offset == SIZE_MAX) {
        return RAWSOCK_SUCCESS;  /* No IP header to finalize */
    }

    if (builder->family == RAWSOCK_IPV4) {
        rawsock_ipv4_header_t* header = (rawsock_ipv4_header_t*)
            (builder->buffer + builder->ip_header_offset);

        /* Set total length */
        header->total_length = htons(builder->current_size - builder->ip_header_offset);

        /* Calculate checksum */
        header->checksum = 0;
        header->checksum = rawsock_calculate_ip_checksum(header, RAWSOCK_IP4_HEADER_SIZE);
    } else if (builder->family == RAWSOCK_IPV6) {
        rawsock_ipv6_header_t* header = (rawsock_ipv6_header_t*)
            (builder->buffer + builder->ip_header_offset);

        /* Set payload length */
        size_t payload_len = builder->current_size - builder->ip_header_offset - RAWSOCK_IP6_HEADER_SIZE;
        header->payload_length = htons(payload_len);
    }

    return RAWSOCK_SUCCESS;
}

static rawsock_error_t finalize_transport_header(rawsock_packet_builder_t* builder) {
    if (builder->transport_header_offset == SIZE_MAX ||
        builder->ip_header_offset == SIZE_MAX) {
        return RAWSOCK_SUCCESS;  /* No transport header or IP header to finalize */
    }

    /* Get source and destination addresses from IP header */
    void* src_addr, *dst_addr;
    size_t addr_len;

    if (builder->family == RAWSOCK_IPV4) {
        rawsock_ipv4_header_t* ip_header = (rawsock_ipv4_header_t*)
            (builder->buffer + builder->ip_header_offset);
        src_addr = &ip_header->src_addr;
        dst_addr = &ip_header->dst_addr;
        addr_len = 4;
    } else {
        rawsock_ipv6_header_t* ip_header = (rawsock_ipv6_header_t*)
            (builder->buffer + builder->ip_header_offset);
        src_addr = ip_header->src_addr;
        dst_addr = ip_header->dst_addr;
        addr_len = 16;
    }

    /* Calculate transport header checksum based on protocol */
    size_t transport_data_len = builder->current_size - builder->transport_header_offset;
    void* transport_header = builder->buffer + builder->transport_header_offset;

    if (builder->transport_protocol == IPPROTO_TCP) {
        rawsock_tcp_header_t* tcp_header = (rawsock_tcp_header_t*)transport_header;
        tcp_header->checksum = 0;
        tcp_header->checksum = rawsock_calculate_transport_checksum(
            src_addr, dst_addr, addr_len, IPPROTO_TCP,
            transport_header, transport_data_len);

    } else if (builder->transport_protocol == IPPROTO_UDP) {
        rawsock_udp_header_t* udp_header = (rawsock_udp_header_t*)transport_header;
        udp_header->length = htons(transport_data_len);
        udp_header->checksum = 0;
        udp_header->checksum = rawsock_calculate_transport_checksum(
            src_addr, dst_addr, addr_len, IPPROTO_UDP,
            transport_header, transport_data_len);

    } else if (builder->transport_protocol == IPPROTO_ICMP) {
        rawsock_icmp_header_t* icmp_header = (rawsock_icmp_header_t*)transport_header;
        icmp_header->checksum = 0;
        icmp_header->checksum = rawsock_calculate_ip_checksum(
            transport_header, transport_data_len);
    }

    return RAWSOCK_SUCCESS;
}

