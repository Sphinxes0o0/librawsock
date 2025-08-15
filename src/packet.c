/**
 * @file packet.c
 * @brief Basic packet parsing and utility functions
 * @author Sphinxes0o0
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "packet.h"

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

