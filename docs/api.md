# LibRawSock API Reference

This document provides a comprehensive reference for the LibRawSock API.

## Table of Contents

- [Introduction](#introduction)
- [Core API](#core-api)
- [Packet Construction API](#packet-construction-api)
- [Error Handling](#error-handling)
- [Data Structures](#data-structures)
- [Constants and Enums](#constants-and-enums)
- [Examples](#examples)

## Introduction

LibRawSock is a C/C++ library that provides a clean, cross-platform interface for raw socket programming. It supports IPv4/IPv6, various protocols, and includes utilities for packet construction and parsing.

### Requirements

- Linux/Unix system with raw socket support
- Root privileges or CAP_NET_RAW capability
- C99 or C++11 compatible compiler

### Quick Start

```c
#include <librawsock/rawsock.h>

// Create a raw socket
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);

// Use the socket...

// Clean up
rawsock_destroy(sock);
```

## Core API

### Socket Management

#### `rawsock_create`

```c
rawsock_t* rawsock_create(rawsock_family_t family, int protocol);
```

Creates a raw socket with default configuration.

**Parameters:**
- `family`: Address family (`RAWSOCK_IPV4` or `RAWSOCK_IPV6`)
- `protocol`: Protocol number (e.g., `IPPROTO_ICMP`, `IPPROTO_TCP`)

**Returns:** Raw socket handle on success, `NULL` on failure.

**Example:**
```c
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
}
```

#### `rawsock_create_with_config`

```c
rawsock_t* rawsock_create_with_config(const rawsock_config_t* config);
```

Creates a raw socket with custom configuration.

**Parameters:**
- `config`: Socket configuration structure

**Returns:** Raw socket handle on success, `NULL` on failure.

**Example:**
```c
rawsock_config_t config = {
    .family = RAWSOCK_IPV4,
    .protocol = IPPROTO_TCP,
    .recv_timeout_ms = 5000,
    .send_timeout_ms = 5000,
    .include_ip_header = 1,
    .broadcast = 0,
    .promiscuous = 0
};

rawsock_t* sock = rawsock_create_with_config(&config);
```

#### `rawsock_destroy`

```c
void rawsock_destroy(rawsock_t* sock);
```

Destroys a raw socket and frees resources.

**Parameters:**
- `sock`: Raw socket handle

**Note:** Safe to call with `NULL` pointer.

### Packet Transmission

#### `rawsock_send`

```c
int rawsock_send(rawsock_t* sock, const void* packet, size_t packet_size, 
                const char* dest_addr);
```

Sends a packet through the raw socket.

**Parameters:**
- `sock`: Raw socket handle
- `packet`: Packet data
- `packet_size`: Size of packet data
- `dest_addr`: Destination address string

**Returns:** Number of bytes sent on success, negative error code on failure.

**Example:**
```c
uint8_t packet[64];
// ... construct packet ...
int sent = rawsock_send(sock, packet, sizeof(packet), "192.168.1.1");
if (sent < 0) {
    fprintf(stderr, "Send failed: %s\n", rawsock_error_string(-sent));
}
```

#### `rawsock_send_to_interface`

```c
int rawsock_send_to_interface(rawsock_t* sock, const void* packet, 
                             size_t packet_size, const char* dest_addr,
                             const char* interface);
```

Sends a packet to a specific network interface.

**Parameters:**
- `sock`: Raw socket handle
- `packet`: Packet data
- `packet_size`: Size of packet data
- `dest_addr`: Destination address string
- `interface`: Interface name (e.g., "eth0")

**Returns:** Number of bytes sent on success, negative error code on failure.

### Packet Reception

#### `rawsock_recv`

```c
int rawsock_recv(rawsock_t* sock, void* buffer, size_t buffer_size,
                rawsock_packet_info_t* packet_info);
```

Receives a packet from the raw socket.

**Parameters:**
- `sock`: Raw socket handle
- `buffer`: Buffer to store received packet
- `buffer_size`: Size of the buffer
- `packet_info`: Pointer to store packet information (optional, can be `NULL`)

**Returns:** Number of bytes received on success, negative error code on failure.

**Example:**
```c
uint8_t buffer[1500];
rawsock_packet_info_t info;

int received = rawsock_recv(sock, buffer, sizeof(buffer), &info);
if (received > 0) {
    printf("Received %d bytes from %s\n", received, info.src_addr);
}
```

### Socket Options

#### `rawsock_set_option`

```c
rawsock_error_t rawsock_set_option(rawsock_t* sock, int option, 
                                  const void* value, size_t value_size);
```

Sets a socket option.

**Parameters:**
- `sock`: Raw socket handle
- `option`: Option name (standard socket options)
- `value`: Option value
- `value_size`: Size of option value

**Returns:** `RAWSOCK_SUCCESS` on success, error code on failure.

#### `rawsock_get_option`

```c
rawsock_error_t rawsock_get_option(rawsock_t* sock, int option, 
                                  void* value, size_t* value_size);
```

Gets a socket option.

**Parameters:**
- `sock`: Raw socket handle
- `option`: Option name
- `value`: Buffer to store option value
- `value_size`: Pointer to size of value buffer

**Returns:** `RAWSOCK_SUCCESS` on success, error code on failure.

### Utility Functions

#### `rawsock_get_version`

```c
const char* rawsock_get_version(void);
```

Returns the library version string.

#### `rawsock_init`

```c
rawsock_error_t rawsock_init(void);
```

Initializes the library (optional, called automatically).

#### `rawsock_cleanup`

```c
void rawsock_cleanup(void);
```

Cleans up library resources (optional).

#### `rawsock_check_privileges`

```c
int rawsock_check_privileges(void);
```

Checks if the current user has sufficient privileges for raw sockets.

**Returns:** 1 if privileges are sufficient, 0 otherwise.

## Packet Construction API

### Packet Builder

#### `rawsock_packet_builder_create`

```c
rawsock_packet_builder_t* rawsock_packet_builder_create(size_t max_size);
```

Creates a new packet builder.

**Parameters:**
- `max_size`: Maximum packet size

**Returns:** Packet builder handle on success, `NULL` on failure.

#### `rawsock_packet_builder_destroy`

```c
void rawsock_packet_builder_destroy(rawsock_packet_builder_t* builder);
```

Destroys packet builder and frees resources.

#### `rawsock_packet_builder_reset`

```c
void rawsock_packet_builder_reset(rawsock_packet_builder_t* builder);
```

Resets packet builder for reuse.

### Header Construction

#### `rawsock_packet_add_ipv4_header`

```c
rawsock_error_t rawsock_packet_add_ipv4_header(rawsock_packet_builder_t* builder,
                                               const char* src_addr,
                                               const char* dst_addr,
                                               uint8_t protocol, uint8_t ttl);
```

Adds an IPv4 header to the packet.

**Example:**
```c
rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
rawsock_packet_add_ipv4_header(builder, "192.168.1.1", "192.168.1.2", 
                               IPPROTO_ICMP, 64);
```

#### `rawsock_packet_add_tcp_header`

```c
rawsock_error_t rawsock_packet_add_tcp_header(rawsock_packet_builder_t* builder,
                                              uint16_t src_port, uint16_t dst_port,
                                              uint32_t seq_num, uint32_t ack_num,
                                              uint8_t flags, uint16_t window);
```

Adds a TCP header to the packet.

#### `rawsock_packet_add_udp_header`

```c
rawsock_error_t rawsock_packet_add_udp_header(rawsock_packet_builder_t* builder,
                                              uint16_t src_port, uint16_t dst_port);
```

Adds a UDP header to the packet.

#### `rawsock_packet_add_icmp_header`

```c
rawsock_error_t rawsock_packet_add_icmp_header(rawsock_packet_builder_t* builder,
                                               uint8_t type, uint8_t code,
                                               uint16_t id, uint16_t sequence);
```

Adds an ICMP header to the packet.

#### `rawsock_packet_add_payload`

```c
rawsock_error_t rawsock_packet_add_payload(rawsock_packet_builder_t* builder,
                                           const void* data, size_t data_size);
```

Adds payload data to the packet.

#### `rawsock_packet_finalize`

```c
rawsock_error_t rawsock_packet_finalize(rawsock_packet_builder_t* builder);
```

Finalizes the packet and calculates checksums.

#### `rawsock_packet_get_data`

```c
rawsock_error_t rawsock_packet_get_data(rawsock_packet_builder_t* builder,
                                        const void** packet_data, size_t* packet_size);
```

Gets the constructed packet data.

**Example usage:**
```c
// Create and build packet
rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
rawsock_packet_add_ipv4_header(builder, "10.0.0.1", "10.0.0.2", IPPROTO_ICMP, 64);
rawsock_packet_add_icmp_header(builder, 8, 0, 1234, 1);
rawsock_packet_add_payload(builder, "Hello", 5);
rawsock_packet_finalize(builder);

// Get packet data and send
const void* packet_data;
size_t packet_size;
rawsock_packet_get_data(builder, &packet_data, &packet_size);
rawsock_send(sock, packet_data, packet_size, "10.0.0.2");

// Cleanup
rawsock_packet_builder_destroy(builder);
```

### Packet Parsing

#### `rawsock_parse_ipv4_header`

```c
rawsock_error_t rawsock_parse_ipv4_header(const void* packet_data, size_t packet_size,
                                          rawsock_ipv4_header_t* header);
```

Parses an IPv4 header from packet data.

#### `rawsock_parse_tcp_header`

```c
rawsock_error_t rawsock_parse_tcp_header(const void* packet_data, size_t packet_size,
                                         rawsock_tcp_header_t* header);
```

Parses a TCP header from packet data.

#### `rawsock_parse_udp_header`

```c
rawsock_error_t rawsock_parse_udp_header(const void* packet_data, size_t packet_size,
                                         rawsock_udp_header_t* header);
```

Parses a UDP header from packet data.

#### `rawsock_parse_icmp_header`

```c
rawsock_error_t rawsock_parse_icmp_header(const void* packet_data, size_t packet_size,
                                          rawsock_icmp_header_t* header);
```

Parses an ICMP header from packet data.

### Checksum Functions

#### `rawsock_calculate_ip_checksum`

```c
uint16_t rawsock_calculate_ip_checksum(const void* data, size_t length);
```

Calculates IP header checksum.

#### `rawsock_calculate_transport_checksum`

```c
uint16_t rawsock_calculate_transport_checksum(const void* src_addr, const void* dst_addr,
                                             size_t addr_len, uint8_t protocol,
                                             const void* data, size_t length);
```

Calculates TCP/UDP checksum with pseudo header.

### Address Utilities

#### `rawsock_addr_str_to_bin`

```c
rawsock_error_t rawsock_addr_str_to_bin(const char* addr_str, rawsock_family_t family,
                                        void* addr_bin);
```

Converts IP address string to binary format.

#### `rawsock_addr_bin_to_str`

```c
rawsock_error_t rawsock_addr_bin_to_str(const void* addr_bin, rawsock_family_t family,
                                        char* addr_str);
```

Converts binary IP address to string format.

## Error Handling

#### `rawsock_get_last_error`

```c
rawsock_error_t rawsock_get_last_error(rawsock_t* sock);
```

Gets the last error code for a socket.

#### `rawsock_error_string`

```c
const char* rawsock_error_string(rawsock_error_t error);
```

Gets a human-readable error description.

**Example:**
```c
int result = rawsock_send(sock, packet, size, dest);
if (result < 0) {
    rawsock_error_t error = -result;
    fprintf(stderr, "Send failed: %s\n", rawsock_error_string(error));
}
```

## Data Structures

### `rawsock_config_t`

Socket configuration structure:

```c
typedef struct {
    rawsock_family_t family;       // Address family
    int protocol;                  // Protocol number
    int recv_timeout_ms;           // Receive timeout in milliseconds
    int send_timeout_ms;           // Send timeout in milliseconds
    uint8_t include_ip_header;     // Include IP header in packets
    uint8_t broadcast;             // Enable broadcast
    uint8_t promiscuous;           // Enable promiscuous mode
} rawsock_config_t;
```

### `rawsock_packet_info_t`

Packet information structure:

```c
typedef struct {
    char src_addr[46];             // Source address string
    char dst_addr[46];             // Destination address string
    uint16_t src_port;             // Source port (if applicable)
    uint16_t dst_port;             // Destination port (if applicable)
    uint8_t protocol;              // Protocol number
    size_t packet_size;            // Total packet size
    uint64_t timestamp_us;         // Timestamp in microseconds
} rawsock_packet_info_t;
```

### Header Structures

```c
typedef struct {
    uint8_t version_ihl;           // Version (4 bits) + IHL (4 bits)
    uint8_t tos;                   // Type of Service
    uint16_t total_length;         // Total Length
    uint16_t id;                   // Identification
    uint16_t flags_fragment;       // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;                   // Time to Live
    uint8_t protocol;              // Protocol
    uint16_t checksum;             // Header Checksum
    uint32_t src_addr;             // Source Address
    uint32_t dst_addr;             // Destination Address
} rawsock_ipv4_header_t;
```

## Constants and Enums

### Address Families

```c
typedef enum {
    RAWSOCK_IPV4 = 0,     // IPv4 address family
    RAWSOCK_IPV6 = 1      // IPv6 address family
} rawsock_family_t;
```

### Error Codes

```c
typedef enum {
    RAWSOCK_SUCCESS = 0,           // Operation successful
    RAWSOCK_ERROR_INVALID_PARAM,   // Invalid parameter
    RAWSOCK_ERROR_SOCKET_CREATE,   // Socket creation failed
    RAWSOCK_ERROR_SOCKET_BIND,     // Socket bind failed
    RAWSOCK_ERROR_SEND,            // Send operation failed
    RAWSOCK_ERROR_RECV,            // Receive operation failed
    RAWSOCK_ERROR_PERMISSION,      // Insufficient permissions
    RAWSOCK_ERROR_TIMEOUT,         // Operation timed out
    RAWSOCK_ERROR_BUFFER_TOO_SMALL,// Buffer too small
    RAWSOCK_ERROR_UNKNOWN          // Unknown error
} rawsock_error_t;
```

## Examples

See the `examples/` directory for complete examples:

- `ping.c`: Simple ping implementation
- `tcp_syn_scan.c`: TCP SYN port scanner
- `packet_sniffer.c`: Basic packet sniffer

## Thread Safety

The LibRawSock library is **not thread-safe**. If you need to use raw sockets from multiple threads, you must provide your own synchronization mechanisms.

## Platform Support

Currently supported platforms:

- Linux (tested)
- Other Unix-like systems (should work but not tested)

## Performance Considerations

- Use packet builders efficiently by reusing them with `rawsock_packet_builder_reset()`
- Consider buffer sizes when receiving packets
- Set appropriate timeouts to avoid blocking indefinitely
- Raw sockets require kernel mode transitions, so they may be slower than regular sockets

## Troubleshooting

### Common Issues

1. **Permission Denied**: Raw sockets require root privileges or CAP_NET_RAW capability
2. **Address Family Not Supported**: IPv6 may not be available on all systems
3. **Operation Not Permitted**: Some systems restrict raw socket usage

### Debugging

Enable debug builds and check error codes:

```c
if (!rawsock_check_privileges()) {
    fprintf(stderr, "Insufficient privileges\n");
    exit(1);
}

rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    fprintf(stderr, "Socket creation failed\n");
    exit(1);
}
```

