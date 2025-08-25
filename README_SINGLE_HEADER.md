# RawSock - Single Header Raw Socket Library

A lightweight, single-header C library for raw socket programming on Linux and macOS.

## Features

- **Single Header** - Just include `rawsock.h` in your project
- **Cross-platform** - Works on Linux and macOS
- **IPv4/IPv6 Support** - Full support for both protocols
- **Packet Parsing** - Built-in parsers for IP, TCP, UDP, and ICMP headers
- **Checksum Calculation** - IP and transport layer checksum utilities
- **Clean API** - Simple and intuitive interface
- **No Dependencies** - Uses only standard system libraries

## Quick Start

1. Copy `rawsock.h` to your project
2. In ONE source file, define the implementation before including:

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"
```

3. In other source files, just include normally:

```c
#include "rawsock.h"
```

## Example Usage

```c
#define RAWSOCK_IMPLEMENTATION
#include "rawsock.h"

int main(void) {
    // Check privileges
    if (!rawsock_check_privileges()) {
        printf("Need root privileges\n");
        return 1;
    }
    
    // Create a raw socket
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) {
        printf("Failed to create socket\n");
        return 1;
    }
    
    // Send a packet
    uint8_t packet[64];
    // ... build your packet ...
    rawsock_send(sock, packet, sizeof(packet), "192.168.1.1");
    
    // Receive a packet
    uint8_t buffer[1024];
    rawsock_packet_info_t info;
    int bytes = rawsock_recv(sock, buffer, sizeof(buffer), &info);
    if (bytes > 0) {
        printf("Received %d bytes from %s\n", bytes, info.src_addr);
    }
    
    // Clean up
    rawsock_destroy(sock);
    return 0;
}
```

## API Reference

### Core Functions

- `rawsock_create()` - Create a raw socket
- `rawsock_create_with_config()` - Create with custom configuration
- `rawsock_destroy()` - Close and free socket
- `rawsock_send()` - Send a packet
- `rawsock_send_to_interface()` - Send via specific interface
- `rawsock_recv()` - Receive a packet
- `rawsock_set_option()` - Set socket option
- `rawsock_get_option()` - Get socket option

### Packet Parsing

- `rawsock_parse_ipv4_header()` - Parse IPv4 header
- `rawsock_parse_ipv6_header()` - Parse IPv6 header
- `rawsock_parse_tcp_header()` - Parse TCP header
- `rawsock_parse_udp_header()` - Parse UDP header
- `rawsock_parse_icmp_header()` - Parse ICMP header

### Utilities

- `rawsock_calculate_ip_checksum()` - Calculate IP checksum
- `rawsock_calculate_transport_checksum()` - Calculate TCP/UDP checksum
- `rawsock_addr_str_to_bin()` - Convert IP string to binary
- `rawsock_addr_bin_to_str()` - Convert binary IP to string
- `rawsock_check_privileges()` - Check for raw socket privileges
- `rawsock_get_version()` - Get library version

## Compilation

Basic compilation:
```bash
gcc -o myprogram myprogram.c
```

With optimizations:
```bash
gcc -O2 -o myprogram myprogram.c
```

For debugging:
```bash
gcc -g -Wall -Wextra -o myprogram myprogram.c
```

## Platform Notes

### Linux
- Requires root privileges or CAP_NET_RAW capability
- Full support for all features

### macOS
- Requires root privileges
- Some limitations on raw socket behavior due to BSD implementation
- IP_HDRINCL option may behave differently than Linux

## Error Handling

All functions return error codes from the `rawsock_error_t` enum:

```c
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    // Socket creation failed
}

int sent = rawsock_send(sock, packet, size, "192.168.1.1");
if (sent < 0) {
    rawsock_error_t error = rawsock_get_last_error(sock);
    printf("Error: %s\n", rawsock_error_string(error));
}
```

## License

This is a simplified single-header version of the original librawsock library.

## Version

Current version: 1.0.0