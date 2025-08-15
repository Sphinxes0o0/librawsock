# LibRawSock - Simple Raw Socket Library

A lightweight C library for raw socket packet capture and sending with a simple, easy-to-use API.

## Features

- **Simple API**: Easy-to-use functions for packet capture and sending
- **Cross-platform**: Works on Linux, macOS, and other Unix-like systems
- **IPv4/IPv6 support**: Both address families supported
- **Minimal dependencies**: Only standard system libraries required
- **Error handling**: Comprehensive error codes and descriptions

## Quick Start

```c
#include <librawsock/rawsock.h>

// Create a raw socket for ICMP packets
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    printf("Failed to create socket: %s\n", rawsock_error_string(rawsock_get_last_error(sock)));
    return -1;
}

// Send a packet
uint8_t packet[64];
// ... construct your packet ...
int sent = rawsock_send(sock, packet, sizeof(packet), "192.168.1.1");
if (sent < 0) {
    printf("Send failed: %s\n", rawsock_error_string(rawsock_get_last_error(sock)));
}

// Receive packets
uint8_t buffer[65535];
rawsock_packet_info_t info;
while (1) {
    int received = rawsock_recv(sock, buffer, sizeof(buffer), &info);
    if (received > 0) {
        printf("Received %zu bytes from %s\n", info.packet_size, info.src_addr);
    }
}

// Clean up
rawsock_destroy(sock);
```

## Building

```bash
./build.sh
```

## API Reference

### Core Functions
- `rawsock_create()` - Create a raw socket
- `rawsock_destroy()` - Destroy a raw socket
- `rawsock_send()` - Send a packet
- `rawsock_recv()` - Receive a packet
- `rawsock_set_timeout()` - Set receive timeout

### Utility Functions
- `rawsock_calculate_ip_checksum()` - Calculate IP checksum
- `rawsock_parse_*_header()` - Parse packet headers
- `rawsock_error_string()` - Get error description

## Requirements

- Unix-like system (Linux, macOS, BSD)
- Root privileges or CAP_NET_RAW capability
- C99 compiler

## License

MIT License

