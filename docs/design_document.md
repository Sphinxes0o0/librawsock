# LibRawSock Design Document

## Project Overview

LibRawSock is a complete C/C++ raw socket network library that provides easy-to-use API interfaces and rich packet processing functionality. The project adopts a modular design, including core raw socket functionality, packet construction and parsing tools, and an extensible protocol analysis framework.

### Version Information
- **Current Version**: 1.0.0
- **Development Language**: C99/C++11
- **Supported Platforms**: Linux/Unix
- **License**: MIT

## Architecture Design

### Overall Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    LibRawSock Network Library               │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Core Layer    │  Packet Layer   │  Protocol Analysis Layer │
├─────────────────┼─────────────────┼─────────────────────────┤
│ • Raw Socket    │ • Packet Construction │ • Extensible Protocol Framework │
│ • Error Handling│ • Protocol Header Parsing │ • TCP Deep Analysis │
│ • Configuration │ • Checksum Calculation │ • Connection State Tracking │
│ • Permission Check│ • Address Conversion │ • Performance Monitoring │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### Module Dependencies

```
Protocol Analysis Layer (analyzer.h, tcp_analyzer.h)
    ↓
Packet Processing Layer (packet.h)
    ↓
Core Layer (rawsock.h)
    ↓
System Call Layer (socket, netinet, arpa)
```

## Core Functionality Design

### 1. Raw Socket Core Layer

#### Design Goals
- Provide cross-platform raw socket abstraction
- Simplify complex system call interfaces
- Complete error handling and state management
- Flexible configuration options support

#### Main Components

**rawsock_t Structure**
```c
struct rawsock {
    int sockfd;                    // Socket file descriptor
    rawsock_family_t family;       // Address family
    int protocol;                  // Protocol number
    rawsock_error_t last_error;    // Last error code
    struct sockaddr_storage local_addr;  // Local address

    // Configuration options
    int recv_timeout_ms;           // Receive timeout
    int send_timeout_ms;           // Send timeout
    uint8_t include_ip_header;     // Include IP header
    uint8_t broadcast;             // Broadcast flag
    uint8_t promiscuous;           // Promiscuous mode
};
```

**Core API Design**
- `rawsock_create()`: Create raw socket
- `rawsock_send()`: Send packet
- `rawsock_recv()`: Receive packet
- `rawsock_destroy()`: Destroy socket

#### Error Handling Strategy
- Unified error code definitions
- User-friendly error descriptions
- Layered error propagation mechanism
- Detailed error context information

### 2. Packet Processing Layer

#### Design Goals
- Provide convenient packet construction tools
- Support multiple network protocol parsing
- Automatic checksum and length field calculation
- Efficient memory management

#### Builder Pattern Design

**Packet Construction Process**
```c
// Create builder
rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);

// Add protocol headers
rawsock_packet_add_ipv4_header(builder, src_ip, dst_ip, protocol, ttl);
```
