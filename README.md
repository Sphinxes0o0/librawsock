# LibRawSock - Raw Socket Network Library

A comprehensive C/C++ library for raw socket programming with clean APIs and robust error handling.

## Features

### Core Raw Socket Functionality
- Cross-platform raw socket abstraction
- Easy-to-use C/C++ APIs
- Packet construction and parsing utilities
- Comprehensive error handling
- IPv4/IPv6 support

### Protocol Analysis Framework (New!)
- Extensible protocol analyzer architecture
- TCP deep packet inspection and analysis
- Connection state tracking and monitoring
- Real-time performance metrics (RTT, throughput, quality)
- Data stream reassembly and application layer extraction

### Advanced TCP Analysis
- Complete TCP state machine implementation (11 states)
- Sequence number analysis and retransmission detection
- TCP options parsing (MSS, Window Scale, SACK, Timestamps)
- Connection quality metrics and anomaly detection
- Bidirectional data flow reconstruction

### Documentation and Testing
- Well-documented with examples
- Full unit test coverage (23 test cases)
- Comprehensive API reference
- Design documentation

## Quick Start

### Basic Raw Socket Usage

```c
#include <librawsock/rawsock.h>

// Create a raw socket
rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
if (!sock) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
}

// Send a packet
uint8_t packet[64];
// ... construct packet ...
int result = rawsock_send(sock, packet, sizeof(packet), "192.168.1.1");

// Clean up
rawsock_destroy(sock);
```

### TCP Connection Analysis

```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

// Create analyzer context
analyzer_context_t* ctx = analyzer_create();

// Register TCP analyzer
analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
analyzer_register_handler(ctx, tcp_handler);

// Set up callbacks
analyzer_set_connection_callback(ctx, connection_callback);
analyzer_set_data_callback(ctx, data_callback);

// Process packets
uint8_t buffer[65536];
while (running) {
    int received = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);
    if (received > 0) {
        struct timeval timestamp;
        gettimeofday(&timestamp, NULL);
        analyzer_process_packet(ctx, buffer, received, &timestamp);
    }
}

// Cleanup
tcp_analyzer_destroy(tcp_handler);
analyzer_destroy(ctx);
```

## Building

### Quick Start

```bash
# Basic build (core library only)
./build.sh

# Build all components (library + tests + examples + tools)
./build.sh --all

# Debug build with tests enabled
./build.sh --type Debug --tests --coverage
```

### CMake Build Options

```bash
# Manual CMake build
mkdir build && cd build

# Configure (select needed components)
cmake -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTS=ON \
      -DBUILD_EXAMPLES=ON \
      -DBUILD_TOOLS=ON \
      ..

# Compile
make -j$(nproc)

# Install
sudo make install
```


## Examples

### Basic Examples
- **Ping Implementation** (`examples/ping.c`) - Complete ping utility
- **TCP SYN Scanner** (`examples/tcp_syn_scan.c`) - Port scanning tool
- **Packet Sniffer** (`examples/packet_sniffer.c`) - Network packet capture

### TCP Analysis Examples
- **TCP Connection Analyzer** (`examples/tcp_connection_analyzer.c`) - Advanced connection monitoring with detailed performance metrics
- **Simple TCP Monitor** (`examples/simple_tcp_monitor.c`) - Basic TCP connection tracking

```bash
# Build examples (using CMake)
./build.sh --examples

# Run TCP connection analyzer (requires root)
sudo ./build/bin/tcp_connection_analyzer -v -s

# Run simple TCP monitor
sudo ./build/bin/simple_tcp_monitor 50

# Run demo in simulation mode
./build/bin/demo_tcp_analysis -d -v
```

## Documentation

- [API Reference](docs/api.md) - Complete API documentation
- [Use Cases](docs/use_cases.md) - Practical usage scenarios
- [TCP Analyzer Guide](docs/tcp_analyzer.md) - TCP analysis framework guide
- [Installation Guide](docs/installation.md) - Building and installation instructions
- [Design Document](docs/design_document.md) - Comprehensive design documentation
- [Examples](examples/) - Working example programs
- [Unit Tests](tests/) - Comprehensive test suite

## Testing

```bash
# Build and run all tests
./build.sh --tests
cd build && ctest

# Run specific test categories
./build/bin/test_analyzer     # Protocol analyzer tests
./build/bin/test_packet       # Packet construction tests  
./build/bin/test_rawsock      # Core raw socket tests

# Run with memory checking (if Valgrind available)
ctest -L valgrind

# Generate coverage report (if enabled)
make coverage
```

## Performance

The TCP analyzer framework provides:
- **Real-time analysis** of TCP connections with minimal overhead
- **High throughput** packet processing (tested with 1M+ packets)
- **Memory efficient** connection tracking with automatic cleanup
- **Scalable architecture** supporting thousands of concurrent connections

## Use Cases

- **Network Monitoring**: Real-time TCP connection monitoring and analysis
- **Performance Analysis**: RTT measurement, throughput analysis, quality metrics
- **Troubleshooting**: Connection state tracking, retransmission analysis
- **Security Analysis**: Anomaly detection, connection pattern analysis
- **Protocol Development**: Network protocol testing and validation

## Requirements

- Linux/Unix system with raw socket support
- Root privileges or CAP_NET_RAW capability
- C99 compatible compiler (GCC 4.9+)
- Standard POSIX libraries

## License

MIT License

