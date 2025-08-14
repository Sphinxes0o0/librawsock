# LibRawSock Use Cases

This page provides "ready-to-run" use cases based on existing examples and APIs, covering typical scenarios such as network monitoring, performance analysis, troubleshooting, and security analysis.

- Prerequisites
  - Linux system, with build tools installed (gcc/clang, cmake, make)
  - Raw sockets require root or CAP_NET_RAW permissions (some use cases can use demonstration mode without root)
  - Execute build script in project root directory

```bash
# Build all components (libraries + tests + examples + tools)
./build.sh --all
# Or only build examples
./build.sh --examples
```

After building, example binaries are located in `build/bin/`.

## Use Case 1: ICMP Ping (Network Connectivity Verification)

- Target: Verify connectivity to target host and round-trip time (RTT)
- Program: `examples/ping.c`
- Run:
```bash
sudo ./build/bin/ping 8.8.8.8 -c 3
```
- Key Points:
  - Use `rawsock_packet_builder_*` to construct IPv4 + ICMP packet
  - Use `rawsock_send`/`rawsock_recv` to send/receive

## Use Case 2: TCP SYN Scan (Port Reachability)

- Target: Quickly determine if target host ports are open
- Program: `examples/tcp_syn_scan.c`
- Run:
```bash
sudo ./build/bin/tcp_syn_scan 192.168.1.10 1 1024
```
- Key Points:
  - Send SYN, determine port status based on SYN-ACK/RST from peer

## Use Case 3: Packet Sniffing (Basic Packet Capture)

- Target: Capture and print basic packet information in real-time on specified network interface
- Program: `examples/packet_sniffer.c`
- Run:
```bash
sudo ./build/bin/packet_sniffer eth0
```
- Key Points:
  - Receive using raw sockets, parse IPv4/TCP/UDP/ICMP headers

## Use Case 4: TCP Connection Analysis (Performance and State)

- Target: Track TCP connection state, statistics, and performance (RTT, retransmissions, etc.)
- Program: `examples/tcp_connection_analyzer.c`
- Run:
```bash
sudo ./build/bin/tcp_connection_analyzer -v -s
```
- Key Points:
  - `analyzer_create` + `tcp_analyzer_create` register handlers
  - Set `connection_callback` / `data_callback`
  - Output connection state, byte count, average RTT, etc.

## Use Case 5: Simple TCP Monitoring (Lightweight Tracing)

- Target: Trace a certain number of TCP connections in a minimal way
- Program: `examples/simple_tcp_monitor.c`
- Run:
```bash
sudo ./build/bin/simple_tcp_monitor 50
```

## Use Case 6: TCP Analysis Demonstration (Root-free Simulation)

- Target: Quickly experience the TCP three-way handshake, HTTP round-trip, and connection closure analysis process in an environment without root permissions
- Program: `examples/demo_tcp_analysis.c`
- Run (simulation):
```bash
./build/bin/demo_tcp_analysis -d -v
```
- Key Points:
  - Construct and inject simulated packets using `rawsock_packet_builder_*`, drive `analyzer_process_packet`

## Use Case 7: Minimal Embedded Example of Library API

- Minimal raw socket usage:
```c
#include <librawsock/rawsock.h>

void example_send_icmp() {
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_ICMP);
    if (!sock) return;
    uint8_t pkt[64] = {0};
    /* Construct pkt ... */
    (void)rawsock_send(sock, pkt, sizeof(pkt), "8.8.8.8");
    rawsock_destroy(sock);
}
```

- Minimal protocol analysis usage:
```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

void example_analyze(const uint8_t* data, size_t len) {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* h = tcp_analyzer_create();
    analyzer_register_handler(ctx, h);
    struct timeval ts; gettimeofday(&ts, NULL);
    (void)analyzer_process_packet(ctx, data, len, &ts);
    tcp_analyzer_destroy(h);
    analyzer_destroy(ctx);
}
```

## Use Case 8: Testing and Coverage

```bash
# Build and run all unit tests
./build.sh --tests
cd build && ctest --output-on-failure

# Run by category
./build/bin/test_analyzer
./build/bin/test_packet
./build/bin/test_rawsock

# Valgrind (if installed)
ctest -L valgrind --output-on-failure

# Coverage (enabled with -DENABLE_COVERAGE=ON)
make coverage
```

## Use Case 9: Permissions and Troubleshooting

- Raw socket permissions:
```bash
# Run as root, or grant binary CAP_NET_RAW
sudo setcap cap_net_raw=eip ./build/bin/packet_sniffer
```
- Common Issues
  - Non-root receives "Insufficient permissions": Use `sudo` or `setcap`
  - IPv6 not available: Confirm kernel and system enable IPv6
  - Receive timeout: Adjust `rawsock_create_with_config`'s `recv_timeout_ms`

## Related Documents

- API Reference: `docs/api.md`
- TCP Analyzer Guide: `docs/tcp_usage_guide.md`
- Example Source Code: `examples/`