# Raw Socket Library Examples

## simple_test.c

Basic smoke test that creates raw sockets and verifies privileges.

```bash
gcc -o simple_test simple_test.c
sudo ./simple_test
```

## capture.c

Packet capture tool demonstrating both manual parsing and `rawsock_recv_auto()`.

```bash
# Compile
gcc -o capture capture.c

# Capture all protocols
sudo ./capture

# Capture specific protocol
sudo ./capture tcp
sudo ./capture udp
sudo ./capture icmp
```

### Features shown

- `RAWSOCK_AUTO_CLOSE` for automatic resource cleanup
- `rawsock_recv_auto()` for high-level packet reception
- Manual `rawsock_parse_ip4/tcp/udp/icmp` for layer-by-layer inspection
- Signal handling for graceful shutdown

## Notes

- All examples require root privileges or `CAP_NET_RAW`
- Only one source file should `#define RAWSOCK_IMPLEMENTATION` when including `rawsock.h`
