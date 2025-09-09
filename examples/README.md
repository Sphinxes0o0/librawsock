# Raw Socket Library Examples

## Capture Tool

A network packet capture tool that demonstrates the usage of the rawsock library.

### Usage

```bash
# Run with sudo to capture all packets
sudo ./capture

# Capture only TCP packets
sudo ./capture tcp

# Capture only UDP packets
sudo ./capture udp

# Capture only ICMP packets
sudo ./capture icmp
```

### Notes

- Requires root privileges to create raw sockets
- Currently only supports IPv4
- Press Ctrl+C to stop capture
