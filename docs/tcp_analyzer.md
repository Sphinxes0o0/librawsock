# TCP Protocol Analyzer

LibRawSock now includes a powerful, extensible protocol analysis framework that provides deep analysis capabilities specifically for TCP protocol.

## Features

### 🔄 TCP Connection State Tracking
- Complete TCP state machine implementation (RFC 793)
- Real-time connection state monitoring
- Connection establishment and closure detection
- Abnormal connection handling (RST, timeout, etc.)

### 📊 Performance Analysis
- RTT (Round Trip Time) measurement and statistics
- Retransmission detection and counting
- Window size tracking
- Congestion control analysis

### 🔍 Advanced Analysis
- TCP option parsing (MSS, window scaling, SACK, timestamps, etc.)
- Sequence number analysis and validation
- Out-of-order packet detection
- Duplicate ACK detection

### 🧩 Data Reassembly
- TCP stream reassembly
- Application layer data extraction
- Bidirectional data flow tracking

## Architecture Design

### Extensible Framework
```c
// Core analyzer context
analyzer_context_t* ctx = analyzer_create();

// Register protocol handler
analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
analyzer_register_handler(ctx, tcp_handler);

// Set callback functions
analyzer_set_connection_callback(ctx, connection_callback);
analyzer_set_data_callback(ctx, data_callback);
```

### Protocol Handler Interface
Each protocol analyzer implements a standard interface:
- `packet_handler`: Process individual packets
- `conn_init`: Initialize connection state
- `conn_cleanup`: Clean up connection resources
- `conn_timeout`: Handle connection timeouts

## API Usage Examples

### Basic TCP Connection Monitoring

```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

void connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                        analyzer_result_t result) {
    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            printf("New connection: %s\n", flow_str);
            break;

        case ANALYZER_RESULT_CONNECTION_CLOSE:
            printf("Connection closed: %s\n", flow_str);
            if (conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
                printf("  Final state: %s\n", tcp_state_to_string(tcp_state->state));
                printf("  RTT: %u μs (%u samples)\n", tcp_state->avg_rtt_us, tcp_state->rtt_samples);
            }
            break;
    }
}

int main() {
    // Create analyzer
    analyzer_context_t* ctx = analyzer_create();

    // Register TCP handler
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    analyzer_set_connection_callback(ctx, connection_callback);

    // Create raw socket
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_TCP);

    // Main loop
    uint8_t buffer[65536];
    while (running) {
        rawsock_packet_info_t packet_info;
        int received = rawsock_recv(sock, buffer, sizeof(buffer), &packet_info);

        if (received > 0) {
            struct timeval timestamp;
            gettimeofday(&timestamp, NULL);
            analyzer_process_packet(ctx, buffer, received, &timestamp);
        }
    }

    // Clean up
    rawsock_destroy(sock);
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    return 0;
}
```

### Data Stream Reassembly

```c
void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t dir, const uint8_t* data, size_t size) {
    char flow_str[64];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));

    printf("Data ready: %s [%s] %zu bytes\n", 
           flow_str, (dir == ANALYZER_DIR_FORWARD) ? "→" : "←", size);

    // Process application layer data
    if (conn->flow_id.dst_port == 80 || conn->flow_id.src_port == 80) {
        // HTTP traffic analysis
        printf("HTTP data: %.*s\n", (int)size, data);
    }

    // Consume data
    tcp_consume_reassembled_data(conn, dir, size);
}
```

## TCP State Analysis

### Supported TCP States
- `TCP_STATE_CLOSED`: Connection closed
- `TCP_STATE_LISTEN`: Listening state
- `TCP_STATE_SYN_SENT`: SYN sent
- `TCP_STATE_SYN_RECEIVED`: SYN received
- `TCP_STATE_ESTABLISHED`: Connection established
- `TCP_STATE_FIN_WAIT_1`: FIN wait 1
- `TCP_STATE_FIN_WAIT_2`: FIN wait 2
- `TCP_STATE_CLOSE_WAIT`: Close wait
- `TCP_STATE_CLOSING`: Closing
- `TCP_STATE_LAST_ACK`: Last ACK
- `TCP_STATE_TIME_WAIT`: Time wait

### Connection Quality Metrics

```c
typedef struct {
    uint32_t rtt_samples;              // RTT samples
    uint32_t min_rtt_us;               // Minimum RTT
    uint32_t max_rtt_us;               // Maximum RTT
    uint32_t avg_rtt_us;               // Average RTT

    size_t retransmit_count;           // Retransmission count
    uint32_t out_of_order_packets[2];  // Out-of-order packets [forward, backward]
    uint32_t duplicate_acks[2];        // Duplicate ACKs
    uint32_t zero_window_probes[2];    // Zero window probes
} tcp_connection_state_t;
```

## TCP Option Parsing

### Supported Option Types
- `TCP_OPT_MSS`: Maximum Segment Size
- `TCP_OPT_WINDOW_SCALE`: Window Scaling
- `TCP_OPT_SACK_PERMITTED`: SACK Permitted
- `TCP_OPT_SACK`: Selective Acknowledgment
- `TCP_OPT_TIMESTAMP`: Timestamps

### Option Parsing Example

```c
tcp_options_t options;
if (tcp_parse_options(tcp_header, &options) == RAWSOCK_SUCCESS) {
    printf("MSS: %u\n", options.mss);
    printf("Window scale: %u\n", options.window_scale);
    printf("SACK permitted: %s\n", options.sack_permitted ? "Yes" : "No");

    if (options.timestamp_val > 0) {
        printf("Timestamp: %u / %u\n", options.timestamp_val, options.timestamp_ecr);
    }
}
```

## Performance Analysis Features

### RTT Measurement
- Initial RTT measurement based on SYN/SYN-ACK
- Precise RTT based on timestamp options
- Exponentially weighted moving average
- Minimum/Maximum/Average RTT statistics

### Retransmission Detection
- Sequence number rollback detection
- Fast retransmit identification
- RTO retransmission detection
- Retransmission counting and analysis

### Congestion Control Analysis
- Effective window size tracking
- Congestion window estimation
- Zero window detection
- Window scaling handling

## Configuration Options

```c
analyzer_config_t config = {
    .max_connections = 1024,           // Maximum connections
    .max_reassembly_size = 65536,      // Reassembly buffer size
    .connection_timeout = 300,         // Connection timeout (seconds)
    .enable_reassembly = 1,            // Enable data reassembly
    .enable_rtt_tracking = 1,          // Enable RTT tracking
    .enable_statistics = 1             // Enable statistics
};
```

## Example Programs

### 1. Simple TCP Monitor
```bash
sudo ./build/simple_tcp_monitor 100
```
- Monitor up to 100 TCP connections
- Display connection establishment and closure
- Basic statistics

### 2. Advanced Connection Analyzer
```bash
sudo ./build/tcp_connection_analyzer -v -s -t 60
```
- Detailed output mode
- Periodically display statistics
- 60-second connection timeout

## Extensibility

### Adding New Protocols
The framework supports easy addition of new protocol analyzers:

1. Implement the protocol handler interface
2. Define protocol-specific state structures
3. Register with the analyzer context

```c
// Custom protocol handler
analyzer_protocol_handler_t* my_protocol_create(void) {
    analyzer_protocol_handler_t* handler = malloc(sizeof(*handler));
    handler->protocol = MY_PROTOCOL_NUMBER;
    handler->packet_handler = my_packet_handler;
    handler->conn_init = my_conn_init;
    handler->conn_cleanup = my_conn_cleanup;
    handler->conn_timeout = my_conn_timeout;
    return handler;
}
```

### Custom Analysis Logic
Custom analysis can be implemented via callback functions:

```c
// Custom connection analysis
void custom_connection_callback(analyzer_context_t* ctx, 
                               analyzer_connection_t* conn, 
                               analyzer_result_t result) {
    // Implement custom logic
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        // New connection handling
    }
}
```

## Best Practices

### Memory Management
- Periodically call `analyzer_cleanup_expired()` to clean up expired connections
- Set appropriate maximum connection count and reassembly buffer size
- Consume reassembled data timely to avoid memory accumulation

### Performance Optimization
- Disable unnecessary features as needed (e.g., data reassembly)
- Use appropriate connection timeouts
- Consider sampling in high-traffic environments

### Error Handling
- Check all API return values
- Correctly handle connection state changes
- Implement appropriate timeout and cleanup mechanisms

## Testing

Run TCP analyzer tests:
```bash
make test
```

Test coverage:
- Protocol handler creation and destruction
- Stream ID utility functions
- TCP state machine transitions
- TCP option parsing
- Packet processing flow
- Connection timeout and cleanup

## Future Extensions

### Planned Features
- Full IPv6 support
- More protocol analyzers (UDP, ICMP, HTTP, etc.)
- Data packet filtering and matching
- Real-time performance metrics
- Export and logging functionality
- Machine learning anomaly detection

### Performance Improvements
- Zero-copy data processing
- Multi-threading support
- Hardware acceleration
- Memory pool management

This TCP protocol analysis framework provides a robust foundation for network analysis, performance monitoring, and security detection. Through its extensible design, it can easily add new protocol support and custom analysis logic.
