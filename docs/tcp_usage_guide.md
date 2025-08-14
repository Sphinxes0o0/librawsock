# TCP Protocol Analysis Usage Guide

This guide provides detailed instructions on how to use LibRawSock's TCP protocol analysis functionality, including basic usage, advanced configuration, and practical application examples.

## Quick Start

### Basic Usage

```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

int main() {
    // 1. Create analyzer context
    analyzer_context_t* ctx = analyzer_create();

    // 2. Create and register TCP handler
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    // 3. Set callback functions
    analyzer_set_connection_callback(ctx, connection_callback);
    analyzer_set_data_callback(ctx, data_callback);

    // 4. Process packets
    uint8_t packet_data[1500];
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);

    analyzer_process_packet(ctx, packet_data, packet_size, &timestamp);

    // 5. Clean up resources
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);

    return 0;
}
```

### Callback Function Implementation

```c
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
            break;
        default:
            break;
    }
}

void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t direction, const uint8_t* data, size_t size) {
    printf("Data: %zu bytes (%s)\n", size, 
           (direction == ANALYZER_DIR_FORWARD) ? "forward" : "reverse");
}
```

## Advanced Configuration

### Custom Configuration

```c
analyzer_config_t config = {
    .max_connections = 10000,         // Maximum connections
    .max_reassembly_size = 65536,     // Reassembly buffer size
    .connection_timeout = 300,        // Connection timeout (seconds)
    .enable_reassembly = 1,           // Enable data reassembly
    .enable_rtt_tracking = 1,         // Enable RTT tracking
    .enable_statistics = 1            // Enable statistics
};

analyzer_context_t* ctx = analyzer_create_with_config(&config);
```

### TCP-Specific Configuration

```c
// TCP analyzer configuration through protocol-specific interface
tcp_analyzer_config_t tcp_config = {
    .track_sequence_numbers = 1,      // Track sequence numbers
    .detect_retransmissions = 1,      // Detect retransmissions
    .parse_options = 1,               // Parse TCP options
    .reassemble_streams = 1,          // Reassemble data streams
    .calculate_rtt = 1                // Calculate RTT
};

// Apply configuration to TCP handler
tcp_analyzer_set_config(tcp_handler, &tcp_config);
```

## Practical Application Examples

### 1. Network Monitoring Application

```c
#include <pcap.h>  // Requires libpcap-dev

void network_monitor() {
    // Create analyzer
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    // Set callbacks
    analyzer_set_connection_callback(ctx, monitor_connection_callback);

    // Open network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle) {
        struct pcap_pkthdr header;
        const u_char* packet;

        while ((packet = pcap_next(handle, &header)) != NULL) {
            struct timeval timestamp = header.ts;
            analyzer_process_packet(ctx, packet, header.len, &timestamp);
        }

        pcap_close(handle);
    }

    // Clean up
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
}

void monitor_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                               analyzer_result_t result) {
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        // Log new connection
        char flow_str[128];
        analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
        syslog(LOG_INFO, "New TCP connection: %s", flow_str);
    }
}
```

### 2. HTTP Traffic Analysis

```c
void http_analyzer() {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    // Special callback for HTTP streams
    analyzer_set_data_callback(ctx, http_data_callback);

    // ... Packet processing loop ...
}

void http_data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                       analyzer_direction_t direction, const uint8_t* data, size_t size) {
    // Detect HTTP requests/responses
    if (size > 4 && memcmp(data, "GET ", 4) == 0) {
        printf("HTTP GET request detected\n");
        // Parse HTTP headers
        parse_http_request(data, size);
    } else if (size > 8 && memcmp(data, "HTTP/1.", 7) == 0) {
        printf("HTTP response detected\n");
        // Parse HTTP response
        parse_http_response(data, size);
    }
}
```

### 3. Performance Monitoring Tool

```c
typedef struct {
    uint64_t total_connections;
    uint64_t active_connections;
    uint64_t bytes_transferred;
    double avg_rtt_ms;
} performance_stats_t;

performance_stats_t g_stats;

void performance_monitor() {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    analyzer_set_connection_callback(ctx, perf_connection_callback);

    // Periodically output statistics
    signal(SIGALRM, print_performance_stats);
    alarm(10);  // Output every 10 seconds

    // ... Packet processing ...
}

void perf_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                            analyzer_result_t result) {
    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            g_stats.total_connections++;
            g_stats.active_connections++;
            break;
        case ANALYZER_RESULT_CONNECTION_CLOSE:
            g_stats.active_connections--;
            // Accumulate transferred bytes
            g_stats.bytes_transferred += conn->stats.bytes_forward + conn->stats.bytes_reverse;
            // Update average RTT
            if (conn->stats.avg_rtt_us > 0) {
                g_stats.avg_rtt_ms = conn->stats.avg_rtt_us / 1000.0;
            }
            break;
        default:
            break;
    }
}

void print_performance_stats(int sig) {
    printf("=== Performance Statistics ===\n");
    printf("Total connections: %lu\n", g_stats.total_connections);
    printf("Active connections: %lu\n", g_stats.active_connections);
    printf("Transferred bytes: %lu\n", g_stats.bytes_transferred);
    printf("Average RTT: %.2f ms\n", g_stats.avg_rtt_ms);

    alarm(10);  // Reset timer
}
```

### 4. Security Analysis Application

```c
typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    time_t last_seen;
    int connection_count;
} connection_tracker_t;

#define MAX_TRACKED_IPS 10000
connection_tracker_t g_trackers[MAX_TRACKED_IPS];

void security_analyzer() {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);

    analyzer_set_connection_callback(ctx, security_connection_callback);

    // ... Processing logic ...
}

void security_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                                analyzer_result_t result) {
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        uint32_t src_ip = conn->flow_id.src_ip;

        // Find or create tracking record
        connection_tracker_t* tracker = find_or_create_tracker(src_ip);
        if (tracker) {
            tracker->connection_count++;
            tracker->last_seen = time(NULL);

            // Detect suspicious activity
            if (tracker->connection_count > 100) {  // Possible port scan
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src_ip, ip_str, INET_ADDRSTRLEN);
                printf("Warning: Suspicious activity detected from %s (%d connections)\n", 
                       ip_str, tracker->connection_count);
            }
        }
    }
}
```

## Advanced Features

### TCP Option Analysis

```c
void analyze_tcp_options(analyzer_connection_t* conn) {
    if (conn->protocol_state) {
        tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;

        if (tcp_state->options_parsed) {
            printf("TCP Option Analysis:\n");
            printf("  MSS: %u\n", tcp_state->mss);
            printf("  Window Scaling: %u\n", tcp_state->window_scale);
            printf("  SACK Supported: %s\n", tcp_state->sack_permitted ? "Yes" : "No");
            printf("  Timestamp: %s\n", tcp_state->has_timestamp ? "Yes" : "No");
        }
    }
}
```

### RTT Measurement and Analysis

```c
void analyze_connection_performance(analyzer_connection_t* conn) {
    if (conn->stats.rtt_samples > 0) {
        double avg_rtt = conn->stats.avg_rtt_us / 1000.0;  // Convert to milliseconds

        printf("Connection Performance Analysis:\n");
        printf("  Average RTT: %.2f ms\n", avg_rtt);
        printf("  RTT Samples: %u\n", conn->stats.rtt_samples);

        // Performance evaluation
        if (avg_rtt < 10) {
            printf("  Network Quality: Excellent (< 10ms)\n");
        } else if (avg_rtt < 50) {
            printf("  Network Quality: Good (< 50ms)\n");
        } else if (avg_rtt < 200) {
            printf("  Network Quality: Average (< 200ms)\n");
        } else {
            printf("  Network Quality: Poor (>= 200ms)\n");
        }
    }
}
```

### Data Stream Reassembly

```c
void handle_reassembled_data(analyzer_context_t* ctx, analyzer_connection_t* conn,
                           analyzer_direction_t direction, const uint8_t* data, size_t size) {
    // Save reassembled data to file
    char filename[256];
    snprintf(filename, sizeof(filename), "stream_%08x_%04x_%04x_%s.dat",
             conn->flow_id.src_ip, conn->flow_id.src_port, conn->flow_id.dst_port,
             (direction == ANALYZER_DIR_FORWARD) ? "fwd" : "rev");

    FILE* fp = fopen(filename, "ab");
    if (fp) {
        fwrite(data, 1, size, fp);
        fclose(fp);
    }

    // Analyze application layer protocol
    if (is_http_data(data, size)) {
        analyze_http_stream(data, size, direction);
    } else if (is_ftp_data(data, size)) {
        analyze_ftp_stream(data, size, direction);
    }
}
```

## Performance Optimization Suggestions

### 1. Memory Management Optimization

```c
// Pre-allocate connection pool
analyzer_config_t config = {
    .max_connections = 10000,     // Set based on expected load
    .max_reassembly_size = 32768, // Appropriate reassembly buffer size
    .connection_timeout = 120     // Reasonable timeout
};
```

### 2. Batch Processing

```c
void batch_process_packets(analyzer_context_t* ctx, 
                         struct packet_batch* batch) {
    for (int i = 0; i < batch->count; i++) {
        analyzer_process_packet(ctx, 
                              batch->packets[i].data,
                              batch->packets[i].size,
                              &batch->packets[i].timestamp);
    }

    // Batch clean up expired connections
    if (batch->count % 1000 == 0) {
        analyzer_cleanup_expired(ctx);
    }
}
```

### 3. Selective Feature Enablement

```c
// Enable features selectively based on requirements
analyzer_config_t lightweight_config = {
    .enable_reassembly = 0,       // Disable when reassembly is not needed
    .enable_rtt_tracking = 0,     // Disable when RTT is not needed
    .enable_statistics = 1        // Keep basic statistics
};
```

## Troubleshooting

### Common Issues and Solutions

1. **Permission Issues**
   ```bash
   # Requires root privileges to access raw sockets
   sudo ./your_program
   # Or set CAP_NET_RAW privileges
   sudo setcap cap_net_raw=eip ./your_program
   ```

2. **Library Path Issues**
   ```bash
   # Set library path
   export LD_LIBRARY_PATH=/path/to/librawsock/lib:$LD_LIBRARY_PATH
   ```

3. **Memory Issues**
   ```c
   // Reduce max connections or buffer size
   config.max_connections = 1000;        // Lower connection count
   config.max_reassembly_size = 16384;   // Reduce buffer
   ```

4. **Performance Issues**
   ```c
   // Disable unnecessary features
   config.enable_reassembly = 0;
   config.enable_rtt_tracking = 0;
   ```

### Debugging Tips

1. **Enable Detailed Logging**
   ```c
   analyzer_set_log_level(ctx, ANALYZER_LOG_DEBUG);
   ```

2. **Statistical Monitoring**
   ```c
   analyzer_stats_t stats;
   analyzer_get_stats(ctx, &stats);
   printf("Processed packets: %lu, Active connections: %lu\n", 
          stats.packets_forward + stats.packets_reverse,
          ctx->active_connections);
   ```

3. **Memory Usage Monitoring**
   ```c
   size_t memory_usage = analyzer_get_memory_usage(ctx);
   printf("Memory usage: %zu bytes\n", memory_usage);
   ```

## Example Projects

Complete example code can be found at:

- `examples/tcp_connection_analyzer.c` - Full TCP connection analyzer
- `examples/simple_tcp_monitor.c` - Simple TCP monitoring tool
- `demo_tcp_analysis.c` - Functional demonstration program
- `stress_test_tcp.c` - Performance test program

## Compilation and Running

### Compilation Example

```bash
# Compile your program
gcc -Wall -Wextra -std=c99 -Iinclude -Llib \
    -o my_analyzer my_analyzer.c -lrawsock

# Run the program
LD_LIBRARY_PATH=./lib ./my_analyzer
```

### Makefile Integration

```makefile
CFLAGS = -Wall -Wextra -std=c99 -Iinclude
LDFLAGS = -Llib -lrawsock

my_analyzer: my_analyzer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

.PHONY: run
run: my_analyzer
	LD_LIBRARY_PATH=./lib ./my_analyzer
```

This usage guide should help you get started and make full use of LibRawSock's TCP protocol analysis functionality. Based on your specific requirements, you can choose appropriate configurations and features to build your network analysis application.
