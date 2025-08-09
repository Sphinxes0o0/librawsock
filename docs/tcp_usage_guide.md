# TCP 协议分析功能使用指南

本指南详细介绍如何使用 LibRawSock 的 TCP 协议分析功能，包括基本用法、高级配置和实际应用示例。

## 快速开始

### 基本使用

```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

int main() {
    // 1. 创建分析器上下文
    analyzer_context_t* ctx = analyzer_create();
    
    // 2. 创建并注册TCP处理器
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    
    // 3. 设置回调函数
    analyzer_set_connection_callback(ctx, connection_callback);
    analyzer_set_data_callback(ctx, data_callback);
    
    // 4. 处理数据包
    uint8_t packet_data[1500];
    struct timeval timestamp;
    gettimeofday(&timestamp, NULL);
    
    analyzer_process_packet(ctx, packet_data, packet_size, &timestamp);
    
    // 5. 清理资源
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    
    return 0;
}
```

### 回调函数实现

```c
void connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                        analyzer_result_t result) {
    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
    
    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            printf("新连接: %s\n", flow_str);
            break;
        case ANALYZER_RESULT_CONNECTION_CLOSE:
            printf("连接关闭: %s\n", flow_str);
            break;
        default:
            break;
    }
}

void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t direction, const uint8_t* data, size_t size) {
    printf("数据: %zu 字节 (%s)\n", size, 
           (direction == ANALYZER_DIR_FORWARD) ? "正向" : "反向");
}
```

## 高级配置

### 自定义配置

```c
analyzer_config_t config = {
    .max_connections = 10000,         // 最大连接数
    .max_reassembly_size = 65536,     // 重组缓冲区大小
    .connection_timeout = 300,        // 连接超时时间(秒)
    .enable_reassembly = 1,           // 启用数据重组
    .enable_rtt_tracking = 1,         // 启用RTT跟踪
    .enable_statistics = 1            // 启用统计功能
};

analyzer_context_t* ctx = analyzer_create_with_config(&config);
```

### TCP特定配置

```c
// TCP分析器支持的配置通过协议特定接口设置
tcp_analyzer_config_t tcp_config = {
    .track_sequence_numbers = 1,      // 跟踪序列号
    .detect_retransmissions = 1,      // 检测重传
    .parse_options = 1,               // 解析TCP选项
    .reassemble_streams = 1,          // 重组数据流
    .calculate_rtt = 1                // 计算RTT
};

// 应用配置到TCP处理器
tcp_analyzer_set_config(tcp_handler, &tcp_config);
```

## 实际应用示例

### 1. 网络监控应用

```c
#include <pcap.h>  // 需要安装libpcap-dev

void network_monitor() {
    // 创建分析器
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    
    // 设置回调
    analyzer_set_connection_callback(ctx, monitor_connection_callback);
    
    // 打开网络接口
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
    
    // 清理
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
}

void monitor_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                               analyzer_result_t result) {
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        // 记录新连接到日志
        char flow_str[128];
        analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
        syslog(LOG_INFO, "New TCP connection: %s", flow_str);
    }
}
```

### 2. HTTP流量分析

```c
void http_analyzer() {
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    
    // 专门处理HTTP流量的回调
    analyzer_set_data_callback(ctx, http_data_callback);
    
    // ... 数据包处理循环 ...
}

void http_data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                       analyzer_direction_t direction, const uint8_t* data, size_t size) {
    // 检测HTTP请求/响应
    if (size > 4 && memcmp(data, "GET ", 4) == 0) {
        printf("HTTP GET 请求检测到\n");
        // 解析HTTP头部
        parse_http_request(data, size);
    } else if (size > 8 && memcmp(data, "HTTP/1.", 7) == 0) {
        printf("HTTP 响应检测到\n");
        // 解析HTTP响应
        parse_http_response(data, size);
    }
}
```

### 3. 性能监控工具

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
    
    // 定期输出统计信息
    signal(SIGALRM, print_performance_stats);
    alarm(10);  // 每10秒输出一次
    
    // ... 数据包处理 ...
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
            // 累计传输字节数
            g_stats.bytes_transferred += conn->stats.bytes_forward + conn->stats.bytes_reverse;
            // 更新平均RTT
            if (conn->stats.avg_rtt_us > 0) {
                g_stats.avg_rtt_ms = conn->stats.avg_rtt_us / 1000.0;
            }
            break;
        default:
            break;
    }
}

void print_performance_stats(int sig) {
    printf("=== 性能统计 ===\n");
    printf("总连接数: %lu\n", g_stats.total_connections);
    printf("活跃连接: %lu\n", g_stats.active_connections);
    printf("传输字节: %lu\n", g_stats.bytes_transferred);
    printf("平均RTT: %.2f ms\n", g_stats.avg_rtt_ms);
    
    alarm(10);  // 重新设置定时器
}
```

### 4. 安全分析应用

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
    
    // ... 处理逻辑 ...
}

void security_connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                                analyzer_result_t result) {
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        uint32_t src_ip = conn->flow_id.src_ip;
        
        // 查找或创建跟踪记录
        connection_tracker_t* tracker = find_or_create_tracker(src_ip);
        if (tracker) {
            tracker->connection_count++;
            tracker->last_seen = time(NULL);
            
            // 检测可疑活动
            if (tracker->connection_count > 100) {  // 可能的端口扫描
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src_ip, ip_str, INET_ADDRSTRLEN);
                printf("警告: 检测到可疑活动来自 %s (%d connections)\n", 
                       ip_str, tracker->connection_count);
            }
        }
    }
}
```

## 高级特性

### TCP选项分析

```c
void analyze_tcp_options(analyzer_connection_t* conn) {
    if (conn->protocol_state) {
        tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
        
        if (tcp_state->options_parsed) {
            printf("TCP选项分析:\n");
            printf("  MSS: %u\n", tcp_state->mss);
            printf("  窗口缩放: %u\n", tcp_state->window_scale);
            printf("  SACK支持: %s\n", tcp_state->sack_permitted ? "是" : "否");
            printf("  时间戳: %s\n", tcp_state->has_timestamp ? "是" : "否");
        }
    }
}
```

### RTT测量和分析

```c
void analyze_connection_performance(analyzer_connection_t* conn) {
    if (conn->stats.rtt_samples > 0) {
        double avg_rtt = conn->stats.avg_rtt_us / 1000.0;  // 转换为毫秒
        
        printf("连接性能分析:\n");
        printf("  平均RTT: %.2f ms\n", avg_rtt);
        printf("  RTT样本数: %u\n", conn->stats.rtt_samples);
        
        // 性能评估
        if (avg_rtt < 10) {
            printf("  网络质量: 优秀 (< 10ms)\n");
        } else if (avg_rtt < 50) {
            printf("  网络质量: 良好 (< 50ms)\n");
        } else if (avg_rtt < 200) {
            printf("  网络质量: 一般 (< 200ms)\n");
        } else {
            printf("  网络质量: 较差 (>= 200ms)\n");
        }
    }
}
```

### 数据流重组

```c
void handle_reassembled_data(analyzer_context_t* ctx, analyzer_connection_t* conn,
                           analyzer_direction_t direction, const uint8_t* data, size_t size) {
    // 保存重组的数据到文件
    char filename[256];
    snprintf(filename, sizeof(filename), "stream_%08x_%04x_%04x_%s.dat",
             conn->flow_id.src_ip, conn->flow_id.src_port, conn->flow_id.dst_port,
             (direction == ANALYZER_DIR_FORWARD) ? "fwd" : "rev");
    
    FILE* fp = fopen(filename, "ab");
    if (fp) {
        fwrite(data, 1, size, fp);
        fclose(fp);
    }
    
    // 分析应用层协议
    if (is_http_data(data, size)) {
        analyze_http_stream(data, size, direction);
    } else if (is_ftp_data(data, size)) {
        analyze_ftp_stream(data, size, direction);
    }
}
```

## 性能优化建议

### 1. 内存管理优化

```c
// 预分配连接池
analyzer_config_t config = {
    .max_connections = 10000,     // 根据预期负载设置
    .max_reassembly_size = 32768, // 适当的重组缓冲区大小
    .connection_timeout = 120     // 合理的超时时间
};
```

### 2. 批量处理

```c
void batch_process_packets(analyzer_context_t* ctx, 
                         struct packet_batch* batch) {
    for (int i = 0; i < batch->count; i++) {
        analyzer_process_packet(ctx, 
                              batch->packets[i].data,
                              batch->packets[i].size,
                              &batch->packets[i].timestamp);
    }
    
    // 批量清理过期连接
    if (batch->count % 1000 == 0) {
        analyzer_cleanup_expired(ctx);
    }
}
```

### 3. 选择性特性启用

```c
// 根据需求选择性启用特性
analyzer_config_t lightweight_config = {
    .enable_reassembly = 0,       // 不需要重组时禁用
    .enable_rtt_tracking = 0,     // 不需要RTT时禁用
    .enable_statistics = 1        // 保留基本统计
};
```

## 故障排除

### 常见问题及解决方案

1. **权限问题**
   ```bash
   # 需要root权限访问原始套接字
   sudo ./your_program
   # 或设置CAP_NET_RAW权限
   sudo setcap cap_net_raw=eip ./your_program
   ```

2. **库路径问题**
   ```bash
   # 设置库路径
   export LD_LIBRARY_PATH=/path/to/librawsock/lib:$LD_LIBRARY_PATH
   ```

3. **内存不足**
   ```c
   // 减少最大连接数或缓冲区大小
   config.max_connections = 1000;        // 降低连接数
   config.max_reassembly_size = 16384;   // 减小缓冲区
   ```

4. **性能问题**
   ```c
   // 禁用不必要的特性
   config.enable_reassembly = 0;
   config.enable_rtt_tracking = 0;
   ```

### 调试技巧

1. **启用详细日志**
   ```c
   analyzer_set_log_level(ctx, ANALYZER_LOG_DEBUG);
   ```

2. **统计信息监控**
   ```c
   analyzer_stats_t stats;
   analyzer_get_stats(ctx, &stats);
   printf("处理包数: %lu, 活跃连接: %lu\n", 
          stats.packets_forward + stats.packets_reverse,
          ctx->active_connections);
   ```

3. **内存使用监控**
   ```c
   size_t memory_usage = analyzer_get_memory_usage(ctx);
   printf("内存使用: %zu bytes\n", memory_usage);
   ```

## 示例项目

完整的示例代码可以在以下位置找到：

- `examples/tcp_connection_analyzer.c` - 完整的TCP连接分析器
- `examples/simple_tcp_monitor.c` - 简单的TCP监控工具
- `demo_tcp_analysis.c` - 功能演示程序
- `stress_test_tcp.c` - 性能测试程序

## 编译和运行

### 编译示例

```bash
# 编译你的程序
gcc -Wall -Wextra -std=c99 -Iinclude -Llib \
    -o my_analyzer my_analyzer.c -lrawsock

# 运行程序
LD_LIBRARY_PATH=./lib ./my_analyzer
```

### Makefile集成

```makefile
CFLAGS = -Wall -Wextra -std=c99 -Iinclude
LDFLAGS = -Llib -lrawsock

my_analyzer: my_analyzer.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

.PHONY: run
run: my_analyzer
	LD_LIBRARY_PATH=./lib ./my_analyzer
```

这个使用指南应该能帮助你快速上手并充分利用LibRawSock的TCP协议分析功能。根据你的具体需求，可以选择适当的配置和特性来构建你的网络分析应用。
