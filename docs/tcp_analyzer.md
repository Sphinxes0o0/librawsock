# TCP Protocol Analyzer

LibRawSock 现在包含了一个强大的、可扩展的协议分析框架，专门针对 TCP 协议提供了深度分析功能。

## 功能特性

### 🔄 TCP 连接状态跟踪
- 完整的 TCP 状态机实现 (RFC 793)
- 实时连接状态监控
- 连接建立和关闭检测
- 异常连接处理 (RST, 超时等)

### 📊 性能分析
- RTT (往返时延) 测量和统计
- 重传检测和计数
- 窗口大小跟踪
- 拥塞控制分析

### 🔍 高级分析
- TCP 选项解析 (MSS, 窗口缩放, SACK, 时间戳等)
- 序列号分析和验证
- 乱序数据包检测
- 重复 ACK 检测

### 🧩 数据重组
- TCP 流重组
- 应用层数据提取
- 双向数据流跟踪

## 架构设计

### 可扩展框架
```c
// 核心分析器上下文
analyzer_context_t* ctx = analyzer_create();

// 注册协议处理器
analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
analyzer_register_handler(ctx, tcp_handler);

// 设置回调函数
analyzer_set_connection_callback(ctx, connection_callback);
analyzer_set_data_callback(ctx, data_callback);
```

### 协议处理器接口
每个协议分析器实现标准接口：
- `packet_handler`: 处理单个数据包
- `conn_init`: 初始化连接状态
- `conn_cleanup`: 清理连接资源
- `conn_timeout`: 处理连接超时

## API 使用示例

### 基本 TCP 连接监控

```c
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

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
            if (conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
                printf("  最终状态: %s\n", tcp_state_to_string(tcp_state->state));
                printf("  RTT: %u μs (%u 样本)\n", tcp_state->avg_rtt_us, tcp_state->rtt_samples);
            }
            break;
    }
}

int main() {
    // 创建分析器
    analyzer_context_t* ctx = analyzer_create();
    
    // 注册 TCP 处理器
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    analyzer_set_connection_callback(ctx, connection_callback);
    
    // 创建原始套接字
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_TCP);
    
    // 主循环
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
    
    // 清理
    rawsock_destroy(sock);
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    return 0;
}
```

### 数据流重组

```c
void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t dir, const uint8_t* data, size_t size) {
    char flow_str[64];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
    
    printf("数据就绪: %s [%s] %zu 字节\n", 
           flow_str, (dir == ANALYZER_DIR_FORWARD) ? "→" : "←", size);
    
    // 处理应用层数据
    if (conn->flow_id.dst_port == 80 || conn->flow_id.src_port == 80) {
        // HTTP 流量分析
        printf("HTTP 数据: %.*s\n", (int)size, data);
    }
    
    // 消费数据
    tcp_consume_reassembled_data(conn, dir, size);
}
```

## TCP 状态分析

### 支持的 TCP 状态
- `TCP_STATE_CLOSED`: 连接关闭
- `TCP_STATE_LISTEN`: 监听状态
- `TCP_STATE_SYN_SENT`: SYN 已发送
- `TCP_STATE_SYN_RECEIVED`: SYN 已接收
- `TCP_STATE_ESTABLISHED`: 连接已建立
- `TCP_STATE_FIN_WAIT_1`: FIN 等待 1
- `TCP_STATE_FIN_WAIT_2`: FIN 等待 2
- `TCP_STATE_CLOSE_WAIT`: 关闭等待
- `TCP_STATE_CLOSING`: 正在关闭
- `TCP_STATE_LAST_ACK`: 最后 ACK
- `TCP_STATE_TIME_WAIT`: 时间等待

### 连接质量指标

```c
typedef struct {
    uint32_t rtt_samples;              // RTT 样本数
    uint32_t min_rtt_us;               // 最小 RTT
    uint32_t max_rtt_us;               // 最大 RTT
    uint32_t avg_rtt_us;               // 平均 RTT
    
    size_t retransmit_count;           // 重传次数
    uint32_t out_of_order_packets[2];  // 乱序包 [前向, 反向]
    uint32_t duplicate_acks[2];        // 重复 ACK
    uint32_t zero_window_probes[2];    // 零窗口探测
} tcp_connection_state_t;
```

## TCP 选项解析

### 支持的选项类型
- `TCP_OPT_MSS`: 最大段大小
- `TCP_OPT_WINDOW_SCALE`: 窗口缩放
- `TCP_OPT_SACK_PERMITTED`: SACK 允许
- `TCP_OPT_SACK`: 选择性确认
- `TCP_OPT_TIMESTAMP`: 时间戳

### 选项解析示例

```c
tcp_options_t options;
if (tcp_parse_options(tcp_header, &options) == RAWSOCK_SUCCESS) {
    printf("MSS: %u\n", options.mss);
    printf("窗口缩放: %u\n", options.window_scale);
    printf("SACK 允许: %s\n", options.sack_permitted ? "是" : "否");
    
    if (options.timestamp_val > 0) {
        printf("时间戳: %u / %u\n", options.timestamp_val, options.timestamp_ecr);
    }
}
```

## 性能分析功能

### RTT 测量
- 基于 SYN/SYN-ACK 的初始 RTT 测量
- 基于时间戳选项的精确 RTT
- 指数加权移动平均
- 最小/最大/平均 RTT 统计

### 重传检测
- 序列号回滚检测
- 快速重传识别
- RTO 重传检测
- 重传统计和分析

### 拥塞控制分析
- 有效窗口大小跟踪
- 拥塞窗口估算
- 零窗口检测
- 窗口缩放处理

## 配置选项

```c
analyzer_config_t config = {
    .max_connections = 1024,           // 最大连接数
    .max_reassembly_size = 65536,      // 重组缓冲区大小
    .connection_timeout = 300,         // 连接超时 (秒)
    .enable_reassembly = 1,            // 启用数据重组
    .enable_rtt_tracking = 1,          // 启用 RTT 跟踪
    .enable_statistics = 1             // 启用统计信息
};
```

## 示例程序

### 1. 简单 TCP 监控器
```bash
sudo ./build/simple_tcp_monitor 100
```
- 监控最多 100 个 TCP 连接
- 显示连接建立和关闭
- 基本统计信息

### 2. 高级连接分析器
```bash
sudo ./build/tcp_connection_analyzer -v -s -t 60
```
- 详细输出模式
- 定期显示统计信息
- 60 秒连接超时

## 扩展性

### 添加新协议
框架支持轻松添加新的协议分析器：

1. 实现协议处理器接口
2. 定义协议特定的状态结构
3. 注册到分析器上下文

```c
// 自定义协议处理器
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

### 自定义分析逻辑
可以通过回调函数实现自定义分析：

```c
// 自定义连接分析
void custom_connection_callback(analyzer_context_t* ctx, 
                               analyzer_connection_t* conn, 
                               analyzer_result_t result) {
    // 实现自定义逻辑
    if (result == ANALYZER_RESULT_CONNECTION_NEW) {
        // 新连接处理
    }
}
```

## 最佳实践

### 内存管理
- 定期调用 `analyzer_cleanup_expired()` 清理过期连接
- 合理设置最大连接数和重组缓冲区大小
- 及时消费重组数据避免内存积累

### 性能优化
- 根据需要禁用不必要的功能 (如数据重组)
- 使用适当的连接超时值
- 在高流量环境中考虑采样

### 错误处理
- 检查所有 API 返回值
- 正确处理连接状态变化
- 实现适当的超时和清理机制

## 测试

运行 TCP 分析器测试：
```bash
make test
```

测试覆盖：
- 协议处理器创建和销毁
- 流 ID 工具函数
- TCP 状态机转换
- TCP 选项解析
- 数据包处理流程
- 连接超时和清理

## 未来扩展

### 计划功能
- IPv6 完整支持
- 更多协议分析器 (UDP, ICMP, HTTP, etc.)
- 数据包过滤和匹配
- 实时性能指标
- 导出和日志功能
- 机器学习异常检测

### 性能改进
- 零拷贝数据处理
- 多线程支持
- 硬件加速
- 内存池管理

这个 TCP 协议分析框架为网络分析、性能监控、安全检测等应用提供了强大的基础。通过可扩展的设计，可以轻松添加新的协议支持和自定义分析逻辑。
