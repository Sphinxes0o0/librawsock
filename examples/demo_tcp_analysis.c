/**
 * @file demo_tcp_analysis.c
 * @brief TCP协议分析器功能演示程序
 * 展示TCP连接状态跟踪、性能监控和数据分析功能
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <librawsock/rawsock.h>
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

/* 全局控制变量 */
static volatile int g_running = 1;
static int g_verbose = 0;
static int g_packets_processed = 0;
static int g_connections_seen = 0;

/* 信号处理函数 */
void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n正在停止TCP分析器...\n");
}

/* 连接事件回调函数 */
void connection_callback(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                        analyzer_result_t result) {
    (void)ctx;
    
    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
    
    switch (result) {
        case ANALYZER_RESULT_CONNECTION_NEW:
            g_connections_seen++;
            printf("🔵 新连接: %s\n", flow_str);
            if (g_verbose && conn->protocol_state) {
                tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
                printf("   状态: %s\n", tcp_state_to_string(tcp_state->state));
            }
            break;
            
        case ANALYZER_RESULT_CONNECTION_CLOSE:
            printf("🔴 连接关闭: %s\n", flow_str);
            if (g_verbose && conn->stats.packets_forward > 0) {
                printf("   转发包数: %lu, 反向包数: %lu\n", 
                       conn->stats.packets_forward,
                       conn->stats.packets_reverse);
                printf("   转发字节: %lu, 反向字节: %lu\n",
                       conn->stats.bytes_forward,
                       conn->stats.bytes_reverse);
                if (conn->stats.avg_rtt_us > 0) {
                    printf("   平均RTT: %.2f ms\n", conn->stats.avg_rtt_us / 1000.0);
                }
            }
            break;
            
        case ANALYZER_RESULT_DATA_READY:
            if (g_verbose) {
                printf("📊 数据准备就绪: %s\n", flow_str);
            }
            break;
            
        default:
            break;
    }
}

/* 数据流回调函数 */
void data_callback(analyzer_context_t* ctx, analyzer_connection_t* conn,
                  analyzer_direction_t direction, const uint8_t* data, size_t size) {
    (void)ctx;
    
    if (!g_verbose) return;
    
    char flow_str[128];
    analyzer_format_flow_id(&conn->flow_id, flow_str, sizeof(flow_str));
    
    printf("📦 数据: %s (%s) %zu 字节\n", 
           flow_str,
           (direction == ANALYZER_DIR_FORWARD) ? "→" : "←",
           size);
    
    /* 如果是HTTP数据，显示前几个字节 */
    if (size > 4 && (memcmp(data, "GET ", 4) == 0 || 
                     memcmp(data, "POST", 4) == 0 ||
                     memcmp(data, "HTTP", 4) == 0)) {
        printf("   HTTP数据: ");
        for (size_t i = 0; i < (size < 40 ? size : 40); i++) {
            if (data[i] >= 32 && data[i] < 127) {
                printf("%c", data[i]);
            } else if (data[i] == '\r') {
                printf("\\r");
            } else if (data[i] == '\n') {
                printf("\\n");
                break;
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

/* 统计信息显示 */
void print_statistics(analyzer_context_t* ctx) {
    printf("\n=== TCP 分析统计 ===\n");
    printf("处理数据包: %d\n", g_packets_processed);
    printf("检测到连接: %d\n", g_connections_seen);
    printf("活跃连接: %lu\n", ctx->active_connections);
    printf("总计连接: %lu\n", ctx->total_connections);
    printf("总计数据包: %lu\n", ctx->total_packets);
}

/* 创建测试TCP数据包 */
size_t create_test_packet(uint8_t* buffer, size_t buffer_size,
                         const char* src_ip, const char* dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack, uint8_t flags,
                         const char* payload) {
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(buffer_size);
    if (!builder) return 0;
    
    /* 添加IP头 */
    if (rawsock_packet_add_ipv4_header(builder, src_ip, dst_ip, IPPROTO_TCP, 64) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }
    
    /* 添加TCP头 */
    if (rawsock_packet_add_tcp_header(builder, src_port, dst_port, seq, ack, flags, 8192) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }
    
    /* 添加载荷 */
    if (payload && strlen(payload) > 0) {
        if (rawsock_packet_add_payload(builder, payload, strlen(payload)) != RAWSOCK_SUCCESS) {
            rawsock_packet_builder_destroy(builder);
            return 0;
        }
    }
    
    /* 完成构造 */
    if (rawsock_packet_finalize(builder) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }
    
    /* 获取数据 */
    const void* packet_data;
    size_t packet_size;
    if (rawsock_packet_get_data(builder, &packet_data, &packet_size) != RAWSOCK_SUCCESS) {
        rawsock_packet_builder_destroy(builder);
        return 0;
    }
    
    if (packet_size <= buffer_size) {
        memcpy(buffer, packet_data, packet_size);
    }
    
    rawsock_packet_builder_destroy(builder);
    return packet_size;
}

/* 运行演示模式 */
void run_demo_mode(analyzer_context_t* ctx) {
    printf("🚀 运行TCP分析演示模式...\n");
    printf("将模拟一个完整的HTTP会话过程\n\n");
    
    uint8_t packet[1500];
    struct timeval timestamp;
    
    /* 模拟HTTP会话：客户端 192.168.1.100:12345 -> 服务器 93.184.216.34:80 */
    
    printf("1️⃣ 三次握手过程\n");
    
    /* SYN */
    gettimeofday(&timestamp, NULL);
    size_t size = create_test_packet(packet, sizeof(packet),
                                   "192.168.1.100", "93.184.216.34",
                                   12345, 80, 1000, 0, TCP_FLAG_SYN, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(10000); /* 10ms RTT */
    
    /* SYN-ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000); /* 1ms */
    
    /* ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001, 2001, TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    
    sleep(1);
    printf("\n2️⃣ HTTP请求和响应\n");
    
    /* HTTP GET请求 */
    gettimeofday(&timestamp, NULL);
    const char* http_request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Demo/1.0\r\n\r\n";
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001, 2001, TCP_FLAG_ACK | TCP_FLAG_PSH, http_request);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(50000); /* 50ms 服务器处理时间 */
    
    /* HTTP响应 */
    gettimeofday(&timestamp, NULL);
    const char* http_response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1270\r\n\r\n<!DOCTYPE html><html>...";
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001, 1001 + strlen(http_request), 
                            TCP_FLAG_ACK | TCP_FLAG_PSH, http_response);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000); /* 1ms */
    
    /* ACK确认 */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001 + strlen(http_request), 
                            2001 + strlen(http_response), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    
    sleep(1);
    printf("\n3️⃣ 连接关闭过程\n");
    
    /* FIN from client */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1001 + strlen(http_request), 
                            2001 + strlen(http_response), TCP_FLAG_FIN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);
    
    /* ACK from server */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001 + strlen(http_response), 
                            1002 + strlen(http_request), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);
    
    /* FIN from server */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "93.184.216.34", "192.168.1.100",
                            80, 12345, 2001 + strlen(http_response), 
                            1002 + strlen(http_request), TCP_FLAG_FIN | TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    usleep(1000);
    
    /* Final ACK */
    gettimeofday(&timestamp, NULL);
    size = create_test_packet(packet, sizeof(packet),
                            "192.168.1.100", "93.184.216.34",
                            12345, 80, 1002 + strlen(http_request), 
                            2002 + strlen(http_response), TCP_FLAG_ACK, NULL);
    if (size > 0) {
        analyzer_process_packet(ctx, packet, size, &timestamp);
        g_packets_processed++;
    }
    
    printf("\n✅ HTTP会话演示完成\n");
}

/* 帮助信息 */
void print_usage(const char* program_name) {
    printf("用法: %s [选项]\n", program_name);
    printf("选项:\n");
    printf("  -v, --verbose    详细输出模式\n");
    printf("  -d, --demo       运行演示模式（模拟TCP会话）\n");
    printf("  -h, --help       显示此帮助信息\n");
    printf("\n");
    printf("示例:\n");
    printf("  %s -d -v        # 运行详细演示模式\n", program_name);
    printf("  sudo %s         # 监控实际网络流量（需要root权限）\n", program_name);
}

int main(int argc, char* argv[]) {
    int demo_mode = 0;
    
    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_verbose = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--demo") == 0) {
            demo_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("未知选项: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("=== LibRawSock TCP 协议分析器演示 ===\n");
    printf("版本: 1.0.0\n");
    printf("时间: %s", ctime(&(time_t){time(NULL)}));
    printf("模式: %s\n", demo_mode ? "演示模式" : "实时监控模式");
    printf("详细输出: %s\n\n", g_verbose ? "开启" : "关闭");
    
    /* 设置信号处理 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* 创建分析器 */
    analyzer_context_t* ctx = analyzer_create();
    if (!ctx) {
        fprintf(stderr, "错误: 无法创建分析器上下文\n");
        return 1;
    }
    
    /* 创建并注册TCP处理器 */
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    if (!tcp_handler) {
        fprintf(stderr, "错误: 无法创建TCP分析器\n");
        analyzer_destroy(ctx);
        return 1;
    }
    
    if (analyzer_register_handler(ctx, tcp_handler) != RAWSOCK_SUCCESS) {
        fprintf(stderr, "错误: 无法注册TCP处理器\n");
        tcp_analyzer_destroy(tcp_handler);
        analyzer_destroy(ctx);
        return 1;
    }
    
    /* 设置回调函数 */
    analyzer_set_connection_callback(ctx, connection_callback);
    analyzer_set_data_callback(ctx, data_callback);
    
    if (demo_mode) {
        /* 演示模式 */
        run_demo_mode(ctx);
    } else {
        /* 实时监控模式 */
        printf("🔍 开始监控TCP连接...\n");
        printf("按 Ctrl+C 停止监控\n\n");
        
        /* 检查权限 */
        if (getuid() != 0) {
            printf("⚠️  警告: 需要root权限才能监控实际网络流量\n");
            printf("💡 提示: 使用 'sudo %s' 或尝试演示模式 '%s -d'\n\n", argv[0], argv[0]);
        }
        
        /* 这里应该添加实际的网络包捕获代码 */
        /* 为演示目的，我们只是等待用户中断 */
        while (g_running) {
            sleep(1);
        }
    }
    
    /* 清理过期连接 */
    size_t cleaned = analyzer_cleanup_expired(ctx);
    if (cleaned > 0) {
        printf("清理了 %zu 个过期连接\n", cleaned);
    }
    
    /* 显示统计信息 */
    print_statistics(ctx);
    
    /* 清理资源 */
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    
    printf("\n👋 TCP分析器已停止\n");
    return 0;
}
