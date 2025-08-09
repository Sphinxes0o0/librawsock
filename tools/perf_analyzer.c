/**
 * @file perf_analyzer.c
 * @brief LibRawSock performance analysis tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

static void print_usage(const char* program) {
    printf("Usage: %s [options]\n", program);
    printf("Options:\n");
    printf("  -c, --connections NUM  Number of connections to simulate (default: 1000)\n");
    printf("  -p, --packets NUM      Number of packets per connection (default: 100)\n");
    printf("  -t, --threads NUM      Number of threads to use (default: 1)\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
}

int main(int argc, char* argv[]) {
    int connections = 1000;
    int packets = 100;
    int threads = 1;
    int verbose = 0;
    
    static struct option long_options[] = {
        {"connections", required_argument, 0, 'c'},
        {"packets", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:p:t:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                connections = atoi(optarg);
                break;
            case 'p':
                packets = atoi(optarg);
                break;
            case 't':
                threads = atoi(optarg);
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("LibRawSock Performance Analyzer\n");
    printf("===============================\n");
    printf("Connections: %d\n", connections);
    printf("Packets per connection: %d\n", packets);
    printf("Threads: %d\n", threads);
    printf("Total packets: %d\n", connections * packets);
    printf("\n");
    
    // 创建分析器
    analyzer_context_t* ctx = analyzer_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create analyzer context\n");
        return 1;
    }
    
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    if (!tcp_handler) {
        fprintf(stderr, "Failed to create TCP handler\n");
        analyzer_destroy(ctx);
        return 1;
    }
    
    analyzer_register_handler(ctx, tcp_handler);
    
    // 运行性能测试
    clock_t start = clock();
    
    // 这里实现具体的性能测试逻辑
    printf("Running performance analysis...\n");
    
    // 模拟数据包处理
    for (int i = 0; i < connections * packets; i++) {
        // 模拟数据包处理
        uint8_t dummy_packet[64] = {0};
        struct timeval timestamp = {0, 0};
        analyzer_process_packet(ctx, dummy_packet, sizeof(dummy_packet), &timestamp);
        
        if (verbose && (i + 1) % 10000 == 0) {
            printf("Processed %d packets\n", i + 1);
        }
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("\nPerformance Results:\n");
    printf("===================\n");
    printf("Total time: %.3f seconds\n", elapsed);
    printf("Packets per second: %.0f\n", (connections * packets) / elapsed);
    printf("Connections: %lu total, %lu active\n", 
           ctx->total_connections, ctx->active_connections);
    
    // 清理
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    
    return 0;
}
