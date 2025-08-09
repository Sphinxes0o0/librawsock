/**
 * @file benchmark.c
 * @brief LibRawSock benchmark suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <librawsock/rawsock.h>
#include <librawsock/packet.h>
#include <librawsock/analyzer.h>
#include <librawsock/tcp_analyzer.h>

typedef struct {
    const char* name;
    int (*benchmark_func)(int iterations);
} benchmark_t;

static int benchmark_packet_creation(int iterations) {
    printf("Benchmarking packet creation (%d iterations)...\n", iterations);
    
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
        if (builder) {
            rawsock_packet_add_ipv4_header(builder, "192.168.1.1", "192.168.1.2", IPPROTO_TCP, 64);
            rawsock_packet_add_tcp_header(builder, 1234, 80, 1000, 0, TCP_FLAG_SYN, 8192);
            rawsock_packet_finalize(builder);
            rawsock_packet_builder_destroy(builder);
        }
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Rate: %.0f packets/sec\n", iterations / elapsed);
    
    return 0;
}

static int benchmark_tcp_analysis(int iterations) {
    printf("Benchmarking TCP analysis (%d iterations)...\n", iterations);
    
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    
    clock_t start = clock();
    
    uint8_t packet[100] = {0};
    struct timeval timestamp = {0, 0};
    
    for (int i = 0; i < iterations; i++) {
        analyzer_process_packet(ctx, packet, sizeof(packet), &timestamp);
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Rate: %.0f packets/sec\n", iterations / elapsed);
    
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    
    return 0;
}

static int benchmark_memory_usage(int iterations) {
    printf("Benchmarking memory usage (%d connections)...\n", iterations);
    
    analyzer_context_t* ctx = analyzer_create();
    analyzer_protocol_handler_t* tcp_handler = tcp_analyzer_create();
    analyzer_register_handler(ctx, tcp_handler);
    
    clock_t start = clock();
    
    // 创建大量连接
    for (int i = 0; i < iterations; i++) {
        uint8_t packet[64] = {0};
        struct timeval timestamp = {0, 0};
        
        // 模拟不同的连接
        packet[12] = (i >> 24) & 0xFF;  // 源IP
        packet[13] = (i >> 16) & 0xFF;
        packet[14] = (i >> 8) & 0xFF;
        packet[15] = i & 0xFF;
        
        analyzer_process_packet(ctx, packet, sizeof(packet), &timestamp);
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("  Time: %.3f seconds\n", elapsed);
    printf("  Connections: %lu\n", ctx->total_connections);
    printf("  Rate: %.0f connections/sec\n", ctx->total_connections / elapsed);
    
    tcp_analyzer_destroy(tcp_handler);
    analyzer_destroy(ctx);
    
    return 0;
}

static benchmark_t benchmarks[] = {
    {"packet_creation", benchmark_packet_creation},
    {"tcp_analysis", benchmark_tcp_analysis},
    {"memory_usage", benchmark_memory_usage},
    {NULL, NULL}
};

static void print_usage(const char* program) {
    printf("Usage: %s [options] [benchmark]\n", program);
    printf("Options:\n");
    printf("  -i, --iterations NUM   Number of iterations (default: 10000)\n");
    printf("  -a, --all             Run all benchmarks\n");
    printf("  -l, --list            List available benchmarks\n");
    printf("  -h, --help            Show this help\n");
    printf("\nAvailable benchmarks:\n");
    for (int i = 0; benchmarks[i].name; i++) {
        printf("  %s\n", benchmarks[i].name);
    }
}

int main(int argc, char* argv[]) {
    int iterations = 10000;
    int run_all = 0;
    int list_only = 0;
    
    static struct option long_options[] = {
        {"iterations", required_argument, 0, 'i'},
        {"all", no_argument, 0, 'a'},
        {"list", no_argument, 0, 'l'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "i:alh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                iterations = atoi(optarg);
                break;
            case 'a':
                run_all = 1;
                break;
            case 'l':
                list_only = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (list_only) {
        printf("Available benchmarks:\n");
        for (int i = 0; benchmarks[i].name; i++) {
            printf("  %s\n", benchmarks[i].name);
        }
        return 0;
    }
    
    printf("LibRawSock Benchmark Suite\n");
    printf("==========================\n");
    printf("Iterations: %d\n\n", iterations);
    
    if (run_all) {
        for (int i = 0; benchmarks[i].name; i++) {
            benchmarks[i].benchmark_func(iterations);
            printf("\n");
        }
    } else if (optind < argc) {
        const char* benchmark_name = argv[optind];
        
        for (int i = 0; benchmarks[i].name; i++) {
            if (strcmp(benchmarks[i].name, benchmark_name) == 0) {
                benchmarks[i].benchmark_func(iterations);
                return 0;
            }
        }
        
        printf("Unknown benchmark: %s\n", benchmark_name);
        return 1;
    } else {
        printf("No benchmark specified. Use --all or specify a benchmark name.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
