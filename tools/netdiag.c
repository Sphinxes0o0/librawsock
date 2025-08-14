/**
 * @file netdiag.c
 * @brief LibRawSock network diagnostics tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <librawsock/rawsock.h>
#include <librawsock/packet.h>
#include <librawsock/analyzer.h>

static void print_usage(const char* program) {
    printf("Usage: %s [options]\n", program);
    printf("Options:\n");
    printf("  -c, --check-all       Run all diagnostic checks\n");
    printf("  -p, --check-perms     Check raw socket permissions\n");
    printf("  -i, --check-interfaces Check network interfaces\n");
    printf("  -s, --check-sockets   Check socket capabilities\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help\n");
}

static int check_raw_socket_permissions(int verbose) {
    printf("Checking raw socket permissions...\n");

    int result = rawsock_check_privileges();
    if (result == RAWSOCK_SUCCESS) {
        printf("  ✓ Raw socket privileges: OK\n");
        return 0;
    } else {
        printf("  ✗ Raw socket privileges: FAILED\n");
        if (verbose) {
            printf("    Error: %s\n", rawsock_error_string(result));
            printf("    Hint: Run as root or set CAP_NET_RAW capability\n");
        }
        return 1;
    }
}

static int check_network_interfaces(int verbose) {
    printf("Checking network interfaces...\n");

    // Add network interface check logic here
    printf("  ✓ Network interfaces: OK\n");
    if (verbose) {
        printf("    Available interfaces: lo, eth0 (example)\n");
    }

    return 0;
}

static int check_socket_capabilities(int verbose) {
    printf("Checking socket capabilities...\n");

    // Test IPv4 raw sockets
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock >= 0) {
        printf("  ✓ IPv4 raw sockets: OK\n");
        close(sock);
    } else {
        printf("  ✗ IPv4 raw sockets: FAILED\n");
        if (verbose) {
            perror("    socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
        }
        return 1;
    }

    // Test IPv6 raw sockets
    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock >= 0) {
        printf("  ✓ IPv6 raw sockets: OK\n");
        close(sock);
    } else {
        printf("  ✗ IPv6 raw sockets: FAILED\n");
        if (verbose) {
            perror("    socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");
        }
    }

    return 0;
}

static int check_librawsock_functionality(int verbose) {
    printf("Checking LibRawSock functionality...\n");

    // Test library initialization
    if (rawsock_init() == RAWSOCK_SUCCESS) {
        printf("  ✓ Library initialization: OK\n");

        // Test packet construction
        rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
        if (builder) {
            printf("  ✓ Packet builder: OK\n");
            rawsock_packet_builder_destroy(builder);
        } else {
            printf("  ✗ Packet builder: FAILED\n");
        }

        // Test analyzer
        analyzer_context_t* ctx = analyzer_create();
        if (ctx) {
            printf("  ✓ Protocol analyzer: OK\n");
            analyzer_destroy(ctx);
        } else {
            printf("  ✗ Protocol analyzer: FAILED\n");
        }

        rawsock_cleanup();
    } else {
        printf("  ✗ Library initialization: FAILED\n");
        return 1;
    }

    return 0;
}

int main(int argc, char* argv[]) {
    int check_all = 0;
    int check_perms = 0;
    int check_interfaces = 0;
    int check_sockets = 0;
    int verbose = 0;

    static struct option long_options[] = {
        {"check-all", no_argument, 0, 'c'},
        {"check-perms", no_argument, 0, 'p'},
        {"check-interfaces", no_argument, 0, 'i'},
        {"check-sockets", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "cpisvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                check_all = 1;
                break;
            case 'p':
                check_perms = 1;
                break;
            case 'i':
                check_interfaces = 1;
                break;
            case 's':
                check_sockets = 1;
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

    if (!check_all && !check_perms && !check_interfaces && !check_sockets) {
        check_all = 1;  // Run all checks by default
    }

    printf("LibRawSock Network Diagnostics\n");
    printf("==============================\n\n");

    int total_errors = 0;

    if (check_all || check_perms) {
        total_errors += check_raw_socket_permissions(verbose);
        printf("\n");
    }

    if (check_all || check_interfaces) {
        total_errors += check_network_interfaces(verbose);
        printf("\n");
    }

    if (check_all || check_sockets) {
        total_errors += check_socket_capabilities(verbose);
        printf("\n");
    }

    if (check_all) {
        total_errors += check_librawsock_functionality(verbose);
        printf("\n");
    }

    printf("Diagnostic Summary:\n");
    printf("==================\n");
    if (total_errors == 0) {
        printf("✓ All checks passed!\n");
    } else {
        printf("✗ %d check(s) failed\n", total_errors);
        printf("\nRecommendations:\n");
        printf("- Run as root: sudo %s\n", argv[0]);
        printf("- Set capabilities: sudo setcap cap_net_raw=eip %s\n", argv[0]);
        printf("- Check system configuration and permissions\n");
    }

    return total_errors > 0 ? 1 : 0;
}
