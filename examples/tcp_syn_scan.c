/**
 * @file tcp_syn_scan.c
 * @brief TCP SYN port scanner using librawsock
 * @author Sphinxes0o0
 * 
 * This example demonstrates how to create and send TCP SYN packets
 * for port scanning using the librawsock library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <librawsock/rawsock.h>
#include <librawsock/packet.h>

/* TCP flags */
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_RST 0x04

/**
 * @brief Print usage information
 */
void print_usage(const char* program_name) {
    printf("Usage: %s <target_ip> <start_port> <end_port>\n", program_name);
    printf("Example:\n");
    printf("  %s 192.168.1.1 1 1000\n", program_name);
    printf("\nNote: This program requires root privileges or CAP_NET_RAW capability.\n");
}

/**
 * @brief Generate random source port
 */
uint16_t get_random_src_port(void) {
    return 32768 + (rand() % (65535 - 32768));
}

/**
 * @brief Generate random sequence number
 */
uint32_t get_random_seq(void) {
    return rand();
}

/**
 * @brief Scan a single port
 */
int scan_port(rawsock_t* sock, rawsock_packet_builder_t* builder,
              const char* target_ip, uint16_t target_port) {

    /* Reset packet builder */
    rawsock_packet_builder_reset(builder);

    /* Generate random source port and sequence number */
    uint16_t src_port = get_random_src_port();
    uint32_t seq_num = get_random_seq();

    /* Add IP header */
    rawsock_error_t err = rawsock_packet_add_ipv4_header(builder, "0.0.0.0", 
                                                        target_ip, IPPROTO_TCP, 64);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to add IP header: %s\n", 
                rawsock_error_string(err));
        return -1;
    }

    /* Add TCP header with SYN flag */
    err = rawsock_packet_add_tcp_header(builder, src_port, target_port,
                                       seq_num, 0, TCP_FLAG_SYN, 8192);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to add TCP header: %s\n", 
                rawsock_error_string(err));
        return -1;
    }

    /* Finalize packet */
    err = rawsock_packet_finalize(builder);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to finalize packet: %s\n", 
                rawsock_error_string(err));
        return -1;
    }

    /* Get packet data */
    const void* packet_data;
    size_t packet_size;
    err = rawsock_packet_get_data(builder, &packet_data, &packet_size);
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to get packet data: %s\n", 
                rawsock_error_string(err));
        return -1;
    }

    /* Send packet */
    int sent = rawsock_send(sock, packet_data, packet_size, target_ip);
    if (sent < 0) {
        fprintf(stderr, "Error: Failed to send packet to port %d: %s\n", 
                target_port, rawsock_error_string(-sent));
        return -1;
    }

    printf("SYN packet sent to %s:%d (src_port: %d, seq: %u)\n",
           target_ip, target_port, src_port, seq_num);

    return 0;
}

/**
 * @brief Main function
 */
int main(int argc, char* argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char* target_ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    /* Validate port range */
    if (start_port < 1 || start_port > 65535 ||
        end_port < 1 || end_port > 65535 ||
        start_port > end_port) {
        fprintf(stderr, "Error: Invalid port range\n");
        return 1;
    }

    /* Check privileges */
    if (!rawsock_check_privileges()) {
        fprintf(stderr, "Error: This program requires root privileges or CAP_NET_RAW capability\n");
        return 1;
    }

    /* Initialize random seed */
    srand(time(NULL));

    /* Initialize library */
    rawsock_error_t err = rawsock_init();
    if (err != RAWSOCK_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize librawsock: %s\n", 
                rawsock_error_string(err));
        return 1;
    }

    /* Create raw socket for TCP */
    rawsock_t* sock = rawsock_create(RAWSOCK_IPV4, IPPROTO_TCP);
    if (!sock) {
        fprintf(stderr, "Error: Failed to create raw socket\n");
        return 1;
    }

    /* Create packet builder */
    rawsock_packet_builder_t* builder = rawsock_packet_builder_create(1500);
    if (!builder) {
        fprintf(stderr, "Error: Failed to create packet builder\n");
        rawsock_destroy(sock);
        return 1;
    }

    printf("Starting TCP SYN scan of %s\n", target_ip);
    printf("Scanning ports %d-%d...\n\n", start_port, end_port);

    int total_ports = end_port - start_port + 1;
    int scanned = 0;

    /* Scan each port */
    for (int port = start_port; port <= end_port; port++) {
        if (scan_port(sock, builder, target_ip, port) == 0) {
            scanned++;
        }

        /* Small delay between packets to avoid overwhelming the target */
        usleep(10000);  /* 10ms delay */

        /* Progress indicator */
        if ((port - start_port + 1) % 100 == 0 || port == end_port) {
            printf("\nProgress: %d/%d ports scanned (%.1f%%)\n",
                   port - start_port + 1, total_ports,
                   100.0 * (port - start_port + 1) / total_ports);
        }
    }

    printf("\nScan completed. %d SYN packets sent.\n", scanned);
    printf("\nNote: This scanner only sends SYN packets. To detect open ports,\n");
    printf("you would need to listen for SYN-ACK responses using a separate\n");
    printf("receiving socket or packet capture mechanism.\n");

    /* Cleanup */
    rawsock_packet_builder_destroy(builder);
    rawsock_destroy(sock);
    rawsock_cleanup();

    return 0;
}

