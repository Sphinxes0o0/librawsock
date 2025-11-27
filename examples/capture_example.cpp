/**
 * @file capture_example.cpp
 * @brief C++ example for packet capture using rawsock library
 * 
 * This example demonstrates how to use the rawsock library to capture
 * network packets using the C++ interface.
 * 
 * Usage:
 *   sudo ./capture_example [interface] [protocol]
 * 
 * Example:
 *   sudo ./capture_example eth0 tcp
 */

#include <rawsock/rawsock.hpp>
#include <iostream>
#include <vector>
#include <csignal>
#include <cstring>

static volatile bool running = true;

void signal_handler(int) {
    running = false;
}

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [interface] [protocol]\n"
              << "  interface: Network interface (default: any)\n"
              << "  protocol: tcp, udp, icmp, or all (default: all)\n"
              << "\nNote: Requires root privileges\n"
              << "Example: sudo " << prog << " eth0 tcp\n";
}

rawsock::protocol parse_protocol(const char* str) {
    if (strcasecmp(str, "tcp") == 0) return rawsock::protocol::tcp;
    if (strcasecmp(str, "udp") == 0) return rawsock::protocol::udp;
    if (strcasecmp(str, "icmp") == 0) return rawsock::protocol::icmp;
    return rawsock::protocol::all;
}

const char* protocol_name(rawsock::protocol proto) {
    switch (proto) {
        case rawsock::protocol::tcp: return "TCP";
        case rawsock::protocol::udp: return "UDP";
        case rawsock::protocol::icmp: return "ICMP";
        default: return "Unknown";
    }
}

int main(int argc, char* argv[]) {
    // Parse arguments
    std::string interface_name;
    rawsock::protocol filter_proto = rawsock::protocol::all;
    
    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        interface_name = argv[1];
    }
    
    if (argc >= 3) {
        filter_proto = parse_protocol(argv[2]);
    }
    
    // Check privileges
    if (!rawsock::capture::check_privileges()) {
        std::cerr << "Error: Root privileges required\n";
        std::cerr << "Please run with: sudo " << argv[0] << "\n";
        return 1;
    }
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    
    // Create capture configuration
    rawsock::capture_config config;
    config.interface_name = interface_name;
    config.filter_protocol = filter_proto;
    config.recv_timeout_ms = 1000;
    config.promiscuous = true;
    
    // Create and open capture
    rawsock::capture cap;
    auto ec = cap.open(config);
    
    if (ec != rawsock::error_code::success) {
        std::cerr << "Error opening capture: " 
                  << rawsock::error_category().message(static_cast<int>(ec)) << "\n";
        return 1;
    }
    
    std::cout << "Starting packet capture...\n"
              << "Interface: " << (interface_name.empty() ? "any" : interface_name) << "\n"
              << "Protocol: " << (filter_proto == rawsock::protocol::all ? "all" : protocol_name(filter_proto)) << "\n"
              << "Press Ctrl+C to stop\n\n";
    
    // Capture buffer
    std::vector<uint8_t> buffer(rawsock::constants::max_packet_size);
    rawsock::packet_info info;
    int packet_count = 0;
    
    // Capture loop
    while (running) {
        int bytes = cap.capture_next(buffer.data(), buffer.size(), &info);
        
        if (bytes > 0) {
            ++packet_count;
            std::cout << "Packet #" << packet_count << ": "
                      << info.src_addr << ":" << info.src_port << " -> "
                      << info.dst_addr << ":" << info.dst_port << " "
                      << "(" << protocol_name(info.proto) << ", " 
                      << info.packet_size << " bytes)\n";
        } else if (bytes == -static_cast<int>(rawsock::error_code::timeout)) {
            // Timeout - continue
            continue;
        } else {
            auto error = cap.last_error();
            if (error != rawsock::error_code::timeout) {
                std::cerr << "Error: " 
                          << rawsock::error_category().message(static_cast<int>(error)) << "\n";
            }
        }
    }
    
    // Print statistics
    std::cout << "\n--- Capture Statistics ---\n";
    std::cout << "Packets captured: " << packet_count << "\n";
    
    uint64_t received, dropped;
    if (cap.get_statistics(received, dropped) == rawsock::error_code::success) {
        std::cout << "Packets received (kernel): " << received << "\n";
        std::cout << "Packets dropped (kernel): " << dropped << "\n";
    }
    
    cap.close();
    return 0;
}
