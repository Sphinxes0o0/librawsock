/**
 * @file rawsock_c.cpp
 * @brief C interface implementation for rawsock library
 * @author Sphinxes0o0
 * @version 2.0.0
 *
 * Copyright (c) 2024 Sphinxes0o0
 * Distributed under the MIT License.
 */

#include "rawsock/rawsock.hpp"
#include "rawsock/rawsock_c.h"

#include <cstring>
#include <new>

// Internal wrapper to hold the C++ capture object
struct rawsock_capture {
    rawsock::capture cpp_capture;
};

// Helper function to convert C++ error code to C error code
static rawsock_error_t convert_error(rawsock::error_code ec) {
    switch (ec) {
        case rawsock::error_code::success:
            return RAWSOCK_SUCCESS;
        case rawsock::error_code::invalid_argument:
            return RAWSOCK_ERROR_INVALID_ARGUMENT;
        case rawsock::error_code::socket_create_failed:
            return RAWSOCK_ERROR_SOCKET_CREATE;
        case rawsock::error_code::socket_bind_failed:
            return RAWSOCK_ERROR_SOCKET_BIND;
        case rawsock::error_code::send_failed:
            return RAWSOCK_ERROR_SEND;
        case rawsock::error_code::recv_failed:
            return RAWSOCK_ERROR_RECV;
        case rawsock::error_code::permission_denied:
            return RAWSOCK_ERROR_PERMISSION;
        case rawsock::error_code::timeout:
            return RAWSOCK_ERROR_TIMEOUT;
        case rawsock::error_code::buffer_too_small:
            return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
        case rawsock::error_code::interface_not_found:
            return RAWSOCK_ERROR_INTERFACE_NOT_FOUND;
        case rawsock::error_code::not_supported:
            return RAWSOCK_ERROR_NOT_SUPPORTED;
        default:
            return RAWSOCK_ERROR_UNKNOWN;
    }
}

// Helper function to convert C config to C++ config
static rawsock::capture_config convert_config(const rawsock_config_t* config) {
    rawsock::capture_config cpp_config;
    
    if (config) {
        cpp_config.interface_name = config->interface_name;
        cpp_config.filter_protocol = static_cast<rawsock::protocol>(config->filter_protocol);
        cpp_config.recv_timeout_ms = config->recv_timeout_ms;
        cpp_config.send_timeout_ms = config->send_timeout_ms;
        cpp_config.promiscuous = config->promiscuous != 0;
        cpp_config.buffer_size = config->buffer_size;
    }
    
    return cpp_config;
}

// Helper function to convert C++ packet_info to C packet_info
static void convert_packet_info(const rawsock::packet_info& cpp_info, 
                                rawsock_packet_info_t* c_info) {
    if (!c_info) return;
    
    std::memset(c_info, 0, sizeof(*c_info));
    std::strncpy(c_info->src_addr, cpp_info.src_addr.c_str(), RAWSOCK_MAX_ADDR_STR - 1);
    std::strncpy(c_info->dst_addr, cpp_info.dst_addr.c_str(), RAWSOCK_MAX_ADDR_STR - 1);
    c_info->src_port = cpp_info.src_port;
    c_info->dst_port = cpp_info.dst_port;
    c_info->protocol = static_cast<uint8_t>(cpp_info.proto);
    c_info->packet_size = cpp_info.packet_size;
    c_info->timestamp_us = cpp_info.timestamp_us;
    std::strncpy(c_info->interface_name, cpp_info.interface_name.c_str(), 
                 RAWSOCK_MAX_INTERFACE_NAME - 1);
}

extern "C" {

const char* rawsock_version(void) {
    return rawsock::version();
}

int rawsock_version_number(void) {
    return rawsock::version_number();
}

int rawsock_check_privileges(void) {
    return rawsock::capture::check_privileges() ? 1 : 0;
}

const char* rawsock_error_string(rawsock_error_t error) {
    switch (error) {
        case RAWSOCK_SUCCESS:
            return "Success";
        case RAWSOCK_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case RAWSOCK_ERROR_SOCKET_CREATE:
            return "Socket creation failed";
        case RAWSOCK_ERROR_SOCKET_BIND:
            return "Socket bind failed";
        case RAWSOCK_ERROR_SEND:
            return "Send operation failed";
        case RAWSOCK_ERROR_RECV:
            return "Receive operation failed";
        case RAWSOCK_ERROR_PERMISSION:
            return "Permission denied (root privileges required)";
        case RAWSOCK_ERROR_TIMEOUT:
            return "Operation timed out";
        case RAWSOCK_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case RAWSOCK_ERROR_INTERFACE_NOT_FOUND:
            return "Network interface not found";
        case RAWSOCK_ERROR_NOT_SUPPORTED:
            return "Operation not supported on this platform";
        case RAWSOCK_ERROR_UNKNOWN:
        default:
            return "Unknown error";
    }
}

void rawsock_config_init(rawsock_config_t* config) {
    if (!config) return;
    
    std::memset(config, 0, sizeof(*config));
    config->filter_protocol = RAWSOCK_PROTO_ALL;
    config->recv_timeout_ms = 5000;
    config->send_timeout_ms = 5000;
    config->promiscuous = 0;
    config->buffer_size = RAWSOCK_MAX_PACKET_SIZE;
}

rawsock_capture_t* rawsock_capture_create(void) {
    try {
        return new rawsock_capture();
    } catch (...) {
        return nullptr;
    }
}

void rawsock_capture_destroy(rawsock_capture_t* capture) {
    delete capture;
}

rawsock_error_t rawsock_capture_open_default(rawsock_capture_t* capture) {
    if (!capture) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    return convert_error(capture->cpp_capture.open());
}

rawsock_error_t rawsock_capture_open(rawsock_capture_t* capture, 
                                      const rawsock_config_t* config) {
    if (!capture) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::capture_config cpp_config = convert_config(config);
    return convert_error(capture->cpp_capture.open(cpp_config));
}

void rawsock_capture_close(rawsock_capture_t* capture) {
    if (capture) {
        capture->cpp_capture.close();
    }
}

int rawsock_capture_is_open(const rawsock_capture_t* capture) {
    if (!capture) {
        return 0;
    }
    return capture->cpp_capture.is_open() ? 1 : 0;
}

int rawsock_capture_next(rawsock_capture_t* capture,
                          void* buffer, size_t buffer_size,
                          rawsock_packet_info_t* info) {
    if (!capture) {
        return -RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::packet_info cpp_info;
    int result = capture->cpp_capture.capture_next(buffer, buffer_size, 
                                                    info ? &cpp_info : nullptr);
    
    if (result > 0 && info) {
        convert_packet_info(cpp_info, info);
    }
    
    return result;
}

int rawsock_capture_next_timeout(rawsock_capture_t* capture,
                                  void* buffer, size_t buffer_size,
                                  int timeout_ms,
                                  rawsock_packet_info_t* info) {
    if (!capture) {
        return -RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::packet_info cpp_info;
    int result = capture->cpp_capture.capture_next_timeout(buffer, buffer_size, timeout_ms,
                                                            info ? &cpp_info : nullptr);
    
    if (result > 0 && info) {
        convert_packet_info(cpp_info, info);
    }
    
    return result;
}

// Callback wrapper structure for C callbacks
struct callback_wrapper {
    rawsock_packet_handler_t handler;
    void* user_data;
};

rawsock_error_t rawsock_capture_start(rawsock_capture_t* capture,
                                       rawsock_packet_handler_t handler,
                                       void* user_data,
                                       size_t count) {
    if (!capture || !handler) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    // Create C++ lambda that calls the C callback
    auto cpp_handler = [handler, user_data](const std::uint8_t* data, 
                                             std::size_t size, 
                                             const rawsock::packet_info& cpp_info) {
        rawsock_packet_info_t c_info;
        convert_packet_info(cpp_info, &c_info);
        handler(data, size, &c_info, user_data);
    };
    
    return convert_error(capture->cpp_capture.start_capture(cpp_handler, count));
}

void rawsock_capture_stop(rawsock_capture_t* capture) {
    if (capture) {
        capture->cpp_capture.stop_capture();
    }
}

int rawsock_capture_send(rawsock_capture_t* capture,
                          const void* data, size_t size) {
    if (!capture) {
        return -RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    return capture->cpp_capture.send_packet(data, size);
}

rawsock_error_t rawsock_capture_last_error(const rawsock_capture_t* capture) {
    if (!capture) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    return convert_error(capture->cpp_capture.last_error());
}

rawsock_error_t rawsock_capture_get_statistics(const rawsock_capture_t* capture,
                                                uint64_t* packets_received,
                                                uint64_t* packets_dropped) {
    if (!capture || !packets_received || !packets_dropped) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    return convert_error(capture->cpp_capture.get_statistics(*packets_received, 
                                                              *packets_dropped));
}

rawsock_error_t rawsock_parse_ethernet(const void* data, size_t size,
                                        rawsock_ethernet_header_t* header) {
    if (!data || !header) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::ethernet_header cpp_header;
    rawsock::error_code ec = rawsock::parse_ethernet_header(data, size, cpp_header);
    
    if (ec == rawsock::error_code::success) {
        std::memcpy(header->dest_mac, cpp_header.dest_mac.data(), 6);
        std::memcpy(header->src_mac, cpp_header.src_mac.data(), 6);
        header->ether_type = cpp_header.ether_type;
    }
    
    return convert_error(ec);
}

rawsock_error_t rawsock_parse_ipv4(const void* data, size_t size,
                                    rawsock_ipv4_header_t* header) {
    if (!data || !header) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::ipv4_header cpp_header;
    rawsock::error_code ec = rawsock::parse_ipv4_header(data, size, cpp_header);
    
    if (ec == rawsock::error_code::success) {
        header->version_ihl = cpp_header.version_ihl;
        header->tos = cpp_header.tos;
        header->total_length = cpp_header.total_length;
        header->id = cpp_header.id;
        header->flags_fragment = cpp_header.flags_fragment;
        header->ttl = cpp_header.ttl;
        header->protocol = cpp_header.protocol;
        header->checksum = cpp_header.checksum;
        header->src_addr = cpp_header.src_addr;
        header->dst_addr = cpp_header.dst_addr;
    }
    
    return convert_error(ec);
}

rawsock_error_t rawsock_parse_tcp(const void* data, size_t size,
                                   rawsock_tcp_header_t* header) {
    if (!data || !header) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::tcp_header cpp_header;
    rawsock::error_code ec = rawsock::parse_tcp_header(data, size, cpp_header);
    
    if (ec == rawsock::error_code::success) {
        header->src_port = cpp_header.src_port;
        header->dst_port = cpp_header.dst_port;
        header->seq_num = cpp_header.seq_num;
        header->ack_num = cpp_header.ack_num;
        header->data_offset_reserved = cpp_header.data_offset_reserved;
        header->flags = cpp_header.flags;
        header->window = cpp_header.window;
        header->checksum = cpp_header.checksum;
        header->urgent_ptr = cpp_header.urgent_ptr;
    }
    
    return convert_error(ec);
}

rawsock_error_t rawsock_parse_udp(const void* data, size_t size,
                                   rawsock_udp_header_t* header) {
    if (!data || !header) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::udp_header cpp_header;
    rawsock::error_code ec = rawsock::parse_udp_header(data, size, cpp_header);
    
    if (ec == rawsock::error_code::success) {
        header->src_port = cpp_header.src_port;
        header->dst_port = cpp_header.dst_port;
        header->length = cpp_header.length;
        header->checksum = cpp_header.checksum;
    }
    
    return convert_error(ec);
}

rawsock_error_t rawsock_parse_icmp(const void* data, size_t size,
                                    rawsock_icmp_header_t* header) {
    if (!data || !header) {
        return RAWSOCK_ERROR_INVALID_ARGUMENT;
    }
    
    rawsock::icmp_header cpp_header;
    rawsock::error_code ec = rawsock::parse_icmp_header(data, size, cpp_header);
    
    if (ec == rawsock::error_code::success) {
        header->type = cpp_header.type;
        header->code = cpp_header.code;
        header->checksum = cpp_header.checksum;
        header->data.echo.id = cpp_header.data.echo.id;
        header->data.echo.sequence = cpp_header.data.echo.sequence;
    }
    
    return convert_error(ec);
}

uint16_t rawsock_calculate_checksum(const void* data, size_t length) {
    return rawsock::calculate_ip_checksum(data, length);
}

int rawsock_get_interface_index(const char* name) {
    if (!name) {
        return -1;
    }
    return rawsock::capture::get_interface_index(name);
}

} // extern "C"
