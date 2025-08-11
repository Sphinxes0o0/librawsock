/**
 * @file analyzer.c
 * @brief Extensible Protocol Analyzer Framework Implementation
 * @author LibRawSock Team
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "librawsock/analyzer.h"
#include "librawsock/packet.h"

/* Internal helper functions */
static analyzer_connection_t* analyzer_find_connection(analyzer_context_t* ctx,
                                                      const analyzer_flow_id_t* flow_id);
static analyzer_connection_t* analyzer_create_connection(analyzer_context_t* ctx,
                                                        const analyzer_flow_id_t* flow_id);
static void analyzer_free_connection(analyzer_context_t* ctx, analyzer_connection_t* conn);
static rawsock_error_t analyzer_parse_packet(const uint8_t* packet_data, size_t packet_size,
                                             analyzer_packet_info_t* packet_info);
static int analyzer_is_expired(const analyzer_connection_t* conn, const struct timeval* now, uint32_t timeout_seconds);

/* ===== Core Analyzer API ===== */

analyzer_context_t* analyzer_create(void) {
    analyzer_config_t config = {
        .max_connections = ANALYZER_MAX_CONNECTIONS,
        .max_reassembly_size = ANALYZER_MAX_REASSEMBLY_SIZE,
        .connection_timeout = ANALYZER_CONNECTION_TIMEOUT,
        .enable_reassembly = 1,
        .enable_rtt_tracking = 1,
        .enable_statistics = 1
    };
    
    return analyzer_create_with_config(&config);
}

analyzer_context_t* analyzer_create_with_config(const analyzer_config_t* config) {
    if (!config) {
        return NULL;
    }
    
    analyzer_context_t* ctx = calloc(1, sizeof(analyzer_context_t));
    if (!ctx) {
        return NULL;
    }
    
    /* Copy configuration */
    ctx->config = *config;
    
    /* Initialize connection table */
    memset(ctx->connection_table, 0, sizeof(ctx->connection_table));
    memset(ctx->handlers, 0, sizeof(ctx->handlers));
    
    /* Initialize statistics */
    ctx->total_packets = 0;
    ctx->total_connections = 0;
    ctx->active_connections = 0;
    ctx->dropped_packets = 0;
    
    /* Initialize connection pool */
    ctx->free_connections = NULL;
    ctx->allocated_connections = 0;
    
    return ctx;
}

void analyzer_destroy(analyzer_context_t* ctx) {
    if (!ctx) {
        return;
    }
    
    /* Free all connections */
    for (size_t i = 0; i < 1024; i++) {
        analyzer_connection_t* conn = ctx->connection_table[i];
        while (conn) {
            analyzer_connection_t* next = conn->next;
            
            /* Call protocol cleanup if available */
            if (conn->handler && conn->handler->conn_cleanup) {
                conn->handler->conn_cleanup(ctx, conn);
            }
            
            /* Free reassembly buffers */
            for (int dir = 0; dir < 2; dir++) {
                if (conn->reassembly_buffer[dir]) {
                    free(conn->reassembly_buffer[dir]);
                }
            }
            
            if (conn->protocol_state) {
                free(conn->protocol_state);
            }
            
            free(conn);
            conn = next;
        }
    }
    
    /* Free connection pool */
    analyzer_connection_t* free_conn = ctx->free_connections;
    while (free_conn) {
        analyzer_connection_t* next = free_conn->next;
        free(free_conn);
        free_conn = next;
    }
    
    free(ctx);
}

rawsock_error_t analyzer_register_handler(analyzer_context_t* ctx, 
                                          analyzer_protocol_handler_t* handler) {
    if (!ctx || !handler || handler->protocol >= 256) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    ctx->handlers[handler->protocol] = handler;
    return RAWSOCK_SUCCESS;
}

analyzer_result_t analyzer_process_packet(analyzer_context_t* ctx,
                                          const uint8_t* packet_data,
                                          size_t packet_size,
                                          const struct timeval* timestamp) {
    if (!ctx || !packet_data || packet_size == 0) {
        return ANALYZER_RESULT_ERROR;
    }
    
    ctx->total_packets++;
    
    /* Parse packet */
    analyzer_packet_info_t packet_info;
    memset(&packet_info, 0, sizeof(packet_info));
    
    packet_info.packet_data = packet_data;
    packet_info.packet_size = packet_size;
    if (timestamp) {
        packet_info.timestamp = *timestamp;
    } else {
        gettimeofday(&packet_info.timestamp, NULL);
    }
    
    if (analyzer_parse_packet(packet_data, packet_size, &packet_info) != RAWSOCK_SUCCESS) {
        ctx->dropped_packets++;
        return ANALYZER_RESULT_DROP;
    }
    
    /* Find or create connection */
    analyzer_connection_t* conn = analyzer_find_connection(ctx, &packet_info.flow_id);
    analyzer_result_t result = ANALYZER_RESULT_OK;
    
    if (!conn) {
        /* Try reverse direction */
        analyzer_flow_id_t reverse_flow;
        analyzer_get_reverse_flow_id(&packet_info.flow_id, &reverse_flow);
        conn = analyzer_find_connection(ctx, &reverse_flow);
        
        if (conn) {
            packet_info.direction = ANALYZER_DIR_REVERSE;
        } else {
            /* Create new connection */
            conn = analyzer_create_connection(ctx, &packet_info.flow_id);
            if (!conn) {
                ctx->dropped_packets++;
                return ANALYZER_RESULT_ERROR;
            }
            
            packet_info.direction = ANALYZER_DIR_FORWARD;
            result = ANALYZER_RESULT_CONNECTION_NEW;
            ctx->total_connections++;
            ctx->active_connections++;
        }
    } else {
        packet_info.direction = ANALYZER_DIR_FORWARD;
    }
    
    /* Update connection activity */
    conn->last_activity = packet_info.timestamp;
    
    /* Update statistics */
    if (packet_info.direction == ANALYZER_DIR_FORWARD) {
        conn->stats.packets_forward++;
        conn->stats.bytes_forward += packet_size;
    } else {
        conn->stats.packets_reverse++;
        conn->stats.bytes_reverse += packet_size;
    }
    
    if (conn->stats.packets_forward + conn->stats.packets_reverse == 1) {
        conn->stats.first_seen = packet_info.timestamp;
    }
    conn->stats.last_seen = packet_info.timestamp;
    
    /* Process packet with protocol handler */
    if (conn->handler && conn->handler->packet_handler) {
        analyzer_result_t handler_result = conn->handler->packet_handler(ctx, conn, &packet_info);
        
        /* Merge results */
        if (handler_result == ANALYZER_RESULT_CONNECTION_CLOSE) {
            result = ANALYZER_RESULT_CONNECTION_CLOSE;
        } else if (handler_result == ANALYZER_RESULT_DATA_READY && result == ANALYZER_RESULT_OK) {
            result = ANALYZER_RESULT_DATA_READY;
        } else if (handler_result == ANALYZER_RESULT_ERROR) {
            result = ANALYZER_RESULT_ERROR;
        }
    }
    
    /* Handle connection close */
    if (result == ANALYZER_RESULT_CONNECTION_CLOSE) {
        ctx->active_connections--;
        if (ctx->connection_callback) {
            ctx->connection_callback(ctx, conn, result);
        }
        analyzer_free_connection(ctx, conn);
    } else if (ctx->connection_callback && result == ANALYZER_RESULT_CONNECTION_NEW) {
        ctx->connection_callback(ctx, conn, result);
    }
    
    return result;
}

void analyzer_set_connection_callback(analyzer_context_t* ctx,
                                     void (*callback)(analyzer_context_t* ctx, 
                                                     analyzer_connection_t* conn, 
                                                     analyzer_result_t result)) {
    if (ctx) {
        ctx->connection_callback = callback;
    }
}

void analyzer_set_data_callback(analyzer_context_t* ctx,
                               void (*callback)(analyzer_context_t* ctx, 
                                               analyzer_connection_t* conn,
                                               analyzer_direction_t dir,
                                               const uint8_t* data, size_t size)) {
    if (ctx) {
        ctx->data_callback = callback;
    }
}

analyzer_connection_t* analyzer_get_connection(analyzer_context_t* ctx,
                                              const analyzer_flow_id_t* flow_id) {
    if (!ctx || !flow_id) {
        return NULL;
    }
    
    return analyzer_find_connection(ctx, flow_id);
}

size_t analyzer_cleanup_expired(analyzer_context_t* ctx) {
    if (!ctx) {
        return 0;
    }
    
    struct timeval now;
    gettimeofday(&now, NULL);
    
    size_t cleaned = 0;
    
    for (size_t i = 0; i < 1024; i++) {
        analyzer_connection_t** conn_ptr = &ctx->connection_table[i];
        
        while (*conn_ptr) {
            analyzer_connection_t* conn = *conn_ptr;
            
            if (analyzer_is_expired(conn, &now, ctx->config.connection_timeout)) {
                /* Remove from hash table */
                *conn_ptr = conn->next;
                
                /* Call timeout handler if available */
                if (conn->handler && conn->handler->conn_timeout) {
                    conn->handler->conn_timeout(ctx, conn);
                }
                
                /* Free connection */
                if (conn->handler && conn->handler->conn_cleanup) {
                    conn->handler->conn_cleanup(ctx, conn);
                }
                
                for (int dir = 0; dir < 2; dir++) {
                    if (conn->reassembly_buffer[dir]) {
                        free(conn->reassembly_buffer[dir]);
                    }
                }
                
                if (conn->protocol_state) {
                    free(conn->protocol_state);
                }
                
                free(conn);
                cleaned++;
                ctx->active_connections--;
            } else {
                conn_ptr = &conn->next;
            }
        }
    }
    
    return cleaned;
}

void analyzer_get_stats(analyzer_context_t* ctx, analyzer_stats_t* stats) {
    if (!ctx || !stats) {
        return;
    }
    
    memset(stats, 0, sizeof(*stats));
    
    /* Aggregate statistics from all connections */
    for (size_t i = 0; i < 1024; i++) {
        analyzer_connection_t* conn = ctx->connection_table[i];
        while (conn) {
            stats->packets_forward += conn->stats.packets_forward;
            stats->packets_reverse += conn->stats.packets_reverse;
            stats->bytes_forward += conn->stats.bytes_forward;
            stats->bytes_reverse += conn->stats.bytes_reverse;
            
            if (conn->stats.rtt_samples > 0) {
                if (stats->rtt_samples == 0) {
                    stats->avg_rtt_us = conn->stats.avg_rtt_us;
                } else {
                    /* Weighted average */
                    uint64_t total_samples = stats->rtt_samples + conn->stats.rtt_samples;
                    stats->avg_rtt_us = (stats->avg_rtt_us * stats->rtt_samples + 
                                         conn->stats.avg_rtt_us * conn->stats.rtt_samples) / total_samples;
                }
                stats->rtt_samples += conn->stats.rtt_samples;
            }
            
            conn = conn->next;
        }
    }
}

/* ===== Utility Functions ===== */

void analyzer_create_flow_id(uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t protocol, analyzer_flow_id_t* flow_id) {
    if (!flow_id) {
        return;
    }
    
    flow_id->src_ip = src_ip;
    flow_id->dst_ip = dst_ip;
    flow_id->src_port = src_port;
    flow_id->dst_port = dst_port;
    flow_id->protocol = protocol;
}

void analyzer_get_reverse_flow_id(const analyzer_flow_id_t* flow_id,
                                 analyzer_flow_id_t* reverse_flow_id) {
    if (!flow_id || !reverse_flow_id) {
        return;
    }
    
    reverse_flow_id->src_ip = flow_id->dst_ip;
    reverse_flow_id->dst_ip = flow_id->src_ip;
    reverse_flow_id->src_port = flow_id->dst_port;
    reverse_flow_id->dst_port = flow_id->src_port;
    reverse_flow_id->protocol = flow_id->protocol;
}

uint32_t analyzer_flow_hash(const analyzer_flow_id_t* flow_id) {
    if (!flow_id) {
        return 0;
    }
    
    /* Simple hash function */
    uint32_t hash = flow_id->src_ip ^ flow_id->dst_ip;
    hash ^= (flow_id->src_port << 16) | flow_id->dst_port;
    hash ^= flow_id->protocol;
    
    return hash % 1024;
}

int analyzer_flow_compare(const analyzer_flow_id_t* flow1,
                         const analyzer_flow_id_t* flow2) {
    if (!flow1 || !flow2) {
        return 0;
    }
    
    return (flow1->src_ip == flow2->src_ip &&
            flow1->dst_ip == flow2->dst_ip &&
            flow1->src_port == flow2->src_port &&
            flow1->dst_port == flow2->dst_port &&
            flow1->protocol == flow2->protocol);
}

void analyzer_format_flow_id(const analyzer_flow_id_t* flow_id,
                             char* buffer, size_t buffer_size) {
    if (!flow_id || !buffer || buffer_size < 64) {
        return;
    }
    
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = flow_id->src_ip;
    dst_addr.s_addr = flow_id->dst_ip;
    
    snprintf(buffer, buffer_size, "%s:%d -> %s:%d (%d)",
             inet_ntoa(src_addr), flow_id->src_port,
             inet_ntoa(dst_addr), flow_id->dst_port,
             flow_id->protocol);
}

/* ===== Internal Helper Functions ===== */

static analyzer_connection_t* analyzer_find_connection(analyzer_context_t* ctx,
                                                      const analyzer_flow_id_t* flow_id) {
    uint32_t hash = analyzer_flow_hash(flow_id);
    analyzer_connection_t* conn = ctx->connection_table[hash];
    
    while (conn) {
        if (analyzer_flow_compare(&conn->flow_id, flow_id)) {
            return conn;
        }
        conn = conn->next;
    }
    
    return NULL;
}

static analyzer_connection_t* analyzer_create_connection(analyzer_context_t* ctx,
                                                        const analyzer_flow_id_t* flow_id) {
    analyzer_connection_t* conn = NULL;
    
    /* Try to reuse from free pool */
    if (ctx->free_connections) {
        conn = ctx->free_connections;
        ctx->free_connections = conn->next;
        memset(conn, 0, sizeof(*conn));
    } else {
        conn = calloc(1, sizeof(analyzer_connection_t));
        if (!conn) {
            return NULL;
        }
        ctx->allocated_connections++;
    }
    
    /* Initialize connection */
    conn->flow_id = *flow_id;
    conn->state = ANALYZER_STATE_INIT;
    gettimeofday(&conn->last_activity, NULL);
    
    /* Find protocol handler */
    conn->handler = ctx->handlers[flow_id->protocol];
    
    /* Initialize protocol state if handler available */
    if (conn->handler && conn->handler->conn_init) {
        analyzer_packet_info_t dummy_packet;
        memset(&dummy_packet, 0, sizeof(dummy_packet));
        dummy_packet.flow_id = *flow_id;
        
        if (conn->handler->conn_init(ctx, conn, &dummy_packet) != ANALYZER_RESULT_OK) {
            /* Roll back allocation count and free */
            if (ctx->allocated_connections > 0) {
                ctx->allocated_connections--;
            }
            free(conn);
            return NULL;
        }
    }
    
    /* Add to hash table */
    uint32_t hash = analyzer_flow_hash(flow_id);
    conn->next = ctx->connection_table[hash];
    ctx->connection_table[hash] = conn;
    
    return conn;
}

static void analyzer_free_connection(analyzer_context_t* ctx, analyzer_connection_t* conn) {
    if (!ctx || !conn) {
        return;
    }
    
    /* Remove from hash table */
    uint32_t hash = analyzer_flow_hash(&conn->flow_id);
    analyzer_connection_t** conn_ptr = &ctx->connection_table[hash];
    
    while (*conn_ptr) {
        if (*conn_ptr == conn) {
            *conn_ptr = conn->next;
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    
    /* Cleanup protocol state */
    if (conn->handler && conn->handler->conn_cleanup) {
        conn->handler->conn_cleanup(ctx, conn);
    }
    
    /* Free reassembly buffers */
    for (int dir = 0; dir < 2; dir++) {
        if (conn->reassembly_buffer[dir]) {
            free(conn->reassembly_buffer[dir]);
        }
    }
    
    if (conn->protocol_state) {
        free(conn->protocol_state);
    }
    
    /* Add to free pool */
    conn->next = ctx->free_connections;
    ctx->free_connections = conn;
}

static rawsock_error_t analyzer_parse_packet(const uint8_t* packet_data, size_t packet_size,
                                             analyzer_packet_info_t* packet_info) {
    if (!packet_data || packet_size < 20 || !packet_info) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Parse IP header */
    rawsock_ipv4_header_t ip_header;
    if (rawsock_parse_ipv4_header(packet_data, packet_size, &ip_header) != RAWSOCK_SUCCESS) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    packet_info->ip_header = packet_data;
    
    /* Calculate header sizes */
    size_t ip_header_len = (ip_header.version_ihl & 0x0F) * 4;
    if (packet_size < ip_header_len) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Set transport header and payload */
    packet_info->transport_header = packet_data + ip_header_len;
    size_t remaining_size = packet_size - ip_header_len;
    
    /* Create flow ID */
    uint16_t src_port = 0, dst_port = 0;
    
    if (ip_header.protocol == IPPROTO_TCP && remaining_size >= 20) {
        rawsock_tcp_header_t tcp_header;
        if (rawsock_parse_tcp_header(packet_info->transport_header, remaining_size, &tcp_header) == RAWSOCK_SUCCESS) {
            src_port = tcp_header.src_port;
            dst_port = tcp_header.dst_port;
            
            size_t tcp_header_len = ((tcp_header.data_offset_reserved >> 4) & 0x0F) * 4;
            if (remaining_size >= tcp_header_len) {
                packet_info->payload = (const uint8_t*)packet_info->transport_header + tcp_header_len;
                packet_info->payload_size = remaining_size - tcp_header_len;
            }
        }
    } else if (ip_header.protocol == IPPROTO_UDP && remaining_size >= 8) {
        rawsock_udp_header_t udp_header;
        if (rawsock_parse_udp_header(packet_info->transport_header, remaining_size, &udp_header) == RAWSOCK_SUCCESS) {
            src_port = udp_header.src_port;
            dst_port = udp_header.dst_port;

            /* UDP payload length should respect UDP header length when sane */
            size_t udp_len = udp_header.length;
            if (remaining_size >= 8) {
                packet_info->payload = (const uint8_t*)packet_info->transport_header + 8;
                if (udp_len >= 8 && udp_len <= remaining_size) {
                    packet_info->payload_size = udp_len - 8;
                } else {
                    packet_info->payload_size = remaining_size - 8;
                }
            }
        }
    } else {
        packet_info->payload = packet_info->transport_header;
        packet_info->payload_size = remaining_size;
    }
    
    analyzer_create_flow_id(ip_header.src_addr, ip_header.dst_addr,
                           src_port, dst_port, ip_header.protocol,
                           &packet_info->flow_id);
    
    return RAWSOCK_SUCCESS;
}

static int analyzer_is_expired(const analyzer_connection_t* conn, const struct timeval* now, uint32_t timeout_seconds) {
    if (!conn || !now) {
        return 0;
    }

    long long diff = (now->tv_sec - conn->last_activity.tv_sec) * 1000000LL +
                     (now->tv_usec - conn->last_activity.tv_usec);

    return (timeout_seconds > 0) ? (diff > (long long)timeout_seconds * 1000000LL) : 0;
}
