/**
 * @file tcp_analyzer.c
 * @brief TCP Protocol Analyzer Implementation
 * @author LibRawSock Team
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "librawsock/tcp_analyzer.h"
#include "librawsock/analyzer.h"
#include "librawsock/packet.h"

/* Internal helper functions */
static tcp_state_t tcp_state_transition(tcp_state_t current_state, uint8_t flags, 
                                        analyzer_direction_t direction);
static int tcp_is_retransmission(tcp_connection_state_t* tcp_state, 
                                 const rawsock_tcp_header_t* tcp_header,
                                 analyzer_direction_t direction);
static void tcp_update_rtt_stats(tcp_connection_state_t* tcp_state, uint32_t rtt_us);
static rawsock_error_t tcp_process_reassembly(analyzer_connection_t* conn,
                                             analyzer_direction_t direction,
                                             uint32_t seq_num, const uint8_t* data, 
                                             size_t data_size);

/* ===== TCP Analyzer API ===== */

analyzer_protocol_handler_t* tcp_analyzer_create(void) {
    analyzer_protocol_handler_t* handler = malloc(sizeof(analyzer_protocol_handler_t));
    if (!handler) {
        return NULL;
    }
    
    handler->protocol = ANALYZER_PROTO_TCP;
    handler->packet_handler = tcp_analyzer_process_packet;
    handler->conn_init = tcp_analyzer_init_connection;
    handler->conn_cleanup = tcp_analyzer_cleanup_connection;
    handler->conn_timeout = tcp_analyzer_handle_timeout;
    handler->protocol_data = NULL;
    
    return handler;
}

void tcp_analyzer_destroy(analyzer_protocol_handler_t* handler) {
    if (handler) {
        free(handler);
    }
}

analyzer_result_t tcp_analyzer_process_packet(analyzer_context_t* ctx,
                                              analyzer_connection_t* conn,
                                              const analyzer_packet_info_t* packet) {
    if (!ctx || !conn || !packet || !packet->transport_header) {
        return ANALYZER_RESULT_ERROR;
    }
    
    tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
    if (!tcp_state) {
        return ANALYZER_RESULT_ERROR;
    }
    
    /* Parse TCP header */
    rawsock_tcp_header_t tcp_header;
    if (rawsock_parse_tcp_header(packet->transport_header, 
                                packet->packet_size - ((const uint8_t*)packet->transport_header - packet->packet_data),
                                &tcp_header) != RAWSOCK_SUCCESS) {
        return ANALYZER_RESULT_ERROR;
    }
    
    /* Analyze packet */
    tcp_analysis_result_t analysis_result;
    memset(&analysis_result, 0, sizeof(analysis_result));
    
    if (tcp_analyze_packet(tcp_state, &tcp_header, packet->payload_size,
                          packet->direction, &packet->timestamp, &analysis_result) != RAWSOCK_SUCCESS) {
        return ANALYZER_RESULT_ERROR;
    }
    
    /* Update connection state */
    tcp_state->state = analysis_result.new_state;
    
    /* Handle state changes */
    analyzer_result_t result = ANALYZER_RESULT_OK;
    
    if (analysis_result.handshake_complete && !tcp_state->handshake_complete) {
        tcp_state->handshake_complete = 1;
        tcp_state->established_time = packet->timestamp;
        conn->state = ANALYZER_STATE_ESTABLISHED;
    }
    
    if (analysis_result.connection_closing) {
        conn->state = ANALYZER_STATE_CLOSING;
    }
    
    if (tcp_state->state == TCP_STATE_CLOSED || tcp_state->rst_seen) {
        conn->state = ANALYZER_STATE_CLOSED;
        result = ANALYZER_RESULT_CONNECTION_CLOSE;
    }
    
    /* Handle data reassembly */
    if (packet->payload_size > 0 && ctx->config.enable_reassembly) {
        if (tcp_process_reassembly(conn, packet->direction, tcp_header.seq_num,
                                  packet->payload, packet->payload_size) == RAWSOCK_SUCCESS) {
            
            /* Check if data is ready */
            const uint8_t* data;
            size_t data_size;
            if (tcp_get_reassembled_data(conn, packet->direction, &data, &data_size)) {
                if (ctx->data_callback) {
                    ctx->data_callback(ctx, conn, packet->direction, data, data_size);
                }
                result = ANALYZER_RESULT_DATA_READY;
            }
        }
    }
    
    /* Update RTT if available */
    if (analysis_result.rtt_sample_us > 0) {
        tcp_update_rtt_stats(tcp_state, analysis_result.rtt_sample_us);
        
        /* Update connection-level RTT */
        conn->stats.rtt_samples++;
        if (conn->stats.rtt_samples == 1) {
            conn->stats.avg_rtt_us = analysis_result.rtt_sample_us;
        } else {
            /* Exponential weighted moving average */
            conn->stats.avg_rtt_us = (conn->stats.avg_rtt_us * 7 + analysis_result.rtt_sample_us) / 8;
        }
    }
    
    return result;
}

analyzer_result_t tcp_analyzer_init_connection(analyzer_context_t* ctx,
                                               analyzer_connection_t* conn,
                                               const analyzer_packet_info_t* packet) {
    (void)ctx;
    (void)packet;
    
    if (!conn) {
        return ANALYZER_RESULT_ERROR;
    }
    
    /* Allocate TCP state */
    tcp_connection_state_t* tcp_state = calloc(1, sizeof(tcp_connection_state_t));
    if (!tcp_state) {
        return ANALYZER_RESULT_ERROR;
    }
    
    /* Initialize TCP state */
    tcp_state->state = TCP_STATE_CLOSED;
    tcp_state->handshake_complete = 0;
    tcp_state->rst_seen = 0;
    tcp_state->simultaneous_close = 0;
    
    /* Initialize sequence states */
    for (int dir = 0; dir < 2; dir++) {
        tcp_state->seq_state[dir].initial_seq = 0;
        tcp_state->seq_state[dir].next_seq = 0;
        tcp_state->seq_state[dir].max_seq = 0;
        tcp_state->seq_state[dir].ack_seq = 0;
        tcp_state->seq_state[dir].window = 0;
        tcp_state->seq_state[dir].mss = 536;  /* Default MSS */
        tcp_state->seq_state[dir].window_scale = 0;
        tcp_state->seq_state[dir].has_timestamp = 0;
    }
    
    /* Initialize RTT tracking */
    tcp_state->rtt_samples = 0;
    tcp_state->min_rtt_us = UINT32_MAX;
    tcp_state->max_rtt_us = 0;
    tcp_state->avg_rtt_us = 0;
    tcp_state->rtt_variance = 0;
    
    /* Initialize performance metrics */
    tcp_state->retransmit_count = 0;
    memset(tcp_state->retransmits, 0, sizeof(tcp_state->retransmits));
    
    for (int dir = 0; dir < 2; dir++) {
        tcp_state->bytes_in_flight[dir] = 0;
        tcp_state->effective_window[dir] = 0;
        tcp_state->congestion_window[dir] = 0;
        tcp_state->out_of_order_packets[dir] = 0;
        tcp_state->duplicate_acks[dir] = 0;
        tcp_state->fast_retransmits[dir] = 0;
        tcp_state->zero_window_probes[dir] = 0;
        tcp_state->fin_seen[dir] = 0;
    }
    
    conn->protocol_state = tcp_state;
    
    return ANALYZER_RESULT_OK;
}

void tcp_analyzer_cleanup_connection(analyzer_context_t* ctx,
                                    analyzer_connection_t* conn) {
    (void)ctx;
    
    if (!conn) {
        return;
    }
    
    if (conn->protocol_state) {
        free(conn->protocol_state);
        conn->protocol_state = NULL;
    }
}

void tcp_analyzer_handle_timeout(analyzer_context_t* ctx,
                                analyzer_connection_t* conn) {
    (void)ctx;
    
    if (!conn || !conn->protocol_state) {
        return;
    }
    
    tcp_connection_state_t* tcp_state = (tcp_connection_state_t*)conn->protocol_state;
    
    /* Mark connection as timed out */
    if (tcp_state->state != TCP_STATE_CLOSED) {
        tcp_state->state = TCP_STATE_CLOSED;
        conn->state = ANALYZER_STATE_CLOSED;
    }
}

/* ===== TCP Analysis Functions ===== */

rawsock_error_t tcp_analyze_packet(tcp_connection_state_t* tcp_state,
                                   const rawsock_tcp_header_t* tcp_header,
                                   size_t payload_size,
                                   analyzer_direction_t direction,
                                   const struct timeval* timestamp,
                                   tcp_analysis_result_t* result) {
    if (!tcp_state || !tcp_header || !result) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memset(result, 0, sizeof(*result));
    result->old_state = tcp_state->state;
    
    /* Analyze TCP flags */
    uint8_t flags = tcp_header->flags;
    
    /* Check for RST */
    if (flags & TCP_FLAG_RST) {
        tcp_state->rst_seen = 1;
        result->new_state = TCP_STATE_CLOSED;
        result->state_changed = (result->old_state != result->new_state);
        result->connection_closing = 1;
        return RAWSOCK_SUCCESS;
    }
    
    /* Update state machine */
    result->new_state = tcp_update_state(tcp_state, tcp_header, direction);
    result->state_changed = (result->old_state != result->new_state);
    
    /* Check for handshake completion */
    if (!tcp_state->handshake_complete) {
        if (tcp_state->state == TCP_STATE_ESTABLISHED ||
            (result->new_state == TCP_STATE_ESTABLISHED && 
             (flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN))) {
            result->handshake_complete = 1;
        }
    }
    
    /* Check for connection closing */
    if (flags & TCP_FLAG_FIN) {
        tcp_state->fin_seen[direction] = 1;
        result->connection_closing = 1;
        
        if (tcp_state->fin_seen[0] && tcp_state->fin_seen[1]) {
            tcp_state->simultaneous_close = 1;
        }
    }
    
    /* Analyze sequence numbers */
    tcp_sequence_state_t* seq_state = &tcp_state->seq_state[direction];
    
    if (tcp_analyze_sequence(seq_state, tcp_header, payload_size, 
                            timestamp, result) != RAWSOCK_SUCCESS) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Check for retransmission */
    if (tcp_is_retransmission(tcp_state, tcp_header, direction)) {
        result->retransmission = 1;
        
        /* Track retransmission */
        if (tcp_state->retransmit_count < 32) {
            tcp_retransmit_info_t* retrans = &tcp_state->retransmits[tcp_state->retransmit_count++];
            retrans->seq_num = tcp_header->seq_num;
            retrans->timestamp = *timestamp;
            retrans->segment_len = payload_size;
            retrans->retransmit_count = 1;
        }
    }
    
    /* Calculate RTT if possible */
    result->rtt_sample_us = tcp_calculate_rtt(tcp_state, tcp_header, direction, timestamp);
    
    /* Check for zero window */
    if (tcp_header->window == 0) {
        result->zero_window = 1;
        tcp_state->zero_window_probes[direction]++;
    }
    
    /* Update effective window */
    tcp_state->effective_window[direction] = tcp_header->window << seq_state->window_scale;
    
    return RAWSOCK_SUCCESS;
}

tcp_state_t tcp_update_state(tcp_connection_state_t* tcp_state,
                            const rawsock_tcp_header_t* tcp_header,
                            analyzer_direction_t direction) {
    if (!tcp_state || !tcp_header) {
        return TCP_STATE_UNKNOWN;
    }
    
    uint8_t flags = tcp_header->flags;
    tcp_state_t current_state = tcp_state->state;
    
    return tcp_state_transition(current_state, flags, direction);
}

rawsock_error_t tcp_analyze_sequence(tcp_sequence_state_t* seq_state,
                                     const rawsock_tcp_header_t* tcp_header,
                                     size_t payload_size,
                                     const struct timeval* timestamp,
                                     tcp_analysis_result_t* result) {
    if (!seq_state || !tcp_header || !result) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    uint32_t seq_num = tcp_header->seq_num;
    uint32_t ack_num = tcp_header->ack_num;
    uint8_t flags = tcp_header->flags;
    
    /* Initialize sequence tracking on SYN */
    if ((flags & TCP_FLAG_SYN) && seq_state->initial_seq == 0) {
        seq_state->initial_seq = seq_num;
        seq_state->next_seq = seq_num + 1;  /* SYN consumes 1 sequence number */
        seq_state->max_seq = seq_num;
        seq_state->window = tcp_header->window;
        seq_state->ts_val = seq_num;  /* Store initial sequence as timestamp marker */
    }
    
    /* Update next expected sequence */
    uint32_t expected_seq = seq_state->next_seq;
    uint32_t segment_len = payload_size;
    
    /* SYN and FIN consume sequence numbers */
    if (flags & TCP_FLAG_SYN) segment_len++;
    if (flags & TCP_FLAG_FIN) segment_len++;
    
    /* Check for out-of-order */
    if (seq_state->initial_seq != 0 && seq_num != expected_seq && segment_len > 0) {
        result->out_of_order = 1;
    }
    
    /* Update sequence state */
    if (seq_num >= seq_state->max_seq) {
        seq_state->max_seq = seq_num;
        seq_state->next_seq = seq_num + segment_len;
    }
    
    /* Update ACK state */
    if (flags & TCP_FLAG_ACK) {
        seq_state->ack_seq = ack_num;
    }
    
    /* Update window */
    seq_state->window = tcp_header->window;
    
    (void)timestamp;  /* Suppress unused parameter warning */
    
    return RAWSOCK_SUCCESS;
}

uint32_t tcp_calculate_rtt(tcp_connection_state_t* tcp_state,
                          const rawsock_tcp_header_t* tcp_header,
                          analyzer_direction_t direction,
                          const struct timeval* timestamp) {
    if (!tcp_state || !tcp_header || !timestamp) {
        return 0;
    }
    
    /* Simple RTT calculation based on SYN/SYN-ACK timing */
    if (direction == ANALYZER_DIR_REVERSE && 
        (tcp_header->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        
        if (tcp_state->syn_time.tv_sec > 0) {
            long long diff = (timestamp->tv_sec - tcp_state->syn_time.tv_sec) * 1000000LL +
                            (timestamp->tv_usec - tcp_state->syn_time.tv_usec);
            
            if (diff > 0 && diff < 10000000) {  /* Reasonable RTT range (< 10s) */
                tcp_state->syn_ack_time = *timestamp;
                return (uint32_t)diff;
            }
        }
    } else if (direction == ANALYZER_DIR_FORWARD && 
               (tcp_header->flags & TCP_FLAG_SYN) && !(tcp_header->flags & TCP_FLAG_ACK)) {
        tcp_state->syn_time = *timestamp;
    }
    
    return 0;
}

/* ===== TCP Options Parsing ===== */

rawsock_error_t tcp_parse_options(const rawsock_tcp_header_t* tcp_header,
                                  tcp_options_t* options) {
    if (!tcp_header || !options) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    memset(options, 0, sizeof(*options));
    
    /* Calculate options length */
    uint8_t header_len = ((tcp_header->data_offset_reserved >> 4) & 0x0F) * 4;
    if (header_len <= 20) {
        return RAWSOCK_SUCCESS;  /* No options */
    }
    
    size_t options_len = header_len - 20;
    const uint8_t* option_data = (const uint8_t*)tcp_header + 20;
    
    size_t offset = 0;
    while (offset < options_len && options->count < 16) {
        uint8_t opt_type = option_data[offset];
        
        if (opt_type == TCP_OPT_END) {
            break;
        }
        
        if (opt_type == TCP_OPT_NOP) {
            offset++;
            continue;
        }
        
        if (offset + 1 >= options_len) {
            break;
        }
        
        uint8_t opt_len = option_data[offset + 1];
        if (opt_len < 2 || offset + opt_len > options_len) {
            break;
        }
        
        tcp_option_t* opt = &options->options[options->count++];
        opt->type = opt_type;
        opt->length = opt_len;
        opt->data = &option_data[offset + 2];
        
        /* Parse common options */
        switch (opt_type) {
            case TCP_OPT_MSS:
                if (opt_len == 4) {
                    uint16_t mss_net;
                    memcpy(&mss_net, opt->data, sizeof(mss_net));
                    options->mss = ntohs(mss_net);
                }
                break;
                
            case TCP_OPT_WINDOW_SCALE:
                if (opt_len == 3) {
                    options->window_scale = opt->data[0];
                }
                break;
                
            case TCP_OPT_SACK_PERMITTED:
                if (opt_len == 2) {
                    options->sack_permitted = 1;
                }
                break;
                
            case TCP_OPT_TIMESTAMP:
                if (opt_len == 10) {
                    uint32_t ts_net, ecr_net;
                    memcpy(&ts_net, opt->data, sizeof(ts_net));
                    memcpy(&ecr_net, opt->data + 4, sizeof(ecr_net));
                    options->timestamp_val = ntohl(ts_net);
                    options->timestamp_ecr = ntohl(ecr_net);
                }
                break;
        }
        
        offset += opt_len;
    }
    
    return RAWSOCK_SUCCESS;
}

const tcp_option_t* tcp_find_option(const tcp_options_t* options,
                                    uint8_t option_type) {
    if (!options) {
        return NULL;
    }
    
    for (size_t i = 0; i < options->count; i++) {
        if (options->options[i].type == option_type) {
            return &options->options[i];
        }
    }
    
    return NULL;
}

/* ===== TCP Data Reassembly ===== */

rawsock_error_t tcp_add_segment(analyzer_connection_t* conn,
                               analyzer_direction_t direction,
                               uint32_t seq_num,
                               const uint8_t* data,
                               size_t data_size) {
    if (!conn || !data || data_size == 0 || direction >= 2) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    /* Simple reassembly - just append in order */
    uint8_t** buffer = &conn->reassembly_buffer[direction];
    size_t* current_size = &conn->reassembly_size[direction];
    size_t* capacity = &conn->reassembly_capacity[direction];
    
    /* Allocate buffer if needed */
    if (!*buffer) {
        *capacity = ANALYZER_MAX_REASSEMBLY_SIZE;
        *buffer = malloc(*capacity);
        if (!*buffer) {
            return RAWSOCK_ERROR_UNKNOWN;
        }
        *current_size = 0;
    }
    
    /* Check if we have space */
    if (*current_size + data_size > *capacity) {
        return RAWSOCK_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Simple in-order reassembly */
    memcpy(*buffer + *current_size, data, data_size);
    *current_size += data_size;
    
    (void)seq_num;  /* Suppress unused parameter warning */
    
    return RAWSOCK_SUCCESS;
}

int tcp_get_reassembled_data(analyzer_connection_t* conn,
                            analyzer_direction_t direction,
                            const uint8_t** data,
                            size_t* data_size) {
    if (!conn || !data || !data_size || direction >= 2) {
        return 0;
    }
    
    if (!conn->reassembly_buffer[direction] || conn->reassembly_size[direction] == 0) {
        return 0;
    }
    
    *data = conn->reassembly_buffer[direction];
    *data_size = conn->reassembly_size[direction];
    
    return 1;
}

void tcp_consume_reassembled_data(analyzer_connection_t* conn,
                                 analyzer_direction_t direction,
                                 size_t bytes_consumed) {
    if (!conn || direction >= 2 || !conn->reassembly_buffer[direction]) {
        return;
    }
    
    size_t* current_size = &conn->reassembly_size[direction];
    
    if (bytes_consumed >= *current_size) {
        *current_size = 0;
    } else {
        memmove(conn->reassembly_buffer[direction],
                conn->reassembly_buffer[direction] + bytes_consumed,
                *current_size - bytes_consumed);
        *current_size -= bytes_consumed;
    }
}

/* ===== Utility Functions ===== */

const char* tcp_state_to_string(tcp_state_t state) {
    switch (state) {
        case TCP_STATE_CLOSED:      return "CLOSED";
        case TCP_STATE_LISTEN:      return "LISTEN";
        case TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case TCP_STATE_SYN_RECEIVED: return "SYN_RECEIVED";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1:  return "FIN_WAIT_1";
        case TCP_STATE_FIN_WAIT_2:  return "FIN_WAIT_2";
        case TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case TCP_STATE_CLOSING:     return "CLOSING";
        case TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        case TCP_STATE_UNKNOWN:
        default:                    return "UNKNOWN";
    }
}

void tcp_flags_to_string(uint8_t flags, char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 16) {
        return;
    }
    
    buffer[0] = '\0';
    
    if (flags & TCP_FLAG_FIN) strcat(buffer, "FIN ");
    if (flags & TCP_FLAG_SYN) strcat(buffer, "SYN ");
    if (flags & TCP_FLAG_RST) strcat(buffer, "RST ");
    if (flags & TCP_FLAG_PSH) strcat(buffer, "PSH ");
    if (flags & TCP_FLAG_ACK) strcat(buffer, "ACK ");
    if (flags & TCP_FLAG_URG) strcat(buffer, "URG ");
    if (flags & TCP_FLAG_ECE) strcat(buffer, "ECE ");
    if (flags & TCP_FLAG_CWR) strcat(buffer, "CWR ");
    
    /* Remove trailing space */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == ' ') {
        buffer[len - 1] = '\0';
    }
}

void tcp_format_connection_info(const tcp_connection_state_t* tcp_state,
                               char* buffer, size_t buffer_size) {
    if (!tcp_state || !buffer || buffer_size < 256) {
        return;
    }
    
    snprintf(buffer, buffer_size,
             "State: %s, RTT: %u us (%u samples), Retransmits: %zu, "
             "Window[0]: %u, Window[1]: %u, Handshake: %s",
             tcp_state_to_string(tcp_state->state),
             tcp_state->avg_rtt_us,
             tcp_state->rtt_samples,
             tcp_state->retransmit_count,
             tcp_state->effective_window[0],
             tcp_state->effective_window[1],
             tcp_state->handshake_complete ? "Complete" : "Incomplete");
}

void tcp_get_connection_stats(const tcp_connection_state_t* tcp_state,
                             analyzer_stats_t* stats) {
    if (!tcp_state || !stats) {
        return;
    }
    
    stats->rtt_samples = tcp_state->rtt_samples;
    stats->avg_rtt_us = tcp_state->avg_rtt_us;
}

/* ===== Internal Helper Functions ===== */

static tcp_state_t tcp_state_transition(tcp_state_t current_state, uint8_t flags, 
                                        analyzer_direction_t direction) {
    /* Simplified TCP state machine */
    switch (current_state) {
        case TCP_STATE_CLOSED:
            if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK)) {
                return (direction == ANALYZER_DIR_FORWARD) ? TCP_STATE_SYN_SENT : TCP_STATE_SYN_RECEIVED;
            }
            break;
            
        case TCP_STATE_SYN_SENT:
            if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
                return TCP_STATE_SYN_RECEIVED;
            }
            break;
            
        case TCP_STATE_SYN_RECEIVED:
            if ((flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_SYN)) {
                return TCP_STATE_ESTABLISHED;
            }
            break;
            
        case TCP_STATE_ESTABLISHED:
            if (flags & TCP_FLAG_FIN) {
                return TCP_STATE_FIN_WAIT_1;
            }
            break;
            
        case TCP_STATE_FIN_WAIT_1:
            if (flags & TCP_FLAG_ACK) {
                return TCP_STATE_FIN_WAIT_2;
            }
            if (flags & TCP_FLAG_FIN) {
                return TCP_STATE_CLOSING;
            }
            break;
            
        case TCP_STATE_FIN_WAIT_2:
            if (flags & TCP_FLAG_FIN) {
                return TCP_STATE_TIME_WAIT;
            }
            break;
            
        case TCP_STATE_CLOSE_WAIT:
            if (flags & TCP_FLAG_FIN) {
                return TCP_STATE_LAST_ACK;
            }
            break;
            
        case TCP_STATE_CLOSING:
            if (flags & TCP_FLAG_ACK) {
                return TCP_STATE_TIME_WAIT;
            }
            break;
            
        case TCP_STATE_LAST_ACK:
            if (flags & TCP_FLAG_ACK) {
                return TCP_STATE_CLOSED;
            }
            break;
            
        case TCP_STATE_TIME_WAIT:
            /* Stay in TIME_WAIT until timeout */
            break;
            
        default:
            break;
    }
    
    return current_state;
}

static int tcp_is_retransmission(tcp_connection_state_t* tcp_state, 
                                 const rawsock_tcp_header_t* tcp_header,
                                 analyzer_direction_t direction) {
    if (!tcp_state || !tcp_header || direction >= 2) {
        return 0;
    }
    
    tcp_sequence_state_t* seq_state = &tcp_state->seq_state[direction];
    
    /* Simple retransmission detection */
    if (seq_state->max_seq > 0 && tcp_header->seq_num < seq_state->max_seq) {
        return 1;
    }
    
    return 0;
}

static void tcp_update_rtt_stats(tcp_connection_state_t* tcp_state, uint32_t rtt_us) {
    if (!tcp_state || rtt_us == 0) {
        return;
    }
    
    tcp_state->rtt_samples++;
    
    if (rtt_us < tcp_state->min_rtt_us) {
        tcp_state->min_rtt_us = rtt_us;
    }
    
    if (rtt_us > tcp_state->max_rtt_us) {
        tcp_state->max_rtt_us = rtt_us;
    }
    
    /* Exponential weighted moving average */
    if (tcp_state->rtt_samples == 1) {
        tcp_state->avg_rtt_us = rtt_us;
        tcp_state->rtt_variance = 0;
    } else {
        uint32_t old_avg = tcp_state->avg_rtt_us;
        tcp_state->avg_rtt_us = (old_avg * 7 + rtt_us) / 8;
        
        /* Update variance */
        uint32_t diff = (rtt_us > old_avg) ? (rtt_us - old_avg) : (old_avg - rtt_us);
        tcp_state->rtt_variance = (tcp_state->rtt_variance * 3 + diff) / 4;
    }
}

static rawsock_error_t tcp_process_reassembly(analyzer_connection_t* conn,
                                             analyzer_direction_t direction,
                                             uint32_t seq_num, const uint8_t* data, 
                                             size_t data_size) {
    if (!conn || !data || data_size == 0) {
        return RAWSOCK_ERROR_INVALID_PARAM;
    }
    
    return tcp_add_segment(conn, direction, seq_num, data, data_size);
}
