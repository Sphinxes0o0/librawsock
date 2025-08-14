/**
 * @file tcp_analyzer.h
 * @brief TCP Protocol Analyzer
 * @author LibRawSock Team
 * @version 1.0.0
 * 
 * This module provides comprehensive TCP protocol analysis including
 * connection state tracking, sequence number analysis, and data reassembly.
 */

#ifndef LIBRAWSOCK_TCP_ANALYZER_H
#define LIBRAWSOCK_TCP_ANALYZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include "analyzer.h"
#include "packet.h"

/**
 * @brief TCP connection states (RFC 793)
 */
typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_UNKNOWN
} tcp_state_t;

/**
 * @brief TCP flags
 */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

/**
 * @brief TCP options types
 */
#define TCP_OPT_END             0
#define TCP_OPT_NOP             1
#define TCP_OPT_MSS             2
#define TCP_OPT_WINDOW_SCALE    3
#define TCP_OPT_SACK_PERMITTED  4
#define TCP_OPT_SACK            5
#define TCP_OPT_TIMESTAMP       8

/**
 * @brief Maximum TCP options length
 */
#define TCP_MAX_OPTIONS_LEN     40

/**
 * @brief TCP sequence number tracking
 */
typedef struct {
    uint32_t initial_seq;       /**< Initial sequence number (ISN) */
    uint32_t next_seq;          /**< Next expected sequence number */
    uint32_t max_seq;           /**< Maximum sequence number seen */
    uint32_t ack_seq;           /**< Last acknowledgment number */
    uint16_t window;            /**< Window size */
    uint16_t mss;               /**< Maximum segment size */
    uint8_t window_scale;       /**< Window scale factor */
    uint8_t has_timestamp;      /**< Timestamp option present */
    uint32_t ts_val;            /**< Timestamp value */
    uint32_t ts_ecr;            /**< Timestamp echo reply */
} tcp_sequence_state_t;

/**
 * @brief TCP option parsing result
 */
typedef struct {
    uint8_t type;               /**< Option type */
    uint8_t length;             /**< Option length */
    const uint8_t* data;        /**< Option data */
} tcp_option_t;

/**
 * @brief TCP options collection
 */
typedef struct {
    tcp_option_t options[16];   /**< Parsed options */
    size_t count;               /**< Number of options */
    uint16_t mss;               /**< MSS value (if present) */
    uint8_t window_scale;       /**< Window scale (if present) */
    uint8_t sack_permitted;     /**< SACK permitted flag */
    uint32_t timestamp_val;     /**< Timestamp value */
    uint32_t timestamp_ecr;     /**< Timestamp echo reply */
} tcp_options_t;

/**
 * @brief TCP retransmission information
 */
typedef struct {
    uint32_t seq_num;           /**< Sequence number */
    struct timeval timestamp;   /**< Original transmission time */
    uint16_t segment_len;       /**< Segment length */
    uint8_t retransmit_count;   /**< Number of retransmissions */
} tcp_retransmit_info_t;

/**
 * @brief TCP connection state information
 */
typedef struct {
    tcp_state_t state;                          /**< Current TCP state */
    tcp_sequence_state_t seq_state[2];          /**< Sequence state [forward, reverse] */

    /* Connection establishment tracking */
    struct timeval syn_time;                    /**< SYN timestamp */
    struct timeval syn_ack_time;               /**< SYN-ACK timestamp */
    struct timeval established_time;           /**< Connection established time */

    /* RTT measurement */
    uint32_t rtt_samples;                      /**< Number of RTT samples */
    uint32_t min_rtt_us;                       /**< Minimum RTT */
    uint32_t max_rtt_us;                       /**< Maximum RTT */
    uint32_t avg_rtt_us;                       /**< Average RTT */
    uint32_t rtt_variance;                     /**< RTT variance */

    /* Retransmission tracking */
    tcp_retransmit_info_t retransmits[32];     /**< Retransmission tracking */
    size_t retransmit_count;                   /**< Number of retransmissions */

    /* Performance metrics */
    uint64_t bytes_in_flight[2];               /**< Bytes in flight [forward, reverse] */
    uint32_t effective_window[2];              /**< Effective window size */
    uint32_t congestion_window[2];             /**< Estimated congestion window */

    /* Flags and state */
    uint8_t handshake_complete;                /**< 3-way handshake complete */
    uint8_t fin_seen[2];                       /**< FIN seen [forward, reverse] */
    uint8_t rst_seen;                          /**< RST seen */
    uint8_t simultaneous_close;                /**< Simultaneous close detected */

    /* Quality metrics */
    uint32_t out_of_order_packets[2];          /**< Out-of-order packets */
    uint32_t duplicate_acks[2];                /**< Duplicate ACKs */
    uint32_t fast_retransmits[2];              /**< Fast retransmits */
    uint32_t zero_window_probes[2];            /**< Zero window probes */
} tcp_connection_state_t;

/**
 * @brief TCP analysis result
 */
typedef struct {
    tcp_state_t old_state;                     /**< Previous state */
    tcp_state_t new_state;                     /**< New state */
    uint8_t state_changed;                     /**< State change flag */
    uint8_t handshake_complete;                /**< Handshake completion flag */
    uint8_t connection_closing;                /**< Connection closing flag */
    uint8_t retransmission;                    /**< Retransmission detected */
    uint8_t out_of_order;                      /**< Out-of-order packet */
    uint8_t duplicate_ack;                     /**< Duplicate ACK */
    uint8_t zero_window;                       /**< Zero window */
    uint32_t rtt_sample_us;                    /**< RTT sample (if available) */
} tcp_analysis_result_t;

/* ===== TCP Analyzer API ===== */

/**
 * @brief Create TCP protocol handler
 * @return TCP protocol handler on success, NULL on failure
 */
analyzer_protocol_handler_t* tcp_analyzer_create(void);

/**
 * @brief Destroy TCP protocol handler
 * @param handler TCP protocol handler
 */
void tcp_analyzer_destroy(analyzer_protocol_handler_t* handler);

/**
 * @brief Analyze TCP packet
 * @param ctx Analyzer context
 * @param conn Connection state
 * @param packet Packet information
 * @return Analysis result
 */
analyzer_result_t tcp_analyzer_process_packet(analyzer_context_t* ctx,
                                              analyzer_connection_t* conn,
                                              const analyzer_packet_info_t* packet);

/**
 * @brief Initialize TCP connection state
 * @param ctx Analyzer context
 * @param conn Connection
 * @param packet Initial packet
 * @return Analysis result
 */
analyzer_result_t tcp_analyzer_init_connection(analyzer_context_t* ctx,
                                               analyzer_connection_t* conn,
                                               const analyzer_packet_info_t* packet);

/**
 * @brief Cleanup TCP connection state
 * @param ctx Analyzer context
 * @param conn Connection
 */
void tcp_analyzer_cleanup_connection(analyzer_context_t* ctx,
                                    analyzer_connection_t* conn);

/**
 * @brief Handle TCP connection timeout
 * @param ctx Analyzer context
 * @param conn Connection
 */
void tcp_analyzer_handle_timeout(analyzer_context_t* ctx,
                                analyzer_connection_t* conn);

/* ===== TCP Analysis Functions ===== */

/**
 * @brief Analyze TCP header and update connection state
 * @param tcp_state TCP connection state
 * @param tcp_header TCP header
 * @param payload_size Payload size
 * @param direction Packet direction
 * @param timestamp Packet timestamp
 * @param result Analysis result output
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t tcp_analyze_packet(tcp_connection_state_t* tcp_state,
                                   const rawsock_tcp_header_t* tcp_header,
                                   size_t payload_size,
                                   analyzer_direction_t direction,
                                   const struct timeval* timestamp,
                                   tcp_analysis_result_t* result);

/**
 * @brief Update TCP state machine
 * @param tcp_state TCP connection state
 * @param tcp_header TCP header
 * @param direction Packet direction
 * @return New TCP state
 */
tcp_state_t tcp_update_state(tcp_connection_state_t* tcp_state,
                            const rawsock_tcp_header_t* tcp_header,
                            analyzer_direction_t direction);

/**
 * @brief Analyze TCP sequence numbers
 * @param seq_state Sequence state
 * @param tcp_header TCP header
 * @param payload_size Payload size
 * @param timestamp Packet timestamp
 * @param result Analysis result output
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t tcp_analyze_sequence(tcp_sequence_state_t* seq_state,
                                     const rawsock_tcp_header_t* tcp_header,
                                     size_t payload_size,
                                     const struct timeval* timestamp,
                                     tcp_analysis_result_t* result);

/**
 * @brief Calculate RTT from TCP timestamps
 * @param tcp_state TCP connection state
 * @param tcp_header TCP header
 * @param direction Packet direction
 * @param timestamp Packet timestamp
 * @return RTT in microseconds, 0 if not available
 */
uint32_t tcp_calculate_rtt(tcp_connection_state_t* tcp_state,
                          const rawsock_tcp_header_t* tcp_header,
                          analyzer_direction_t direction,
                          const struct timeval* timestamp);

/* ===== TCP Options Parsing ===== */

/**
 * @brief Parse TCP options from header
 * @param tcp_header TCP header
 * @param options Output options structure
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t tcp_parse_options(const rawsock_tcp_header_t* tcp_header,
                                  tcp_options_t* options);

/**
 * @brief Find specific TCP option
 * @param options Parsed options
 * @param option_type Option type to find
 * @return Option pointer on success, NULL if not found
 */
const tcp_option_t* tcp_find_option(const tcp_options_t* options,
                                    uint8_t option_type);

/* ===== TCP Data Reassembly ===== */

/**
 * @brief Add segment to reassembly buffer
 * @param conn Connection
 * @param direction Data direction
 * @param seq_num Sequence number
 * @param data Segment data
 * @param data_size Data size
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t tcp_add_segment(analyzer_connection_t* conn,
                               analyzer_direction_t direction,
                               uint32_t seq_num,
                               const uint8_t* data,
                               size_t data_size);

/**
 * @brief Check for complete data in reassembly buffer
 * @param conn Connection
 * @param direction Data direction
 * @param data Output data pointer
 * @param data_size Output data size
 * @return 1 if data available, 0 otherwise
 */
int tcp_get_reassembled_data(analyzer_connection_t* conn,
                            analyzer_direction_t direction,
                            const uint8_t** data,
                            size_t* data_size);

/**
 * @brief Clear reassembled data
 * @param conn Connection
 * @param direction Data direction
 * @param bytes_consumed Number of bytes consumed
 */
void tcp_consume_reassembled_data(analyzer_connection_t* conn,
                                 analyzer_direction_t direction,
                                 size_t bytes_consumed);

/* ===== Utility Functions ===== */

/**
 * @brief Get TCP state name
 * @param state TCP state
 * @return State name string
 */
const char* tcp_state_to_string(tcp_state_t state);

/**
 * @brief Get TCP flags string
 * @param flags TCP flags
 * @param buffer Output buffer (at least 16 bytes)
 * @param buffer_size Buffer size
 */
void tcp_flags_to_string(uint8_t flags, char* buffer, size_t buffer_size);

/**
 * @brief Format TCP connection info
 * @param tcp_state TCP connection state
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 */
void tcp_format_connection_info(const tcp_connection_state_t* tcp_state,
                               char* buffer, size_t buffer_size);

/**
 * @brief Get TCP connection statistics
 * @param tcp_state TCP connection state
 * @param stats Output statistics
 */
void tcp_get_connection_stats(const tcp_connection_state_t* tcp_state,
                             analyzer_stats_t* stats);

#ifdef __cplusplus
}
#endif

#endif /* LIBRAWSOCK_TCP_ANALYZER_H */
