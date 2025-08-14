/**
 * @file analyzer.h
 * @brief Extensible Protocol Analyzer Framework
 * @author Sphinxes0o0
 * @version 1.0.0
 * 
 * This module provides an extensible framework for protocol analysis,
 * including connection tracking, state management, and data reassembly.
 */

#ifndef LIBRAWSOCK_ANALYZER_H
#define LIBRAWSOCK_ANALYZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>
#include "rawsock.h"

/**
 * @brief Maximum number of tracked connections
 */
#define ANALYZER_MAX_CONNECTIONS 1024

/**
 * @brief Maximum reassembly buffer size per connection
 */
#define ANALYZER_MAX_REASSEMBLY_SIZE 65536

/**
 * @brief Connection timeout in seconds
 */
#define ANALYZER_CONNECTION_TIMEOUT 300

/**
 * @brief Protocol types for analyzer
 */
typedef enum {
    ANALYZER_PROTO_TCP = 6,
    ANALYZER_PROTO_UDP = 17,
    ANALYZER_PROTO_ICMP = 1,
    ANALYZER_PROTO_UNKNOWN = 0
} analyzer_protocol_t;

/**
 * @brief Connection direction
 */
typedef enum {
    ANALYZER_DIR_FORWARD = 0,   /**< Client to server */
    ANALYZER_DIR_REVERSE = 1    /**< Server to client */
} analyzer_direction_t;

/**
 * @brief Generic connection state
 */
typedef enum {
    ANALYZER_STATE_INIT = 0,
    ANALYZER_STATE_ESTABLISHING,
    ANALYZER_STATE_ESTABLISHED,
    ANALYZER_STATE_CLOSING,
    ANALYZER_STATE_CLOSED,
    ANALYZER_STATE_RESET,
    ANALYZER_STATE_ERROR
} analyzer_state_t;

/**
 * @brief Connection 5-tuple identifier
 */
typedef struct {
    uint32_t src_ip;           /**< Source IP address (IPv4) */
    uint32_t dst_ip;           /**< Destination IP address (IPv4) */
    uint16_t src_port;         /**< Source port */
    uint16_t dst_port;         /**< Destination port */
    uint8_t protocol;          /**< Protocol number */
} analyzer_flow_id_t;

/**
 * @brief Connection statistics
 */
typedef struct {
    uint64_t packets_forward;   /**< Packets in forward direction */
    uint64_t packets_reverse;   /**< Packets in reverse direction */
    uint64_t bytes_forward;     /**< Bytes in forward direction */
    uint64_t bytes_reverse;     /**< Bytes in reverse direction */
    struct timeval first_seen;  /**< First packet timestamp */
    struct timeval last_seen;   /**< Last packet timestamp */
    uint32_t rtt_samples;       /**< Number of RTT samples */
    uint32_t avg_rtt_us;        /**< Average RTT in microseconds */
} analyzer_stats_t;

/**
 * @brief Forward declarations
 */
typedef struct analyzer_connection analyzer_connection_t;
typedef struct analyzer_context analyzer_context_t;
typedef struct analyzer_protocol_handler analyzer_protocol_handler_t;

/**
 * @brief Packet processing result
 */
typedef enum {
    ANALYZER_RESULT_OK = 0,           /**< Packet processed successfully */
    ANALYZER_RESULT_DROP,             /**< Packet should be dropped */
    ANALYZER_RESULT_ERROR,            /**< Processing error */
    ANALYZER_RESULT_CONNECTION_NEW,   /**< New connection detected */
    ANALYZER_RESULT_CONNECTION_CLOSE, /**< Connection closed */
    ANALYZER_RESULT_DATA_READY        /**< Reassembled data available */
} analyzer_result_t;

/**
 * @brief Packet information for analysis
 */
typedef struct {
    const uint8_t* packet_data;       /**< Raw packet data */
    size_t packet_size;               /**< Packet size */
    struct timeval timestamp;         /**< Packet timestamp */
    analyzer_flow_id_t flow_id;       /**< Flow identifier */
    analyzer_direction_t direction;   /**< Packet direction */

    /* Protocol-specific data pointers */
    const void* ip_header;            /**< IP header pointer */
    const void* transport_header;     /**< Transport header pointer */
    const void* payload;              /**< Payload pointer */
    size_t payload_size;              /**< Payload size */
} analyzer_packet_info_t;

/**
 * @brief Protocol handler callback functions
 */
typedef analyzer_result_t (*analyzer_packet_handler_t)(
    analyzer_context_t* ctx,
    analyzer_connection_t* conn,
    const analyzer_packet_info_t* packet
);

typedef analyzer_result_t (*analyzer_connection_init_t)(
    analyzer_context_t* ctx,
    analyzer_connection_t* conn,
    const analyzer_packet_info_t* packet
);

typedef void (*analyzer_connection_cleanup_t)(
    analyzer_context_t* ctx,
    analyzer_connection_t* conn
);

typedef void (*analyzer_connection_timeout_t)(
    analyzer_context_t* ctx,
    analyzer_connection_t* conn
);

/**
 * @brief Protocol handler structure
 */
struct analyzer_protocol_handler {
    analyzer_protocol_t protocol;              /**< Protocol type */
    analyzer_packet_handler_t packet_handler;  /**< Packet processing function */
    analyzer_connection_init_t conn_init;      /**< Connection initialization */
    analyzer_connection_cleanup_t conn_cleanup;/**< Connection cleanup */
    analyzer_connection_timeout_t conn_timeout;/**< Connection timeout handler */
    void* protocol_data;                       /**< Protocol-specific data */
};

/**
 * @brief Generic connection structure
 */
struct analyzer_connection {
    analyzer_flow_id_t flow_id;        /**< Connection identifier */
    analyzer_state_t state;            /**< Connection state */
    analyzer_stats_t stats;            /**< Connection statistics */

    /* Protocol-specific state */
    analyzer_protocol_handler_t* handler;  /**< Protocol handler */
    void* protocol_state;               /**< Protocol-specific state data */

    /* Reassembly buffers */
    uint8_t* reassembly_buffer[2];      /**< Reassembly buffers [forward, reverse] */
    size_t reassembly_size[2];          /**< Current buffer sizes */
    size_t reassembly_capacity[2];      /**< Buffer capacities */

    /* Hash table linkage */
    analyzer_connection_t* next;        /**< Next connection in hash bucket */

    /* Timeout management */
    struct timeval last_activity;      /**< Last activity timestamp */
    uint8_t timeout_pending;           /**< Timeout flag */
};

/**
 * @brief Analyzer configuration
 */
typedef struct {
    size_t max_connections;            /**< Maximum tracked connections */
    size_t max_reassembly_size;        /**< Maximum reassembly buffer size */
    uint32_t connection_timeout;       /**< Connection timeout in seconds */
    uint8_t enable_reassembly;         /**< Enable TCP reassembly */
    uint8_t enable_rtt_tracking;       /**< Enable RTT tracking */
    uint8_t enable_statistics;         /**< Enable detailed statistics */
} analyzer_config_t;

/**
 * @brief Main analyzer context
 */
struct analyzer_context {
    analyzer_config_t config;                              /**< Configuration */
    analyzer_connection_t* connection_table[1024];         /**< Connection hash table */
    analyzer_protocol_handler_t* handlers[256];            /**< Protocol handlers */

    /* Statistics */
    uint64_t total_packets;             /**< Total packets processed */
    uint64_t total_connections;         /**< Total connections seen */
    uint64_t active_connections;        /**< Currently active connections */
    uint64_t dropped_packets;           /**< Dropped packets */

    /* Memory management */
    analyzer_connection_t* free_connections;   /**< Free connection pool */
    size_t allocated_connections;       /**< Allocated connections */

    /* Callbacks */
    void (*connection_callback)(analyzer_context_t* ctx, analyzer_connection_t* conn, analyzer_result_t result);
    void (*data_callback)(analyzer_context_t* ctx, analyzer_connection_t* conn, 
                         analyzer_direction_t dir, const uint8_t* data, size_t size);

    void* user_data;                    /**< User data pointer */
};

/* ===== Core Analyzer API ===== */

/**
 * @brief Create analyzer context with default configuration
 * @return Analyzer context on success, NULL on failure
 */
analyzer_context_t* analyzer_create(void);

/**
 * @brief Create analyzer context with custom configuration
 * @param config Analyzer configuration
 * @return Analyzer context on success, NULL on failure
 */
analyzer_context_t* analyzer_create_with_config(const analyzer_config_t* config);

/**
 * @brief Destroy analyzer context and free resources
 * @param ctx Analyzer context
 */
void analyzer_destroy(analyzer_context_t* ctx);

/**
 * @brief Register protocol handler
 * @param ctx Analyzer context
 * @param handler Protocol handler
 * @return RAWSOCK_SUCCESS on success, error code on failure
 */
rawsock_error_t analyzer_register_handler(analyzer_context_t* ctx, 
                                          analyzer_protocol_handler_t* handler);

/**
 * @brief Process a packet through the analyzer
 * @param ctx Analyzer context
 * @param packet_data Raw packet data
 * @param packet_size Packet size
 * @param timestamp Packet timestamp
 * @return Analysis result
 */
analyzer_result_t analyzer_process_packet(analyzer_context_t* ctx,
                                          const uint8_t* packet_data,
                                          size_t packet_size,
                                          const struct timeval* timestamp);

/**
 * @brief Set connection event callback
 * @param ctx Analyzer context
 * @param callback Callback function
 */
void analyzer_set_connection_callback(analyzer_context_t* ctx,
                                     void (*callback)(analyzer_context_t* ctx, 
                                                     analyzer_connection_t* conn, 
                                                     analyzer_result_t result));

/**
 * @brief Set data ready callback
 * @param ctx Analyzer context
 * @param callback Callback function
 */
void analyzer_set_data_callback(analyzer_context_t* ctx,
                               void (*callback)(analyzer_context_t* ctx, 
                                               analyzer_connection_t* conn,
                                               analyzer_direction_t dir,
                                               const uint8_t* data, size_t size));

/**
 * @brief Get connection by flow ID
 * @param ctx Analyzer context
 * @param flow_id Flow identifier
 * @return Connection on success, NULL if not found
 */
analyzer_connection_t* analyzer_get_connection(analyzer_context_t* ctx,
                                              const analyzer_flow_id_t* flow_id);

/**
 * @brief Cleanup expired connections
 * @param ctx Analyzer context
 * @return Number of connections cleaned up
 */
size_t analyzer_cleanup_expired(analyzer_context_t* ctx);

/**
 * @brief Get analyzer statistics
 * @param ctx Analyzer context
 * @param stats Output statistics structure
 */
void analyzer_get_stats(analyzer_context_t* ctx, analyzer_stats_t* stats);

/* ===== Utility Functions ===== */

/**
 * @brief Create flow ID from packet information
 * @param src_ip Source IP address
 * @param dst_ip Destination IP address
 * @param src_port Source port
 * @param dst_port Destination port
 * @param protocol Protocol number
 * @param flow_id Output flow ID
 */
void analyzer_create_flow_id(uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port,
                             uint8_t protocol, analyzer_flow_id_t* flow_id);

/**
 * @brief Get reverse flow ID
 * @param flow_id Original flow ID
 * @param reverse_flow_id Output reverse flow ID
 */
void analyzer_get_reverse_flow_id(const analyzer_flow_id_t* flow_id,
                                 analyzer_flow_id_t* reverse_flow_id);

/**
 * @brief Calculate flow hash
 * @param flow_id Flow identifier
 * @return Hash value
 */
uint32_t analyzer_flow_hash(const analyzer_flow_id_t* flow_id);

/**
 * @brief Compare flow IDs
 * @param flow1 First flow ID
 * @param flow2 Second flow ID
 * @return 1 if equal, 0 otherwise
 */
int analyzer_flow_compare(const analyzer_flow_id_t* flow1,
                         const analyzer_flow_id_t* flow2);

/**
 * @brief Format flow ID as string
 * @param flow_id Flow identifier
 * @param buffer Output buffer (at least 64 bytes)
 * @param buffer_size Buffer size
 */
void analyzer_format_flow_id(const analyzer_flow_id_t* flow_id,
                             char* buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* LIBRAWSOCK_ANALYZER_H */
