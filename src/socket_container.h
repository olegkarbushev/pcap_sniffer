#ifndef PACKET_CONTAINER_H
#define PACKET_CONTAINER_H

typedef enum {
    SYN = 0,
    SYN_ACK,
    ACK,
    FIN1,
    FIN2,
    FIN_ACK1,
    FIN_ACK2
} state_t;

typedef enum {
    UNKNOWN = -1,
    FAILED = 0,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    DISCONNECTED,
} status_t;

/*
 * Container holds src and dst addresses.
 * Could be extended in case it's needed to hold a pointer to the packet.
 */
typedef struct {
    uint32_t src_addr;
    uint16_t src_port;

    uint32_t dst_addr;
    uint16_t dst_port;

    uint32_t retries;

    /* flags */
    union {
        uint8_t flags;
        struct {
            uint8_t fin:  1,
                    syn:  1,
                    rst:  1,
                    psh:  1,
                    ack:  1,
                    urg:  1,
                    ece:  1,
                    cwr:  1;
        };
    };

    state_t state;
    status_t status;
} socket_container_t;

#endif // PACKET_CONTAINER_H
