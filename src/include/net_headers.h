#ifndef NET_HEADERS_H
#define NET_HEADERS_H

#include <stdint.h>

#if !defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__) && defined(__BYTE_ORDER)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN__
#endif

#endif

#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c%c%c"
#define PRINTF_BYTE_TO_BINARY_INT8(i)    \
    (((i) & 0x80ll) ? '1' : '0'), \
    (((i) & 0x40ll) ? '1' : '0'), \
    (((i) & 0x20ll) ? '1' : '0'), \
    (((i) & 0x10ll) ? '1' : '0'), \
    (((i) & 0x08ll) ? '1' : '0'), \
    (((i) & 0x04ll) ? '1' : '0'), \
    (((i) & 0x02ll) ? '1' : '0'), \
    (((i) & 0x01ll) ? '1' : '0')

#define PRINTF_BINARY_PATTERN_INT16 \
    PRINTF_BINARY_PATTERN_INT8              PRINTF_BINARY_PATTERN_INT8
#define PRINTF_BYTE_TO_BINARY_INT16(i) \
    PRINTF_BYTE_TO_BINARY_INT8((i) >> 8),   PRINTF_BYTE_TO_BINARY_INT8(i)
#define PRINTF_BINARY_PATTERN_INT32 \
    PRINTF_BINARY_PATTERN_INT16             PRINTF_BINARY_PATTERN_INT16
#define PRINTF_BYTE_TO_BINARY_INT32(i) \
    PRINTF_BYTE_TO_BINARY_INT16((i) >> 16), PRINTF_BYTE_TO_BINARY_INT16(i)
#define PRINTF_BINARY_PATTERN_INT64    \
    PRINTF_BINARY_PATTERN_INT32             PRINTF_BINARY_PATTERN_INT32
#define PRINTF_BYTE_TO_BINARY_INT64(i) \
    PRINTF_BYTE_TO_BINARY_INT32((i) >> 32), PRINTF_BYTE_TO_BINARY_INT32(i)


/* Octets in ethernet address */
#define ETH_ALEN 6

struct ethhdr
{
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    /* packet type ID */
    uint16_t      h_proto;
} __attribute__((packed));

#define IP_HEADER_PROTOCOL_TCP 6
#define IP_HEADER_PROTOCOL_UDP 17

struct iphdr
{

#if defined(__LITTLE_ENDIAN__)

    uint8_t  ihl:4,
             version:4;

#elif defined (__BIG_ENDIAN__)

    uint8_t  version:4,
             ihl:4;

#else

#error "Neither __LITTLE_ENDIAN__ nor __BIG_ENDIAN__ are defined"

#endif

    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;

    union {
        uint16_t flags;
        struct {
#if defined(__LITTLE_ENDIAN__)
        uint16_t res1: 4,
                 doff: 4,
                 fin:  1,
                 syn:  1,
                 rst:  1,
                 psh:  1,
                 ack:  1,
                 urg:  1,
                 ece:  1,
                 cwr:  1;
#elif defined(__BIG_ENDIAN__)
        uint16_t doff: 4,
                 res1: 4,
                 cwr:  1,
                 ece:  1,
                 urg:  1,
                 ack:  1,
                 psh:  1,
                 rst:  1,
                 syn:  1,
                 fin:  1;
#else
#error "Neither __LITTLE_ENDIAN__ nor __BIG_ENDIAN__ are defined"
#endif
        };
    };

    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

struct udphdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
} __attribute__((packed));

#endif /* NET_HEADERS_H */
