#include "packet_handler.h"

#define FIN_BIT (1<<0)
#define SYN_BIT (1<<1)
#define ACK_BIT (1<<4)

int8_t g_syn_retries = 6;

// not used for now
#if 0
void print_data_hex(const uint8_t* data, int size) {
    int offset = 0;
    int nlines = size / PRINT_BYTES_PER_LINE;

    if (nlines * PRINT_BYTES_PER_LINE < size)
        nlines++;

    printf("        ");

    for (int i = 0; i < PRINT_BYTES_PER_LINE; i++)
        printf("%02X ", i);

    printf("\n\n");

    for (int line = 0; line < nlines; line++) {
        printf("%04X    ", offset);
        for (int j = 0; j < PRINT_BYTES_PER_LINE; j++) {
            if (offset + j >= size)
                printf("   ");
            else
                printf("%02X ", data[offset + j]);
        }

        printf("   ");

        for (int j = 0; j < PRINT_BYTES_PER_LINE; j++) {
            if (offset + j >= size)
                printf(" ");
            else if (data[offset + j] > 31 && data[offset + j] < 127)
                printf("%c", data[offset + j]);
            else
                printf(".");
        }

        offset += PRINT_BYTES_PER_LINE;
        printf("\n");
    }
}
#endif


/* In case of heavy traffic - this callback would cause delay
 * and ringbuffer or queue is preferable to be used.
 * the callback will only save package, but package parsing should
 * be done in a separate thread
 *
 * For this now it looks like parsing just in handle_packet
 * does not cause performance issues.
 */
void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes) {
    struct iphdr* ip_header = (struct iphdr*) (bytes + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char source_ip_str[16];
    char dest_ip_str[16];
    strncpy(source_ip_str, inet_ntoa(source.sin_addr), sizeof(source_ip_str));
    strncpy(dest_ip_str, inet_ntoa(dest.sin_addr), sizeof(dest_ip_str));

    int source_port = 0;
    int dest_port = 0;
    int data_size = 0;
    int ip_header_size = ip_header->ihl * 4;

    int syn = 0;
    int fin = 0;
    int ack = 0;

    uint16_t flags_full = 0;
    uint8_t flags = 0;

    char* next_header = (char* ) ip_header + ip_header_size;

    /* KEY to be stored in hashtable
     * formatted:
     * "src_addr:src:port-dst_addr:dst_port"
     * pros:
     *      makes it possible to put/get values from hashtable
     * cons:
     *      depends on string formatting
     *      some packets has swapped src<->dst addr, port
     */
    char key[50];

    if (ip_header->protocol == IP_HEADER_PROTOCOL_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr* ) next_header;
        source_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
        int tcp_header_size = tcp_header->doff * 4;
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - tcp_header_size;

        syn = tcp_header->syn;
        fin = tcp_header->fin;
        ack = tcp_header->ack;

        flags_full = tcp_header->flags;

        /* since we need only less significant part */
        flags = (flags_full & 0xff00) >> 8;

        socket_container_t new_socket;

        new_socket.flags = flags;
        new_socket.status = UNKNOWN;
        new_socket.retries = 0;

        new_socket.src_addr = ip_header->saddr;
        new_socket.src_port = ntohs(tcp_header->source);

        new_socket.dst_addr = ip_header->daddr;
        new_socket.dst_addr = ntohs(tcp_header->dest);

        socket_container_t *_socket = NULL;

        uint8_t masked_flags = flags & (SYN_BIT + ACK_BIT + FIN_BIT);
        switch (masked_flags) {
            case SYN_BIT: /* SYN */
                log_printf(LOG_DEBUG, "\r\n1. SYN %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: "PRINTF_BIN_FMT_INT8" \r\n",
                        source_ip_str, source_port, dest_ip_str, dest_port,
                        syn, fin, ack, PRINTF_BINARY_INT8(flags));

                new_socket.state = SYN;
                new_socket.status = CONNECTING;

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                log_printf(LOG_VERBOSE, "key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if ( _socket ) {
                    // TODO: here must be more robust retries handling
                    log_printf(LOG_DEBUG, "SYN retries %d for: %s \r\n", ++(_socket->retries), key);
                    _socket->flags = flags;
                    if (_socket->retries >= g_syn_retries ) {
                        _socket->status = FAILED;
                        //FAILED
                        log_printf(LOG_INFO, "FAILED       %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                source_ip_str, source_port, dest_ip_str, dest_port,
                                _socket->retries, registry_get_size());
                    }
                }

                break;

            case (SYN_BIT + ACK_BIT): /* SYN + ACK */
                log_printf(LOG_DEBUG, "\r\n2. SYN-ACK %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: "PRINTF_BIN_FMT_INT8"  \r\n",
                        source_ip_str, source_port, dest_ip_str, dest_port,
                        syn, fin, ack, PRINTF_BINARY_INT8(flags));

                /* in this case server socket responds to client, but we need key formatted: src-dst */
                new_socket.src_addr = ip_header->daddr;
                new_socket.src_port = ntohs(tcp_header->dest);
                new_socket.dst_addr = ip_header->saddr;
                new_socket.dst_addr = ntohs(tcp_header->source);

                new_socket.state = SYN_ACK;
                new_socket.status = CONNECTING;

                sprintf(key, "%s:%d-%s:%d", dest_ip_str, dest_port, source_ip_str, source_port);
                log_printf(LOG_VERBOSE, "key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if (_socket) {
                    if (_socket->state == SYN) {
                        _socket->flags = flags;
                        _socket->state = new_socket.state;
                        _socket->status = new_socket.status;
                    } else {
                        // got SYN + ACK, but there was no SYN sent before
                        _socket->state = UNKNOWN;
                        bool remove_ret = registry_remove_socket(key);
                        log_printf(LOG_VERBOSE, "SYN+ACK but no previous SYN, removing socket from registry: %s res: %s size: %d \r\n",
                                key, remove_ret ? "success":"failed", registry_get_size());
                    }
                }
                break;

            case ACK_BIT: /* ACK */
                log_printf(LOG_DEBUG, "\r\n1. ACK %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: "PRINTF_BIN_FMT_INT8 " \r\n",
                        source_ip_str, source_port, dest_ip_str, dest_port,
                        syn, fin, ack, PRINTF_BINARY_INT8(flags));

                new_socket.state = ACK;

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                log_printf(LOG_VERBOSE, "key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if (!_socket) {
                    // since could not find registered socket, doing swap and try again
                    log_printf(LOG_VERBOSE, "swap src<->dst\r\n");
                    sprintf(key, "%s:%d-%s:%d", dest_ip_str, dest_port, source_ip_str, source_port);
                    _socket = registry_get_socket(key);
                }
                if (_socket) {
                    /* check stored socket state */
                    switch (_socket->state) {
                        case SYN_ACK:
                            log_printf(LOG_INFO, "CONNECTED    %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                    source_ip_str, source_port, dest_ip_str, dest_port,
                                    _socket->retries, registry_get_size());

                            _socket->flags = flags;
                            _socket->state = new_socket.state;
                            _socket->status = CONNECTED;
                            break;

                        case FIN_ACK2:
                            log_printf(LOG_INFO, "DISCONNECTED %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                    source_ip_str, source_port, dest_ip_str, dest_port,
                                    _socket->retries, registry_get_size());

                            _socket->flags = flags;
                            _socket->state = new_socket.state;
                            _socket->status = DISCONNECTED;
                            _socket->retries = 0;

                            bool remove_ret = registry_remove_socket(key);
                            log_printf(LOG_VERBOSE, "removing socket from registry: %s res: %s size: %d \r\n",
                                    key, remove_ret ? "success":"failed", registry_get_size());
                            break;

                        default:
                            log_printf(LOG_VERBOSE, "received ACK for previous socket state: %d\r\n", _socket->state);
                            break;
                    }
                } else {
                    log_printf(LOG_VERBOSE, "could not find socket for: %s \r\n", key);
                    return;
                }
                break;

            case FIN_BIT: /* FIN, FIN + ACK */
            case FIN_BIT + ACK_BIT:
                log_printf(LOG_DEBUG, "\r\n1. FIN %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: "PRINTF_BIN_FMT_INT8 " \r\n",
                        source_ip_str, source_port, dest_ip_str, dest_port,
                        syn, fin, ack, PRINTF_BINARY_INT8(flags));

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                log_printf(LOG_VERBOSE, "key: %s \r\n", key);

                new_socket.status = DISCONNECTING;

                _socket = registry_get_socket(key);
                if (_socket) {
                    new_socket.state = (_socket->state == FIN_ACK1) ? FIN_ACK2:FIN_ACK1;

                    _socket->flags = flags;
                    _socket->state = new_socket.state;
                    _socket->status = new_socket.status;
                } else {
                    /* FIN + ACK from dst, so reverse src <-> dst to check if we have this socket */
                    sprintf(key, "%s:%d-%s:%d", dest_ip_str, dest_port, source_ip_str, source_port);
                    log_printf(LOG_VERBOSE, "key: %s \r\n", key);

                    _socket = registry_get_socket(key);
                    if (_socket) {
                        new_socket.state = (_socket->state == FIN_ACK1) ? FIN_ACK2:FIN_ACK1;

                        _socket->flags = flags;
                        _socket->state = new_socket.state;
                        _socket->status = new_socket.status;
                    }
                }
                break;

            default:
                log_printf(LOG_DEBUG, "unsupported masked flags: %d \r\n", masked_flags);
                return;
        }

        if (!_socket) {
            log_printf(LOG_DEBUG, "socket: %s is not present in registry \r\n", key);

            /* allocated packet will be destroyed on hash table unref */
            socket_container_t *socket2store = (socket_container_t *) malloc(sizeof(socket_container_t));

            *socket2store = new_socket;

            if (registry_add_socket(key, socket2store)) {
                log_printf(LOG_DEBUG, "added %s to registry, size: %d \r\n", key, registry_get_size());
            } else {
                log_printf(LOG_ERROR, "FAILED to add socket to the registry :( \r\n");
                exit(EXIT_FAILURE);
            }
        }
    }

#if 0
    if (data_size > 0) {
        int headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }
#endif
}
