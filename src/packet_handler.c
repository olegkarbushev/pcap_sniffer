#include "packet_handler.h"

#define FIN_BIT (1<<0)
#define SYN_BIT (1<<1)
#define ACK_BIT (1<<4)

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


void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes) {
    // struct ethhdr* ethernet_header = (struct ethhdr *)bytes;
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

        /* here should be handling of packets */
        flags = (flags_full & 0xff00) >> 8; /* since we need only less significant part */

        char key[50];

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
                //printf("\r\n1. SYN %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                //        source_ip_str, source_port, dest_ip_str, dest_port,
                //        syn, fin, ack, flags);

                new_socket.state = SYN;
                new_socket.status = CONNECTING;

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                //printf("key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if ( _socket ) {
                    // TODO: here must be more robust retries handling
                    printf("SYN retries %d for: %s \r\n", ++(_socket->retries), key);
                    _socket->flags = flags;
                    if (_socket->retries >= 6 ) {
                        _socket->status = FAILED;
                              //FAILED
                        printf("FAILED       %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                source_ip_str, source_port, dest_ip_str, dest_port,
                                _socket->retries, registry_get_size());
                    }
                }

                break;

            case (SYN_BIT + ACK_BIT): /* SYN + ACK */
                //printf("\r\n2. SYN-ACK %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                //        source_ip_str, source_port, dest_ip_str, dest_port,
                //        syn, fin, ack, flags);

                /* in this case server socket responds to client, but we need key formatted: src-dst */
                new_socket.src_addr = ip_header->daddr;
                new_socket.src_port = ntohs(tcp_header->dest);
                new_socket.dst_addr = ip_header->saddr;
                new_socket.dst_addr = ntohs(tcp_header->source);

                new_socket.state = SYN_ACK;
                new_socket.status = CONNECTING;

                sprintf(key, "%s:%d-%s:%d", dest_ip_str, dest_port, source_ip_str, source_port);
                //printf("key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if (_socket) {
                    if (_socket->state == SYN) {
                        _socket->flags = flags;
                        _socket->state = new_socket.state;
                        _socket->status = new_socket.status;
                    } else {
                        printf("got SYN-ACK, but there was no SYN before! \r\n");
                        printf("SYN-ACK %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                                source_ip_str, source_port, dest_ip_str, dest_port,
                                syn, fin, ack, flags);

                        _socket->state = UNKNOWN;
                        bool remove_ret = registry_remove_socket(key);
                        printf("removing socket from registry: %s res: %s size: %d \r\n",
                                key, remove_ret ? "success":"failed", registry_get_size());
                    }
                }
                break;

            case ACK_BIT: /* ACK */
                //printf("\r\n3. ACK %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                //        source_ip_str, source_port, dest_ip_str, dest_port,
                //        syn, fin, ack, flags);

                new_socket.state = ACK;

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                //printf("key: %s \r\n", key);

                _socket = registry_get_socket(key);
                if (!_socket) {
                    //printf("swap src<->dst\r\n");
                    sprintf(key, "%s:%d-%s:%d", dest_ip_str, dest_port, source_ip_str, source_port);
                    _socket = registry_get_socket(key);
                }
                if (_socket) {
                    /* check stored socket state */
                    switch (_socket->state) {
                        case SYN_ACK:
                            printf("CONNECTED    %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                    source_ip_str, source_port, dest_ip_str, dest_port,
                                    _socket->retries, registry_get_size());

                            _socket->flags = flags;
                            _socket->state = new_socket.state;
                            _socket->status = CONNECTED;
                            break;

                        case FIN_ACK2:
                            printf("DISCONNECTED %-15s:%-5d -> %-15s:%-5d, retries:%d sockets count: %d \r\n\r\n",
                                    source_ip_str, source_port, dest_ip_str, dest_port,
                                    _socket->retries, registry_get_size());

                            _socket->flags = flags;
                            _socket->state = new_socket.state;
                            _socket->status = DISCONNECTED;
                            _socket->retries = 0;

                            bool remove_ret = registry_remove_socket(key);
                            printf("removing socket from registry: %s res: %s size: %d \r\n",
                                    key, remove_ret ? "success":"failed", registry_get_size());
                            break;

                        default:
                            //printf("received ACK \r\n");
                            break;
                    }
                } else {
                    //printf("could not find socket for: %s \r\n", key);
                    return;
                }
                break;

            case FIN_BIT: /* FIN, FIN + ACK */
            case FIN_BIT + ACK_BIT:
                //printf("\r\n1. FIN %-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                //        source_ip_str, source_port, dest_ip_str, dest_port,
                //        syn, fin, ack, flags);

                sprintf(key, "%s:%d-%s:%d", source_ip_str, source_port, dest_ip_str, dest_port);
                //printf("key1: %s \r\n", key);

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
                    //printf("key2: %s \r\n", key);

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
                //printf("Failed to get masked flags: %d \r\n", masked_flags);
                return;
        }

        if (!_socket) {
            //printf("socket: %s is not present in registry \r\n", key);

            /* allocated packet will be destroyed on hash table unref */
            socket_container_t *socket2store = (socket_container_t *) malloc(sizeof(socket_container_t));

            *socket2store = new_socket;

            if (registry_add_socket(key, socket2store)) {
                //printf("added %s to registry, size: %d \r\n", key, registry_get_size());
            } else {
                //printf("FAILED to add socket to the registry :( \r\n");
            }
        }
    }
#if 0
    /* Commented out UDP packets handling */
    else if (ip_header->protocol == IP_HEADER_PROTOCOL_UDP) { /* currently we need only TCP */
        struct udphdr* udp_header = (struct udphdr* ) next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - sizeof(struct udphdr);
    }
#endif

#if 0
    if (data_size > 0) {
        int headers_size = hdr->len - data_size;
        print_data_hex(bytes + headers_size, data_size);
    }
#endif
}
