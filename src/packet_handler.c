#include "packet_handler.h"


void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes) {
    // struct ethhdr* ethernet_header = (struct ethhdr *)bytes;
    struct iphdr* ip_header = (struct iphdr*) (bytes + sizeof(struct ethhdr));
    struct sockaddr_in source, dest;

    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char source_ip_str[128];
    char dest_ip_str[128];
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

        printf("\r\n%-15s:%-5d -> %-15s:%-5d, syn:%d, fin:%d, ack:%d flags: %#02x \r\n",
                source_ip_str, source_port, dest_ip_str, dest_port,
                syn, fin, ack, flags);

    } /* Commented out UDP packets handling */
    else if (ip_header->protocol == IP_HEADER_PROTOCOL_UDP) { /* currently we need only TCP */
        struct udphdr* udp_header = (struct udphdr* ) next_header;
        source_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        data_size = hdr->len - sizeof(struct ethhdr) - ip_header_size - sizeof(struct udphdr);
    }
}
