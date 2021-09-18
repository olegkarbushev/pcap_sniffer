#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap.h>

#include "include/net_headers.h"
#include "socket_registry.h"

#include "socket_container.h"

// not used for now
#define PRINT_BYTES_PER_LINE 16

// not used for now
#if 0
void print_data_hex(const uint8_t* data, int size);
#endif

void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes);

#endif // PACKET_HANDLER_H
