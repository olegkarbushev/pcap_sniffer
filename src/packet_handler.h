#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <pcap.h>

#include "include/net_headers.h"

void print_data_hex(const uint8_t* data, int size);
void handle_packet(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes);

#endif // PACKET_HANDLER_H
