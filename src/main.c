#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <pcap.h>

#include "packet_handler.h"

#define ALIGNMENT_SPACES 20

void print_all_interfaces() {
    int error;
    pcap_if_t *interfaces, *cur_interface;
    char err_buff[PCAP_ERRBUF_SIZE];

    error = pcap_findalldevs(&interfaces, err_buff);
    if (error != 0) {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", err_buff);
        return;
    }

    cur_interface = interfaces;
    int i=0;

    char *table_header[] = {"num", "interface name", "description"};
    printf("%*s   %*s   %*s\n\r", -3, table_header[0], -ALIGNMENT_SPACES, table_header[1], -ALIGNMENT_SPACES, table_header[2]);
    printf("%*c   %*c   %*c\n\r", -3, '-', -ALIGNMENT_SPACES, '-', -ALIGNMENT_SPACES, '-');
    while (cur_interface) {
        printf("%-3d : %*s   %*s\n\r", i++, -ALIGNMENT_SPACES, cur_interface->name, -ALIGNMENT_SPACES,
                cur_interface->description ? cur_interface->description : "(no description)");
        cur_interface = cur_interface->next;
    }

    if (interfaces)
        pcap_freealldevs(interfaces);
}

// TODO: make a nice Usage
void print_usage() {
    fprintf(stderr, "Usage: Here woud be Usage soon\r\n");
}

//  Option to sniff all interfaces
int opt_all = 0;

int main(int argc, char *argv[]) {

    const char* device = NULL;
    const char* filter = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    printf("INFO: pcap sniffer, sniffs traffic for established connections on specific or all interfaces \r\n");

    if ( argc <= 1 ) {
        print_all_interfaces();
        print_usage();
        exit(1);
    }

    argc--;
    argv++;
    while (argc) {
        if (!strcmp(*argv, "-i")) {
            argc--;
            argv++;
            printf("Interface name: -i %s\n\r", *argv);
            device = *argv;
        } else {
            opt_all = 1;
        }

        if (!strcmp(*argv, "-f")) {
            argc--;
            argv++;
            printf("Filter:  %s\n\r", *argv);
            filter = *argv;
        }

        if (!strcmp(*argv, "-a")) {
            opt_all = 1;
            device = NULL;
        }

        argc--;
        argv++;
    }

    pcap_t* pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filterprog;
    res = pcap_compile(pcap, &filterprog, filter, 0, PCAP_NETMASK_UNKNOWN);
    if (res != 0) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(pcap));
        goto error;
    }

    res = pcap_setfilter(pcap, &filterprog);
    if (res != 0) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(pcap));
        goto error;
    }

    printf("Listening %s, filter: %s...\n", device, filter);

    res = pcap_loop(pcap, -1, handle_packet, NULL);
    printf("pcap_loop returned %d\n", res);

    pcap_close(pcap);
    return 0;

error:
    pcap_close(pcap);
    return 1;
}
