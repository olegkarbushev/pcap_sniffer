#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <signal.h>
#include <string.h>

#include <pcap.h>

#include "socket_registry.h"
#include "packet_handler.h"

#include "logger.h"

#define ALIGNMENT_SPACES 20

/* Extern variables */
extern g_syn_retries;

extern g_loglevel;

extern char *optarg;
extern int optind;

/* Global variables */
pcap_t* pcap;

char* g_log_file_name = NULL;


int opt_all = 0;

void int_handler(int signo) {
    if (signo == SIGINT) {
        log_printf(LOG_ERROR, "\r\nSIGINT terminating pcap_loop \r\n");
        if (pcap)
            pcap_breakloop(pcap);
    }
}

void exit_handler() {
    log_close_file();
}

void print_all_interfaces() {
    int error;
    pcap_if_t *interfaces, *cur_interface;
    char err_buff[PCAP_ERRBUF_SIZE];

    error = pcap_findalldevs(&interfaces, err_buff);
    if (error != 0) {
        log_printf(LOG_ERROR, "pcap_findalldevs failed: %s\n", err_buff);
        return;
    }

    cur_interface = interfaces;
    int i=0;

    char *table_header[] = {"num", "interface name", "description"};
    log_printf(LOG_INFO, "%*s   %*s   %*s\n\r", -3, table_header[0], -ALIGNMENT_SPACES, table_header[1], -ALIGNMENT_SPACES, table_header[2]);
    log_printf(LOG_INFO, "%*c   %*c   %*c\n\r", -3, '-', -ALIGNMENT_SPACES, '-', -ALIGNMENT_SPACES, '-');
    while (cur_interface) {
        log_printf(LOG_INFO, "%-3d : %*s   %*s\n\r", i++, -ALIGNMENT_SPACES, cur_interface->name, -ALIGNMENT_SPACES,
                cur_interface->description ? cur_interface->description : "(no description)");
        cur_interface = cur_interface->next;
    }

    if (interfaces)
        pcap_freealldevs(interfaces);
}

// TODO: make a nice Usage
void print_usage(char *argv) {
    log_printf(LOG_ERROR, "Usage: Here would be Usage soon %s\r\n", argv);
    printf("INFO: pcap sniffer, sniffs traffic for established connections on specific or all interfaces \r\n");
}

int main(int argc, char *argv[]) {

    const char* device = NULL;
    const char* filter = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res, opt;

    if ( argc <= 1 ) {
        print_all_interfaces();
        print_usage(argv[0]);
        exit(1);
    }

    /* register signal handler for graceful pcap_loop termination */
    signal(SIGINT, int_handler);

    atexit(exit_handler);

    uint8_t retries_treshhold;
    while ((opt = getopt(argc, argv, "i:f:r:av::")) != -1) {
        switch (opt) {
            case 'i':
                device = optarg;
                break;
            case 'f':
                g_log_file_name = optarg;
                log_open_file(g_log_file_name);
                break;
            case 'a':
                opt_all = 1;
                device = NULL;
                break;
            case 'v':
                g_loglevel = LOG_DEBUG;
                if (optarg) {
                    if (!strcmp(optarg, "v"))
                        g_loglevel = LOG_VERBOSE;
                }
                break;
            case 'r':
                retries_treshhold = (uint8_t) atoi(optarg);
                if (retries_treshhold != 0)
                    g_syn_retries = retries_treshhold;
                break;

                break;
            default: /* '?' */
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
    if (pcap == NULL) {
        log_printf(LOG_ERROR, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filterprog;
    res = pcap_compile(pcap, &filterprog, filter, 0, PCAP_NETMASK_UNKNOWN);
    if (res != 0) {
        log_printf(LOG_ERROR, "pcap_compile failed: %s\n", pcap_geterr(pcap));
        goto error;
    }

    res = pcap_setfilter(pcap, &filterprog);
    if (res != 0) {
        log_printf(LOG_ERROR, "pcap_setfilter failed: %s\n", pcap_geterr(pcap));
        goto error;
    }

    log_printf(LOG_DEBUG, "Listening %s, filter: %s...\n", device, filter);

    registry_init();

    res = pcap_loop(pcap, -1, handle_packet, NULL);
    log_printf(LOG_DEBUG, "pcap_loop returned %d\n", res);

    registry_destroy();

    pcap_close(pcap);
    return EXIT_SUCCESS;

error:
    pcap_close(pcap);
    return EXIT_FAILURE;
}
