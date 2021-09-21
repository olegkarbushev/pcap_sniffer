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
pcap_t* g_pcap;

char* g_log_file_name = NULL;

// filter for SYN, ACK, FIN
const char *syn_ack_fin_filter = "(tcp[13] & 19 != 0)";

int g_opt_print_all = 0;

void int_handler(int signo) {
    if (signo == SIGINT) {
        log_printf(LOG_DEBUG, "\r\nSIGINT terminating pcap_loop \r\n");
        if (g_pcap)
            pcap_breakloop(g_pcap);
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
        log_printf(LOG_ERROR, "pcap_findalldevs failed: %s\r\n", err_buff);
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

void print_usage(char *argv) {
    log_printf(LOG_ERROR, "Usage: \n\t%s [-p] [-i interface name] [-f log file] [-v] [-r retries threshold]\r\n", argv);
    log_printf(LOG_ERROR, "\n\tSniffs traffic for established/terminated connections on specific or all interfaces \r\n");
    log_printf(LOG_ERROR, "\n\tExample usage: \n\t%s -i eth0 -vv -f logfile.log\r\n", argv);
}

int main(int argc, char *argv[]) {
    const char* device = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filterprog;
    int res, opt;

    if ( argc <= 1 ) {
        print_usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    // register signal handler for graceful pcap_loop termination
    signal(SIGINT, int_handler);

    atexit(exit_handler);

    uint8_t retries_treshhold;
    while ((opt = getopt(argc, argv, "i:f:r:pv::")) != -1) {
        switch (opt) {
            case 'i':
                device = optarg;
                break;
            case 'f':
                g_log_file_name = optarg;
                log_open_file(g_log_file_name);
                break;
            case 'p':
                g_opt_print_all = 1;
                break;
            case 'v':
                g_loglevel = LOG_DEBUG;
                if (optarg) {
                    if (!strcmp(optarg, "v")) g_loglevel = LOG_VERBOSE;
                }
                break;
            case 'r':
                retries_treshhold = (uint8_t) atoi(optarg);
                if (retries_treshhold != 0)
                    g_syn_retries = retries_treshhold;
                break;

            default: /* '?' */
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (g_opt_print_all) {
        print_all_interfaces();
        exit(EXIT_SUCCESS);
    }

    g_pcap = pcap_open_live(device, 65535, 1, 100, errbuf);
    if (g_pcap == NULL) {
        log_printf(LOG_ERROR, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    res = pcap_compile(g_pcap, &filterprog, syn_ack_fin_filter, 0, PCAP_NETMASK_UNKNOWN);
    if (res != 0) {
        log_printf(LOG_ERROR, "pcap_compile failed: %s\n", pcap_geterr(g_pcap));
        goto error;
    }

    res = pcap_setfilter(g_pcap, &filterprog);
    if (res != 0) {
        log_printf(LOG_ERROR, "pcap_setfilter failed: %s\n", pcap_geterr(g_pcap));
        goto error;
    }

    log_printf(LOG_DEBUG, "Listening %s, filter: %s...\n", device, syn_ack_fin_filter);

    registry_init();

    res = pcap_loop(g_pcap, -1, handle_packet, NULL);
    log_printf(LOG_DEBUG, "pcap_loop returned %d\n", res);

    registry_destroy();

    pcap_close(g_pcap);
    return EXIT_SUCCESS;

error:
    pcap_close(g_pcap);
    return EXIT_FAILURE;
}
