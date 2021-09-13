#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

int main() {
    printf("pcap sniffer, supposed to snif traffic \r\n");

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i=0;
    if (pcap_findalldevs(&interfaces, error) == -1) {
        printf("\nerror in pcap findall devs");
        return -1;
    }

    printf("\n the interfaces present on the system are:\n");
    for (temp=interfaces; temp; temp=temp->next) {
        printf("\n%d  :  %s", i++, temp->name);
    }
    printf("\a\n\r");

    return 0;
}
