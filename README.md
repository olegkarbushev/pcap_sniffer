# Traffic sniffer using libpcap

Supposed to sniff traffic on specific interface to catch established/terminated tcp socket connections.

Uses [libpcap](https://www.tcpdump.org/) under the hood for packets capturing.

Incoming packets are stored in hashtable by Glib.
Where **key** is a C string "src_addr:src_port-dst_addr:dst_port", probably this approach to store the packet is not the best.
But as appeared it fits for the case we need to check the connection state only.

## Project structure
```
./
  /src
    /include - header files
    /libpcap - src code of libpcap, https://github.com/the-tcpdump-group/libpcap.git.
    / - pcap_sniffer src code
  /bin - contains binaries
  /obj - contains obj files
```

## Build
To build ***libpcap*** library run:
```
cd src/libpcap
./configure && make -j6
```
To build the ***pcap_sniffer*** run:
```
make all
```

## Usage
***pcap_sniffer*** requires **sudo** privileges.
```
sudo pcap_sniffer -i eth0 -f logfile.log
```
### keys
- ***p*** - prints all available interfaces
- ***i*** - sets the interface to be sniffed
- ***f*** - sets the log file name
- ***r*** - sets the **failed** threshold for **SYN** packets
- ***v*** - sets the verbosity level of output. [-v DEBUG, -vv VERBOSE]

## Issues/Limitations
- Current ***pcap_sniffer*** implementation handles packages right into a callback function. This could have delays or even missing packages in case of heavy networking traffic.

***Room for improvement***
- [ ] Refactor packet handling code.
- [ ] Make packet handling in a separate thread and use a ring buffer for incoming packets.
