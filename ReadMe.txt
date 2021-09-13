Traffic sniffer for coding assignment.

Supposed to sniff net traffic using libpcap https://www.tcpdump.org/
libpcap is linked statically.

* Project structure:
./
  /src
    /libpcap - src code of libpcap, https://github.com/the-tcpdump-group/libpcap.git
    /
  /bin - contains binaries
  /obj - contains obj files

* Build:
to build libpcap library run:

    cd src/libpcap
    ./configure && make -j6
