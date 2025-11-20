# project



sudo apt-get install libpcap-dev

run:
gcc -o packet_capture packet_capture.c sr_utils.c -lpcap

Resources:
https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
https://www.tcpdump.org/pcap.html