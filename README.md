# CSCD58 Final Project: Packet Sniffer

## Usage

```bash
# prerequisites
sudo apt-get install libpcap-dev
sudo apt-get install libncurses-dev
sudo apt install gnuplot


# compile
make

# run
sudo ./packet_sniffer -h
```

## Options

```bash
Usage: ./packet_sniffer [-i <interface>] [-p <protocol>] [-l] [-h]
  -i <interface>   Interface to sniff on
  -p <protocol>    Protocol to filter (default=any)
  -l               List available interfaces
  -h               View usage information
```

## Resources

- <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html>
- <https://www.tcpdump.org/pcap.html>
- https://tldp.org/HOWTO/NCURSES-Programming-HOWTO/index.html
