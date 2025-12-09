# CSCD58 Final Project: Packet Sniffer

## Usage

```bash
# prerequisites
sudo apt-get install libpcap-dev
sudo apt-get install libncurses-dev
sudo apt install gnuplot gnuplot-x11 libcairo2


# compile
make

# run
sudo ./packet_sniffer -h
```

## Options

```bash
Usage: ./packet_sniffer [-i [interface]] [-o <filename>] [-p <protocol>] [-t <duration>] [-h]
  -i [interface]   Interface to sniff on
                   If interface is omitted, lists available interfaces
  -o <filename>    File to save captured packets (default=stdout)
  -p <protocol>    Protocol to filter (default=any)
  -t <duration>    Duration to sniff in seconds (default=unlimited)
  -h               View usage information
```

## Test Cases

tcp seq num wrap around
```
mininet> h1 tcpreplay --intf1=h1-eth0 pcap_samples/tcp_wraparound.pcap
```

## Resources

- <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html>
- <https://www.tcpdump.org/pcap.html>
- https://tldp.org/HOWTO/NCURSES-Programming-HOWTO/index.html
