# CSCD58 Final Project: Packet Sniffer

## Usage

```bash
# prerequisites
sudo apt-get install libpcap-dev
sudo apt-get install libncurses-dev

# compile
make

# run
sudo ./packet_sniffer -i interface
```

## Options

```bash
Usage: ./packet_sniffer.out -i <interface> [-o <filename>] [-p <protocol>] [-t <duration>] [-h]
  -i <interface>    Interface to sniff on
  -o <filename>     File to save captured packets (default=stdout)
  -p <protocol>     Protocol to filter (default=any)
  -t <duration>     Duration to sniff in seconds (default=unlimited)
  -h                View usage information
```

## Resources

- <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html>
- <https://www.tcpdump.org/pcap.html>
