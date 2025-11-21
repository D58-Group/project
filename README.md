# CSCD58 Final Project: Packet Sniffer

```bash
$ gcc packet_sniffer.c -o packet_sniffer.out
$ ./packet_sniffer.out -h
Usage: ./packet_sniffer.out -i <interface> [-o <filename>] [-p <protocol>] [-t <duration>] [-h]
  -i <interface>    Interface to sniff on
  -o <filename>     File to save captured packets (default=stdout)
  -p <protocol>     Protocol to filter (default=any)
  -t <duration>     Duration to sniff in seconds (default=unlimited)
  -h                View usage information
```
