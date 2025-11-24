# CSCD58 Final Project: Packet Sniffer

## Compile

```bash
gcc -o packet_sniffer packet_sniffer.c
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
