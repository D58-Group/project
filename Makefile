CC=gcc
CFLAGS=-Wall -g
# LIBS=-lpcap -lncurses
LIBS=-lpcap

all: packet_sniffer

packet_sniffer: packet_sniffer.o sr_utils.o sorting.o
	$(CC) $(CFLAGS) -o packet_sniffer packet_sniffer.o sr_utils.o sorting.o $(LDFLAGS)

packet_sniffer.o: packet_sniffer.c sr_utils.h sorting.h
	$(CC) $(CFLAGS) -c -o packet_sniffer.o packet_sniffer.c

sr_utils.o: sr_utils.c sr_utils.h sr_protocol.h
	$(CC) $(CFLAGS) -c -o sr_utils.o sr_utils.c

sorting.o: sorting.c sorting.h sr_utils.h sr_protocol.h
	$(CC) $(CFLAGS) -c -o sorting.o sorting.c

clean:
	rm -f packet_sniffer packet_sniffer.o sr_utils.o sorting.o
