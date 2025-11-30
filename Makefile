CC=gcc
CFLAGS=-Wall -g
LIBS=-lpcap -lncurses -lpthread

TARGET=packet_sniffer
SRCS=packet_sniffer.c sr_utils.c sorting.c
OBJS=$(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
