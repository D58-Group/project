#include <errno.h>
#include <ncurses.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"

struct packet_node {
  const uint8_t* packet;
  const struct pcap_pkthdr* packet_hdr;
  struct packet_node* prev;
  struct packet_node* next;
} typedef packet_node_t;

packet_node_t *packet_list = NULL;

char* usage =
    "Usage:"
    " %s -i <interface> [-o <filename>] [-p <protocol>] [-t <duration>] [-h]\n"
    "  -i <interface>    Interface to sniff on\n"
    "  -o <filename>     File to save captured packets (default=stdout)\n"
    "  -p <protocol>     Protocol to filter (default=any)\n"
    "  -t <duration>     Duration to sniff in seconds (default=unlimited)\n"
    "  -h                View usage information\n";

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

options_t parse_options(int argc, char* argv[]) {
  options_t options;

  options.interface = NULL;
  options.filename = NULL;
  options.protocol = NULL;
  options.duration = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      options.interface = argv[++i];
    } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
      options.filename = argv[++i];
    } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      options.protocol = argv[++i];
    } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      options.duration = atoi(argv[++i]);
    } else if (strcmp(argv[i], "-h") == 0) {
      printf(usage, argv[0]);
      exit(0);
    } else {
      printf("Unknown option: %s\n", argv[i]);
      printf(usage, argv[0]);
      exit(1);
    }
  }

  if (options.interface == NULL) {
    printf("Error: Interface is required.\n");
    printf(usage, argv[0]);
    exit(1);
  }

  return options;
}

packet_node_t *add_packet_node(const uint8_t* packet, const struct pcap_pkthdr* packet_hdr,
   packet_node_t *prev, packet_node_t *next) {
  packet_node_t *node = malloc(sizeof(packet_node_t));
  node->packet = packet;
  node->packet_hdr = packet_hdr;
  node->prev = prev;
  node->next = next;

  if (packet_list != NULL) {
    packet_list->prev = node;
  }

  packet_list = node;
  return node;
}

void delete_packet_nodes(packet_node_t *node) {
  packet_node_t *next = node->next;
  free(node);
  if (next != NULL) {
    delete_packet_nodes(node);
  }
}

int get_packet_list_length(int length, packet_node_t *node) {
  if (node->next == NULL) {
    return length;
  }
  return get_packet_list_length(length + 1, node->next);
}

void print_packet_node(packet_node_t *node) {
  printw("packet: \n");
  printw("timestamp: %d\n", node->packet_hdr->ts);
  printw("packet type: %d\n", ethertype((uint8_t *)(node->packet)));

}

void handle_packet(uint8_t * args_unused, const struct pcap_pkthdr* header,
                   const uint8_t* packet) {
  packet_node_t *new_node = add_packet_node(packet, header, NULL, packet_list);

  print_hdrs((uint8_t*)packet, header->len);
  /* Uncomment below for ncurses ui */
  // printw("length: %d \n", header->len);
  // printw("list length: %d\n", get_packet_list_length(0, new_node));
  // print_packet_node(new_node);
  // refresh();
  // getch();
  // endwin();
}

int main(int argc, char* argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t* device;
  pcap_t* packet_capture_handle;
  int promisc = 1;  // promiscuous mode
  int to_ms = 750;  // read time in ms
  int continue_sniffing = 1;


  // struct pcap_pkthdr hdr;

  // Parse command line options
  options_t options = parse_options(argc, argv);
  printf("Sniffing on interface: %s\n", options.interface);
  printf("Output file: %s\n", options.filename ? options.filename : "stdout");
  printf("Protocol filter: %s\n", options.protocol ? options.protocol : "any");
  printf("Duration: %d\n", options.duration);

  // List devices and select first device in list
  pcap_findalldevs(&device, errbuf);  // TODO free list with pcap_freealldevs

  if (device == NULL) {
    printf("Error finding devices, %s", errbuf);
    exit(1);
  }
  printf("Capturing packets on device: %s", device->name);

  // TODO: add option for inputing device name instead of using default

  // TODO: Allow for reading packets from pathname using pcap_open_offline, and
  // pcap_fopen_offline()

  // TODO: Can filter using pcap_compile and pcap_setfilter

  // Capture packets on device
  packet_capture_handle =
      pcap_open_live(device->name, BUFSIZ, promisc, to_ms, errbuf);

  if (packet_capture_handle == NULL) {
    printf("Error opening device %s", errbuf);
    exit(1);
  }

  
  // Initiate ncurses
  // initscr();
  // noecho();
  // cbreak();
  // keypad(stdscr, TRUE);

  // -1 means to sniff until error occurs
  pcap_loop(packet_capture_handle, -1, handle_packet, NULL);

  // Close session
  pcap_close(packet_capture_handle);
  return 0;
}