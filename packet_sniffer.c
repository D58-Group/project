#include <errno.h>
// #include <ncurses.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "sr_utils.h"
#include "sorting.h"

struct packet_node {
  const uint8_t* packet;
  const struct pcap_pkthdr* packet_hdr;
  struct packet_node* prev;
  struct packet_node* next;
} typedef packet_node_t;

packet_node_t* packet_list = NULL;

char* usage =
    "Usage: "
    "%s [-i [interface]] [-o <filename>] [-p <protocol>] [-t <duration>] [-h]\n"
    "  -i [interface]   Interface to sniff on\n"
    "                   If interface is omitted, lists available interfaces\n"
    "  -o <filename>    File to save captured packets (default=stdout)\n"
    "  -p <protocol>    Protocol to filter (default=any)\n"
    "  -t <duration>    Duration to sniff in seconds (default=unlimited)\n"
    "  -h               View usage information\n";

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

options_t parse_options(int argc, char* argv[]) {
  if (argc == 1) {
    printf(usage, argv[0]);
    exit(0);
  }

  options_t options;
  options.interface = NULL;
  options.filename = NULL;
  options.protocol = NULL;
  options.duration = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0) {
      if (i + 1 < argc) {
        options.interface = argv[++i];
      }
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
      printf("Invalid argument: %s\n", argv[i]);
      printf(usage, argv[0]);
      exit(1);
    }
  }

  return options;
}

pcap_if_t* find_device_by_name(pcap_if_t* devices, const char* name) {
  pcap_if_t* device = devices;
  while (device != NULL) {
    if (strcmp(device->name, name) == 0) {
      return device;
    }
    device = device->next;
  }
  return NULL;
}

packet_node_t* add_packet_node(const uint8_t* packet,
                               const struct pcap_pkthdr* packet_hdr,
                               packet_node_t* prev, packet_node_t* next) {
  packet_node_t* node = malloc(sizeof(packet_node_t));
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

void delete_packet_nodes(packet_node_t* node) {
  packet_node_t* next = node->next;
  free(node);
  if (next != NULL) {
    delete_packet_nodes(node);
  }
}

int get_packet_list_length(int length, packet_node_t* node) {
  if (node->next == NULL) {
    return length;
  }
  return get_packet_list_length(length + 1, node->next);
}

// void print_packet_node(packet_node_t* node) {
//   printw("packet: \n");
//   printw("timestamp: %d\n", node->packet_hdr->ts);
//   printw("packet type: %d\n", ethertype((uint8_t*)(node->packet)));
// }

void print_available_devices(pcap_if_t* devices) {
  pcap_if_t* device = devices;
  printf("Available devices are:\n");
  while (device != NULL) {
    printf("  %s\n", device->name);
    device = device->next;
  }
}

void handle_packet(uint8_t* args_unused, const struct pcap_pkthdr* header,
                   const uint8_t* packet) {
  // packet_node_t* new_node = add_packet_node(packet, header, NULL, packet_list);

  options_t *opts = (options_t *)args_unused;

  /*filtering */
  if (!match_protocol(packet, header->len, opts->protocol)) {
      return; 
  }

  printf("Got packet of length %u\n", header->len);
  fflush(stdout);

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
  pcap_if_t* devices;  // all devices
  pcap_if_t* device;   // selected device
  pcap_t* packet_capture_handle;
  int promisc = 1;  // promiscuous mode
  int to_ms = 750;  // read timeout in ms
  // struct pcap_pkthdr hdr;

  // Parse command line options
  options_t options = parse_options(argc, argv);

  // Find all available devices
  if (pcap_findalldevs(&devices, errbuf) == -1) {
    printf("Error finding devices: %s\n", errbuf);
    exit(1);
  }

  // Select device
  if (options.interface == NULL) {
    print_available_devices(devices);
    pcap_freealldevs(devices);
    exit(1);
  } else {
    device = find_device_by_name(devices, options.interface);
    if (device == NULL) {
      printf("Device '%s' not found\n", options.interface);
      print_available_devices(devices);
      pcap_freealldevs(devices);
      exit(1);
    }
  }

  // TODO: Allow for reading packets from pathname using pcap_open_offline, and
  // pcap_fopen_offline()

  // TODO: Can filter using pcap_compile and pcap_setfilter

  printf("Capturing packets on device: %s\n", options.interface);

  packet_capture_handle =
      pcap_open_live(options.interface, BUFSIZ, promisc, to_ms, errbuf);

  if (packet_capture_handle == NULL) {
    printf("Error opening device '%s': %s\n", options.interface, errbuf);
    exit(1);
  }

  // Initiate ncurses
  // initscr();
  // noecho();
  // cbreak();
  // keypad(stdscr, TRUE);

  printf("pcap_open_live succeeded, starting capture loop\n");

  // -1 means to sniff until error occurs
  int rc = pcap_loop(packet_capture_handle, -1, handle_packet, (u_char *)&options);
  printf("pcap_loop returned with code %d\n", rc);

  // Close session
  pcap_close(packet_capture_handle);

  // Free device list
  pcap_freealldevs(devices);
  return 0;
}