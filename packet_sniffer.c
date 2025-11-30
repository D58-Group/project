#include "packet_sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ncurses.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sorting.h"
#include "sr_protocol.h"
#include "sr_utils.h"

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
                               packet_node_t* prev,
                               packet_node_t* next,
                               unsigned int number,
                               double rel_time) {
  packet_node_t* node = malloc(sizeof(packet_node_t));
  if (!node) {
    return NULL;
  }

  //copy header and length 
  node->hdr = *packet_hdr;          
  node->length = packet_hdr->len;

  //copy bytes from packer
  node->packet = malloc(packet_hdr->len);
  if (!node->packet) {
    free(node);
    return NULL;
  }
  memcpy(node->packet, packet, packet_hdr->len);

  node->number   = number;
  node->time_rel = rel_time;

  node->src_ip = 0;
  node->dst_ip = 0;
  node->proto  = 0;

  //IP handling
  if (packet_hdr->len >= sizeof(sr_ethernet_hdr_t)) {
    uint16_t ethtype_val = ethertype(node->packet);
    if (ethtype_val == ethertype_ip &&
        packet_hdr->len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {

      const sr_ip_hdr_t *ip =
        (const sr_ip_hdr_t *)(node->packet + sizeof(sr_ethernet_hdr_t));

      node->src_ip = ntohl(ip->ip_src);
      node->dst_ip = ntohl(ip->ip_dst);
      node->proto  = ip->ip_p;
    }
  }

  //add to packet list
  node->prev = prev;
  node->next = next;
  if (next) {
    next->prev = node;
  }
  if (packet_list == next || packet_list == NULL) {
    packet_list = node;
  }
  
  node->info = format_hdrs_to_string(node->packet, node->length);
  return node;
}

void delete_packet_nodes(packet_node_t* node) {
  while (node) {
    packet_node_t* next = node->next;
    free(node->packet);
    if (node->info)
      free(node->info);
    free(node);
    node = next;
  }
}


int get_packet_list_length(int length, packet_node_t* node) {
  if (node->next == NULL) {
    return length;
  }
  return get_packet_list_length(length + 1, node->next);
}

void print_packet_node(packet_node_t* node) {
  printw("packet: \n");
  printw("timestamp: %d\n", (long)node->hdr.ts.tv_sec);
  printw("packet type: %d\n", ethertype((uint8_t*)(node->packet)));
}


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
  
  options_t *opts = (options_t *)args_unused;

  // filter first: only keep packets that match
  if (!match_protocol(packet, header->len, opts->protocol)) {
      return;
  }

  // static state for numbering and time
  static unsigned int packet_count = 0;
  static struct timeval first_ts;
  static int first_ts_set = 0;

  packet_count++;

  if (!first_ts_set) {
    first_ts = header->ts;
    first_ts_set = 1;
  }

  double t = (header->ts.tv_sec  - first_ts.tv_sec) +
             (header->ts.tv_usec - first_ts.tv_usec) / 1e6;

  // add to packet list 
  packet_node_t* new_node =
    add_packet_node(packet, header, NULL, packet_list, packet_count, t);


  if (!new_node) {
    //mem fail
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
  int rc = pcap_loop(packet_capture_handle, -1, handle_packet, (uint8_t *)&options);
  printf("pcap_loop returned with code %d\n", rc);

  // Close session
  pcap_close(packet_capture_handle);

  // Free device list
  pcap_freealldevs(devices);
  return 0;
}