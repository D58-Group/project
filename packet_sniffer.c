#include <errno.h>
#include <ncurses.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sr_utils.h"
#include "sorting.h"
#include <arpa/inet.h> 
#include "sr_protocol.h"


#define MAX_ROWS 10000
#define MAX_COLS 140

/* Packet Node Structure */
struct packet_node {
  uint8_t *packet;
  struct pcap_pkthdr hdr;      
  struct packet_node *prev;
  struct packet_node *next;

  unsigned int number;         
  double time_rel;             

  uint32_t src_ip;             
  uint32_t dst_ip;
  enum protocol proto;

  unsigned char ar_sha[ETHER_ADDR_LEN];
  unsigned char ar_tha[ETHER_ADDR_LEN];

  uint32_t length;             
  
  char *info; 

};
typedef struct packet_node packet_node_t;

/* Global Variables */
packet_node_t *packet_list = NULL;
packet_node_t *first_node = NULL;
int pad_length = 0;
WINDOW *pad = NULL;
WINDOW *win_title = NULL;
int current_line = 0;
int previous_line = -1;
pthread_t key_event_thread;
const int PACKET_NUM_INDEX = 0;
const int TIME_INDEX = 10;
const int SOURCE_INDEX = 30;
const int DESTINATION_INDEX = 60;
const int PROTOCOL_INDEX = 90;
const int LENGTH_INDEX = 110;

/* Command Line Argument Functions */

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
  memset(node->ar_sha, 0, ETHER_ADDR_LEN);
  memset(node->ar_tha, 0, ETHER_ADDR_LEN);

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
    } else if (ethtype_val == ethertype_arp &&
      packet_hdr->len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(node->packet + sizeof(sr_ethernet_hdr_t));
      node->proto = (uint8_t)ethertype_arp;
      node->src_ip = ntohl(arp_hdr->ar_sip);
      node->dst_ip = ntohl(arp_hdr->ar_tip);
      memcpy(node->ar_sha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(node->ar_tha, arp_hdr->ar_tha, ETHER_ADDR_LEN);
    }
    else {
      node->proto = ethtype_val;
    }
  }

  node->proto = get_protocol(node->packet);

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

void refresh_pad() {
  if (current_line < 0) {
    current_line = 0;
  } else if (current_line >= pad_length) {
    current_line = pad_length - 1;
  }
  if (has_colors()) {
     mvwchgat(pad, current_line, 0, -1, A_REVERSE, 1, NULL);
  }
  prefresh(pad, current_line, 0, 2, 0, 20, MAX_COLS - 1);
}

void print_pad_row(packet_node_t *node){
  if (has_colors() && pad_length == current_line) {
    attron(COLOR_PAIR(1));
  }
  char buf[100];
  mvwprintw(pad, pad_length, PACKET_NUM_INDEX, "%u", node->number);
  mvwprintw(pad, pad_length, TIME_INDEX, "%lf", node->time_rel);

  char src[120];
  char dst[120];
  uint8_t proto = node->proto;
  if (proto == ARP) {
    convert_addr_eth_to_str(node->ar_sha, src);
    convert_addr_eth_to_str(node->ar_tha, dst);
  } else if (proto == ICMP || TCP || UDP || IPV4) {
    convert_addr_ip_int_to_str(node->src_ip, src);
    convert_addr_ip_int_to_str(node->dst_ip, dst);
  } else {
    // TODO handle other cases
  }

  mvwprintw(pad, pad_length, SOURCE_INDEX, "%s", src);
  mvwprintw(pad, pad_length, DESTINATION_INDEX, "%s", dst);

  if (proto == ARP) {
    sprintf(buf, "%s", "ARP");
  } else if (proto == ICMP) {
    sprintf(buf, "%s", "ICMP");
  } else if (proto == TCP) {
    sprintf(buf, "%s", "TCP");
  } else if (proto == UDP) {
    sprintf(buf, "%s", "UDP");
  } else if (proto == IPV4) {
    sprintf(buf, "%s", "IPv4");
  } else {
    sprintf(buf, "%s", "OTHER");
  }

  mvwprintw(pad, pad_length, PROTOCOL_INDEX, "%s", buf);
  mvwprintw(pad, pad_length, LENGTH_INDEX, "%d", node->length);

  if (has_colors() && pad_length == current_line) {
    attroff(COLOR_PAIR(1));
  }

  pad_length += 1;
}

void update_pad() {
  werase(pad);
  pad_length = 0;
  packet_node_t* node = first_node;
  while (node != NULL) {
    print_pad_row(node);
    node = node->prev;
  }
  refresh_pad();
}

void handle_packet(uint8_t* args, const struct pcap_pkthdr* header,
                   const uint8_t* packet) {
  
  options_t *opts = (options_t *)args;

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

  if (!first_ts_set) {
    first_node = new_node;
    first_ts_set = 1;
  }

  // Update pad display with new packet
  update_pad();
}

void display_sniffer_header() {
  win_title = newwin(1, MAX_COLS, 0, 0);
  werase(win_title);
  wrefresh(win_title);
  // box(win_title, '|', '-');  
  mvwprintw(win_title, 0, PACKET_NUM_INDEX, "Number");
  mvwprintw(win_title, 0, TIME_INDEX, "Time");
  mvwprintw(win_title, 0, SOURCE_INDEX, "Source");
  mvwprintw(win_title, 0, DESTINATION_INDEX, "Destination");
  mvwprintw(win_title, 0, PROTOCOL_INDEX, "Protocol");
  mvwprintw(win_title, 0, LENGTH_INDEX, "Length");
  wrefresh(win_title);
}

/* ncurses dynamic terminal */
void initialize_pad() {
  pad = newpad(MAX_ROWS, MAX_COLS);
  wattron(pad, COLOR_PAIR(2));
  display_sniffer_header();
  refresh_pad();

  if(pad == NULL) {
    endwin();
    fprintf(stderr, "Error creating pad: %s\n", strerror(errno));
    exit(1);
  }
}

void *handle_key_event(void *arg) {
  int key;
  while(1) {
    key = wgetch(stdscr);
    switch(key) {
      case KEY_UP:
        if (current_line <= 0) {
          current_line = 0;
        } else {
          previous_line = current_line;
          current_line -= 1;
        }
        if (has_colors()) {
          mvwchgat(pad, current_line, 0, -1, A_REVERSE, 1, NULL);
          mvwchgat(pad, previous_line, 0, -1, A_NORMAL, 2, NULL);
        }
        refresh_pad();
        break;
      case KEY_DOWN:
        if (current_line >= MAX_ROWS) {
          current_line = MAX_ROWS;
        } else {
          previous_line = current_line;
          current_line += 1;
        }
        if (has_colors()) {
          mvwchgat(pad, current_line, 0, -1, A_REVERSE, 1, NULL);
          mvwchgat(pad, previous_line, 0, -1, A_NORMAL, 2, NULL);
        }
        refresh_pad();
        break;
      default:
        break;
    }
  }
}

void delete_windows() {
  if (pad != NULL) {
    delwin(pad);
  }
  if (win_title != NULL) {
    delwin(win_title);
  }
  endwin();
}

/* Handling Ctrl-C */
void handle_signal(int signal) {
  // Free packet list
  if (packet_list != NULL) {
    delete_packet_nodes(packet_list);
  }


  // Exit key event thread
  pthread_cancel(key_event_thread);
  pthread_join(key_event_thread, NULL);

  int max_cols, max_rows;
  getmaxyx(pad, max_rows, max_cols);

  // Close ncurses window
  delete_windows();
  
  printf("current_line: %d\n", current_line);
  printf("max_rows: %d, max_cols: %d\n", max_rows, max_cols);

  printf("Closing packet sniffer \n");
  exit(0);
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

  // Handle ctrl-c
  signal(SIGINT, handle_signal);

  pthread_create(&key_event_thread, NULL, handle_key_event, NULL);
  
  // Initiate ncurses
  initscr();
  if(has_colors()) {
    start_color();
    init_pair(1, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(2, COLOR_WHITE, COLOR_BLACK);
  }
  noecho();
  cbreak();
  keypad(stdscr, TRUE);

  // Setup pad
  initialize_pad();

  // -1 means to sniff until error occurs
  int rc = pcap_loop(packet_capture_handle, -1, handle_packet, (uint8_t *)&options);
  printf("pcap_loop returned with code %d\n", rc);

  // Close session
  pcap_close(packet_capture_handle);

  // Free device list
  pcap_freealldevs(devices);
  return 0;
}