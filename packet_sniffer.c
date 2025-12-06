#include "packet_sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <ncurses.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sorting.h"
#include "tcp_reassembly.h"
#include "utils.h"

#define MAX_ROWS 30000
#define MAX_COLS 120
#define TS_WINDOW_SEC 1.0

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

char* usage =
    "Usage: "
    "%s [-i [interface]] [-o <filename>] [-p <protocol>] [-t <duration>] [-h]\n"
    "  -i [interface]   Interface to sniff on\n"
    "                   If interface is omitted, lists available interfaces\n"
    "  -o <filename>    File to save captured packets (default=stdout)\n"
    "  -p <protocol>    Protocol to filter (default=any)\n"
    "  -t <duration>    Duration to sniff in seconds (default=unlimited)\n"
    "  -h               View usage information\n";

typedef struct ts_bin {
  double start_time;

  uint64_t pkt_count;
  uint64_t byte_count;

  uint64_t ipv4_count;
  uint64_t arp_count;

  uint64_t tcp_count;
  uint64_t udp_count;
  uint64_t icmp_count;

  uint64_t http_count;

  struct ts_bin* next;
} ts_bin_t;

static uint64_t total_pkts = 0;
static uint64_t total_bytes = 0;
static uint64_t total_ipv4_count = 0;
static uint64_t total_arp_count = 0;
static uint64_t total_tcp_count = 0;
static uint64_t total_udp_count = 0;
static uint64_t total_icmp_count = 0;
static uint64_t total_http_count = 0;

static ts_bin_t* ts_head = NULL;
static ts_bin_t* ts_tail = NULL;
static pthread_mutex_t ts_lock = PTHREAD_MUTEX_INITIALIZER;

/* Global Variables */
packet_node_t* packet_list = NULL;
packet_node_t* last_node = NULL;
int pad_length = 0;
pcap_t* packet_capture_handle;
WINDOW* pad = NULL;
WINDOW* win_title = NULL;
WINDOW* info_pad = NULL;
WINDOW* win_key = NULL;
WINDOW* stats = NULL;
WINDOW* win_packet_num = NULL;
int current_line = 0;
int previous_line = -1;
int top_line = 0;
int current_info_line = 0;
int max_info_lines = 0;
int exceeded_max_rows = 0;
pthread_t key_event_thread;
const int PACKET_NUM_INDEX = 0;
const int TIME_INDEX = 10;
const int SOURCE_INDEX = 30;
const int DESTINATION_INDEX = 60;
const int PROTOCOL_INDEX = 90;
const int LENGTH_INDEX = 105;
const int STATS_X = 0;
const int STATS_Y = 0;
const int STATS_ROWS = 4;
const int STATS_COLS = MAX_COLS;
const int PAD_ROWS_TO_DISPLAY = 15;
const int INFO_ROWS_TO_DISPLAY = 15;
const int INFO_PAD_ROWS = 100;
const int INFO_PAD_COLS = 80;
const int TITLE_PAD_ROWS = 1;
const int TITLE_PAD_X = 0;
const int TITLE_PAD_Y = STATS_Y + STATS_ROWS;
const int PAD_X = 0;
const int PAD_Y = TITLE_PAD_Y + 2;
const int PACKET_NUM_ROWS = 2;
const int PACKET_NUM_COLS = 50;
const int PACKET_NUM_X = 0;
const int PACKET_NUM_Y = PAD_Y + PAD_ROWS_TO_DISPLAY + 3;
const int INFO_PAD_X = 0;
const int INFO_PAD_Y = PACKET_NUM_Y + PACKET_NUM_ROWS + 1;
const int KEY_X = 80;
const int KEY_Y = PACKET_NUM_Y;
const int KEY_ROWS = 15;
const int KEY_COLS = MAX_COLS - KEY_X;

/* Command Line Argument Functions */
pthread_mutex_t packet_list_lock = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
  SORT_BY_NUMBER,
  SORT_BY_TIME,
  SORT_BY_SRC,
  SORT_BY_DST,
  SORT_BY_PROTO,
  SORT_BY_LENGTH,
  SORT_BY_INFO
} sort_key_t;

static sort_key_t current_sort_key = SORT_BY_NUMBER;
static int current_sort_ascending = 1;

static int packet_list_count(packet_node_t* head) {
  int n = 0;
  while (head) {
    n++;
    head = head->next;
  }
  return n;
}

static void packet_list_to_array(packet_node_t* head, packet_node_t** arr,
                                 int n) {
  int i = 0;
  while (head && i < n) {
    arr[i++] = head;
    head = head->next;
  }
}

static packet_node_t* array_to_packet_list(packet_node_t** arr, int n) {
  if (n == 0) return NULL;

  for (int i = 0; i < n; i++) {
    packet_node_t* prev = (i > 0) ? arr[i - 1] : NULL;
    packet_node_t* next = (i < n - 1) ? arr[i + 1] : NULL;
    arr[i]->prev = prev;
    arr[i]->next = next;
  }
  return arr[0];
}

static int cmp_double(double a, double b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

static int cmp_uint32(uint32_t a, uint32_t b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

static int packet_node_cmp(packet_node_t* a, packet_node_t* b) {
  int result = 0;

  switch (current_sort_key) {
    case SORT_BY_NUMBER:
      if (a->number < b->number)
        result = -1;
      else if (a->number > b->number)
        result = 1;
      else
        result = 0;
      break;

    case SORT_BY_TIME:
      result = cmp_double(a->time_rel, b->time_rel);
      break;

    case SORT_BY_SRC:
      result = cmp_uint32(a->src_ip, b->src_ip);
      break;

    case SORT_BY_DST:
      result = cmp_uint32(a->dst_ip, b->dst_ip);
      break;

    case SORT_BY_PROTO:
      if (a->proto < b->proto)
        result = -1;
      else if (a->proto > b->proto)
        result = 1;
      else
        result = 0;
      break;

    case SORT_BY_LENGTH:
      if (a->length < b->length)
        result = -1;
      else if (a->length > b->length)
        result = 1;
      else
        result = 0;
      break;

    case SORT_BY_INFO:
      if (!a->info && !b->info)
        result = 0;
      else if (!a->info)
        result = -1;
      else if (!b->info)
        result = 1;
      else
        result = strcmp(a->info, b->info);
      break;
  }

  if (!current_sort_ascending) result = -result;

  return result;
}

static int packet_cmp(const void* pa, const void* pb) {
  const packet_node_t* a = *(const packet_node_t* const*)pa;
  const packet_node_t* b = *(const packet_node_t* const*)pb;

  return packet_node_cmp((packet_node_t*)a, (packet_node_t*)b);
}

void sort_packet_list(sort_key_t key, int ascending) {
  pthread_mutex_lock(&packet_list_lock);

  int n = packet_list_count(packet_list);
  if (n <= 1) {
    pthread_mutex_unlock(&packet_list_lock);
    return;
  }

  packet_node_t** arr = malloc(n * sizeof(packet_node_t*));
  if (!arr) {
    pthread_mutex_unlock(&packet_list_lock);
    return;
  }

  packet_list_to_array(packet_list, arr, n);

  current_sort_key = key;
  current_sort_ascending = ascending ? 1 : 0;

  qsort(arr, n, sizeof(packet_node_t*), packet_cmp);

  packet_list = array_to_packet_list(arr, n);

  free(arr);

  pthread_mutex_unlock(&packet_list_lock);
}

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

packet_node_t* create_packet_node(const uint8_t* packet,
                                  const struct pcap_pkthdr* packet_hdr,
                                  unsigned int number, double rel_time) {
  packet_node_t* node = malloc(sizeof(packet_node_t));
  if (!node) {
    return NULL;
  }

  // copy header and length
  node->hdr = *packet_hdr;
  node->length = packet_hdr->len;

  // copy bytes from packer
  node->packet = malloc(packet_hdr->len);
  if (!node->packet) {
    free(node);
    return NULL;
  }
  memcpy(node->packet, packet, packet_hdr->len);

  node->number = number;
  node->time_rel = rel_time;

  node->src_ip = 0;
  node->dst_ip = 0;
  node->proto = 0;
  memset(node->ar_sha, 0, ETHER_ADDR_LEN);
  memset(node->ar_tha, 0, ETHER_ADDR_LEN);

  // IP handling
  if (packet_hdr->len >= sizeof(ethernet_hdr_t)) {
    uint16_t ethtype_val = ethertype(node->packet);
    if (ethtype_val == ethertype_ip &&
        packet_hdr->len >= sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t)) {
      const ip_hdr_t* ip =
          (const ip_hdr_t*)(node->packet + sizeof(ethernet_hdr_t));

      node->src_ip = ntohl(ip->ip_src);
      node->dst_ip = ntohl(ip->ip_dst);
      node->proto = ip->ip_p;
    } else if (ethtype_val == ethertype_arp &&
               packet_hdr->len >= sizeof(ethernet_hdr_t) + sizeof(arp_hdr_t)) {
      arp_hdr_t* arp_hdr = (arp_hdr_t*)(node->packet + sizeof(ethernet_hdr_t));
      node->proto = (uint8_t)ethertype_arp;
      node->src_ip = ntohl(arp_hdr->ar_sip);
      node->dst_ip = ntohl(arp_hdr->ar_tip);
      memcpy(node->ar_sha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(node->ar_tha, arp_hdr->ar_tha, ETHER_ADDR_LEN);
    } else {
      node->proto = ethtype_val;
    }
  }

  node->proto = get_protocol(node->packet);
  node->info = format_hdrs_to_string(node->packet, node->length);
  node->http_msg = NULL;

  node->next = NULL;
  node->prev = NULL;

  return node;
}

void get_position_for_new_node(packet_node_t* new_node, packet_node_t** prev,
                               packet_node_t** next) {
  packet_node_t* a = NULL;
  packet_node_t* b = new_node;
  packet_node_t* c = packet_list;

  if (b == NULL || c == NULL) {
    *prev = NULL;
    *next = NULL;
    return;
  }

  // Traverse through list to determine where to insert new node
  while (c != NULL) {
    if (packet_node_cmp(b, c) != 1) {
      *prev = a;
      *next = c;
      return;
    }
    a = c;
    c = c->next;
  }
  *prev = a;
  *next = c;
}

void add_to_packet_list(packet_node_t* node) {
  packet_node_t* prev = NULL;
  packet_node_t* next = NULL;

  // Get prev and next values for new node
  get_position_for_new_node(node, &prev, &next);

  // Add to packet list
  node->prev = prev;
  node->next = next;

  // Update other nodes to point to new node
  if (prev) {
    prev->next = node;
  }
  if (next) {
    next->prev = node;
  }

  // If node is at the beginning of the list, set it at the head
  if (packet_list == next || packet_list == NULL) {
    packet_list = node;
  }

  // If node is at the end of list, set it as the last node
  if (last_node == prev || last_node == NULL) {
    last_node = node;
  }
}

void delete_packet_nodes(packet_node_t* node) {
  pthread_mutex_lock(&packet_list_lock);
  while (node) {
    packet_node_t* next = node->next;
    free(node->packet);
    if (node->info) {
      free(node->info);
    }
    if (node->http_msg) {
      free_http_message(node->http_msg);
    }
    free(node);
    node = next;
  }
  pthread_mutex_unlock(&packet_list_lock);
}

int get_packet_list_length(int length, packet_node_t* node) {
  if (node->next == NULL) {
    return length;
  }
  return get_packet_list_length(length + 1, node->next);
}

packet_node_t* get_packet_by_index(int index) {
  int count = 0;
  packet_node_t* node = packet_list;
  while (node->next != NULL && count < index) {
    node = node->next;
    count += 1;
  }
  return node;
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
  // Make sure current line is visible
  if (current_line < 0) {
    current_line = 0;
  } else if (current_line >= pad_length) {
    current_line = pad_length - 1;
  }

  // Highlight the current line
  if (has_colors()) {
    mvwchgat(pad, current_line, 0, -1, A_REVERSE, 1, NULL);
  }

  // Move the view of the pad if the current line isn't visible
  if (current_line < top_line) {
    top_line = current_line;
  }
  if (current_line > top_line + PAD_ROWS_TO_DISPLAY - 1) {
    top_line = current_line - PAD_ROWS_TO_DISPLAY + 1;
  }

  // Refresh the pad
  prefresh(pad, top_line, 0, PAD_Y, PAD_X, PAD_Y + PAD_ROWS_TO_DISPLAY - 1,
           MAX_COLS - 1);
}

void print_pad_row(packet_node_t* node) {
  // Highlight current row
  if (has_colors() && pad_length == current_line) {
    attron(COLOR_PAIR(1));
  }

  // Print number and time
  char buf[100];
  mvwprintw(pad, pad_length, PACKET_NUM_INDEX, "%u", node->number);
  mvwprintw(pad, pad_length, TIME_INDEX, "%lf", node->time_rel);

  // Print source and destination
  char src[120];
  char dst[120];
  uint8_t proto = node->proto;
  if (proto == ARP) {
    convert_addr_eth_to_str(node->ar_sha, src);
    convert_addr_eth_to_str(node->ar_tha, dst);
  } else if (proto == ICMP || proto == TCP || proto == UDP || proto == IPV4 ||
             proto == HTTP) {
    convert_addr_ip_int_to_str(node->src_ip, src);
    convert_addr_ip_int_to_str(node->dst_ip, dst);
  } else {
    // TODO handle other cases
  }

  mvwprintw(pad, pad_length, SOURCE_INDEX, "%s", src);
  mvwprintw(pad, pad_length, DESTINATION_INDEX, "%s", dst);

  // Print protocol
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
  } else if (proto == HTTP) {
    sprintf(buf, "%s", "HTTP");
  } else {
    sprintf(buf, "%s", "OTHER");
  }

  mvwprintw(pad, pad_length, PROTOCOL_INDEX, "%s", buf);

  // Print length
  mvwprintw(pad, pad_length, LENGTH_INDEX, "%d", node->length);

  // Turn off highlighting
  if (has_colors() && pad_length == current_line) {
    attroff(COLOR_PAIR(1));
  }

  pad_length += 1;
}

void update_pad() {
  werase(pad);
  pad_length = 0;
  packet_node_t* node = packet_list;

  // Print each row of packet list
  while (node != NULL) {
    print_pad_row(node);
    node = node->next;
  }
  refresh_pad();
}

// check if is ip4
static inline int is_ipv4(const uint8_t* pkt, uint32_t caplen) {
  if (caplen < sizeof(ethernet_hdr_t)) return 0;
  return ethertype((uint8_t*)pkt) == ethertype_ip;
}

// check if arp
static inline int is_arp(const uint8_t* pkt, uint32_t caplen) {
  if (caplen < sizeof(ethernet_hdr_t)) return 0;
  return ethertype((uint8_t*)pkt) == ethertype_arp;
}

// check if http
static int is_http(const uint8_t* pkt, uint32_t caplen) {
  // should be ip
  if (!is_ipv4(pkt, caplen)) return 0;

  const ip_hdr_t* ip = (const ip_hdr_t*)(pkt + sizeof(ethernet_hdr_t));

  // should be tcp
  if (ip->ip_p != 6) return 0;

  uint32_t ip_hdr_len = ip->ip_hl * 4;
  uint32_t offset = sizeof(ethernet_hdr_t) + ip_hdr_len;

  if (caplen < offset + sizeof(tcp_hdr_t)) return 0;

  const tcp_hdr_t* tcp =
      (const tcp_hdr_t*)(pkt + sizeof(ethernet_hdr_t) + ip_hdr_len);

  uint16_t sport = ntohs(tcp->tcp_src);
  uint16_t dport = ntohs(tcp->tcp_dst);

  // check the ports
  if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080 ||
      sport == 8000 || dport == 8000)
    return 1;

  // check methid
  uint32_t tcp_hdr_len = tcp->tcp_off * 4;
  uint32_t payload_offset = offset + tcp_hdr_len;
  if (payload_offset >= caplen) return 0;

  const char* pl = (const char*)(pkt + payload_offset);
  uint32_t plen = caplen - payload_offset;

  if (plen >= 3 && (!memcmp(pl, "GET", 3) || !memcmp(pl, "PUT", 3) ||
                    !memcmp(pl, "POST", 4) || !memcmp(pl, "HEAD", 4) ||
                    !memcmp(pl, "HTTP", 4)))
    return 1;

  return 0;
}

// make new bins
static ts_bin_t* ts_make_bin_for_time(double t_rel) {
  if (!ts_head) {
    ts_bin_t* bin = calloc(1, sizeof(ts_bin_t));
    if (!bin) return NULL;
    bin->start_time = floor(t_rel / TS_WINDOW_SEC) * TS_WINDOW_SEC;
    ts_head = ts_tail = bin;
    return bin;
  }

  while (t_rel >= ts_tail->start_time + TS_WINDOW_SEC) {
    ts_bin_t* bin = calloc(1, sizeof(ts_bin_t));
    if (!bin) return ts_tail;
    bin->start_time = ts_tail->start_time + TS_WINDOW_SEC;
    ts_tail->next = bin;
    ts_tail = bin;
  }

  return ts_tail;
}

static void ts_update(double t_rel, const uint8_t* packet,
                      const struct pcap_pkthdr* hdr) {
  pthread_mutex_lock(&ts_lock);

  ts_bin_t* bin = ts_make_bin_for_time(t_rel);
  if (!bin) {
    pthread_mutex_unlock(&ts_lock);
    return;
  }

  bin->pkt_count++;
  bin->byte_count += hdr->len;

  total_pkts++;
  total_bytes += hdr->len;

  // l1
  if (is_ipv4(packet, hdr->len)) {
    bin->ipv4_count++;
    total_ipv4_count++;
  } else if (is_arp(packet, hdr->len)) {
    bin->arp_count++;
    total_arp_count++;
  }

  // l4
  uint8_t p = 0;
  if (is_ipv4(packet, hdr->len)) {
    const ip_hdr_t* ip = (const ip_hdr_t*)(packet + sizeof(ethernet_hdr_t));
    p = ip->ip_p;

    if (p == 6) {
      bin->tcp_count++;
      total_tcp_count++;
    } else if (p == 17) {
      bin->udp_count++;
      total_udp_count++;
    } else if (p == 1) {
      bin->icmp_count++;
      total_icmp_count++;
    }
  }

  /* HTTP */
  if (is_http(packet, hdr->len)) {
    bin->http_count++;
    total_http_count++;
  }

  pthread_mutex_unlock(&ts_lock);
}

void refresh_stats_window() {
  wrefresh(stats);
  // mvwprintw(stats, 0, 0, "Packets: %d", total_pkts);
  // mvwprintw(stats, 0, 20, "Bytes: %d", total_bytes);
  // mvwprintw(stats, 0, 40, "IPv4: %d", total_ipv4_count);
  // mvwprintw(stats, 0, 60, "ARP: %d", total_arp_count);
  // mvwprintw(stats, 0, 80, "TCP: %d", total_tcp_count);
  // mvwprintw(stats, 0, 100, "UDP: %d", total_udp_count);
  // mvwprintw(stats, 1, 0, "ICMP: %d", total_icmp_count);
  // mvwprintw(stats, 1, , "OTHER L4: %d", total_other_l4);
  // mvwprintw(stats, 1, 100, "HTTP: %d", total_http_count);
  mvwprintw(stats, 0, 0, "Packets");
  mvwprintw(stats, 0, 12, "IPv4");
  mvwprintw(stats, 0, 22, "ARP");
  mvwprintw(stats, 0, 32, "TCP");
  mvwprintw(stats, 0, 42, "UDP");
  mvwprintw(stats, 0, 52, "ICMP");
  mvwprintw(stats, 0, 62, "HTTP");
  mvwprintw(stats, 0, 72, "Bytes");
  mvwprintw(stats, 1, 0, "%d", total_pkts);
  mvwprintw(stats, 1, 12, "%d", total_ipv4_count);
  mvwprintw(stats, 1, 22, "%d", total_arp_count);
  mvwprintw(stats, 1, 32, "%d", total_tcp_count);
  mvwprintw(stats, 1, 42, "%d", total_udp_count);
  mvwprintw(stats, 1, 52, "%d", total_icmp_count);
  mvwprintw(stats, 1, 62, "%d", total_http_count);
  mvwprintw(stats, 1, 72, "%d", total_bytes);
  wmove(stats, 3, 0);
  whline(stats, '-', MAX_COLS);
  wrefresh(stats);
}

void create_stats_window() {
  // Print header of table for packet list
  stats = newwin(STATS_ROWS, STATS_COLS, STATS_Y, STATS_X);
  werase(stats);
  refresh_stats_window();
}

void delete_windows() {
  if (pad != NULL) {
    werase(pad);
    delwin(pad);
  }
  if (win_title != NULL) {
    werase(win_title);
    delwin(win_title);
  }
  if (info_pad != NULL) {
    werase(info_pad);
    delwin(info_pad);
  }
  if (win_key != NULL) {
    werase(win_key);
    delwin(win_key);
  }
  if (win_packet_num != NULL) {
    werase(win_packet_num);
    delwin(win_packet_num);
  }
  if (stats != NULL) {
    werase(stats);
    delwin(stats);
  }
  endwin();
}

void close_program() {
  // Free packet list
  if (packet_list != NULL) {
    delete_packet_nodes(packet_list);
  }

  // Exit key event thread
  pthread_cancel(key_event_thread);
  pthread_join(key_event_thread, NULL);

  // Close ncurses window
  delete_windows();

  // Close session
  pcap_close(packet_capture_handle);

  if (exceeded_max_rows) {
    printf("Reached maximum number of packets %d\n", MAX_ROWS);
  }

  printf("Closing packet sniffer \n");
  exit(0);
}

void handle_packet(uint8_t* args, const struct pcap_pkthdr* header,
                   const uint8_t* packet) {
  options_t* opts = (options_t*)args;

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

  double t = (header->ts.tv_sec - first_ts.tv_sec) +
             (header->ts.tv_usec - first_ts.tv_usec) / 1e6;

  ts_update(t, packet, header);

  // create and add to packet list
  pthread_mutex_lock(&packet_list_lock);
  packet_node_t* new_node = create_packet_node(packet, header, packet_count, t);
  add_to_packet_list(new_node);
  pthread_mutex_unlock(&packet_list_lock);

  if (match_protocol(packet, header->len, "tcp")) {
    // fprintf(stderr, "Processing TCP packet number %u\n", packet_count);
    process_tcp_packet(new_node);
  }

  if (!new_node) {
    // mem fail
    return;
  }

  if (!first_ts_set) {
    packet_list = new_node;
    last_node = new_node;
    first_ts_set = 1;
  }

  if (get_packet_list_length(0, packet_list) >= MAX_ROWS) {
    exceeded_max_rows = 1;
    close_program();
  }

  // Update pad display with new packet
  update_pad();

  // Update stats
  refresh_stats_window();
}

void display_sniffer_header() {
  // Print header of table for packet list
  win_title = newwin(TITLE_PAD_ROWS, MAX_COLS, TITLE_PAD_Y, TITLE_PAD_X);
  werase(win_title);
  wrefresh(win_title);
  mvwprintw(win_title, 0, PACKET_NUM_INDEX, "Number");
  mvwprintw(win_title, 0, TIME_INDEX, "Time");
  mvwprintw(win_title, 0, SOURCE_INDEX, "Source");
  mvwprintw(win_title, 0, DESTINATION_INDEX, "Destination");
  mvwprintw(win_title, 0, PROTOCOL_INDEX, "Protocol");
  mvwprintw(win_title, 0, LENGTH_INDEX, "Length");

  wrefresh(win_title);
}

void display_packet_number() {
  // Print title containing packet number
  win_packet_num =
      newwin(PACKET_NUM_ROWS, PACKET_NUM_COLS, PACKET_NUM_Y, PACKET_NUM_X);
  werase(win_packet_num);
  wrefresh(win_packet_num);
  mvwprintw(win_packet_num, 0, 0, "  PACKET INFORMATION");
  wmove(win_packet_num, 1, 0);
  whline(win_packet_num, '-', PACKET_NUM_COLS - 1);
  wrefresh(win_packet_num);
}

void display_key_window() {
  // Print list of key commands
  win_key = newwin(KEY_ROWS, KEY_COLS, KEY_Y, KEY_X);
  werase(win_key);
  wrefresh(win_key);
  box(win_key, '|', '-');
  mvwprintw(win_key, 0, 0, "KEY COMMANDS");
  mvwprintw(win_key, 1, 2, "UP KEY");
  mvwprintw(win_key, 1, 13, "Scroll Up");
  mvwprintw(win_key, 2, 2, "DOWN KEY");
  mvwprintw(win_key, 2, 13, "Scroll Down");
  mvwprintw(win_key, 3, 2, "1");
  mvwprintw(win_key, 3, 13, "Sort by Number");
  mvwprintw(win_key, 4, 2, "2");
  mvwprintw(win_key, 4, 13, "Sort by Time");
  mvwprintw(win_key, 5, 2, "3");
  mvwprintw(win_key, 5, 13, "Sort by Source");
  mvwprintw(win_key, 6, 2, "4");
  mvwprintw(win_key, 6, 13, "Sort by Destination");
  mvwprintw(win_key, 7, 2, "5");
  mvwprintw(win_key, 7, 13, "Sort by Protocol");
  mvwprintw(win_key, 8, 2, "6");
  mvwprintw(win_key, 8, 13, "Sort by Length");
  mvwprintw(win_key, 9, 2, "7");
  mvwprintw(win_key, 9, 13, "Sort by Packet Info");
  mvwprintw(win_key, 10, 2, "a");
  mvwprintw(win_key, 10, 13, "Sort in Ascending Order");
  mvwprintw(win_key, 11, 2, "d");
  mvwprintw(win_key, 11, 13, "Sort in Descending Order");
  mvwprintw(win_key, 12, 2, "LEFT KEY");
  mvwprintw(win_key, 12, 13, "Scroll Up on Packet Info");
  mvwprintw(win_key, 13, 2, "RIGHT KEY");
  mvwprintw(win_key, 13, 13, "Scroll Down on Packet Info");
  wrefresh(win_key);
}

void refresh_info_pad() {
  wclrtoeol(info_pad);
  prefresh(info_pad, current_info_line, 0, INFO_PAD_Y, INFO_PAD_X,
           INFO_PAD_Y + INFO_ROWS_TO_DISPLAY - 1, INFO_PAD_COLS - 1);
}

void display_header_info() {
  // Print header information for current line
  if (!(packet_list != NULL && current_line >= 0 &&
        current_line < get_packet_list_length(0, packet_list))) {
    return;
  }

  packet_node_t* node = get_packet_by_index(current_line);
  if (node == NULL) {
    return;
  }

  // Display packet number title
  werase(win_packet_num);
  mvwprintw(win_packet_num, 0, 0, "  PACKET NUMBER %d", node->number);
  wmove(win_packet_num, 1, 0);
  whline(win_packet_num, '-', PACKET_NUM_COLS - 1);
  wrefresh(win_packet_num);

  current_info_line = 0;
  werase(info_pad);
  wrefresh(info_pad);
  // mvwprintw(info_pad, 0, 0, "%s", node->info);
  char* info = node->info;
  int info_length = strlen(info);
  char buf[info_length + 1];
  char line[info_length + 1];
  int line_count = 0;

  sprintf(buf, "%s", "");
  sprintf(line, "%s", "");

  max_info_lines = 0;
  for (int i = 0; i < info_length; i++) {
    if (info[i] == '\n') {
      mvwprintw(info_pad, line_count, 0, "%s", line);
      line_count += 1;
      sprintf(buf, "%s", "");
      sprintf(line, "%s", "");
      max_info_lines += 1;
    } else {
      buf[0] = info[i];
      buf[1] = '\0';
      strcat(line, buf);
    }
  }

  if (node->proto == HTTP && node->http_msg != NULL) {
    if (node->http_msg->segment_count > 1) {
      mvwprintw(info_pad, line_count, 0,
                "[%d Reassembled TCP segments (%u bytes)]",
                node->http_msg->segment_count,
                node->http_msg->header_len + node->http_msg->data_len);
      line_count += 1;
      max_info_lines += 1;
      tcp_segment_t* segment = node->http_msg->segments;
      while (segment != NULL) {
        mvwprintw(info_pad, line_count, 0, "\tFrame %u (Payload: %u bytes)",
                  segment->id, segment->len);
        segment = segment->next;
        line_count += 1;
        max_info_lines += 1;
      }
    }

    mvwprintw(info_pad, line_count, 0, "%s", "HTTP header:");
    line_count += 1;
    max_info_lines += 1;

    char* http_info = http_hdr_to_str(node->http_msg);
    if (http_info != NULL) {
      int http_info_len = strlen(http_info);
      sprintf(buf, "\t%s", "");
      sprintf(line, "%s", "");
      for (int i = 0; i < http_info_len; i++) {
        if (http_info[i] == '\n') {
          mvwprintw(info_pad, line_count, 0, "\t%s", line);
          line_count += 1;
          sprintf(buf, "%s", "");
          sprintf(line, "%s", "");
          max_info_lines += 1;
        } else {
          buf[0] = http_info[i];
          buf[1] = '\0';
          strcat(line, buf);
        }
      }
      free(http_info);
    }
  }

  refresh_info_pad();
}

void create_header_info_pad() {
  // Initialize pad for header info
  info_pad = newpad(INFO_PAD_ROWS, MAX_COLS);
  wattron(pad, COLOR_PAIR(2));

  if (info_pad == NULL) {
    endwin();
    fprintf(stderr, "Error creating info pad: %s\n", strerror(errno));
    exit(1);
  }

  // Packet Info title
  werase(info_pad);
  prefresh(info_pad, current_info_line, 0, INFO_PAD_Y, INFO_PAD_X,
           INFO_PAD_Y + INFO_ROWS_TO_DISPLAY - 1, INFO_PAD_COLS - 1);
}

/* ncurses dynamic terminal */
void initialize_windows() {
  // Initialize packets pad
  pad = newpad(MAX_ROWS, MAX_COLS);
  wattron(pad, COLOR_PAIR(2));

  if (pad == NULL) {
    endwin();
    fprintf(stderr, "Error creating pad: %s\n", strerror(errno));
    exit(1);
  }

  // Initialize window for stats
  create_stats_window();

  // Initialize header with titles for columns
  display_sniffer_header();

  // Initialize window for packet number
  display_packet_number();

  // Initialize pad with header info
  create_header_info_pad();

  // Initialize window for keyboard legend
  display_key_window();
}

void update_after_key_press() {
  if (has_colors()) {
    mvwchgat(pad, current_line, 0, -1, A_REVERSE, 1, NULL);
    mvwchgat(pad, previous_line, 0, -1, A_NORMAL, 2, NULL);
  }
  refresh_pad();
  display_header_info();
}

void handle_sort() {
  sort_packet_list(current_sort_key, current_sort_ascending);
  current_line = 0;
  update_pad();
  update_after_key_press();
}

void* handle_key_event(void* arg) {
  int key;
  while (1) {
    key = wgetch(stdscr);
    switch (key) {
      case KEY_UP:
        if (current_line <= 0) {
          current_line = 0;
        } else {
          previous_line = current_line;
          current_line -= 1;
        }
        update_after_key_press();
        break;
      case KEY_DOWN:
        if (current_line >= MAX_ROWS) {
          current_line = MAX_ROWS;
        } else {
          previous_line = current_line;
          current_line += 1;
        }
        update_after_key_press();
        break;
      case '1':
        current_sort_key = SORT_BY_NUMBER;
        handle_sort();
        break;
      case '2':
        current_sort_key = SORT_BY_TIME;
        handle_sort();
        break;
      case '3':
        current_sort_key = SORT_BY_SRC;
        handle_sort();
        break;
      case '4':
        current_sort_key = SORT_BY_DST;
        handle_sort();
        break;
      case '5':
        current_sort_key = SORT_BY_PROTO;
        handle_sort();
        break;
      case '6':
        current_sort_key = SORT_BY_LENGTH;
        handle_sort();
        break;
      case '7':
        current_sort_key = SORT_BY_INFO;
        handle_sort();
        break;
      case 'a':
        current_sort_ascending = 1;
        handle_sort();
        break;
      case 'A':
        current_sort_ascending = 1;
        handle_sort();
        break;
      case 'd':
        current_sort_ascending = 0;
        handle_sort();
        break;
      case 'D':
        current_sort_ascending = 0;
        handle_sort();
        break;
      case KEY_LEFT:
        if (current_info_line <= 0) {
          current_info_line = 0;
        } else {
          current_info_line -= 1;
        }
        refresh_info_pad();
        break;
      case KEY_RIGHT:
        if (current_info_line >= max_info_lines - INFO_ROWS_TO_DISPLAY) {
          current_info_line = max_info_lines - INFO_ROWS_TO_DISPLAY;
        } else {
          current_info_line += 1;
        }
        refresh_info_pad();
        break;
      default:
        break;
    }
  }
}

/* Handling Ctrl-C */
void handle_signal(int signal) { close_program(); }

void handle_resize_signal(int signal) {
  delete_windows();
  initialize_windows();
  update_after_key_press();
}

int main(int argc, char* argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t* devices;  // all devices
  pcap_if_t* device;   // selected device
  int promisc = 1;     // promiscuous mode
  int to_ms = 750;     // read timeout in ms
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

  // Handle resizing
  signal(SIGWINCH, handle_resize_signal);

  // Initiate ncurses
  initscr();
  if (has_colors()) {
    start_color();
    init_pair(1, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(2, COLOR_WHITE, COLOR_BLACK);
  }
  noecho();
  cbreak();
  keypad(stdscr, TRUE);

  int terminal_y, terminal_x;
  getmaxyx(stdscr, terminal_y, terminal_x);

  if (terminal_x < MAX_COLS || terminal_y < INFO_PAD_Y + INFO_ROWS_TO_DISPLAY) {
    endwin();
    printf(
        "Increase terminal size and run again in order to view packets "
        "properly\n");
    exit(0);
  }

  // Start checking for key commands
  pthread_create(&key_event_thread, NULL, handle_key_event, NULL);

  // Setup windows
  initialize_windows();

  // -1 means to sniff until error occurs
  int rc =
      pcap_loop(packet_capture_handle, -1, handle_packet, (uint8_t*)&options);
  printf("pcap_loop returned with code %d\n", rc);

  // Close session
  pcap_close(packet_capture_handle);

  // Free device list
  pcap_freealldevs(devices);
  free_all_tcp_streams();
  return 0;
}