#include <errno.h>
#include <ncurses.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "sr_utils.h"
#include "sr_protocol.h"

#define MAX_ROWS 10000
#define MAX_COLS 180

/* Packet Node Structure */
struct packet_node {
  const uint8_t* packet;
  const struct pcap_pkthdr* packet_hdr;
  struct packet_node* prev;
  struct packet_node* next;
} typedef packet_node_t;

/* Global Variables */
packet_node_t *packet_list = NULL;
int pad_length = 0;
WINDOW *pad = NULL;
WINDOW *win_title = NULL;
int current_line = 0;
pthread_t key_event_thread;
struct timeval start_time;

/* Command Line Argument Functions */
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

/* Packet list functions */
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
    delete_packet_nodes(next);
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

void refresh_pad() {
  if (current_line < 0) {
    current_line = 0;
  } else if (current_line >= pad_length) {
    current_line = pad_length - 1;
  }
   prefresh(pad, current_line, 0, 2, 0, 20, 80);
}

void handle_packet(uint8_t * args_unused, const struct pcap_pkthdr* header,
                   const uint8_t* packet) {
  if (pad_length == 0) {
    start_time = header->ts;
  }
  packet_node_t *new_node = add_packet_node(packet, header, NULL, packet_list);
  // printw("length: %d \n", header->len);
  // printw("list length: %d\n", get_packet_list_length(0, new_node));
  // print_packet_node(new_node);
  // refresh();
  // getch();
  // endwin();
  /* timestamp, type, length, src, dst*/

  // Set start time if it's the first packet

  wmove(pad, pad_length, 2);
  char buf[50];
  struct timeval time_diff;
  timersub(&header->ts, &start_time, &time_diff);
  
  sprintf(buf, "%ld.%06ld", time_diff.tv_sec, time_diff.tv_usec);
  waddstr(pad, buf);

  wmove(pad, pad_length, 20);
  sprintf(buf, "%d", header->len);
  waddstr(pad, buf);

  enum protocol proto = get_protocol(packet);
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
  
  wmove(pad, pad_length, 30);
  // sprintf(buf, "%s", get_protocol(packet));
  waddstr(pad, buf);

  wmove(pad, pad_length, 45);
  char src[120];
  char dst[120];
  get_source_dest(src, dst, packet);
  waddstr(pad, src);
  wmove(pad, pad_length, 70);
  waddstr(pad, dst);



  // int max_cols, max_rows;
  // getmaxyx(pad, max_cols, max_rows);

  refresh_pad();
  pad_length += 1;
}

void display_sniffer_header() {
  win_title = newwin(1, MAX_COLS, 0, 0);
  werase(win_title);
  wrefresh(win_title);
  // box(win_title, '|', '-');  
  mvwprintw(win_title, 0, 0, "Time");
  mvwprintw(win_title, 0, 20, "Length");
  mvwprintw(win_title, 0, 30, "Protocol");
  mvwprintw(win_title, 0, 45, "Source");
  mvwprintw(win_title, 0, 70, "Destination");
  wrefresh(win_title);
}

/* ncurses dynamic terminal */
void initialize_pad() {
  pad = newpad(MAX_ROWS, MAX_COLS);
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
          current_line -= 1;
        }
        refresh_pad();
        break;
      case KEY_DOWN:
        if (current_line >= MAX_ROWS) {
          current_line = MAX_ROWS;
        } else {
          current_line += 1;
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

void display_window() {

}

int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  //   pcap_if_t* device;
  pcap_t *packet_capture_handle;
  int promisc = 1;  // promiscuous mode
  int to_ms = 750;  // read timeout in ms
  // struct pcap_pkthdr hdr;

  // Parse command line options
  options_t options = parse_options(argc, argv);

  printf("Sniffing on interface: %s\n", options.interface);
  printf("Output file: %s\n", options.filename ? options.filename : "stdout");
  printf("Protocol filter: %s\n", options.protocol ? options.protocol : "any");
  printf("Duration: %d\n", options.duration);
  fflush(stdout);

  // List devices and select first device in list
  // pcap_findalldevs(&device, errbuf);  // TODO free list with pcap_freealldevs

  // if (device == NULL) {
  //   printf("Error finding devices, %s", errbuf);
  //   exit(1);
  // }


  // TODO: add option for inputing device name instead of using default

  // TODO: Allow for reading packets from pathname using pcap_open_offline, and
  // pcap_fopen_offline()

  // TODO: Can filter using pcap_compile and pcap_setfilter


  printf("Capturing packets on device: %s\n", options.interface);
  fflush(stdout);

  packet_capture_handle =
      pcap_open_live(options.interface, BUFSIZ, promisc, to_ms, errbuf);

  if (packet_capture_handle == NULL) {
    fprintf(stderr, "Error opening device '%s': %s\n",
            options.interface, errbuf);
    fflush(stderr);
    exit(1);
  }

  // Handle ctrl-c
  signal(SIGINT, handle_signal);

  pthread_create(&key_event_thread, NULL, handle_key_event, NULL);
  
  // Initiate ncurses
  initscr();
  noecho();
  cbreak();
  keypad(stdscr, TRUE);


  // Setup pad
  initialize_pad();

  // Set start time
  gettimeofday(&start_time, NULL);

  // -1 means to sniff until error occurs
  int rc = pcap_loop(packet_capture_handle, -1, handle_packet, NULL);
  printf("pcap_loop returned with code %d\n", rc);
  fflush(stdout);
  

  // Close session
  pcap_close(packet_capture_handle);
  return 0;
}