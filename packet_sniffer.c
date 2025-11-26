#include <errno.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"

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


void handle_packet(u_char *args_unused,
                   const struct pcap_pkthdr *header,
                   const u_char *packet) {
  (void)args_unused; 

  printf("Got packet of length %u\n", header->len);
  fflush(stdout);

  print_hdrs((uint8_t *)packet, header->len);
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

  printf("pcap_open_live succeeded, starting capture loop\n");
  fflush(stdout);

  // -1 means to sniff until error occurs
  int rc = pcap_loop(packet_capture_handle, -1, handle_packet, NULL);
  printf("pcap_loop returned with code %d\n", rc);
  fflush(stdout);
  

  // Close session
  pcap_close(packet_capture_handle);
  return 0;
}