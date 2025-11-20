#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>  
#include <errno.h>
#include "sr_utils.h"

void handle_packet(u_char *args_unused, const struct pcap_pkthdr *header, const u_char *packet) {
  print_hdrs((uint8_t *) packet, header->len);
}

int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *device;
  pcap_t *packet_capture_handle;
  int promisc = 1; // promiscuous mode
  int to_ms = 750; // read time in ms
  struct pcap_pkthdr hdr;

  // List devices and select first device in list
  pcap_findalldevs(&device, errbuf); // TODO free list with pcap_freealldevs

  if (device == NULL) {
    printf("Error finding devices, %s", errbuf);
    exit(1);
  }
  printf("Capturing packets on device: %s", device->name);

  // TODO: add option for inputing device name instead of using default

  // TODO: Allow for reading packets from pathname using pcap_open_offline, and pcap_fopen_offline()

  // TODO: Can filter using pcap_compile and pcap_setfilter

  // Capture packets on device
  packet_capture_handle = pcap_open_live(device->name, BUFSIZ, promisc, to_ms, errbuf);

  if (packet_capture_handle == NULL) {
    printf("Error opening device %s", errbuf);
    exit(1);
  }

  //-1 means to sniff until error occurs
  pcap_loop(packet_capture_handle, -1, handle_packet, NULL);

  // Close session
  pcap_close(packet_capture_handle);
  return 0;
}