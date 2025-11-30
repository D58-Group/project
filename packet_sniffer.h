#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdint.h>

struct packet_node {
  struct pcap_pkthdr hdr;
  struct packet_node* prev;
  struct packet_node* next;

  uint8_t* packet;
  uint32_t length;

  unsigned int number;
  double time_rel;

  uint32_t src_ip;
  uint32_t dst_ip;
  uint8_t proto;

  char* info;
} typedef packet_node_t;

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

#endif
