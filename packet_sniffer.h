#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdint.h>
#include "tcp_reassembly.h"

struct packet_node {
  uint8_t *packet;
  struct pcap_pkthdr hdr;      
  struct packet_node *prev;
  struct packet_node *next;

  unsigned int number;         
  double time_rel;             

  uint32_t src_ip;             
  uint32_t dst_ip;
  uint8_t  proto;              

  uint32_t length;             
  
  char *info; 

  // http specific
  uint8_t* http_buf;
  uint32_t http_buf_len;
  tcp_segment_t* tcp_segments;
} typedef packet_node_t;

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

#endif
