#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdint.h>

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

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

#endif
