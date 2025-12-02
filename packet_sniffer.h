#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <stdint.h>
#include "sr_protocol.h"
#include "sr_utils.h"

struct tcp_segment {
  uint32_t id;               // frame number
  uint32_t seq;              // tcp sequence number
  uint32_t len;              // data length
  uint8_t* data;             // data
  struct tcp_segment* next;  // next segment
} typedef tcp_segment_t;

struct tcp_stream {
  // used to identify the stream
  uint32_t src_ip;     // source IP address
  uint32_t dest_ip;    // destination IP address
  uint16_t src_port;   // source port
  uint16_t dest_port;  // destination port

  // reassembly info
  tcp_segment_t* segments;  // linked list of segments
  uint32_t init_seq;        // initial sequence number
  uint32_t next_seq;        // next expected sequence number
  uint8_t* http_buf;        // reassembled HTTP data
  uint32_t http_buf_len;    // length of reassembled HTTP data
  struct tcp_stream* next;
} typedef tcp_stream_t;

struct http_message {
  uint8_t* header;
  uint32_t header_len;
  uint8_t* data;            
  uint32_t data_len;             
} typedef http_message_t;

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

  // optional
  http_message_t* http_msg;
} typedef packet_node_t;

struct options {
  char* interface;
  char* filename;
  char* protocol;
  int duration;
} typedef options_t;

#endif
