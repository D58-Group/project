#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <stdint.h>

struct tcp_segment {
  uint32_t seq;              // sequence number
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
  uint32_t init_seq;        // initial sequence number
  tcp_segment_t* segments;  // linked list of segments
  struct tcp_stream* next;
} typedef tcp_stream_t;

tcp_segment_t* create_tcp_segment(uint32_t, uint32_t, uint8_t*);
void insert_tcp_segment(tcp_stream_t*, tcp_segment_t*);
tcp_stream_t* create_tcp_stream(uint32_t, uint32_t, uint16_t, uint16_t,
                                uint32_t);
tcp_stream_t* get_tcp_stream(uint32_t, uint32_t, uint16_t, uint16_t);
void handle_tcp_packet(uint8_t*, uint32_t);
void print_tcp_stream(tcp_stream_t*);
void print_all_tcp_streams();
void try_reassemble_http(tcp_stream_t*);

#endif
