#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <stdint.h>

#include "packet_sniffer.h"

http_message_t* create_http_message(uint8_t* header, uint32_t header_len,
                                    uint8_t* data, uint32_t data_len);
void free_http_message(http_message_t* http_msg);

tcp_stream_t* init_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
                              uint16_t src_port, uint16_t dest_port,
                              uint32_t init_seq);
tcp_stream_t* find_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
                              uint16_t src_port, uint16_t dest_port);
void destroy_tcp_stream(tcp_stream_t* stream);

tcp_segment_t* create_tcp_segment(uint32_t id, uint32_t seq, uint32_t len,
                                  uint8_t* data);
void insert_tcp_segment(tcp_stream_t* stream, tcp_segment_t* new_segment);
void destroy_first_n_tcp_segments(tcp_stream_t* stream, int n);

void free_tcp_stream(tcp_stream_t* stream);
void free_all_tcp_streams();

http_message_t* try_reassembling_http(tcp_stream_t* stream);
void process_tcp_packet(packet_node_t* packet_node);

#endif
