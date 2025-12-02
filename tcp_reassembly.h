#ifndef TCP_REASSEMBLY_H
#define TCP_REASSEMBLY_H

#include <stdint.h>

#include "packet_sniffer.h"

void process_tcp_packet(packet_node_t*);
void print_tcp_stream(tcp_stream_t*);
void print_all_tcp_streams();
void try_reassemble_http(tcp_stream_t*);
void free_all_tcp_streams();

#endif
