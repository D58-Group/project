#include "tcp_reassembly.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_utils.h"

tcp_stream_t* streams_list = NULL;

tcp_segment_t* create_tcp_segment(uint32_t seq, uint32_t len, uint8_t* data) {
  tcp_segment_t* segment = malloc(sizeof(tcp_segment_t));
  if (!segment) {
    return NULL;
  }
  segment->seq = seq;
  segment->len = len;
  segment->data = malloc(len);
  if (!segment->data) {
    free(segment);
    return NULL;
  }
  memcpy(segment->data, data, len);
  segment->next = NULL;
  return segment;
}

void insert_tcp_segment(tcp_stream_t* stream, tcp_segment_t* new_segment) {
  // if the stream has no segments, add as first
  if (stream->segments == NULL) {
    stream->segments = new_segment;
    return;
  }

  // insert segment in order based on sequence number
  tcp_segment_t* current = stream->segments;
  while (current != NULL && current->seq < new_segment->seq) {
    if (current->next == NULL) {
      current->next = new_segment;
    } else if (current->next->seq > new_segment->seq) {
      new_segment->next = current->next;
      current->next = new_segment;
    } else {
      current = current->next;
    }
  }
}

tcp_stream_t* create_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
                                uint16_t src_port, uint16_t dest_port,
                                uint32_t init_seq) {
  tcp_stream_t* stream = malloc(sizeof(tcp_stream_t));
  if (!stream) {
    return NULL;
  }
  stream->src_ip = src_ip;
  stream->dest_ip = dest_ip;
  stream->src_port = src_port;
  stream->dest_port = dest_port;
  stream->init_seq = init_seq;
  stream->segments = NULL;
  stream->next = NULL;
  return stream;
}

tcp_stream_t* get_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
                             uint16_t src_port, uint16_t dest_port) {
  tcp_stream_t* stream = streams_list;
  while (stream != NULL) {
    if (stream->src_ip == src_ip && stream->dest_ip == dest_ip &&
        stream->src_port == src_port && stream->dest_port == dest_port) {
      return stream;
    }
    stream = stream->next;
  }
  return NULL;
}

void handle_tcp_packet(uint8_t* packet, uint32_t len) {
  // extract tcp/ip info
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t ip_hdr_len = ip_hdr->ip_hl * 4;
  sr_tcp_hdr_t* tcp_hdr =
      (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);
  uint32_t src_ip = ntohl(ip_hdr->ip_src);
  uint32_t dest_ip = ntohl(ip_hdr->ip_dst);
  uint16_t src_port = ntohs(tcp_hdr->tcp_src);
  uint16_t dest_port = ntohs(tcp_hdr->tcp_dst);
  uint32_t seq = ntohl(tcp_hdr->tcp_seq);
  uint16_t tcp_data_offset = (tcp_hdr->tcp_offx2 >> 4) * 4;
  uint32_t payload_offset =
      sizeof(sr_ethernet_hdr_t) + ip_hdr_len + tcp_data_offset;
  uint8_t* payload_data =
      len - payload_offset > 0 ? (uint8_t*)(packet + payload_offset) : NULL;

  // find or create tcp stream
  tcp_stream_t* stream = get_tcp_stream(src_ip, dest_ip, src_port, dest_port);
  if (!stream) {
    stream = create_tcp_stream(src_ip, dest_ip, src_port, dest_port, seq);
    if (!stream) {
      return;
    }
    stream->next = streams_list;
    streams_list = stream;
  }

  // create and add tcp segment
  tcp_segment_t* segment =
      create_tcp_segment(seq, len - payload_offset, payload_data);
  if (!segment) {
    return;
  }
  insert_tcp_segment(stream, segment);

  print_all_tcp_streams();
}

void print_tcp_stream(tcp_stream_t* stream) {
  fprintf(stderr, "-------------\n");
  fprintf(stderr, "TCP Stream:\n");
  fprintf(stderr, "From \n");
  print_addr_ip_int(stream->src_ip);
  print_addr_ip_int(stream->dest_ip);
  fprintf(stderr, ":%u to %u\n", stream->src_port, stream->dest_port);
  fprintf(stderr, "-------------\n");

  tcp_segment_t* segment = stream->segments;
  while (segment != NULL) {
    fprintf(stderr, "  Seq: %u, Relative Seq: %u, Len: %u\n", segment->seq,
            segment->seq - stream->init_seq, segment->len);

    // if (segment->len > 0 && segment->data != NULL) {
    //   for (uint32_t i = 0; i < segment->len; i++) {
    //     char c = segment->data[i];
    //     if (c >= 32 && c <= 126) {  // printable characters
    //        fprintf(stderr, "%c", c);
    //     } else {
    //        fprintf(stderr, ".");
    //     }
    //   }
    //    fprintf(stderr, "\n");
    // }
    segment = segment->next;
  }
}

void print_all_tcp_streams() {
  fprintf(
      stderr,
      "---------------------------------------------------------------------"
      "\n");

  tcp_stream_t* stream = streams_list;
  while (stream != NULL) {
    print_tcp_stream(stream);
    stream = stream->next;
  }

  fprintf(
      stderr,
      "-------------------------------------------------------------------\n");
}
