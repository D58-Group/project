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

  // if no payload, don't bother
  if (len <= payload_offset) {
    return;
  }

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

  try_reassemble_http(stream);
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
    // fprintf(stderr, "  Next Seq: %u, Next Relative Seq: %u\n",
    //         stream->next_seq, stream->next_seq - stream->init_seq);

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

int is_http_request(uint8_t* data, uint32_t len) {
  if (len < 4) {
    return 0;
  }
  // Simple check for HTTP methods
  if (memcmp(data, "GET ", 4) == 0 || memcmp(data, "POST", 4) == 0 ||
      memcmp(data, "HEAD", 4) == 0 || memcmp(data, "PUT ", 4) == 0 ||
      memcmp(data, "DELE", 4) == 0 || memcmp(data, "OPTI", 4) == 0) {
    return 1;
  }
  return 0;
}

int is_http_response(uint8_t* data, uint32_t len) {
  if (len < 5) {
    return 0;
  }
  // Simple check for HTTP response status line
  if (memcmp(data, "HTTP/1.", 5) == 0) {
    return 1;
  }
  return 0;
}

int is_http_stream(tcp_stream_t* stream) {
  tcp_segment_t* segment = stream->segments;
  if (segment == NULL) {
    return 0;
  }
  if (is_http_request(segment->data, segment->len) ||
      is_http_response(segment->data, segment->len)) {
    return 1;
  }
  return 0;
}

void try_reassemble_http(tcp_stream_t* stream) {
  printf("trying to reassemble\n");

  if (!is_http_stream(stream) || stream->segments == NULL) {
    fprintf(stderr, "Not an HTTP stream or no segments\n");
    return;
  }

  int http_length = 0;
  uint8_t* http_data = NULL;

  int segment_count = 0;
  tcp_segment_t* prev_segment = NULL;
  tcp_segment_t* curr_segment = stream->segments;
  while (curr_segment != NULL) {
    // check for missing segment
    if (prev_segment != NULL &&
        curr_segment->seq != prev_segment->seq + prev_segment->len) {
      fprintf(stderr, "missing segment detected>>>>>>>>>>>>>>>>>>>\n");
      // missing segment detected
      free(http_data);
      return;
    }

    // append segment data to buffer
    http_data = realloc(http_data, http_length + curr_segment->len);
    if (!http_data) {
      return;
    }
    memcpy(http_data + http_length, curr_segment->data, curr_segment->len);
    http_length += curr_segment->len;

    prev_segment = curr_segment;
    curr_segment = curr_segment->next;
    segment_count++;
  }

  // print the http buffer
  printf("--------------------------------------------------------------\n");
  printf("Reassembled HTTP Data (length %d):\n", http_length);
  printf("Number of segments: %d\n", segment_count);
  print_http_header(http_data, http_length);
  printf("--------------------------------------------------------------\n");
  free(http_data);
}

void free_tcp_stream(tcp_stream_t* stream) {
  tcp_segment_t* segment = stream->segments;
  while (segment != NULL) {
    tcp_segment_t* next = segment->next;
    free(segment->data);
    free(segment);
    segment = next;
  }
  free(stream);
}

void free_all_tcp_streams() {
  tcp_stream_t* stream = streams_list;
  while (stream != NULL) {
    tcp_stream_t* next = stream->next;
    free_tcp_stream(stream);
    stream = next;
  }
  streams_list = NULL;
}

void print_http_header(uint8_t* data, uint32_t len) {
  fprintf(stderr, "HTTP Header:\n");
  fwrite(data, 1, len, stderr);
  fprintf(stderr, "\n");
 }