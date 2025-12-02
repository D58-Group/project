#include "tcp_reassembly.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_utils.h"

tcp_stream_t* streams_list = NULL;

// TODO CHECK SYN AND FIN FLAGS
// TODO ONLY INIT IF SYN FLAG IS SET
// TODO ONLY REASSEMBLE HTTP STREAMS
// TODO HANDLE TIMEOUTS
// TODO HANDLE SEQ NUMBER WRAPAROUND

///////////////////////////////////////////////////////////////////////////////
// HELPER FUNCTIONS
///////////////////////////////////////////////////////////////////////////////

int find_substring(uint8_t* data, uint32_t len, const char* substr) {
  uint32_t substr_len = strlen(substr);
  for (uint32_t i = 0; i <= len - substr_len; i++) {
    if (memcmp(data + i, substr, substr_len) == 0) {
      return i;
    }
  }
  return -1;
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

void print_tcp_stream(tcp_stream_t* stream) {
  fprintf(stderr, "-------------\n");
  fprintf(stderr, "TCP Stream:\n");
  fprintf(stderr, "From: \n");
  print_addr_ip_int(stream->src_ip);
  fprintf(stderr, "Port %u\n", stream->src_port);
  fprintf(stderr, "To: \n");
  print_addr_ip_int(stream->dest_ip);
  fprintf(stderr, "Port %u\n", stream->dest_port);

  tcp_segment_t* segment = stream->segments;
  while (segment != NULL) {
    fprintf(stderr, "Segment:\n");
    fprintf(stderr, "\tID: %u\n", segment->id);
    fprintf(stderr, "\tSeq: %u\n", segment->seq);
    fprintf(stderr, "\tRel Seq: %u\n", segment->seq - stream->init_seq);
    fprintf(stderr, "\tLen: %u\n", segment->len);
    fprintf(stderr, "-------------\n");

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

char* tcp_stream_to_str(tcp_stream_t* stream) {
  char* output = NULL;
  size_t out_size = 0;

  FILE* mem = open_memstream(&output, &out_size);
  if (!mem) return NULL;

  // redirects prints
  FILE* saved = stderr;
  stderr = mem;

  print_tcp_stream(stream);

  // put it back
  fflush(mem);
  stderr = saved;
  fclose(mem);

  return output;
}

////////////////////////////////////////////////////////////////////////////////
// HANDLING TCP STREAMS AND SEGMENTS
////////////////////////////////////////////////////////////////////////////////

tcp_stream_t* init_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
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
  stream->next_seq = init_seq;
  stream->http_buf = NULL;
  stream->http_buf_len = 0;
  stream->segments = NULL;
  stream->next = NULL;

  return stream;
}

tcp_stream_t* find_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
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

tcp_segment_t* create_tcp_segment(uint32_t id, uint32_t seq, uint32_t len,
                                  uint8_t* data) {
  tcp_segment_t* segment = malloc(sizeof(tcp_segment_t));
  if (!segment) {
    return NULL;
  }
  segment->id = id;
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

///////////////////////////////////////////////////////////////////////////////
// REASSEMBLY
///////////////////////////////////////////////////////////////////////////////
void try_reassemble_http(tcp_stream_t* stream) {
  printf("trying to reassemble\n");

  if (!is_http_stream(stream) || stream->segments == NULL) {
    fprintf(stderr, "Not an HTTP stream or no segments\n");
    return;
  }

  int http_buf_len = 0;
  uint8_t* http_buf = NULL;

  int segment_count = 0;
  tcp_segment_t* prev_segment = NULL;
  tcp_segment_t* curr_segment = stream->segments;
  while (curr_segment != NULL) {
    // check for missing segment
    if (prev_segment != NULL &&
        curr_segment->seq != prev_segment->seq + prev_segment->len) {
      fprintf(stderr, "missing segment detected>>>>>>>>>>>>>>>>>>>\n");
      // missing segment detected
      free(http_buf);
      return;
    }

    segment_count++;

    // increase buffer size
    http_buf = realloc(http_buf, http_buf_len + curr_segment->len);
    if (!http_buf) {
      return;
    }

    // append segment data to buffer
    memcpy(http_buf + http_buf_len, curr_segment->data, curr_segment->len);
    http_buf_len += curr_segment->len;

    // find the end of the http header
    if (http_buf_len >= 4) {
      int hdr_end_idx = find_substring(http_buf, http_buf_len, "\r\n\r\n");

      if (hdr_end_idx != -1) {
        // found end of http header
        hdr_end_idx += 4;  // include the \r\n\r\n

        // check if content-length is specified
        // this gives us the length of the payload
        int con_len_start_idx =
            find_substring(http_buf, hdr_end_idx, "Content-Length: ");
        if (con_len_start_idx != -1) {
          // content-length found
          con_len_start_idx += strlen("Content-Length: ");

          // find end of content-length line
          int con_len_end_idx =
              find_substring(http_buf + con_len_start_idx,
                             hdr_end_idx - con_len_start_idx, "\r\n");

          if (con_len_end_idx != -1) {
            // extract content length
            con_len_end_idx += con_len_start_idx;

            // allocate string for content length
            char con_len_str[con_len_end_idx - con_len_start_idx + 1];
            memcpy(con_len_str, http_buf + con_len_start_idx,
                   con_len_end_idx - con_len_start_idx);
            con_len_str[con_len_end_idx - con_len_start_idx] = '\0';

            // convert to integer
            int con_len = atoi(con_len_str);

            // total http message length
            int http_msg_len = hdr_end_idx + con_len;

            // should be equal but just in case
            if (http_buf_len >= http_msg_len) {
              // complete http message reassembled
              printf(
                  "------------------------------------------------------------"
                  "--\n");
              printf("HTTP MESSAGE FULLY REASSEMBLED\n");
              printf("Reassembled HTTP Data (length %d):\n", http_buf_len);
              printf("Number of segments: %d\n", segment_count);

              // fwrite(http_buf, 1, hdr_end_idx, stdout); // print header only
              fwrite(http_buf, 1, http_buf_len, stdout);  // print full message
              printf("\n");

              printf(
                  "------------------------------------------------------------"
                  "--\n");
              free(http_buf);
              return;
            }
          }
        }
      }
    }

    prev_segment = curr_segment;
    curr_segment = curr_segment->next;
  }

  // print the http buffer
  printf("--------------------------------------------------------------\n");
  printf("reassembling tcp stream (length %d):\n", http_buf_len);
  printf("Number of segments: %d\n", segment_count);
  fwrite(http_buf, 1, http_buf_len, stdout);
  printf("\n");
  printf("--------------------------------------------------------------\n");
  free(http_buf);
}

void process_tcp_packet(packet_node_t* packet_node) {
  uint8_t* packet = packet_node->packet;
  uint32_t id = packet_node->number;
  uint32_t len = packet_node->length;

  // parse headers
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t ip_hdr_len = ip_hdr->ip_hl * 4;
  sr_tcp_hdr_t* tcp_hdr =
      (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + ip_hdr_len);

  // use these to identify the stream
  uint32_t src_ip = ntohl(ip_hdr->ip_src);
  uint32_t dest_ip = ntohl(ip_hdr->ip_dst);
  uint16_t src_port = ntohs(tcp_hdr->tcp_src);
  uint16_t dest_port = ntohs(tcp_hdr->tcp_dst);

  // get segment info
  uint32_t seq = ntohl(tcp_hdr->tcp_seq);
  uint16_t tcp_offset = (tcp_hdr->tcp_off >> 4) * 4;
  uint32_t data_offset = sizeof(sr_ethernet_hdr_t) + ip_hdr_len + tcp_offset;
  uint8_t* data = NULL;
  if (len > data_offset) {
    data = (uint8_t*)(packet + data_offset);
  }

  // find or create tcp stream
  tcp_stream_t* stream = find_tcp_stream(src_ip, dest_ip, src_port, dest_port);
  if (!stream) {
    // open new stream only if SYN flag is set
    uint8_t tcp_flags = tcp_hdr->tcp_flags;
    if ((tcp_flags & TH_SYN) == 0) {
      return;
    }
    stream = init_tcp_stream(src_ip, dest_ip, src_port, dest_port, seq);
    if (!stream) {
      return;
    }
    stream->next = streams_list;
    streams_list = stream;
  }

  // create and save the tcp segment
  tcp_segment_t* segment = create_tcp_segment(id, seq, len - data_offset, data);
  if (!segment) {
    return;
  }
  insert_tcp_segment(stream, segment);

  // todo: append after reassembly (last tcp packet only)
  packet_node->info = tcp_stream_to_str(stream); // temp

  // try_reassemble_http(stream);
}

////////////////////////////////////////////////////////////////////////////////
// CLEANUP
////////////////////////////////////////////////////////////////////////////////

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
