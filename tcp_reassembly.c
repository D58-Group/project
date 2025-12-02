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

int find_substr(uint8_t* data, uint32_t len, const char* substr) {
  uint32_t substr_len = strlen(substr);
  for (uint32_t i = 0; i <= len - substr_len; i++) {
    if (memcmp(data + i, substr, substr_len) == 0) {
      return i;
    }
  }
  return -1;
}

int is_http_request(uint8_t* data, uint32_t len) {
  const char* methods[] = {"GET ",   "POST ",   "HEAD ",   "PUT ",
                           "PATCH ", "DELETE ", "OPTIONS "};
  for (int i = 0; i < 7; i++) {
    if (len >= strlen(methods[i])) {
      if (memcmp(data, (uint8_t*)methods[i], strlen(methods[i])) == 0) {
        return 1;
      }
    }
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

    if (segment->len > 0 && segment->data != NULL) {
      for (uint32_t i = 0; i < segment->len; i++) {
        char c = segment->data[i];
        if (c >= 32 && c <= 126) {  // printable characters
          fprintf(stderr, "%c", c);
        } else {
          fprintf(stderr, ".");
        }
      }
      fprintf(stderr, "\n");
    }
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

void remove_tcp_stream(tcp_stream_t* stream) {
  if (streams_list == NULL || stream == NULL) {
    return;
  }
  if (streams_list == stream) {
    streams_list = streams_list->next;
    free_tcp_stream(stream);
    return;
  }
  tcp_stream_t* current = streams_list;
  while (current->next != NULL) {
    if (current->next == stream) {
      current->next = stream->next;
      free_tcp_stream(stream);
      return;
    }
    current = current->next;
  }
}

void remove_first_n_tcp_segments(tcp_stream_t* stream, int n) {
  tcp_segment_t* curr = stream->segments;
  tcp_segment_t* prev = NULL;
  int count = 0;

  while (curr != NULL && count < n) {
    prev = curr;
    curr = curr->next;
    free(prev->data);
    free(prev);
    count++;
  }
  stream->segments = curr;
}

///////////////////////////////////////////////////////////////////////////////
// REASSEMBLY
///////////////////////////////////////////////////////////////////////////////

http_message_t* try_reassembling_http(tcp_stream_t* stream) {
  if (stream->segments == NULL) {
    return NULL;
  }

  int http_verified = 0;
  int http_buf_len = 0;
  uint8_t* http_buf = NULL;

  int segment_count = 0;
  tcp_segment_t* prev = NULL;
  tcp_segment_t* curr = stream->segments;

  while (curr != NULL) {
    // check if we have the next segment in sequence
    if (prev != NULL && curr->seq != prev->seq + prev->len) {
      // missing segment
      free(http_buf);
      return NULL;
    }

    segment_count++;

    // increase buffer size
    http_buf = realloc(http_buf, http_buf_len + curr->len);
    if (!http_buf) {
      return NULL;
    }

    // append segment data to buffer
    memcpy(http_buf + http_buf_len, curr->data, curr->len);
    http_buf_len += curr->len;

    // check that this is an http stream
    if (!http_verified && http_buf_len >= 4) {
      if (is_http_request(http_buf, http_buf_len) ||
          is_http_response(http_buf, http_buf_len)) {
        http_verified = 1;
      } else {
        // not an http stream
        free(http_buf);
        return NULL;
      }
    }

    // check if we have a complete http message
    if (http_buf_len >= 4) {
      // check if we have the end of http header
      int hdr_end = find_substr(http_buf, http_buf_len, "\r\n\r\n");
      if (hdr_end != -1) {
        hdr_end += 4;

        // check for content-length header
        int conlen_start = find_substr(http_buf, hdr_end, "Content-Length: ");
        if (conlen_start != -1) {
          // content-length found
          conlen_start += strlen("Content-Length: ");

          // find end of content-length line
          int conlen_end = find_substr(http_buf + conlen_start,
                                       hdr_end - conlen_start, "\r\n");

          if (conlen_end != -1) {
            // extract content length
            conlen_end += conlen_start;

            // allocate string for content length
            char conlen_str[conlen_end - conlen_start + 1];
            memcpy(conlen_str, http_buf + conlen_start,
                   conlen_end - conlen_start);
            conlen_str[conlen_end - conlen_start] = '\0';

            // convert to integer
            int conlen = atoi(conlen_str);

            // total http message length
            int http_msg_len = hdr_end + conlen;

            // should be equal but just in case
            if (http_buf_len >= http_msg_len) {
              http_message_t* reassembled = malloc(sizeof(http_message_t));
              if (!reassembled) {
                free(http_buf);
                return NULL;
              }

              reassembled->header = malloc(hdr_end);
              memcpy(reassembled->header, http_buf, hdr_end);
              reassembled->header_len = hdr_end;

              reassembled->data = malloc(conlen);
              memcpy(reassembled->data, http_buf + hdr_end, conlen);
              reassembled->data_len = conlen;

              remove_first_n_tcp_segments(stream, segment_count);
              free(http_buf);
              return reassembled;
            }
          }
        } else {
          // no content-length, assume header only
          http_message_t* reassembled = malloc(sizeof(http_message_t));
          if (!reassembled) {
            free(http_buf);
            return NULL;
          }

          reassembled->header = malloc(hdr_end);
          memcpy(reassembled->header, http_buf, hdr_end);
          reassembled->header_len = hdr_end;

          reassembled->data = NULL;
          reassembled->data_len = 0;

          remove_first_n_tcp_segments(stream, segment_count);
          free(http_buf);
          return reassembled;
        }
      }
    }

    prev = curr;
    curr = curr->next;
  }

  free(http_buf);
  return NULL;
}
/*


void try_reassemble_http(tcp_stream_t* stream) {
  if (!is_http_stream(stream)) {
    // not an http stream, remove it
    // no point in processing since we're only reassembling http
    remove_tcp_stream(stream);
    return;
  }

  if (stream->segments == NULL) {
    return;
  }

  int http_buf_len = 0;
  uint8_t* http_buf = NULL;

  int segment_count = 0;
  tcp_segment_t* prev = NULL;
  tcp_segment_t* curr = stream->segments;
  while (curr != NULL) {
    // check if we have the next segment in sequence
    if (prev != NULL && curr->seq != prev->seq + prev->len) {
      // missing segment detected
      free(http_buf);
      return;
    }

    segment_count++;

    // increase buffer size
    http_buf = realloc(http_buf, http_buf_len + curr->len);
    if (!http_buf) {
      return;
    }

    // append segment data to buffer
    memcpy(http_buf + http_buf_len, curr->data, curr->len);
    http_buf_len += curr->len;

    // check if we have a complete http message
    if (http_buf_len >= 4) {
      // find end of http header
      int hdr_end = find_substr(http_buf, http_buf_len, "\r\n\r\n");
      if (hdr_end != -1) {
        hdr_end += 4;

        // check for content-length header
        int conlen_start = find_substr(http_buf, hdr_end, "Content-Length: ");
        if (conlen_start != -1) {
          // content-length found
          conlen_start += strlen("Content-Length: ");

          // find end of content-length line
          int conlen_end = find_substr(http_buf + conlen_start,
                                       hdr_end - conlen_start, "\r\n");

          if (conlen_end != -1) {
            // extract content length
            conlen_end += conlen_start;

            // allocate string for content length
            char conlen_str[conlen_end - conlen_start + 1];
            memcpy(conlen_str, http_buf + conlen_start,
                   conlen_end - conlen_start);
            conlen_str[conlen_end - conlen_start] = '\0';

            // convert to integer
            int conlen = atoi(conlen_str);

            // total http message length
            int http_msg_len = hdr_end + conlen;

            // should be equal but just in case
            if (http_buf_len >= http_msg_len) {
              // complete http message reassembled
              // printf(
              // "------------------------------------------------------------"
              //     "--\n");
              // printf("HTTP MESSAGE FULLY REASSEMBLED\n");
              // printf("Reassembled HTTP Data (length %d):\n", http_buf_len);
              // printf("Number of segments: %d\n", segment_count);

              // // fwrite(http_buf, 1, hdr_end, stdout); // print header only
              // fwrite(http_buf, 1, http_buf_len, stdout);  // print full
              // message printf("\n");

              // printf(
              // "------------------------------------------------------------"
              //     "--\n");
              // free(http_buf);
              return;
            }
          }
        }
      }
    }

    prev = curr;
    curr = curr->next;
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


*/

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
  if (len <= data_offset) {
    // no payload, dont bother
    return;
  }

  // debugging
  // packet_node->info = tcp_stream_to_str(stream);

  // create and save the tcp segment
  tcp_segment_t* segment = create_tcp_segment(id, seq, len - data_offset, data);
  if (!segment) {
    return;
  }
  insert_tcp_segment(stream, segment);

  // debugging
  // packet_node->info = tcp_stream_to_str(stream);

  // try reassembling http message
  packet_node->http_msg = try_reassembling_http(stream);
  if (packet_node->http_msg != NULL) {
    packet_node->proto = HTTP;
  }
}
