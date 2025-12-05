#include "tcp_reassembly.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protocol.h"
#include "utils.h"

tcp_stream_t* streams_list = NULL;

/* HELPER FUNCTIONS */

int find_str(uint8_t* data, uint32_t len, const char* substr) {
  uint32_t substr_len = strlen(substr);
  for (uint32_t i = 0; i <= len - substr_len; i++) {
    if (memcmp(data + i, substr, substr_len) == 0) {
      return i;
    }
  }
  return -1;
}

int is_http_req(uint8_t* data, uint32_t len) {
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

int is_http_rep(uint8_t* data, uint32_t len) {
  return len >= 5 && memcmp(data, "HTTP/", 5) == 0;
}

void print_tcp_stream(tcp_stream_t* stream) {
  fprintf(stdout, "-------------\n");
  fprintf(stdout, "TCP Stream:\n");
  fprintf(stdout, "From: \n");
  print_addr_ip_int(stream->src_ip);
  fprintf(stdout, "Port %u\n", stream->src_port);
  fprintf(stdout, "To: \n");
  print_addr_ip_int(stream->dest_ip);
  fprintf(stdout, "Port %u\n", stream->dest_port);

  tcp_segment_t* segment = stream->segments;
  while (segment != NULL) {
    fprintf(stdout, "Segment:\n");
    fprintf(stdout, "\tID: %u\n", segment->id);
    fprintf(stdout, "\tSeq: %u\n", segment->seq);
    fprintf(stdout, "\tRel Seq: %u\n", segment->seq - stream->init_seq);
    fprintf(stdout, "\tLen: %u\n", segment->len);
    fprintf(stdout, "-------------\n");

    if (segment->len > 0 && segment->data != NULL) {
      for (uint32_t i = 0; i < segment->len; i++) {
        char c = segment->data[i];
        if (c >= 32 && c <= 126) {  // printable characters
          fprintf(stdout, "%c", c);
        } else {
          fprintf(stdout, ".");
        }
      }
      fprintf(stdout, "\n");
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
  FILE* saved = stdout;
  stdout = mem;

  print_tcp_stream(stream);

  // put it back
  fflush(mem);
  stdout = saved;
  fclose(mem);

  return output;
}

/* TCP STREAM MANAGEMENT */

http_message_t* create_http_message(uint8_t* header, uint32_t header_len,
                                    uint8_t* data, uint32_t data_len,
                                    uint8_t segment_count) {
  http_message_t* http_msg = malloc(sizeof(http_message_t));
  if (!http_msg) {
    return NULL;
  }

  // copy header
  http_msg->header = malloc(header_len);
  if (!http_msg->header) {
    free(http_msg);
    return NULL;
  }
  memcpy(http_msg->header, header, header_len);
  http_msg->header_len = header_len;

  // copy data (if any)
  if (data_len > 0) {
    http_msg->data = malloc(data_len);
    if (!http_msg->data) {
      free(http_msg->header);
      free(http_msg);
      return NULL;
    }
    memcpy(http_msg->data, data, data_len);
    http_msg->data_len = data_len;
  } else {
    http_msg->data = NULL;
    http_msg->data_len = 0;
  }

  http_msg->segment_count = segment_count;
  return http_msg;
}

void free_http_message(http_message_t* http_msg) {
  if (http_msg) {
    if (http_msg->header) {
      free(http_msg->header);
    }
    if (http_msg->data) {
      free(http_msg->data);
    }
    free(http_msg);
  }
}

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
  stream->http_buf = NULL;
  stream->http_buf_len = 0;
  stream->segments = NULL;
  stream->next = NULL;

  stream->last_active = time(NULL);
  return stream;
}

tcp_stream_t* find_tcp_stream(uint32_t src_ip, uint32_t dest_ip,
                              uint16_t src_port, uint16_t dest_port) {
  time_t timeout = 7200;  // 2h -- based on the tcp keep alive time
  time_t now = time(NULL);

  tcp_stream_t* match = NULL;
  tcp_stream_t* prev = NULL;
  tcp_stream_t* curr = streams_list;

  while (curr != NULL) {
    if (difftime(now, curr->last_active) > timeout) {
      if (prev == NULL) {
        streams_list = curr->next;
      } else {
        prev->next = curr->next;
      }
      tcp_stream_t* inactive = curr;
      curr = curr->next;
      destroy_tcp_stream(inactive);
      continue;
    }

    if (curr->src_ip == src_ip && curr->dest_ip == dest_ip &&
        curr->src_port == src_port && curr->dest_port == dest_port) {
      match = curr;
      break;
    }

    prev = curr;
    curr = curr->next;
  }
  return match;
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

void destroy_tcp_stream(tcp_stream_t* stream) {
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

void destroy_first_n_tcp_segments(tcp_stream_t* stream, int n) {
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

/* HTTP REASSEMBLY */

http_message_t* try_reassembling_http(tcp_stream_t* stream) {
  if (stream->segments == NULL) {
    return NULL;
  }

  int is_http = 0;
  int buf_len = 0;
  uint8_t* buf = NULL;

  int segment_count = 0;
  tcp_segment_t* prev = NULL;
  tcp_segment_t* curr = stream->segments;

  while (curr != NULL) {
    // check if we have the next segment in sequence
    if (prev != NULL && curr->seq != prev->seq + prev->len) {
      free(buf);
      return NULL;
    }

    segment_count++;

    // increase buffer size
    buf = realloc(buf, buf_len + curr->len);
    if (!buf) {
      return NULL;
    }

    // append segment data to buffer
    memcpy(buf + buf_len, curr->data, curr->len);
    buf_len += curr->len;

    // check that this is indeed an http stream
    if (!is_http && buf_len >= 7) {
      if (is_http_req(buf, buf_len) || is_http_rep(buf, buf_len)) {
        is_http = 1;
      } else {
        free(buf);
        return NULL;
      }
    }

    // check if we have a complete http message
    if (buf_len >= 4) {
      // check if we have the full http header
      int hdr_end = find_str(buf, buf_len, "\r\n\r\n");
      if (hdr_end != -1) {
        hdr_end += 4;

        // check for content-length header
        int cl_start = find_str(buf, hdr_end, "Content-Length: ");
        if (cl_start != -1) {
          cl_start += strlen("Content-Length: ");

          // find end of content-length line
          int cl_end = find_str(buf + cl_start, hdr_end - cl_start, "\r\n");
          if (cl_end != -1) {
            cl_end += cl_start;

            // extract content length as string
            char cl_str[cl_end - cl_start + 1];
            memcpy(cl_str, buf + cl_start, cl_end - cl_start);
            cl_str[cl_end - cl_start] = '\0';

            // convert to integer
            int content_len = atoi(cl_str);

            // total http data length
            int http_data_len = hdr_end + content_len;

            // should be equal but just in case
            if (buf_len >= http_data_len) {
              // create http message
              http_message_t* http_msg = create_http_message(
                  buf, hdr_end, buf + hdr_end, content_len, segment_count);
              if (!http_msg) {
                free(buf);
                return NULL;
              }
              // remove used segments from stream
              destroy_first_n_tcp_segments(stream, segment_count);
              free(buf);
              return http_msg;
            }
          }
        } else {
          // no content-length, assume header only
          http_message_t* http_msg =
              create_http_message(buf, hdr_end, NULL, 0, segment_count);
          if (!http_msg) {
            free(buf);
            return NULL;
          }
          // remove used segments from stream
          destroy_first_n_tcp_segments(stream, segment_count);
          free(buf);
          return http_msg;
        }
      }
    }

    prev = curr;
    curr = curr->next;
  }

  free(buf);
  return NULL;
}

void process_tcp_packet(packet_node_t* packet_node) {
  uint8_t* packet = packet_node->packet;
  uint32_t id = packet_node->number;
  uint32_t len = packet_node->length;

  // parse headers
  ip_hdr_t* ip_hdr = (ip_hdr_t*)(packet + sizeof(ethernet_hdr_t));
  uint16_t ip_hdr_len = ip_hdr->ip_hl * 4;
  tcp_hdr_t* tcp_hdr =
      (tcp_hdr_t*)(packet + sizeof(ethernet_hdr_t) + ip_hdr_len);

  // use these to identify the stream
  uint32_t src_ip = ntohl(ip_hdr->ip_src);
  uint32_t dest_ip = ntohl(ip_hdr->ip_dst);
  uint16_t src_port = ntohs(tcp_hdr->tcp_src);
  uint16_t dest_port = ntohs(tcp_hdr->tcp_dst);

  // get segment info
  uint32_t seq = ntohl(tcp_hdr->tcp_seq);
  uint16_t tcp_offset = (tcp_hdr->tcp_off >> 4) * 4;
  uint32_t data_offset = sizeof(ethernet_hdr_t) + ip_hdr_len + tcp_offset;
  uint8_t* data = NULL;
  if (len > data_offset) {
    data = (uint8_t*)(packet + data_offset);
  }

  // extract tcp flags
  uint8_t tcp_flags = tcp_hdr->tcp_flags;
  int syn_flag = tcp_flags & TH_SYN;
  int fin_flag = tcp_flags & TH_FIN;
  int rst_flag = tcp_flags & TH_RST;

  // find or create tcp stream
  tcp_stream_t* stream = find_tcp_stream(src_ip, dest_ip, src_port, dest_port);
  if (stream) {
    stream->last_active = time(NULL);
  } else {
    if (!syn_flag) {
      return;
    }
    stream = init_tcp_stream(src_ip, dest_ip, src_port, dest_port, seq);
    if (!stream) {
      return;
    }
    stream->next = streams_list;
    streams_list = stream;
  }

  // no payload, don't bother storing
  if (len <= data_offset) {
    // if connection closing, just free the stream
    if (fin_flag || rst_flag) {
      destroy_tcp_stream(stream);
    }
    return;
  }

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

  // payload has been processed, safe to free the stream if closing
  if (fin_flag || rst_flag) {
    destroy_tcp_stream(stream);
  }
}
