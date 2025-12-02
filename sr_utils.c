#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);

  uint8_t  ihl_words     = iphdr->ip_hl;
  uint16_t total_len     = ntohs(iphdr->ip_len);
  uint32_t header_bytes  = (uint32_t)ihl_words * 4;
  uint32_t payload_bytes = (total_len > header_bytes) ? (total_len - header_bytes) : 0;

  uint8_t dscp = iphdr->ip_tos >> 2;
  uint8_t ecn  = iphdr->ip_tos & 0x3;

  uint16_t off = ntohs(iphdr->ip_off);
  int flag_reserved = (off & IP_RF) ? 1 : 0;
  int flag_df       = (off & IP_DF) ? 1 : 0;
  int flag_mf       = (off & IP_MF) ? 1 : 0;
  uint16_t frag_off = off & IP_OFFMASK;

  const char *proto_name = "UNKNOWN";
  switch (iphdr->ip_p) {
    case ip_protocol_icmp: proto_name = "ICMP"; break;
    case ip_protocol_tcp:  proto_name = "TCP";  break;
    case ip_protocol_udp:  proto_name = "UDP";  break;
  }

  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length (words): %d\n", ihl_words);
  fprintf(stderr, "\theader length (bytes): %u\n", (unsigned)header_bytes);
  fprintf(stderr, "\tDSCP: %u\n", dscp);
  fprintf(stderr, "\tECN: %u\n", ecn);
  fprintf(stderr, "\ttotal length: %u\n", (unsigned)total_len);
  fprintf(stderr, "\tpayload length: %u\n", (unsigned)payload_bytes);
  fprintf(stderr, "\tid: %u\n", (unsigned)ntohs(iphdr->ip_id));

  fprintf(stderr, "\tflags: R=%d, DF=%d, MF=%d\n",
          flag_reserved, flag_df, flag_mf);
  fprintf(stderr, "\tfragment offset: %u\n", (unsigned)frag_off);
  fprintf(stderr, "\tTTL: %u\n", (unsigned)iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %u (%s)\n",
          (unsigned)iphdr->ip_p, proto_name);

  /* Keep checksum in NBO, but show as hex */
  fprintf(stderr, "\tchecksum: 0x%04x\n", ntohs(iphdr->ip_sum));

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}


/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);

  // if (icmp_hdr->type == icmp_type_3) {
  //   fr
  // }
}


void print_hdr_udp(uint8_t *buf) {
  sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(buf);
  fprintf(stderr, "UDP header:\n");
  //host order
  fprintf(stderr, "\tsrc: %u\n", (unsigned)ntohs(udp_hdr->udp_src));
  fprintf(stderr, "\tdst: %u\n", (unsigned)ntohs(udp_hdr->udp_dst));
  fprintf(stderr, "\tlen: %u\n", (unsigned)ntohs(udp_hdr->udp_len));
  //NBO-hex
  fprintf(stderr, "\tchecksum: 0x%04x\n", ntohs(udp_hdr->udp_sum));
}


void print_hdr_tcp(uint8_t *buf) {
  sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)buf;

  uint8_t data_offset = (tcp_hdr->tcp_off >> 4);  
  uint8_t flags       = tcp_hdr->tcp_flags;

  fprintf(stderr, "TCP header:\n");
  fprintf(stderr, "\tsrc: %u\n", (unsigned)ntohs(tcp_hdr->tcp_src));
  fprintf(stderr, "\tdst: %u\n", (unsigned)ntohs(tcp_hdr->tcp_dst));
  fprintf(stderr, "\tseq: %u\n", (unsigned)ntohl(tcp_hdr->tcp_seq));
  fprintf(stderr, "\tack: %u\n", (unsigned)ntohl(tcp_hdr->tcp_ack));
  fprintf(stderr, "\toffset (words): %u\n", (unsigned)data_offset);
  fprintf(stderr, "\toffset (bytes): %u\n", (unsigned)(data_offset * 4));

  fprintf(stderr, "\tflags: 0x%02x (", flags);
  int first = 1;
  if (flags & 0x01) { fprintf(stderr, "%sFIN", first ? "" : "|"); first = 0; }
  if (flags & 0x02) { fprintf(stderr, "%sSYN", first ? "" : "|"); first = 0; }
  if (flags & 0x04) { fprintf(stderr, "%sRST", first ? "" : "|"); first = 0; }
  if (flags & 0x08) { fprintf(stderr, "%sPSH", first ? "" : "|"); first = 0; }
  if (flags & 0x10) { fprintf(stderr, "%sACK", first ? "" : "|"); first = 0; }
  if (flags & 0x20) { fprintf(stderr, "%sURG", first ? "" : "|"); first = 0; }
  if (first) fprintf(stderr, "none");
  fprintf(stderr, ")\n");

  fprintf(stderr, "\twindow: %u\n", (unsigned)ntohs(tcp_hdr->tcp_win));
  fprintf(stderr, "\tchecksum: 0x%04x\n", ntohs(tcp_hdr->tcp_sum));
  fprintf(stderr, "\turgptr: %u\n", (unsigned)ntohs(tcp_hdr->tcp_urp));
}


void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));

  /* extra Wireshark-style summary */
  char sip[INET_ADDRSTRLEN];
  char tip[INET_ADDRSTRLEN];
  struct in_addr a_sip = { .s_addr = arp_hdr->ar_sip };
  struct in_addr a_tip = { .s_addr = arp_hdr->ar_tip };
  inet_ntop(AF_INET, &a_sip, sip, sizeof(sip));
  inet_ntop(AF_INET, &a_tip, tip, sizeof(tip));

  uint16_t op = ntohs(arp_hdr->ar_op);
  if (op == arp_op_request) {
    fprintf(stderr, "\t[who has %s? tell %s]\n", tip, sip);
  } else if (op == arp_op_reply) {
    fprintf(stderr, "\t[%s is-at ", sip);
    print_addr_eth(arp_hdr->ar_sha); /* this already prints newline */
  }
}


/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    } else if(ip_proto == ip_protocol_udp) { /* UDP */
        minlength += sizeof(sr_udp_hdr_t);
        if (length < minlength)
          fprintf(stderr, "Failed to print UDP header, insufficient length\n");
        else
          print_hdr_udp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    } else if (ip_proto == ip_protocol_tcp) { /* TCP */
        minlength += sizeof(sr_tcp_hdr_t);
        if (length < minlength)
          fprintf(stderr, "Failed to print TCP header, insufficient length\n");
        else {
          print_hdr_tcp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          // sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          // int tcp_data_offset = tcp_hdr->tcp_off >> 4;  /* get data offset (last 4 bytes are reserved) */
          // int tcp_header_length = tcp_data_offset * 4;
          // if (length > sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + tcp_header_length) {
            // fprintf(stderr, "\tTCP payload\n");
            // size_t payload_len =
            //   length - tcp_header_length - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);

            // fprintf(stderr, "\tHeader length: %d\n", tcp_header_length);
            // fprintf(stderr, "\tPayload length: %zu\n", payload_len);

            // fwrite(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + tcp_header_length,
            //   1, payload_len, stderr);
            // fwrite("\n", 1, 1, stderr);
          // }
        }
    }
  }

  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

////////////////////////////////////////////////////////////////////////
// For ncurses display
//////////////////////////////////////////////
enum protocol get_protocol(const uint8_t *packet) {
  uint16_t ether_type = ethertype((uint8_t *)packet);
  if (ether_type == ethertype_arp) {
    return ARP;
  } else if (ether_type == ethertype_ip) {
    uint8_t ip_proto = ip_protocol((uint8_t *)packet + sizeof(sr_ethernet_hdr_t));
    if (ip_proto == ip_protocol_icmp) {
      return ICMP;
    } else if (ip_proto == ip_protocol_udp) {
      return UDP;
    } else if (ip_proto == ip_protocol_tcp) {
      return TCP;
    } else {
      return IPV4;
    }
  } 
  return OTHER;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void convert_addr_eth_to_str(uint8_t *addr, char *str_addr) {
  strcpy(str_addr, "");
  char buf[100];
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      strcat(str_addr, ":");
    sprintf(buf, "%02X", cur);
    strcat(str_addr, buf);
  }
}

void convert_addr_ip_int_to_str(uint32_t ip, char *str_addr) {
  uint32_t curOctet = ip >> 24;
  strcpy(str_addr, "");
  char buf[100];
  sprintf(buf, "%d.", curOctet);
  strcat(str_addr, buf);
  curOctet = (ip << 8) >> 24;
  sprintf(buf, "%d.", curOctet);
  strcat(str_addr, buf);
  curOctet = (ip << 16) >> 24;
  sprintf(buf, "%d.", curOctet);
  strcat(str_addr, buf);
  curOctet = (ip << 24) >> 24;
  sprintf(buf, "%d\n", curOctet);
  strcat(str_addr, buf);
}

void get_source_dest(char *src, char *dst, const uint8_t *packet) {
  uint16_t ether_type = ethertype((uint8_t *)packet);
   if (ether_type == ethertype_arp) {
     sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
     // sender mac
    convert_addr_eth_to_str(arp_hdr->ar_sha, src);
     // destination mac
    convert_addr_eth_to_str(arp_hdr->ar_tha, dst);
  } else if (ether_type == ethertype_ip) {
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    // sender ip address
    convert_addr_ip_int_to_str(ntohl(iphdr->ip_src), src);
    // destination ip address
    convert_addr_ip_int_to_str(ntohl(iphdr->ip_dst), dst);
  } else {
    //TODO
  }
}


char *format_hdrs_to_string(uint8_t *buf, uint32_t length) {
    char *output = NULL;
    size_t out_size = 0;

    FILE *mem = open_memstream(&output, &out_size);
    if (!mem) return NULL;

    //redirects prints 
    FILE *saved = stderr;
    stderr = mem;

    print_hdrs(buf, length);   

    //put it back 
    fflush(mem);
    stderr = saved;
    fclose(mem); 

    return output; 
}

void print_http_hdr(uint8_t *buf, uint32_t length) {
  fwrite(buf, 1, length, stderr);
}

char *http_hdr_to_str(uint8_t *buf, uint32_t length) {
    char *output = NULL;
    size_t out_size = 0;

    FILE *mem = open_memstream(&output, &out_size);
    if (!mem) return NULL;

    //redirects prints 
    FILE *saved = stderr;
    stderr = mem;

    print_http_hdr(buf, length);   

    //put it back 
    fflush(mem);
    stderr = saved;
    fclose(mem); 

    return output; 
}