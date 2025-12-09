#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

uint16_t cksum(const void* _data, int len) {
  const uint8_t* data = _data;
  uint32_t sum;

  for (sum = 0; len >= 2; data += 2, len -= 2) sum += data[0] << 8 | data[1];
  if (len > 0) sum += data[0] << 8;
  while (sum > 0xffff) sum = (sum >> 16) + (sum & 0xffff);
  sum = htons(~sum);
  return sum ? sum : 0xffff;
}

uint16_t ethertype(uint8_t* buf) {
  ethernet_hdr_t* ehdr = (ethernet_hdr_t*)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t* buf) {
  ip_hdr_t* iphdr = (ip_hdr_t*)(buf);
  return iphdr->ip_p;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t* addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0) printf(":");
    printf("%02X", cur);
  }
  printf("\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    printf("inet_ntop error on address conversion\n");
  else
    printf("%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  printf("%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  printf("%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  printf("%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  printf("%d\n", curOctet);
}

/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t* buf) {
  ethernet_hdr_t* ehdr = (ethernet_hdr_t*)buf;
  printf("ETHERNET header:\n");
  printf("\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  printf("\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  uint16_t ether_type = ntohs(ehdr->ether_type);
  if (ether_type == ethertype_ip)
    printf("\ttype: IP (%d)\n", ether_type);
  else if (ether_type == ethertype_arp)
    printf("\ttype: ARP (%d)\n", ether_type);
  else {
    printf("\ttype: UNKNOWN (%d)\n", ether_type);
  }
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t* buf) {
  ip_hdr_t* iphdr = (ip_hdr_t*)(buf);

  uint8_t ihl_words = iphdr->ip_hl;
  uint16_t total_len = ntohs(iphdr->ip_len);
  uint32_t header_bytes = (uint32_t)ihl_words * 4;
  uint32_t payload_bytes =
      (total_len > header_bytes) ? (total_len - header_bytes) : 0;

  uint8_t dscp = iphdr->ip_tos >> 2;
  uint8_t ecn = iphdr->ip_tos & 0x3;

  uint16_t off = ntohs(iphdr->ip_off);
  int flag_reserved = (off & IP_RF) ? 1 : 0;
  int flag_df = (off & IP_DF) ? 1 : 0;
  int flag_mf = (off & IP_MF) ? 1 : 0;
  uint16_t frag_off = off & IP_OFFMASK;

  const char* proto_name = "UNKNOWN";
  switch (iphdr->ip_p) {
    case ip_protocol_icmp:
      proto_name = "ICMP";
      break;
    case ip_protocol_tcp:
      proto_name = "TCP";
      break;
    case ip_protocol_udp:
      proto_name = "UDP";
      break;
  }

  printf("IP header:\n");
  printf("\tversion: %d\n", iphdr->ip_v);
  printf("\theader length (words): %d\n", ihl_words);
  printf("\theader length (bytes): %u\n", (unsigned)header_bytes);
  printf("\tDSCP: %u\n", dscp);
  printf("\tECN: %u\n", ecn);
  printf("\ttotal length: %u\n", (unsigned)total_len);
  printf("\tpayload length: %u\n", (unsigned)payload_bytes);
  printf("\tid: %u\n", (unsigned)ntohs(iphdr->ip_id));

  printf("\tflags: R=%d, DF=%d, MF=%d\n", flag_reserved, flag_df, flag_mf);
  printf("\tfragment offset: %u\n", (unsigned)frag_off);
  printf("\tTTL: %u\n", (unsigned)iphdr->ip_ttl);
  printf("\tprotocol: %u (%s)\n", (unsigned)iphdr->ip_p, proto_name);

  /* Keep checksum in NBO, but show as hex */
  printf("\tchecksum: 0x%04x\n", ntohs(iphdr->ip_sum));

  printf("\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  printf("\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t* buf) {
  icmp_hdr_t* icmp_hdr = (icmp_hdr_t*)(buf);
  printf("ICMP header:\n");
  printf("\ttype: %d\n", icmp_hdr->icmp_type);
  printf("\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO, but show as hex */
  printf("\tchecksum: 0x%04x\n", ntohs(icmp_hdr->icmp_sum));

  if (icmp_hdr->icmp_type == 0) {
    printf("\t[Echo (Ping) Reply] \n");
  } else if (icmp_hdr->icmp_type == 8) {
    printf("\t[Echo (Ping) Request] \n");
  } else if (icmp_hdr->icmp_type == 11 && icmp_hdr->icmp_code == 0) {
    printf("\t[Time Exceeded] \n");
  } else if (icmp_hdr->icmp_type == 3) {
    icmp_t3_hdr_t *icmp_t3_hdr = (icmp_t3_hdr_t *)(buf);

    // Print IP header of ICMP data
    if (icmp_t3_hdr->icmp_type == 3 && icmp_t3_hdr->icmp_code == 0) {
      printf("\t[Destination Net Unreachable] \n\n");
      printf("IP header of ICMP Data: \n");
      print_hdr_ip(icmp_t3_hdr->data);
    } else if (icmp_t3_hdr->icmp_type == 3 && icmp_t3_hdr->icmp_code == 1) {
      printf("\t[Destination Host Unreachable] \n\n");
      printf("IP header of ICMP Data: \n");
      print_hdr_ip(icmp_t3_hdr->data);
    } else if (icmp_t3_hdr->icmp_type == 3 && icmp_t3_hdr->icmp_code == 3) {
      printf("\t[Port Unreachable] \n\n");
      printf("IP header of ICMP Data: \n");
      print_hdr_ip(icmp_t3_hdr->data);
    }
  }
}

void print_hdr_udp(uint8_t* buf) {
  udp_hdr_t* udp_hdr = (udp_hdr_t*)(buf);
  printf("UDP header:\n");
  // host order
  printf("\tsrc: %u\n", (unsigned)ntohs(udp_hdr->udp_src));
  printf("\tdst: %u\n", (unsigned)ntohs(udp_hdr->udp_dst));
  printf("\tlen: %u\n", (unsigned)ntohs(udp_hdr->udp_len));
  // NBO-hex
  printf("\tchecksum: 0x%04x\n", ntohs(udp_hdr->udp_sum));
}

void print_hdr_tcp(uint8_t* buf) {
  tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)buf;

  uint8_t data_offset = (tcp_hdr->tcp_off >> 4);
  uint8_t flags = tcp_hdr->tcp_flags;

  printf("TCP header:\n");
  printf("\tsrc: %u\n", (unsigned)ntohs(tcp_hdr->tcp_src));
  printf("\tdst: %u\n", (unsigned)ntohs(tcp_hdr->tcp_dst));
  printf("\tseq: %u\n", (unsigned)ntohl(tcp_hdr->tcp_seq));
  printf("\tack: %u\n", (unsigned)ntohl(tcp_hdr->tcp_ack));
  printf("\toffset (words): %u\n", (unsigned)data_offset);
  printf("\toffset (bytes): %u\n", (unsigned)(data_offset * 4));

  printf("\tflags: 0x%02x (", flags);
  int first = 1;
  if (flags & 0x01) {
    printf("%sFIN", first ? "" : "|");
    first = 0;
  }
  if (flags & 0x02) {
    printf("%sSYN", first ? "" : "|");
    first = 0;
  }
  if (flags & 0x04) {
    printf("%sRST", first ? "" : "|");
    first = 0;
  }
  if (flags & 0x08) {
    printf("%sPSH", first ? "" : "|");
    first = 0;
  }
  if (flags & 0x10) {
    printf("%sACK", first ? "" : "|");
    first = 0;
  }
  if (flags & 0x20) {
    printf("%sURG", first ? "" : "|");
    first = 0;
  }
  if (first) printf("none");
  printf(")\n");

  printf("\twindow: %u\n", (unsigned)ntohs(tcp_hdr->tcp_win));
  printf("\tchecksum: 0x%04x\n", ntohs(tcp_hdr->tcp_sum));
  printf("\turgptr: %u\n", (unsigned)ntohs(tcp_hdr->tcp_urp));
}

void print_hdr_arp(uint8_t* buf) {
  arp_hdr_t* arp_hdr = (arp_hdr_t*)(buf);
  printf("ARP header\n");
  printf("\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  printf("\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  printf("\thardware address length: %d\n", arp_hdr->ar_hln);
  printf("\tprotocol address length: %d\n", arp_hdr->ar_pln);
  printf("\topcode: %d\n", ntohs(arp_hdr->ar_op));

  printf("\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  printf("\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  printf("\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  printf("\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));

  /* extra Wireshark-style summary */
  char sip[INET_ADDRSTRLEN];
  char tip[INET_ADDRSTRLEN];
  struct in_addr a_sip = {.s_addr = arp_hdr->ar_sip};
  struct in_addr a_tip = {.s_addr = arp_hdr->ar_tip};
  inet_ntop(AF_INET, &a_sip, sip, sizeof(sip));
  inet_ntop(AF_INET, &a_tip, tip, sizeof(tip));

  uint16_t op = ntohs(arp_hdr->ar_op);
  if (op == arp_op_request) {
    printf("\t[who has %s? tell %s]\n", tip, sip);
  } else if (op == arp_op_reply) {
    printf("\t[%s is-at ", sip);
    print_addr_eth(arp_hdr->ar_sha); /* this already prints newline */
  }
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t* buf, uint32_t length) {
  /* Ethernet */
  int minlength = sizeof(ethernet_hdr_t);
  if (length < minlength) {
    printf("Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(ip_hdr_t);
    if (length < minlength) {
      printf("Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(icmp_hdr_t);
      if (length < minlength)
        printf("Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));
    } else if (ip_proto == ip_protocol_udp) { /* UDP */
      minlength += sizeof(udp_hdr_t);
      if (length < minlength)
        printf("Failed to print UDP header, insufficient length\n");
      else
        print_hdr_udp(buf + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));
    } else if (ip_proto == ip_protocol_tcp) { /* TCP */
      minlength += sizeof(tcp_hdr_t);
      if (length < minlength)
        printf("Failed to print TCP header, insufficient length\n");
      else {
        print_hdr_tcp(buf + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));
      }
    }
  }

  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(arp_hdr_t);
    if (length < minlength)
      printf("Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(ethernet_hdr_t));
  } else {
    printf("Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

////////////////////////////////////////////////////////////////////////
// For ncurses display
//////////////////////////////////////////////
enum protocol get_protocol(const uint8_t* packet) {
  uint16_t ether_type = ethertype((uint8_t*)packet);
  if (ether_type == ethertype_arp) {
    return ARP;
  } else if (ether_type == ethertype_ip) {
    uint8_t ip_proto = ip_protocol((uint8_t*)packet + sizeof(ethernet_hdr_t));
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
void convert_addr_eth_to_str(uint8_t* addr, char* str_addr) {
  strcpy(str_addr, "");
  char buf[100];
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0) strcat(str_addr, ":");
    sprintf(buf, "%02X", cur);
    strcat(str_addr, buf);
  }
}

void convert_addr_ip_int_to_str(uint32_t ip, char* str_addr) {
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

void get_source_dest(char* src, char* dst, const uint8_t* packet) {
  uint16_t ether_type = ethertype((uint8_t*)packet);
  if (ether_type == ethertype_arp) {
    arp_hdr_t* arp_hdr = (arp_hdr_t*)(packet + sizeof(ethernet_hdr_t));
    // sender mac
    convert_addr_eth_to_str(arp_hdr->ar_sha, src);
    // destination mac
    convert_addr_eth_to_str(arp_hdr->ar_tha, dst);
  } else if (ether_type == ethertype_ip) {
    ip_hdr_t* iphdr = (ip_hdr_t*)(packet + sizeof(ethernet_hdr_t));
    // sender ip address
    convert_addr_ip_int_to_str(ntohl(iphdr->ip_src), src);
    // destination ip address
    convert_addr_ip_int_to_str(ntohl(iphdr->ip_dst), dst);
  } else {
    // TODO
  }
}

char* format_hdrs_to_string(uint8_t* buf, uint32_t length) {
  char* output = NULL;
  size_t out_size = 0;

  FILE* mem = open_memstream(&output, &out_size);
  if (!mem) return NULL;

  // redirects prints
  FILE* saved = stdout;
  stdout = mem;

  print_hdrs(buf, length);

  // put it back
  fflush(mem);
  stdout = saved;
  fclose(mem);

  return output;
}

void print_http_hdr(uint8_t* buf, uint32_t length) {
  fwrite(buf, 1, length, stdout);
}

char* http_hdr_to_str(http_message_t* http_msg) {
  char* output = NULL;
  size_t out_size = 0;

  FILE* mem = open_memstream(&output, &out_size);
  if (!mem) return NULL;

  // redirects prints
  FILE* saved = stdout;
  stdout = mem;

  print_http_hdr(http_msg->header, http_msg->header_len);

  // put it back
  fflush(mem);
  stdout = saved;
  fclose(mem);

  return output;
}
