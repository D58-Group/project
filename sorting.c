#include "sorting.h"

#include <arpa/inet.h>
#include <string.h>

#include "protocol.h"
#include "utils.h"

int match_protocol(const uint8_t* packet, uint32_t len, const char* proto) {
  if (!proto || strcmp(proto, "any") == 0) return 1;

  if (len < sizeof(ethernet_hdr_t)) return 0;
  const uint8_t* buf = (const uint8_t*)packet;

  uint16_t ethtype = ethertype((uint8_t*)buf);

  /* ARP */
  if (strcmp(proto, "arp") == 0) {
    return ethtype == ethertype_arp;
  }

  /* IP */
  if (ethtype != ethertype_ip ||
      len < sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t)) {
    return 0;
  }

  const uint8_t* ip_buf = buf + sizeof(ethernet_hdr_t);
  uint8_t ip_proto = ip_protocol((uint8_t*)ip_buf);

  if (strcmp(proto, "icmp") == 0) return ip_proto == ip_protocol_icmp;

  if (strcmp(proto, "tcp") == 0) return ip_proto == ip_protocol_tcp;

  if (strcmp(proto, "udp") == 0) return ip_proto == ip_protocol_udp;

  /* HTTP */
  if (strcmp(proto, "http") == 0) {
    if (ip_proto != ip_protocol_tcp) return 0;

    /* TCP header*/
    if (len < sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t)) {
      return 0;
    }

    const tcp_hdr_t* tcp_hdr =
        (const tcp_hdr_t*)(buf + sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t));

    uint16_t sport = ntohs(tcp_hdr->tcp_src);
    uint16_t dport = ntohs(tcp_hdr->tcp_dst);

    /* check port*/
    if (sport == 80 || dport == 80
        /* || sport == 8080 || dport == 8080 */) {
      return 1;
    }
    return 0;
  }

  /* no protocol match */
  return 0;
}