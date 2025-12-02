#ifndef SR_UTILS_H
#define SR_UTILS_H

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);
void print_hdr_tcp(uint8_t *buf);
void print_hdr_udp(uint8_t *buf);


/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

/* Dynamic ui*/
enum protocol get_protocol(const uint8_t *packet);
void convert_addr_eth_to_str(uint8_t *addr, char *str_addr);
void convert_addr_ip_int_to_str(uint32_t ip, char *str_addr);
void get_source_dest(char *src, char *dst, const uint8_t *packet);
//used to put the print_hdrs output in a string
char *format_hdrs_to_string(uint8_t *buf, uint32_t length);
char *http_hdr_to_str(uint8_t *buf, uint32_t length);
#endif /* -- SR_UTILS_H -- */
