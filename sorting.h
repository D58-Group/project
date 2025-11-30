#ifndef SORTING_H
#define SORTING_H

#include <pcap.h>
#include <stdint.h>

int match_protocol(const uint8_t* packet, uint32_t len, const char* proto);

#endif
