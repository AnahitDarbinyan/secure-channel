#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
 * Parse an IPv4/TCP packet.
 * len is the number of bytes available in the buffer.
 * Returns 0 on success and fills iph, tcph, payload, payload_len
 * (payload_len = TCP payload bytes only, may be 0).
 * Returns -1 if the packet is not a valid, unfragmented IPv4 TCP
 * packet (caller should accept it unchanged).
 */
int parse_packet(unsigned char *packet, int len,
                 struct iphdr **iph, struct tcphdr **tcph,
                 unsigned char **payload, int *payload_len);


void recalculate_checksums(struct iphdr *iph, struct tcphdr *tcph);

#endif  /* PACKET_UTILS_H */