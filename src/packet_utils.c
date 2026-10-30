#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet_utils.h"

#define IP_MF      0x2000
#define IP_OFFMASK 0x1fff

int parse_packet(unsigned char *packet, int len,
                 struct iphdr **iph, struct tcphdr **tcph,
                 unsigned char **payload, int *payload_len)
{
    if (packet == NULL || len < (int)sizeof(struct iphdr))
        return -1;

    struct iphdr *ip = (struct iphdr *)packet;

    if (ip->version != 4 || ip->ihl < 5 || ip->protocol != IPPROTO_TCP)
        return -1;

    int ip_hl = ip->ihl * 4;
    int total = ntohs(ip->tot_len);

    if (total > len || total < ip_hl + (int)sizeof(struct tcphdr))
        return -1;

    if (ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK))
        return -1;

    struct tcphdr *tcp = (struct tcphdr *)(packet + ip_hl);
    int tcp_hl = tcp->doff * 4;

    if (tcp->doff < 5 || tcp_hl > total - ip_hl)
        return -1;

    *iph = ip;
    *tcph = tcp;
    *payload = packet + ip_hl + tcp_hl;
    *payload_len = total - ip_hl - tcp_hl;
    return 0;
}

/* Add a block of bytes to a running 32-bit one's-complement sum. */
static uint32_t sum_bytes(uint32_t acc, const void *vdata, size_t length)
{
    const unsigned char *data = vdata;
    size_t i;

    for (i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += word;
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += word;
    }
    return acc;
}

static uint16_t fold_checksum(uint32_t acc)
{
    while (acc >> 16)
        acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc;
}

/* Caller must update iph->tot_len before calling this. */
void recalculate_checksums(struct iphdr *iph, struct tcphdr *tcph)
{
    int ip_hl = iph->ihl * 4;
    int tcp_len = ntohs(iph->tot_len) - ip_hl;

    if (ip_hl < (int)sizeof(struct iphdr) || tcp_len < (int)sizeof(struct tcphdr))
        return;

    /* IPv4 header checksum */
    iph->check = 0;
    iph->check = fold_checksum(sum_bytes(0, iph, ip_hl));

    /* TCP checksum: pseudo-header + TCP header + payload */
    struct {
        uint32_t src_addr;
        uint32_t dest_addr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_length;
    } __attribute__((packed)) pseudo;

    pseudo.src_addr   = iph->saddr;
    pseudo.dest_addr  = iph->daddr;
    pseudo.zero       = 0;
    pseudo.protocol   = IPPROTO_TCP;
    pseudo.tcp_length = htons((uint16_t)tcp_len);

    tcph->check = 0;
    uint32_t acc = sum_bytes(0, &pseudo, sizeof(pseudo));
    acc = sum_bytes(acc, tcph, (size_t)tcp_len);
    tcph->check = fold_checksum(acc);
}