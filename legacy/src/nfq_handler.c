
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "secure_crypto.h"

#define IP_MF 0x2000
#define IP_OFFMASK 0x1FFF
#define TEST_PORT 5003

static unsigned short calculate_checksum(
    const unsigned char *data,
    int length
) {
    unsigned long sum = 0;

    while (length > 1) {
        sum += ((unsigned int)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += (unsigned int)data[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((unsigned short)(~sum));
}

static unsigned short calculate_tcp_checksum(
    struct iphdr *ip,
    struct tcphdr *tcp,
    int tcp_length
) {
    unsigned long sum = 0;

    unsigned char *src = (unsigned char *)&ip->saddr;
    unsigned char *dst = (unsigned char *)&ip->daddr;

    for (int i = 0; i < 4; i += 2) {
        sum += ((unsigned int)src[i] << 8) | src[i + 1];
        sum += ((unsigned int)dst[i] << 8) | dst[i + 1];
    }

    sum += IPPROTO_TCP;
    sum += tcp_length;

    unsigned char *data = (unsigned char *)tcp;
    int length = tcp_length;

    while (length > 1) {
        sum += ((unsigned int)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    if (length == 1) {
        sum += (unsigned int)data[0] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return htons((unsigned short)(~sum));
}

static int packet_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *packet,
    void *user_data
) {
    (void)message;
    (void)user_data;

    struct nfqnl_msg_packet_hdr *packet_header =
        nfq_get_msg_packet_hdr(packet);

    if (packet_header == NULL) {
        return 0;
    }

    unsigned int packet_id = ntohl(packet_header->packet_id);
    unsigned char *packet_data = NULL;

    int packet_length = nfq_get_payload(packet, &packet_data);

    if (packet_length < 0 || packet_data == NULL) {
        return nfq_set_verdict(
            queue, packet_id, NF_ACCEPT, 0, NULL
        );
    }

    printf("\n--- Packet received ---\n");
    printf("Packet ID: %u\n", packet_id);
    printf("Packet length: %d bytes\n", packet_length);

    /* Validate minimum IPv4 header size. */
    if (packet_length < (int)sizeof(struct iphdr)) {
        goto accept_unchanged;
    }

    struct iphdr *ip = (struct iphdr *)packet_data;

    /* Validate IPv4 and TCP packet. */
    if (ip->version != 4 ||
        ip->ihl < 5 ||
        ip->protocol != IPPROTO_TCP) {
        goto accept_unchanged;
    }

    unsigned int ip_header_length = ip->ihl * 4;
    unsigned int ip_total_length = ntohs(ip->tot_len);

    if (ip_total_length > (unsigned int)packet_length ||
        ip_total_length < ip_header_length ||
        packet_length < (int)ip_header_length) {
        goto accept_unchanged;
    }

    /* Ignore fragmented IPv4 packets. */
    if ((ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK)) != 0) {
        goto accept_unchanged;
    }

    /* Check that a complete minimum TCP header exists. */
    if (ip_total_length <
        ip_header_length + sizeof(struct tcphdr)) {
        goto accept_unchanged;
    }

    struct tcphdr *tcp =
        (struct tcphdr *)(packet_data + ip_header_length);

    unsigned int tcp_header_length = tcp->doff * 4;

    /* Validate TCP header length. */
    if (tcp->doff < 5 ||
        tcp_header_length > ip_total_length - ip_header_length) {
        goto accept_unchanged;
    }

    printf("Source port: %u\n", ntohs(tcp->source));
    printf("Destination port: %u\n", ntohs(tcp->dest));

    int tcp_length =
        (int)(ip_total_length - ip_header_length);

    int payload_length =
        tcp_length - (int)tcp_header_length;

    printf("TCP payload length: %d bytes\n", payload_length);

    /* Only modify packets sent to the test destination port. */
    if (ntohs(tcp->dest) == TEST_PORT && payload_length > 0) {

        unsigned char *payload =
            packet_data + ip_header_length + tcp_header_length;

        printf("Original payload: ");

        for (int i = 0; i < payload_length; i++) {
            putchar(isprint((unsigned char)payload[i])
                    ? payload[i] : '.');
        }

        printf("\n");

        int modified = 0;

        for (int i = 0; i <= payload_length - 5; i++) {

            if (memcmp(payload + i, "HELLO", 5) == 0) {

                memcpy(payload + i, "WORLD", 5);
                modified = 1;
                i += 4;
            }
        }

        if (modified) {
            /* Recalculate TCP checksum. */
            tcp->check = 0;
            tcp->check = calculate_tcp_checksum(
                ip,
                tcp,
                tcp_length
            );

            /* Recalculate IPv4 header checksum. */
            ip->check = 0;
            ip->check = calculate_checksum(
                (unsigned char *)ip,
                (int)ip_header_length
            );

            printf("Payload modified: HELLO -> WORLD\n");
        }

        printf("Modified payload: ");

        for (int i = 0; i < payload_length; i++) {
            putchar(isprint((unsigned char)payload[i])
                    ? payload[i] : '.');
        }

        printf("\n");
    }

    printf("Verdict: ACCEPT\n");
    fflush(stdout);

    return nfq_set_verdict(
        queue,
        packet_id,
        NF_ACCEPT,
        (uint32_t)packet_length,
        packet_data
    );

accept_unchanged:

    printf("Verdict: ACCEPT (unchanged)\n");
    fflush(stdout);

    return nfq_set_verdict(
        queue, packet_id, NF_ACCEPT, 0, NULL
    );
}

int main(void) {

    struct nfq_handle *handle;
    struct nfq_q_handle *queue;
    char buffer[65536];

    printf("Starting NFQUEUE packet modification test...\n");

    handle = nfq_open();

    if (handle == NULL) {
        fprintf(stderr, "Error opening NFQUEUE handle\n");
        return 1;
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "Warning: could not unbind IPv4 handler\n");
    }

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "Error binding IPv4 handler\n");
        nfq_close(handle);
        return 1;
    }

    queue = nfq_create_queue(
        handle, 0, &packet_callback, NULL
    );

    if (queue == NULL) {
        fprintf(stderr, "Error creating queue 0\n");
        nfq_close(handle);
        return 1;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error setting packet copy mode\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return 1;
    }

    printf("Listening on NFQUEUE 0...\n");
    printf("Test destination port: %d\n", TEST_PORT);
    printf("Press Ctrl+C to stop.\n");

    int file_descriptor = nfq_fd(handle);

    while (1) {
        int received = recv(
            file_descriptor,
            buffer,
            sizeof(buffer),
            0
        );

        if (received >= 0) {
            nfq_handle_packet(handle, buffer, received);
        } else if (errno != EINTR) {
            perror("recv");
            break;
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return 0;
}
