#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "secure_crypto.h"

#define TEST_PORT 5009
#define QUEUE_NUMBER 1

static unsigned char test_key[KEY_SIZE] = {0};

static int packet_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *packet,
    void *user_data
) {
    (void)message;
    (void)user_data;

    struct nfqnl_msg_packet_hdr *header =
        nfq_get_msg_packet_hdr(packet);

    if (header == NULL) {
        return 0;
    }

    unsigned int packet_id = ntohl(header->packet_id);
    unsigned char *packet_data = NULL;

    int packet_length = nfq_get_payload(packet, &packet_data);

    if (packet_length < 0 || packet_data == NULL) {
        return nfq_set_verdict(
            queue, packet_id, NF_ACCEPT, 0, NULL
        );
    }

    if (packet_length < (int)sizeof(struct iphdr)) {
        goto accept_unchanged;
    }

    struct iphdr *ip = (struct iphdr *)packet_data;

    if (ip->version != 4 ||
        ip->ihl < 5 ||
        ip->protocol != IPPROTO_TCP) {
        goto accept_unchanged;
    }

    unsigned int ip_header_length = ip->ihl * 4;
    unsigned int ip_total_length = ntohs(ip->tot_len);

    if (ip_total_length > (unsigned int)packet_length ||
        ip_total_length < ip_header_length + sizeof(struct tcphdr)) {
        goto accept_unchanged;
    }

    if ((ntohs(ip->frag_off) & 0x3fff) != 0) {
        goto accept_unchanged;
    }

    struct tcphdr *tcp =
        (struct tcphdr *)(packet_data + ip_header_length);

    unsigned int tcp_header_length = tcp->doff * 4;

    if (tcp->doff < 5 ||
        tcp_header_length > ip_total_length - ip_header_length) {
        goto accept_unchanged;
    }

    if (ntohs(tcp->dest) != TEST_PORT) {
        goto accept_unchanged;
    }

    int payload_length =
        (int)(ip_total_length - ip_header_length - tcp_header_length);

    if (payload_length <= 0) {
        goto accept_unchanged;
    }

    unsigned char *payload =
        packet_data + ip_header_length + tcp_header_length;

    unsigned char encrypted[65536];
    unsigned char decrypted[65536];

    printf("\n--- NFQUEUE AES-GCM test ---\n");
    printf("Packet ID: %u\n", packet_id);
    printf("Original payload: %.*s\n", payload_length, payload);

    int encrypted_length = encrypt_tcp_payload(
        test_key,
        payload,
        payload_length,
        encrypted
    );

    if (encrypted_length < 0) {
        printf("AES-GCM encryption FAILED\n");
        goto accept_unchanged;
    }

    printf("Encrypted payload length: %d bytes\n", encrypted_length);

    int decrypted_length = decrypt_tcp_payload(
        test_key,
        encrypted,
        encrypted_length,
        decrypted
    );

    if (decrypted_length < 0) {
        printf("AES-GCM decryption FAILED\n");
        goto accept_unchanged;
    }

    printf("Decrypted payload: %.*s\n",
           decrypted_length, decrypted);

    if (decrypted_length == payload_length &&
        memcmp(payload, decrypted, payload_length) == 0) {
        printf("SUCCESS: AES-GCM round trip verified!\n");
    } else {
        printf("FAILED: Decrypted payload does not match!\n");
    }

    printf("Original TCP packet will be accepted unchanged.\n");
    fflush(stdout);

accept_unchanged:

    return nfq_set_verdict(
        queue, packet_id, NF_ACCEPT, 0, NULL
    );
}

int main(void) {
    struct nfq_handle *handle;
    struct nfq_q_handle *queue;
    unsigned char buffer[65536];

    printf("Starting NFQUEUE AES-GCM integration test...\n");
    printf("Queue number: %d\n", QUEUE_NUMBER);
    printf("Test destination port: %d\n", TEST_PORT);

    handle = nfq_open();

    if (handle == NULL) {
        fprintf(stderr, "ERROR: Could not open NFQUEUE handle.\n");
        return 1;
    }

    nfq_unbind_pf(handle, AF_INET);

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "ERROR: Could not bind IPv4.\n");
        nfq_close(handle);
        return 1;
    }

    queue = nfq_create_queue(
        handle, QUEUE_NUMBER, &packet_callback, NULL
    );

    if (queue == NULL) {
        fprintf(stderr, "ERROR: Could not create NFQUEUE.\n");
        nfq_close(handle);
        return 1;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "ERROR: Could not set packet copy mode.\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return 1;
    }

    printf("Listening on NFQUEUE %d...\n", QUEUE_NUMBER);
    printf("Press Ctrl+C to stop.\n");
    fflush(stdout);

    int fd = nfq_fd(handle);

    while (1) {
        int received = recv(fd, buffer, sizeof(buffer), 0);

        if (received >= 0) {
            nfq_handle_packet(handle, (char *)buffer, received);
        } else if (errno == EINTR) {
            continue;
        } else {
            perror("NFQUEUE receive");
            break;
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return 0;
}