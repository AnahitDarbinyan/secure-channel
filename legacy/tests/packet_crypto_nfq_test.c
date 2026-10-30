
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/rand.h>
#include "secure_crypto.h"

static unsigned char session_key[KEY_SIZE];

static int packet_callback(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *data,
    void *user_data)
{
    (void)message;
    (void)user_data;

    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(data);
    if (header == NULL)
        return 0;

    uint32_t id = ntohl(header->packet_id);
    unsigned char *packet = NULL;
    int packet_length = nfq_get_payload(data, &packet);

    if (packet_length < (int)sizeof(struct iphdr))
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    struct iphdr *ip = (struct iphdr *)packet;

    if (ip->version != 4 || ip->protocol != IPPROTO_TCP)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    int ip_header_length = ip->ihl * 4;

    if (ip_header_length < 20 || packet_length < ip_header_length)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    if (ntohs(ip->tot_len) > packet_length ||
        ntohs(ip->tot_len) < ip_header_length + 20)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    struct tcphdr *tcp =
        (struct tcphdr *)(packet + ip_header_length);

    int tcp_header_length = tcp->doff * 4;

    if (tcp_header_length < 20 ||
        ntohs(ip->tot_len) < ip_header_length + tcp_header_length)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    if (ntohs(tcp->dest) != 5004)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    int payload_length =
        ntohs(ip->tot_len) - ip_header_length - tcp_header_length;

    if (payload_length <= 0)
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    unsigned char *payload =
        packet + ip_header_length + tcp_header_length;

    unsigned char encrypted[60028];
    unsigned char decrypted[60001];

    int encrypted_length = encrypt_tcp_payload(
        session_key, payload, payload_length, encrypted);

    if (encrypted_length < 0) {
        printf("Encryption failed.\n");
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
    }

    int decrypted_length = decrypt_tcp_payload(
        session_key, encrypted, encrypted_length, decrypted);

    if (decrypted_length != payload_length ||
        memcmp(payload, decrypted, payload_length) != 0) {
        printf("Encryption/decryption verification failed.\n");
    } else {
        printf("TCP payload intercepted: %d bytes\n", payload_length);
        printf("AES-GCM encrypted payload: %d bytes\n", encrypted_length);
        printf("AES-GCM decryption verified successfully.\n\n");
    }

    return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
}

int main(void)
{
    if (RAND_bytes(session_key, KEY_SIZE) != 1) {
        fprintf(stderr, "Session key generation failed.\n");
        return 1;
    }

    struct nfq_handle *handle = nfq_open();
    if (handle == NULL) {
        fprintf(stderr, "Could not open NFQUEUE.\n");
        return 1;
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0 ||
        nfq_bind_pf(handle, AF_INET) < 0) {
        fprintf(stderr, "Could not bind IPv4 queue.\n");
        nfq_close(handle);
        return 1;
    }

    struct nfq_q_handle *queue =
        nfq_create_queue(handle, 1, &packet_callback, NULL);

    if (queue == NULL) {
        fprintf(stderr, "Could not create queue 1.\n");
        nfq_close(handle);
        return 1;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Could not set packet copy mode.\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return 1;
    }

    printf("NFQUEUE crypto integration test running.\n");
    printf("Monitoring outgoing TCP payloads to port 5004.\n");
    printf("Press Ctrl+C to stop.\n\n");

    int fd = nfq_fd(handle);
    char buffer[65536];

    while (1) {
        int received = recv(fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            perror("NFQUEUE receive");
            break;
        }

        if (nfq_handle_packet(handle, buffer, received) < 0) {
            fprintf(stderr, "Error processing queued packet.\n");
            break;
        }
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);
    return 0;
}
