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
#include "session_auth.h"
#include <openssl/rand.h>
#include "secure_crypto.h"

#define TEST_PORT 5009
#define QUEUE_NUMBER 1

static unsigned char test_key[KEY_SIZE];

static int establish_authenticated_test_session(void) {
    EVP_PKEY *device1_private = NULL;
    EVP_PKEY *device2_private = NULL;
    EVP_PKEY *device1_peer = NULL;
    EVP_PKEY *device2_peer = NULL;

    unsigned char device1_public[PUBLIC_KEY_SIZE];
    unsigned char device2_public[PUBLIC_KEY_SIZE];

    unsigned char shared1[KEY_SIZE];
    unsigned char shared2[KEY_SIZE];

    unsigned char salt[SALT_SIZE];
    unsigned char transcript[SESSION_TRANSCRIPT_SIZE];

    unsigned char proof1[SESSION_PROOF_SIZE];
    unsigned char proof2[SESSION_PROOF_SIZE];

    unsigned char key1[KEY_SIZE];
    unsigned char key2[KEY_SIZE];

    int success = 0;

    printf("\nEstablishing authenticated test session...\n");

    if (!generate_key_pair(&device1_private) ||
        !generate_key_pair(&device2_private)) {
        printf("ERROR: X25519 key generation failed.\n");
        goto cleanup;
    }

    if (!export_public_key(device1_private, device1_public) ||
        !export_public_key(device2_private, device2_public)) {
        printf("ERROR: Public key export failed.\n");
        goto cleanup;
    }

    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        printf("ERROR: Session salt generation failed.\n");
        goto cleanup;
    }

    if (!import_public_key(device2_public, &device1_peer) ||
        !import_public_key(device1_public, &device2_peer)) {
        printf("ERROR: Peer public key import failed.\n");
        goto cleanup;
    }

    if (!derive_shared_secret(
            device1_private, device1_peer, shared1) ||
        !derive_shared_secret(
            device2_private, device2_peer, shared2)) {
        printf("ERROR: Shared secret derivation failed.\n");
        goto cleanup;
    }

    if (memcmp(shared1, shared2, KEY_SIZE) != 0) {
        printf("ERROR: X25519 shared secrets do not match.\n");
        goto cleanup;
    }

    printf("SUCCESS: X25519 shared secrets match.\n");

    memcpy(transcript, device1_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           device2_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2,
           salt, SALT_SIZE);

    if (!session_make_proof("Device1", transcript, proof1) ||
        !session_make_proof("Device2", transcript, proof2)) {
        printf("ERROR: Session authentication proof failed.\n");
        goto cleanup;
    }

    if (!session_verify_proof("Device1", transcript, proof1) ||
        !session_verify_proof("Device2", transcript, proof2)) {
        printf("ERROR: Session authentication verification failed.\n");
        goto cleanup;
    }

    printf("SUCCESS: PSK authentication proofs verified.\n");

    if (!session_derive_key(
            shared1, salt, "Device1-to-Device2", key1) ||
        !session_derive_key(
            shared2, salt, "Device1-to-Device2", key2)) {
        printf("ERROR: Directional session key derivation failed.\n");
        goto cleanup;
    }

    if (memcmp(key1, key2, KEY_SIZE) != 0) {
        printf("ERROR: Session keys do not match.\n");
        goto cleanup;
    }

    memcpy(test_key, key1, KEY_SIZE);

    printf("SUCCESS: HKDF-SHA-256 session keys match.\n");
    printf("Authenticated test key is ready for NFQUEUE.\n");

    success = 1;

cleanup:
    EVP_PKEY_free(device1_private);
    EVP_PKEY_free(device2_private);
    EVP_PKEY_free(device1_peer);
    EVP_PKEY_free(device2_peer);

    return success;
}

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
    if (!establish_authenticated_test_session()) {
        fprintf(stderr, "ERROR: Authenticated session setup failed.\n");
        return 1;
    }
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