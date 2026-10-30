#include "handshake.h"
#include "session_auth.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>

#define HANDSHAKE_PORT 5006

/*
 * Handshake message order:
 *
 * Device1 -> Device2: Device1 public key (32 bytes)
 * Device2 -> Device1: Device2 public key (32) + salt (16)
 * Device2 -> Device1: server authentication proof (32)
 * Device1 -> Device2: client authentication proof (32)
 *
 * Both devices derive the same directional traffic key.
 */

static int create_server_socket(uint16_t port)
{
    int fd = -1;
    int reuse = 1;

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static int connect_to_server(
    const char *server_ip,
    uint16_t port
) {
    int fd;
    struct sockaddr_in address;

    if (server_ip == NULL)
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip,
                  &address.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IP address\n");
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&address,
                sizeof(address)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static int perform_client_handshake(
    int fd,
    unsigned char traffic_key[KEY_SIZE]
) {
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *peer_key = NULL;

    unsigned char client_public[PUBLIC_KEY_SIZE];
    unsigned char server_public[PUBLIC_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    unsigned char transcript[SESSION_TRANSCRIPT_SIZE];
    unsigned char server_proof[SESSION_PROOF_SIZE];
    unsigned char client_proof[SESSION_PROOF_SIZE];

    int success = 0;

    memset(shared_secret, 0, sizeof(shared_secret));
    memset(traffic_key, 0, KEY_SIZE);

    /* Generate Device1's X25519 key pair. */
    if (!generate_key_pair(&private_key) ||
        !export_public_key(private_key, client_public)) {
        fprintf(stderr, "Device1: key generation failed\n");
        goto cleanup;
    }

    /* Send Device1's public key. */
    if (!session_send_all(fd, client_public,
                          PUBLIC_KEY_SIZE)) {
        fprintf(stderr, "Device1: public key send failed\n");
        goto cleanup;
    }

    /* Receive Device2's public key and fresh salt. */
    if (!session_receive_all(fd, server_public,
                             PUBLIC_KEY_SIZE) ||
        !session_receive_all(fd, salt, SALT_SIZE)) {
        fprintf(stderr, "Device1: server key receive failed\n");
        goto cleanup;
    }

    /* Import Device2's public key. */
    if (!import_public_key(server_public, &peer_key)) {
        fprintf(stderr, "Device1: invalid server public key\n");
        goto cleanup;
    }

    /* Construct the same transcript on both devices. */
    memcpy(transcript, client_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           server_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2,
           salt, SALT_SIZE);

    /* Calculate X25519 shared secret. */
    if (!derive_shared_secret(private_key, peer_key,
                              shared_secret)) {
        fprintf(stderr, "Device1: shared secret failed\n");
        goto cleanup;
    }

    /* Verify Device2's PSK authentication proof. */
    if (!session_receive_all(fd, server_proof,
                             SESSION_PROOF_SIZE)) {
        fprintf(stderr, "Device1: server proof missing\n");
        goto cleanup;
    }

    if (!session_verify_proof(
            "SERVER",
            transcript,
            server_proof)) {
        fprintf(stderr, "Device1: server authentication failed\n");
        goto cleanup;
    }

    /* Authenticate Device1 to Device2. */
    if (!session_make_proof(
            "CLIENT",
            transcript,
            client_proof)) {
        fprintf(stderr, "Device1: proof generation failed\n");
        goto cleanup;
    }

    if (!session_send_all(fd, client_proof,
                          SESSION_PROOF_SIZE)) {
        fprintf(stderr, "Device1: proof send failed\n");
        goto cleanup;
    }

    /* Derive the Device1-to-Device2 traffic key. */
    if (!session_derive_key(
            shared_secret,
            salt,
            "device1-to-device2",
            traffic_key)) {
        fprintf(stderr, "Device1: traffic key derivation failed\n");
        goto cleanup;
    }

    success = 1;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(peer_key);

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(client_proof, sizeof(client_proof));

    if (!success)
        OPENSSL_cleanse(traffic_key, KEY_SIZE);

    return success;
}

static int perform_server_handshake(
    int fd,
    unsigned char traffic_key[KEY_SIZE]
) {
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *peer_key = NULL;

    unsigned char client_public[PUBLIC_KEY_SIZE];
    unsigned char server_public[PUBLIC_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    unsigned char transcript[SESSION_TRANSCRIPT_SIZE];
    unsigned char server_proof[SESSION_PROOF_SIZE];
    unsigned char client_proof[SESSION_PROOF_SIZE];

    int success = 0;

    memset(shared_secret, 0, sizeof(shared_secret));
    memset(traffic_key, 0, KEY_SIZE);

    /* Receive Device1's public key. */
    if (!session_receive_all(fd, client_public,
                             PUBLIC_KEY_SIZE)) {
        fprintf(stderr, "Device2: client public key missing\n");
        goto cleanup;
    }

    /* Generate Device2's X25519 key pair and fresh salt. */
    if (!generate_key_pair(&private_key) ||
        !export_public_key(private_key, server_public) ||
        RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Device2: key or salt generation failed\n");
        goto cleanup;
    }

    /* Send Device2's public key and salt. */
    if (!session_send_all(fd, server_public,
                          PUBLIC_KEY_SIZE) ||
        !session_send_all(fd, salt, SALT_SIZE)) {
        fprintf(stderr, "Device2: public key send failed\n");
        goto cleanup;
    }

    /* Import Device1's public key. */
    if (!import_public_key(client_public, &peer_key)) {
        fprintf(stderr, "Device2: invalid client public key\n");
        goto cleanup;
    }

    /* Construct the transcript in the same order as Device1. */
    memcpy(transcript, client_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           server_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2,
           salt, SALT_SIZE);

    /* Calculate X25519 shared secret. */
    if (!derive_shared_secret(private_key, peer_key,
                              shared_secret)) {
        fprintf(stderr, "Device2: shared secret failed\n");
        goto cleanup;
    }

    /* Send Device2's authentication proof. */
    if (!session_make_proof(
            "SERVER",
            transcript,
            server_proof)) {
        fprintf(stderr, "Device2: proof generation failed\n");
        goto cleanup;
    }

    if (!session_send_all(fd, server_proof,
                          SESSION_PROOF_SIZE)) {
        fprintf(stderr, "Device2: proof send failed\n");
        goto cleanup;
    }

    /* Verify Device1's authentication proof. */
    if (!session_receive_all(fd, client_proof,
                             SESSION_PROOF_SIZE)) {
        fprintf(stderr, "Device2: client proof missing\n");
        goto cleanup;
    }

    if (!session_verify_proof(
            "CLIENT",
            transcript,
            client_proof)) {
        fprintf(stderr, "Device2: client authentication failed\n");
        goto cleanup;
    }

    /* Derive the same Device1-to-Device2 traffic key. */
    if (!session_derive_key(
            shared_secret,
            salt,
            "device1-to-device2",
            traffic_key)) {
        fprintf(stderr, "Device2: traffic key derivation failed\n");
        goto cleanup;
    }

    success = 1;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(peer_key);

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(client_proof, sizeof(client_proof));

    if (!success)
        OPENSSL_cleanse(traffic_key, KEY_SIZE);

    return success;
}

int device_handshake(
    int is_server,
    const char *server_ip,
    uint16_t port,
    unsigned char traffic_key[KEY_SIZE]
) {
    int fd = -1;
    int result = 0;

    if (traffic_key == NULL || port == 0)
        return 0;

    if (is_server) {
        printf("Device2: Waiting for Device1 on port %u...\n",
               (unsigned int)port);

        int listener = create_server_socket(port);

        if (listener < 0)
            return 0;

        fd = accept(listener, NULL, NULL);

        if (fd < 0) {
            perror("accept");
            close(listener);
            return 0;
        }

        close(listener);

        printf("Device1 connected.\n");

        result = perform_server_handshake(fd, traffic_key);
    } else {
        printf("Device1: Connecting to Device2 at %s:%u...\n",
               server_ip ? server_ip : "(missing)",
               (unsigned int)port);

        fd = connect_to_server(server_ip, port);

        if (fd < 0)
            return 0;

        result = perform_client_handshake(fd, traffic_key);
    }

    close(fd);

    if (result) {
        printf("Authenticated handshake successful.\n");
        printf("Device1-to-Device2 traffic key established.\n");
    } else {
        fprintf(stderr, "Handshake failed.\n");
    }

    return result;
}