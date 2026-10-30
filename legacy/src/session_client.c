#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "session_auth.h"

#define SESSION_PORT 5006
#define SERVER_ADDRESS "127.0.0.1"

int main(void)
{
    int sock = -1;
    int result = 1;

    EVP_PKEY *private_key = NULL;
    EVP_PKEY *peer_key = NULL;

    unsigned char local_public[PUBLIC_KEY_SIZE];
    unsigned char peer_public[PUBLIC_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char secret[KEY_SIZE];
    unsigned char transcript[SESSION_TRANSCRIPT_SIZE];
    unsigned char client_proof[SESSION_PROOF_SIZE];
    unsigned char server_proof[SESSION_PROOF_SIZE];

    unsigned char send_key[KEY_SIZE];
    unsigned char receive_key[KEY_SIZE];

    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(SESSION_PORT);

    if (inet_pton(AF_INET, SERVER_ADDRESS,
                  &server.sin_addr) != 1) {
        printf("Invalid server address.\n");
        goto cleanup;
    }

    printf("Device1: Connecting to Device2...\n");

    if (connect(sock, (struct sockaddr *)&server,
                sizeof(server)) < 0) {
        perror("connect");
        goto cleanup;
    }

    printf("Connected to Device2.\n");

    if (!generate_key_pair(&private_key) ||
        !export_public_key(private_key, local_public)) {
        printf("Device1 key generation failed.\n");
        goto cleanup;
    }

    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        printf("Salt generation failed.\n");
        goto cleanup;
    }

    if (!session_send_all(sock, local_public, PUBLIC_KEY_SIZE) ||
        !session_send_all(sock, salt, SALT_SIZE)) {
        printf("Could not send Device1 handshake data.\n");
        goto cleanup;
    }

    if (!session_receive_all(sock, peer_public, PUBLIC_KEY_SIZE)) {
        printf("Could not receive Device2 public key.\n");
        goto cleanup;
    }

    if (!import_public_key(peer_public, &peer_key) ||
        !derive_shared_secret(private_key, peer_key, secret)) {
        printf("Shared-secret derivation failed.\n");
        goto cleanup;
    }

    memcpy(transcript, local_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           peer_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2, salt, SALT_SIZE);

    if (!session_make_proof(
            "Device1 authentication", transcript, client_proof) ||
        !session_send_all(sock, client_proof, SESSION_PROOF_SIZE)) {
        printf("Could not send Device1 authentication proof.\n");
        goto cleanup;
    }

    printf("Device1 authentication proof sent.\n");

    if (!session_receive_all(sock, server_proof,
                             SESSION_PROOF_SIZE)) {
        printf("Could not receive Device2 authentication proof.\n");
        goto cleanup;
    }

    if (!session_verify_proof(
            "Device2 authentication", transcript, server_proof)) {
        printf("Device2 authentication FAILED.\n");
        goto cleanup;
    }

    printf("PASS: Device2 authenticated.\n");

    if (!session_derive_key(
            secret, salt, "Device1-to-Device2", send_key) ||
        !session_derive_key(
            secret, salt, "Device2-to-Device1", receive_key)) {
        printf("Directional key derivation failed.\n");
        goto cleanup;
    }

    printf("PASS: Directional AES-256 keys derived.\n");
    printf("Device1 send key corresponds to Device2 receive key.\n");
    printf("Device1 receive key corresponds to Device2 send key.\n");
    printf("\nDEVICE1 SESSION HANDSHAKE SUCCESSFUL!\n");

    result = 0;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(peer_key);

    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(send_key, sizeof(send_key));
    OPENSSL_cleanse(receive_key, sizeof(receive_key));

    if (sock >= 0)
        close(sock);

    return result;
}
