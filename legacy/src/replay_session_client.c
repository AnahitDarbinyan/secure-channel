#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "replay_network.h"

#define SESSION_PORT 5008
#define SERVER_ADDRESS "127.0.0.1"
#define MESSAGE_COUNT 3

int main(void)
{
    int sock = -1, result = 1;
    EVP_PKEY *private_key = NULL, *peer_key = NULL;

    unsigned char local_public[PUBLIC_KEY_SIZE];
    unsigned char peer_public[PUBLIC_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char secret[KEY_SIZE] = {0};
    unsigned char transcript[SESSION_TRANSCRIPT_SIZE];
    unsigned char client_proof[SESSION_PROOF_SIZE];
    unsigned char server_proof[SESSION_PROOF_SIZE];
    unsigned char send_key[KEY_SIZE] = {0};
    unsigned char receive_key[KEY_SIZE] = {0};
    unsigned char response[REPLAY_MAX_MESSAGE + 1];

    replay_state send_state, receive_state;
    replay_state_init(&send_state);
    replay_state_init(&receive_state);

    struct sockaddr_in server = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        goto cleanup;
    }

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
        !export_public_key(private_key, local_public) ||
        RAND_bytes(salt, SALT_SIZE) != 1)
        goto cleanup;

    if (!session_send_all(sock, local_public, PUBLIC_KEY_SIZE) ||
        !session_send_all(sock, salt, SALT_SIZE) ||
        !session_receive_all(sock, peer_public, PUBLIC_KEY_SIZE))
        goto cleanup;

    if (!import_public_key(peer_public, &peer_key) ||
        !derive_shared_secret(private_key, peer_key, secret))
        goto cleanup;

    memcpy(transcript, local_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           peer_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2, salt, SALT_SIZE);

    if (!session_make_proof(
            "Device1 authentication", transcript, client_proof) ||
        !session_send_all(sock, client_proof, SESSION_PROOF_SIZE) ||
        !session_receive_all(sock, server_proof, SESSION_PROOF_SIZE))
        goto cleanup;

    if (!session_verify_proof(
            "Device2 authentication", transcript, server_proof)) {
        printf("Device2 authentication failed.\n");
        goto cleanup;
    }

    printf("Device2 authenticated.\n");

    if (!session_derive_key(
            secret, salt, "Device1-to-Device2", send_key) ||
        !session_derive_key(
            secret, salt, "Device2-to-Device1", receive_key))
        goto cleanup;

    printf("Directional session keys established.\n\n");

    for (int i = 0; i < MESSAGE_COUNT; i++) {
        char message[128];
        int message_length = snprintf(
            message, sizeof(message),
            "Hello from Device1, message %d", i + 1);

        if (message_length < 0 ||
            message_length >= (int)sizeof(message) ||
            !send_replay_message(
                sock, send_key, &send_state,
                (unsigned char *)message, message_length)) {
            printf("Failed to send encrypted message.\n");
            goto cleanup;
        }

        printf("Device1 sent encrypted message %d.\n", i + 1);

        int response_length = receive_replay_message(
            sock, receive_key, &receive_state,
            response, sizeof(response));

        if (response_length < 0) {
            printf("ERROR: Response rejected (result %d).\n",
                   response_length);
            goto cleanup;
        }

        printf("Device1 received authenticated response %d: %s\n\n",
               i + 1, response);
    }

    printf("DEVICE1 REPLAY-PROTECTED COMMUNICATION SUCCESSFUL!\n");
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
