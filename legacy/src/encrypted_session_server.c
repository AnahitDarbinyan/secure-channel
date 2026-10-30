#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "session_message.h"

#define SESSION_PORT 5007

int main(void)
{
    int listener = -1;
    int client = -1;
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

    unsigned char receive_key[KEY_SIZE] = {0};
    unsigned char send_key[KEY_SIZE] = {0};

    unsigned char message[MAX_MESSAGE_SIZE + 1] = {0};

    struct sockaddr_in address = {0};

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        goto cleanup;
    }

    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));

    address.sin_family = AF_INET;
    address.sin_port = htons(SESSION_PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listener, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        goto cleanup;
    }

    if (listen(listener, 1) < 0) {
        perror("listen");
        goto cleanup;
    }

    printf("Device2: Waiting on TCP port %d...\n", SESSION_PORT);

    client = accept(listener, NULL, NULL);
    if (client < 0) {
        perror("accept");
        goto cleanup;
    }

    printf("Device1 connected.\n");

    if (!session_receive_all(client, peer_public, PUBLIC_KEY_SIZE) ||
        !session_receive_all(client, salt, SALT_SIZE))
        goto cleanup;

    if (!generate_key_pair(&private_key) ||
        !export_public_key(private_key, local_public))
        goto cleanup;

    if (!session_send_all(client, local_public, PUBLIC_KEY_SIZE))
        goto cleanup;

    if (!import_public_key(peer_public, &peer_key) ||
        !derive_shared_secret(private_key, peer_key, secret))
        goto cleanup;

    memcpy(transcript, peer_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           local_public, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2, salt, SALT_SIZE);

    if (!session_receive_all(client, client_proof, SESSION_PROOF_SIZE))
        goto cleanup;

    if (!session_verify_proof(
            "Device1 authentication", transcript, client_proof)) {
        printf("Device1 authentication failed.\n");
        goto cleanup;
    }

    printf("Device1 authenticated successfully.\n");

    if (!session_make_proof(
            "Device2 authentication", transcript, server_proof) ||
        !session_send_all(client, server_proof, SESSION_PROOF_SIZE))
        goto cleanup;

    if (!session_derive_key(
            secret, salt, "Device1-to-Device2", receive_key) ||
        !session_derive_key(
            secret, salt, "Device2-to-Device1", send_key))
        goto cleanup;

    printf("Directional session keys established.\n\n");

    int received_length = receive_encrypted_message(
        client, receive_key, message, sizeof(message));

    if (received_length < 0) {
        printf("ERROR: Device1 message authentication/decryption failed.\n");
        goto cleanup;
    }

    printf("Device2: AES-GCM authentication successful.\n");
    printf("Device2 received: %s\n", message);

    const unsigned char response[] =
        "Secure response from Device2!";

    if (!send_encrypted_message(
            client, send_key, response,
            (int)strlen((const char *)response))) {
        printf("ERROR: Could not send encrypted response.\n");
        goto cleanup;
    }

    printf("Device2: Encrypted response sent successfully.\n");
    printf("\nDEVICE2 ENCRYPTED COMMUNICATION SUCCESSFUL!\n");

    result = 0;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(peer_key);

    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(receive_key, sizeof(receive_key));
    OPENSSL_cleanse(send_key, sizeof(send_key));

    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);

    return result;
}
