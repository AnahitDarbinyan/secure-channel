#include "secure_crypto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SERVER_IP "127.0.0.1"
#define PORT 5001

int main(void)
{
    int socket_fd = -1;
    struct sockaddr_in server_address;

    EVP_PKEY *client_key = NULL;
    EVP_PKEY *server_key = NULL;

    unsigned char client_public[PUBLIC_KEY_SIZE];
    unsigned char server_public[PUBLIC_KEY_SIZE];
    unsigned char salt[SALT_SIZE];
    unsigned char shared_secret[KEY_SIZE];
    unsigned char aes_key[KEY_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[MAX_MESSAGE_SIZE];
    unsigned char tag[TAG_SIZE];

    const unsigned char message[] = "Hello securely from Device1!";
    uint32_t network_length;

    int message_length = (int)strlen((const char *)message);
    int ciphertext_length;
    int result = 1;

    if (message_length <= 0 || message_length > MAX_MESSAGE_SIZE) {
        printf("Invalid message length.\n");
        goto cleanup;
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0) {
        perror("Socket creation failed");
        goto cleanup;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP,
                  &server_address.sin_addr) != 1) {
        printf("Invalid server IP address.\n");
        goto cleanup;
    }

    if (connect(socket_fd, (struct sockaddr *)&server_address,
                sizeof(server_address)) < 0) {
        perror("Connection failed");
        goto cleanup;
    }

    printf("Connected to Device2.\n");

    if (!generate_key_pair(&client_key) ||
        !export_public_key(client_key, client_public)) {
        printf("Device1 key generation failed.\n");
        goto cleanup;
    }

    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        printf("Random salt generation failed.\n");
        goto cleanup;
    }

    if (!send_all(socket_fd, client_public, PUBLIC_KEY_SIZE) ||
        !send_all(socket_fd, salt, SALT_SIZE)) {
        printf("Failed to send handshake data.\n");
        goto cleanup;
    }

    printf("Device1 public key and salt sent.\n");

    if (!receive_all(socket_fd, server_public, PUBLIC_KEY_SIZE)) {
        printf("Failed to receive Device2 public key.\n");
        goto cleanup;
    }

    if (!import_public_key(server_public, &server_key)) {
        printf("Could not import Device2 public key.\n");
        goto cleanup;
    }

    if (!derive_shared_secret(client_key, server_key, shared_secret)) {
        printf("Shared secret derivation failed.\n");
        goto cleanup;
    }

    if (!derive_aes_key(shared_secret, salt, aes_key)) {
        printf("AES key derivation failed.\n");
        goto cleanup;
    }

    printf("X25519 key exchange completed.\n");
    printf("HKDF-SHA-256 session key derived.\n");

    if (RAND_bytes(nonce, NONCE_SIZE) != 1) {
        printf("Nonce generation failed.\n");
        goto cleanup;
    }

    ciphertext_length = encrypt_message(
        aes_key,
        nonce,
        message,
        message_length,
        ciphertext,
        tag
    );

    if (ciphertext_length < 0) {
        printf("Message encryption failed.\n");
        goto cleanup;
    }

    printf("AES-256-GCM encryption successful.\n");

    network_length = htonl((uint32_t)ciphertext_length);

    if (!send_all(socket_fd, nonce, NONCE_SIZE) ||
        !send_all(socket_fd, &network_length, sizeof(network_length))) {
        printf("Failed to send message metadata.\n");
        goto cleanup;
    }

    if (!send_all(socket_fd, ciphertext, (size_t)ciphertext_length) ||
        !send_all(socket_fd, tag, TAG_SIZE)) {
        printf("Failed to send encrypted message.\n");
        goto cleanup;
    }

    printf("Encrypted message sent to Device2.\n");

    result = 0;

cleanup:
    if (socket_fd >= 0)
        close(socket_fd);

    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_key);

    return result;
}
