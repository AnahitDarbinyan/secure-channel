#include "secure_crypto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#define PORT 5001

int main(void)
{
    int server_fd = -1;
    int client_fd = -1;

    struct sockaddr_in address;

    EVP_PKEY *server_key = NULL;
    EVP_PKEY *client_key = NULL;

    unsigned char server_public[PUBLIC_KEY_SIZE];
    unsigned char client_public[PUBLIC_KEY_SIZE];

    unsigned char salt[SALT_SIZE];
    unsigned char shared_secret[KEY_SIZE];
    unsigned char aes_key[KEY_SIZE];

    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[MAX_MESSAGE_SIZE];
    unsigned char tag[TAG_SIZE];
    unsigned char plaintext[MAX_MESSAGE_SIZE + 1];

    uint32_t network_length;
    uint32_t message_length;

    int result = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("Socket creation failed");
        goto cleanup;
    }

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("Bind failed");
        goto cleanup;
    }

    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        goto cleanup;
    }

    printf("Device2: Waiting for Device1 on port %d...\n", PORT);

    client_fd = accept(server_fd, NULL, NULL);

    if (client_fd < 0) {
        perror("Accept failed");
        goto cleanup;
    }

    printf("Device1 connected!\n");

    if (!receive_all(client_fd, client_public, PUBLIC_KEY_SIZE) ||
        !receive_all(client_fd, salt, SALT_SIZE)) {
        printf("Failed to receive handshake data.\n");
        goto cleanup;
    }

    if (!generate_key_pair(&server_key) ||
        !export_public_key(server_key, server_public)) {
        printf("Device2 key generation failed.\n");
        goto cleanup;
    }

    if (!send_all(client_fd, server_public, PUBLIC_KEY_SIZE)) {
        printf("Failed to send public key.\n");
        goto cleanup;
    }

    if (!import_public_key(client_public, &client_key)) {
        printf("Could not import Device1 public key.\n");
        goto cleanup;
    }

    if (!derive_shared_secret(server_key, client_key, shared_secret)) {
        printf("Shared secret derivation failed.\n");
        goto cleanup;
    }

    if (!derive_aes_key(shared_secret, salt, aes_key)) {
        printf("AES key derivation failed.\n");
        goto cleanup;
    }

    printf("X25519 key exchange completed.\n");
    printf("HKDF-SHA-256 session key derived.\n");

    if (!receive_all(client_fd, nonce, NONCE_SIZE) ||
        !receive_all(client_fd, &network_length, sizeof(network_length))) {
        printf("Failed to receive message metadata.\n");
        goto cleanup;
    }

    message_length = ntohl(network_length);

    if (message_length == 0 || message_length > MAX_MESSAGE_SIZE) {
        printf("Invalid message length.\n");
        goto cleanup;
    }

    if (!receive_all(client_fd, ciphertext, message_length) ||
        !receive_all(client_fd, tag, TAG_SIZE)) {
        printf("Failed to receive encrypted message.\n");
        goto cleanup;
    }

    if (!decrypt_message(aes_key, nonce, ciphertext,
                         (int)message_length, tag, plaintext)) {
        printf("ERROR: Authentication failed!\n");
        goto cleanup;
    }

    printf("AES-256-GCM authentication successful!\n");
    printf("Decrypted message: %s\n", plaintext);

    result = 0;

cleanup:
    if (client_fd >= 0)
        close(client_fd);

    if (server_fd >= 0)
        close(server_fd);

    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_key);

    return result;
}
