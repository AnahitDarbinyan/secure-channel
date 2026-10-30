#ifndef SESSION_MESSAGE_H
#define SESSION_MESSAGE_H

#include <stdint.h>
#include <arpa/inet.h>
#include "session_auth.h"

#define SESSION_MAX_CIPHERTEXT (MAX_MESSAGE_SIZE + NONCE_SIZE + TAG_SIZE)

static int send_encrypted_message(
    int socket_fd,
    const unsigned char key[KEY_SIZE],
    const unsigned char *message,
    int message_length)
{
    unsigned char encrypted[SESSION_MAX_CIPHERTEXT];

    if (message_length < 0 || message_length > MAX_MESSAGE_SIZE)
        return 0;

    int encrypted_length = encrypt_tcp_payload(
        key, message, message_length, encrypted);

    if (encrypted_length < 0 ||
        encrypted_length > SESSION_MAX_CIPHERTEXT)
        return 0;

    uint32_t network_length = htonl((uint32_t)encrypted_length);

    if (!session_send_all(
            socket_fd, &network_length, sizeof(network_length)))
        return 0;

    return session_send_all(
        socket_fd, encrypted, (size_t)encrypted_length);
}

static int receive_encrypted_message(
    int socket_fd,
    const unsigned char key[KEY_SIZE],
    unsigned char *message,
    int message_capacity)
{
    uint32_t network_length;

    if (!session_receive_all(
            socket_fd, &network_length, sizeof(network_length)))
        return -1;

    uint32_t encrypted_length = ntohl(network_length);

    if (encrypted_length < NONCE_SIZE + TAG_SIZE ||
        encrypted_length > SESSION_MAX_CIPHERTEXT)
        return -1;

    unsigned char encrypted[SESSION_MAX_CIPHERTEXT];

    if (!session_receive_all(
            socket_fd, encrypted, encrypted_length))
        return -1;

    if (message_capacity < MAX_MESSAGE_SIZE + 1)
        return -1;

    int decrypted_length = decrypt_tcp_payload(
        key, encrypted, (int)encrypted_length, message);

    if (decrypted_length < 0 ||
        decrypted_length > MAX_MESSAGE_SIZE)
        return -1;

    message[decrypted_length] = '\0';
    return decrypted_length;
}

#endif
