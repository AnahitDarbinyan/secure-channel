#ifndef REPLAY_NETWORK_H
#define REPLAY_NETWORK_H

#include <stdint.h>
#include "session_replay.h"

static int send_replay_message(
    int fd,
    const unsigned char key[KEY_SIZE],
    replay_state *state,
    const unsigned char *message,
    int message_length)
{
    unsigned char encrypted[REPLAY_ENCRYPTED_MAX];

    int encrypted_length = replay_encrypt(
        key, state, message, message_length, encrypted);

    if (encrypted_length < 0)
        return 0;

    uint32_t network_length = htonl((uint32_t)encrypted_length);

    if (!session_send_all(fd, &network_length, sizeof(network_length)))
        return 0;

    return session_send_all(
        fd, encrypted, (size_t)encrypted_length);
}

static int receive_replay_message(
    int fd,
    const unsigned char key[KEY_SIZE],
    replay_state *state,
    unsigned char *message,
    int message_capacity)
{
    uint32_t network_length;

    if (!session_receive_all(fd, &network_length, sizeof(network_length)))
        return -1;

    uint32_t encrypted_length = ntohl(network_length);

    if (encrypted_length < NONCE_SIZE + 8 + TAG_SIZE ||
        encrypted_length > REPLAY_ENCRYPTED_MAX)
        return -1;

    if (message_capacity < REPLAY_MAX_MESSAGE + 1)
        return -1;

    unsigned char encrypted[REPLAY_ENCRYPTED_MAX];

    if (!session_receive_all(fd, encrypted, encrypted_length))
        return -1;

    int length = replay_decrypt(
        key, state, encrypted, (int)encrypted_length, message);

    if (length < 0)
        return length;

    message[length] = '\0';
    return length;
}

#endif
