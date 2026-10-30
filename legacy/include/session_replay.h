#ifndef SESSION_REPLAY_H
#define SESSION_REPLAY_H

#include <stdint.h>
#include <string.h>
#include "session_auth.h"

#define REPLAY_MAX_MESSAGE 1024
#define REPLAY_PLAIN_MAX (REPLAY_MAX_MESSAGE + 8)
#define REPLAY_ENCRYPTED_MAX (REPLAY_PLAIN_MAX + NONCE_SIZE + TAG_SIZE)

typedef struct {
    uint64_t next_send;
    uint64_t next_receive;
} replay_state;

static void replay_store_counter(
    unsigned char output[8], uint64_t counter)
{
    for (int i = 7; i >= 0; i--) {
        output[i] = (unsigned char)(counter & 0xff);
        counter >>= 8;
    }
}

static uint64_t replay_load_counter(const unsigned char input[8])
{
    uint64_t counter = 0;

    for (int i = 0; i < 8; i++)
        counter = (counter << 8) | input[i];

    return counter;
}

static void replay_state_init(replay_state *state)
{
    state->next_send = 0;
    state->next_receive = 0;
}

/* Encrypt a message with its sequence counter inside
   the authenticated AES-GCM ciphertext. */
static int replay_encrypt(
    const unsigned char key[KEY_SIZE],
    replay_state *state,
    const unsigned char *message,
    int message_length,
    unsigned char *output)
{
    if (state == NULL || message == NULL || output == NULL ||
        message_length < 0 ||
        message_length > REPLAY_MAX_MESSAGE ||
        state->next_send == UINT64_MAX)
        return -1;

    unsigned char plaintext[REPLAY_PLAIN_MAX];

    replay_store_counter(plaintext, state->next_send);

    if (message_length > 0)
        memcpy(plaintext + 8, message, (size_t)message_length);

    int encrypted_length = encrypt_tcp_payload(
        key, plaintext, message_length + 8, output);

    if (encrypted_length < 0)
        return -1;

    state->next_send++;
    return encrypted_length;
}

/* Decrypt and verify that the sequence counter is exactly
   the next expected counter. */
static int replay_decrypt(
    const unsigned char key[KEY_SIZE],
    replay_state *state,
    const unsigned char *input,
    int input_length,
    unsigned char *message)
{
    if (state == NULL || input == NULL || message == NULL ||
        input_length < NONCE_SIZE + 8 + TAG_SIZE ||
        input_length > REPLAY_ENCRYPTED_MAX)
        return -1;

    unsigned char plaintext[REPLAY_PLAIN_MAX + 1];

    int plaintext_length = decrypt_tcp_payload(
        key, input, input_length, plaintext);

    if (plaintext_length < 8)
        return -1;

    uint64_t received_counter = replay_load_counter(plaintext);

    if (received_counter != state->next_receive)
        return -2;

    int message_length = plaintext_length - 8;

    if (message_length > REPLAY_MAX_MESSAGE)
        return -1;

    if (message_length > 0)
        memcpy(message, plaintext + 8, (size_t)message_length);

    state->next_receive++;
    return message_length;
}

#endif
