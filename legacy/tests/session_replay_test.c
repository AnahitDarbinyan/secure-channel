#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "session_replay.h"

int main(void)
{
    unsigned char key[KEY_SIZE];
    unsigned char wrong_key[KEY_SIZE];

    unsigned char encrypted[REPLAY_ENCRYPTED_MAX];
    unsigned char encrypted_second[REPLAY_ENCRYPTED_MAX];

    unsigned char decrypted[REPLAY_MAX_MESSAGE + 1];

    const unsigned char message[] =
        "Hello securely from Device1!";

    const int message_length =
        (int)strlen((const char *)message);

    replay_state sender;
    replay_state receiver;

    replay_state_init(&sender);
    replay_state_init(&receiver);

    printf("Starting replay protection tests...\n\n");

    if (RAND_bytes(key, KEY_SIZE) != 1 ||
        RAND_bytes(wrong_key, KEY_SIZE) != 1) {
        printf("ERROR: Key generation failed.\n");
        return 1;
    }

    printf("Test 1: Normal encrypted message\n");

    int encrypted_length = replay_encrypt(
        key, &sender, message, message_length, encrypted);

    if (encrypted_length < 0) {
        printf("FAIL: Encryption failed.\n");
        return 1;
    }

    int decrypted_length = replay_decrypt(
        key, &receiver, encrypted, encrypted_length, decrypted);

    if (decrypted_length != message_length ||
        memcmp(message, decrypted, message_length) != 0) {
        printf("FAIL: Normal message verification failed.\n");
        return 1;
    }

    printf("PASS: Encrypted message accepted and verified.\n");

    printf("\nTest 2: Replay the same message\n");

    int replay_result = replay_decrypt(
        key, &receiver, encrypted, encrypted_length, decrypted);

    if (replay_result != -2) {
        printf("FAIL: Replayed message was not rejected.\n");
        return 1;
    }

    printf("PASS: Replayed message rejected.\n");

    printf("\nTest 3: Out-of-order message\n");

    int second_length = replay_encrypt(
        key, &sender, message, message_length, encrypted_second);

    if (second_length < 0) {
        printf("FAIL: Second encryption failed.\n");
        return 1;
    }

    replay_state out_of_order_receiver;
    replay_state_init(&out_of_order_receiver);

    int order_result = replay_decrypt(
        key, &out_of_order_receiver,
        encrypted_second, second_length, decrypted);

    if (order_result != -2) {
        printf("FAIL: Out-of-order message was not rejected.\n");
        return 1;
    }

    printf("PASS: Out-of-order message rejected.\n");

    printf("\nTest 4: Modified ciphertext\n");

    encrypted_second[NONCE_SIZE] ^= 0x01;

    int tamper_result = replay_decrypt(
        key, &receiver,
        encrypted_second, second_length, decrypted);

    if (tamper_result != -1) {
        printf("FAIL: Modified ciphertext was accepted.\n");
        return 1;
    }

    printf("PASS: Modified ciphertext rejected.\n");

    printf("\nTest 5: Incorrect key\n");

    replay_state wrong_receiver;
    replay_state_init(&wrong_receiver);

    int wrong_key_result = replay_decrypt(
        wrong_key, &wrong_receiver,
        encrypted, encrypted_length, decrypted);

    if (wrong_key_result != -1) {
        printf("FAIL: Incorrect key was accepted.\n");
        return 1;
    }

    printf("PASS: Incorrect key rejected.\n");

    printf("\nALL REPLAY AND TAMPER TESTS PASSED!\n");

    return 0;
}
