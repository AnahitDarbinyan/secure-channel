
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "secure_crypto.h"

#define TEST_BUFFER_SIZE 2048

static int test_round_trip(
    const char *name,
    const unsigned char *message,
    int message_length)
{
    unsigned char key[KEY_SIZE];
    unsigned char encrypted[TEST_BUFFER_SIZE];
    unsigned char decrypted[TEST_BUFFER_SIZE];

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        printf("FAIL: Could not generate key.\n");
        return 0;
    }

    int encrypted_length = encrypt_tcp_payload(
        key, message, message_length, encrypted);

    if (encrypted_length < 0) {
        printf("FAIL: %s encryption failed.\n", name);
        return 0;
    }

    int decrypted_length = decrypt_tcp_payload(
        key, encrypted, encrypted_length, decrypted);

    if (decrypted_length != message_length ||
        memcmp(message, decrypted, message_length) != 0) {
        printf("FAIL: %s round-trip verification failed.\n", name);
        return 0;
    }

    printf("PASS: %s encryption and decryption (%d bytes).\n",
           name, message_length);

    return 1;
}

int main(void)
{
    const unsigned char text[] = "Hello from Device1!";
    unsigned char binary[] = {
        0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff
    };

    unsigned char large_message[1024];
    unsigned char key[KEY_SIZE];
    unsigned char wrong_key[KEY_SIZE];
    unsigned char encrypted[TEST_BUFFER_SIZE];
    unsigned char decrypted[TEST_BUFFER_SIZE];

    memset(large_message, 0x5A, sizeof(large_message));

    printf("Starting packet encryption security tests...\n\n");

    if (!test_round_trip("Text payload", text, sizeof(text) - 1))
        return 1;

    if (!test_round_trip("Binary payload", binary, sizeof(binary)))
        return 1;

    if (!test_round_trip("Large payload", large_message,
                         sizeof(large_message)))
        return 1;

    printf("\nTesting tamper detection...\n");

    if (RAND_bytes(key, KEY_SIZE) != 1 ||
        RAND_bytes(wrong_key, KEY_SIZE) != 1)
        return 1;

    int encrypted_length = encrypt_tcp_payload(
        key, text, sizeof(text) - 1, encrypted);

    if (encrypted_length < 0)
        return 1;

    encrypted[NONCE_SIZE] ^= 0x01;

    if (decrypt_tcp_payload(
            key, encrypted, encrypted_length, decrypted) != -1) {
        printf("FAIL: Modified ciphertext was accepted.\n");
        return 1;
    }

    printf("PASS: Modified ciphertext rejected.\n");

    printf("\nTesting incorrect key rejection...\n");

    encrypted_length = encrypt_tcp_payload(
        key, text, sizeof(text) - 1, encrypted);

    if (encrypted_length < 0)
        return 1;

    if (decrypt_tcp_payload(
            wrong_key, encrypted, encrypted_length, decrypted) != -1) {
        printf("FAIL: Incorrect key was accepted.\n");
        return 1;
    }

    printf("PASS: Incorrect key rejected.\n");

    printf("\nALL PACKET CRYPTO SECURITY TESTS PASSED!\n");

    return 0;
}
