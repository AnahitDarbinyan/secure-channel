#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#include "secure_crypto.h"

int encrypt_tcp_payload(
    const unsigned char key[KEY_SIZE],
    const unsigned char *plaintext,
    int plaintext_length,
    unsigned char *output
);

int decrypt_tcp_payload(
    const unsigned char key[KEY_SIZE],
    const unsigned char *input,
    int input_length,
    unsigned char *plaintext
);

int main(void)
{
    unsigned char key[KEY_SIZE];
    unsigned char encrypted[1024];
    unsigned char decrypted[1024];

    const unsigned char message[] =
        "Hello securely through TCP payload!";

    int message_length = (int)strlen((const char *)message);

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        printf("ERROR: Key generation failed.\n");
        return 1;
    }

    printf("Original message: %s\n", message);

    int encrypted_length = encrypt_tcp_payload(
        key,
        message,
        message_length,
        encrypted
    );

    if (encrypted_length < 0) {
        printf("ERROR: Encryption failed.\n");
        return 1;
    }

    printf("AES-256-GCM encryption successful.\n");
    printf("Original payload length: %d bytes\n", message_length);
    printf("Encrypted payload length: %d bytes\n", encrypted_length);

    int decrypted_length = decrypt_tcp_payload(
        key,
        encrypted,
        encrypted_length,
        decrypted
    );

    if (decrypted_length < 0) {
        printf("ERROR: Decryption or authentication failed.\n");
        return 1;
    }

    decrypted[decrypted_length] = '\0';

    printf("AES-256-GCM authentication successful.\n");
    printf("Decrypted message: %s\n", decrypted);

    if (decrypted_length != message_length ||
        memcmp(message, decrypted, message_length) != 0) {
        printf("ERROR: Messages do not match.\n");
        return 1;
    }
        printf("\nTesting tamper detection...\n");

    /* Change one byte of the encrypted ciphertext */
    encrypted[NONCE_SIZE] ^= 0x01;

    int tampered_result = decrypt_tcp_payload(
        key,
        encrypted,
        encrypted_length,
        decrypted
    );

    if (tampered_result != -1) {
        printf("ERROR: Tampered message was accepted!\n");
        return 1;
    }

    printf("SUCCESS: Tampered message rejected!\n");

    printf("\nSUCCESS: Packet encryption test passed!\n");

    return 0;
}
