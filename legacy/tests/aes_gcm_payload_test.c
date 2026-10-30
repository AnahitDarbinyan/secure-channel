
#include <stdio.h>
#include <string.h>
#include "secure_crypto.h"

int main(void) {
    unsigned char key[KEY_SIZE] = {0};
    unsigned char original[] = "HELLO";
    unsigned char encrypted[128];
    unsigned char decrypted[128];

    int encrypted_length = encrypt_tcp_payload(
        key, original, 5, encrypted
    );

    if (encrypted_length < 0) {
        printf("Encryption FAILED\n");
        return 1;
    }

    printf("Original payload: HELLO\n");
    printf("Encrypted payload length: %d bytes\n",
           encrypted_length);

    int decrypted_length = decrypt_tcp_payload(
        key, encrypted, encrypted_length, decrypted
    );

    if (decrypted_length != 5 ||
        memcmp(original, decrypted, 5) != 0) {
        printf("Normal decryption FAILED\n");
        return 1;
    }

    printf("Decrypted payload: %.*s\n",
           decrypted_length, decrypted);
    printf("SUCCESS: Normal AES-GCM decryption passed!\n");

    encrypted[15] ^= 0x01;

    int tampered_length = decrypt_tcp_payload(
        key, encrypted, encrypted_length, decrypted
    );

    if (tampered_length < 0) {
        printf("SUCCESS: Tampered ciphertext rejected!\n");
    } else {
        printf("FAILED: Tampered ciphertext was accepted!\n");
        return 1;
    }
        encrypted_length = encrypt_tcp_payload(
        key, original, 5, encrypted
    );

    if (encrypted_length < 0) {
        printf("Encryption FAILED\n");
        return 1;
    }

    unsigned char wrong_key[KEY_SIZE] = {1};

    int wrong_key_length = decrypt_tcp_payload(
        wrong_key, encrypted, encrypted_length, decrypted
    );

    if (wrong_key_length < 0) {
        printf("SUCCESS: Wrong encryption key rejected!\n");
    } else {
        printf("FAILED: Wrong encryption key was accepted!\n");
        return 1;
    }
    
    printf("\nALL AES-GCM PAYLOAD SECURITY TESTS PASSED!\n");
    return 0;
}
