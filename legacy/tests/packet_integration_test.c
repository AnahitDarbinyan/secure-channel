
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "secure_crypto.h"

int main(void)
{
    unsigned char key[KEY_SIZE];
    unsigned char encrypted[1024];
    unsigned char decrypted[1024];

    const unsigned char message[] =
        "Hello from Device1 to Device2!";

    int message_length = (int)strlen((const char *)message);

    if (RAND_bytes(key, KEY_SIZE) != 1) {
        printf("ERROR: Key generation failed.\n");
        return 1;
    }

    printf("Device1: Original TCP payload: %s\n", message);

    int encrypted_length = encrypt_tcp_payload(
        key, message, message_length, encrypted
    );

    if (encrypted_length < 0) {
        printf("ERROR: Encryption failed.\n");
        return 1;
    }

    printf("Device1: AES-256-GCM encryption successful.\n");
    printf("Device1: Encrypted payload: %d bytes\n",
           encrypted_length);

    int decrypted_length = decrypt_tcp_payload(
        key, encrypted, encrypted_length, decrypted
    );

    if (decrypted_length < 0) {
        printf("ERROR: Authentication or decryption failed.\n");
        return 1;
    }

    if (decrypted_length != message_length ||
        memcmp(message, decrypted, message_length) != 0) {
        printf("ERROR: Decrypted payload does not match.\n");
        return 1;
    }

    printf("Device2: AES-256-GCM authentication successful.\n");
    printf("Device2: Decrypted TCP payload: %s\n", decrypted);

    printf("\nSUCCESS: Packet crypto integration test passed!\n");

    return 0;
}
