
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "secure_crypto.h"

int main(void)
{
    EVP_PKEY *device1_private = NULL;
    EVP_PKEY *device2_private = NULL;
    EVP_PKEY *device1_public = NULL;
    EVP_PKEY *device2_public = NULL;

    unsigned char device1_pub[PUBLIC_KEY_SIZE];
    unsigned char device2_pub[PUBLIC_KEY_SIZE];

    unsigned char secret1[KEY_SIZE];
    unsigned char secret2[KEY_SIZE];

    unsigned char salt[SALT_SIZE];
    unsigned char key1[KEY_SIZE];
    unsigned char key2[KEY_SIZE];

    printf("Generating Device1 key pair...\n");
    if (!generate_key_pair(&device1_private))
        goto error;

    printf("Generating Device2 key pair...\n");
    if (!generate_key_pair(&device2_private))
        goto error;

    if (!export_public_key(device1_private, device1_pub) ||
        !export_public_key(device2_private, device2_pub))
        goto error;

    if (!import_public_key(device2_pub, &device2_public) ||
        !import_public_key(device1_pub, &device1_public))
        goto error;

    printf("Performing X25519 key exchange...\n");

    if (!derive_shared_secret(device1_private, device2_public, secret1) ||
        !derive_shared_secret(device2_private, device1_public, secret2))
        goto error;

    if (memcmp(secret1, secret2, KEY_SIZE) != 0) {
        printf("ERROR: Shared secrets do not match.\n");
        goto error;
    }

    printf("SUCCESS: X25519 shared secrets match.\n");

    if (RAND_bytes(salt, SALT_SIZE) != 1)
        goto error;

    if (!derive_aes_key(secret1, salt, key1) ||
        !derive_aes_key(secret2, salt, key2))
        goto error;

    if (memcmp(key1, key2, KEY_SIZE) != 0) {
        printf("ERROR: Session keys do not match.\n");
        goto error;
    }

    printf("SUCCESS: HKDF-SHA-256 session keys match.\n");
    printf("\nSUCCESS: Device1 and Device2 session key test passed!\n");

    EVP_PKEY_free(device1_private);
    EVP_PKEY_free(device2_private);
    EVP_PKEY_free(device1_public);
    EVP_PKEY_free(device2_public);
    return 0;

error:
    printf("ERROR: Session key test failed.\n");
    EVP_PKEY_free(device1_private);
    EVP_PKEY_free(device2_private);
    EVP_PKEY_free(device1_public);
    EVP_PKEY_free(device2_public);
    return 1;
}
