
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include "secure_crypto.h"

#define PROOF_SIZE 32

static int derive_labelled_key(
    const unsigned char *secret,
    const unsigned char *salt,
    const char *label,
    unsigned char output[KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t output_length = KEY_SIZE;

    if (ctx == NULL)
        return 0;

    int ok =
        EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(
            ctx, salt, SALT_SIZE) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            ctx, secret, KEY_SIZE) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx, (const unsigned char *)label,
            strlen(label)) > 0 &&
        EVP_PKEY_derive(ctx, output, &output_length) > 0;

    EVP_PKEY_CTX_free(ctx);

    return ok && output_length == KEY_SIZE;
}

static int make_proof(
    const unsigned char *psk,
    const char *label,
    const unsigned char *transcript,
    size_t transcript_length,
    unsigned char proof[PROOF_SIZE])
{
    unsigned char message[256];
    size_t label_length = strlen(label);

    if (label_length + transcript_length > sizeof(message))
        return 0;

    memcpy(message, label, label_length);
    memcpy(message + label_length, transcript, transcript_length);

    unsigned int proof_length = 0;

    unsigned char *result = HMAC(
        EVP_sha256(),
        psk, KEY_SIZE,
        message, label_length + transcript_length,
        proof, &proof_length);

    return result != NULL && proof_length == PROOF_SIZE;
}

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
    unsigned char psk[KEY_SIZE];

    unsigned char transcript[
        PUBLIC_KEY_SIZE * 2 + SALT_SIZE];

    unsigned char device1_proof[PROOF_SIZE];
    unsigned char device2_proof[PROOF_SIZE];

    unsigned char device1_send_key[KEY_SIZE];
    unsigned char device2_receive_key[KEY_SIZE];

    unsigned char device2_send_key[KEY_SIZE];
    unsigned char device1_receive_key[KEY_SIZE];

    int result = 1;

    printf("Starting authenticated session test...\n\n");

    /* Test-only PSK. In a real system, provision this secret
       securely and never hardcode it in the source code. */
    static const unsigned char test_psk[KEY_SIZE] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
    };

    memcpy(psk, test_psk, KEY_SIZE);

    printf("Device1: Generating X25519 key pair...\n");
    if (!generate_key_pair(&device1_private))
        goto cleanup;

    printf("Device2: Generating X25519 key pair...\n");
    if (!generate_key_pair(&device2_private))
        goto cleanup;

    if (!export_public_key(device1_private, device1_pub) ||
        !export_public_key(device2_private, device2_pub))
        goto cleanup;

    if (!import_public_key(device2_pub, &device2_public) ||
        !import_public_key(device1_pub, &device1_public))
        goto cleanup;

    if (!derive_shared_secret(
            device1_private, device2_public, secret1) ||
        !derive_shared_secret(
            device2_private, device1_public, secret2))
        goto cleanup;

    if (CRYPTO_memcmp(secret1, secret2, KEY_SIZE) != 0) {
        printf("FAIL: Shared secrets do not match.\n");
        goto cleanup;
    }

    printf("PASS: X25519 shared secrets match.\n");

    if (RAND_bytes(salt, SALT_SIZE) != 1)
        goto cleanup;

    memcpy(transcript, device1_pub, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE,
           device2_pub, PUBLIC_KEY_SIZE);
    memcpy(transcript + PUBLIC_KEY_SIZE * 2, salt, SALT_SIZE);

    printf("\nAuthenticating Device1...\n");

    if (!make_proof(psk, "Device1 authentication",
                    transcript, sizeof(transcript), device1_proof))
        goto cleanup;

    unsigned char expected_device1_proof[PROOF_SIZE];

    if (!make_proof(psk, "Device1 authentication",
                    transcript, sizeof(transcript),
                    expected_device1_proof))
        goto cleanup;

    if (CRYPTO_memcmp(device1_proof,
                      expected_device1_proof, PROOF_SIZE) != 0) {
        printf("FAIL: Device1 authentication failed.\n");
        goto cleanup;
    }

    printf("PASS: Device1 authenticated using PSK.\n");

    printf("\nAuthenticating Device2...\n");

    if (!make_proof(psk, "Device2 authentication",
                    transcript, sizeof(transcript), device2_proof))
        goto cleanup;

    unsigned char expected_device2_proof[PROOF_SIZE];

    if (!make_proof(psk, "Device2 authentication",
                    transcript, sizeof(transcript),
                    expected_device2_proof))
        goto cleanup;

    if (CRYPTO_memcmp(device2_proof,
                      expected_device2_proof, PROOF_SIZE) != 0) {
        printf("FAIL: Device2 authentication failed.\n");
        goto cleanup;
    }

    printf("PASS: Device2 authenticated using PSK.\n");

    printf("\nDeriving directional session keys...\n");

    if (!derive_labelled_key(
            secret1, salt, "Device1-to-Device2",
            device1_send_key) ||
        !derive_labelled_key(
            secret2, salt, "Device1-to-Device2",
            device2_receive_key) ||
        !derive_labelled_key(
            secret2, salt, "Device2-to-Device1",
            device2_send_key) ||
        !derive_labelled_key(
            secret1, salt, "Device2-to-Device1",
            device1_receive_key))
        goto cleanup;

    if (CRYPTO_memcmp(device1_send_key,
                      device2_receive_key, KEY_SIZE) != 0 ||
        CRYPTO_memcmp(device2_send_key,
                      device1_receive_key, KEY_SIZE) != 0) {
        printf("FAIL: Directional keys do not match.\n");
        goto cleanup;
    }

    if (CRYPTO_memcmp(device1_send_key,
                      device2_send_key, KEY_SIZE) == 0) {
        printf("FAIL: Directional keys should be different.\n");
        goto cleanup;
    }

    printf("PASS: Device1 send key matches Device2 receive key.\n");
    printf("PASS: Device2 send key matches Device1 receive key.\n");
    printf("PASS: The two directional keys are different.\n");

    printf("\nALL AUTHENTICATED SESSION TESTS PASSED!\n");
    result = 0;

cleanup:
    if (result != 0)
        printf("ERROR: Authenticated session test failed.\n");

    EVP_PKEY_free(device1_private);
    EVP_PKEY_free(device2_private);
    EVP_PKEY_free(device1_public);
    EVP_PKEY_free(device2_public);

    OPENSSL_cleanse(secret1, sizeof(secret1));
    OPENSSL_cleanse(secret2, sizeof(secret2));
    OPENSSL_cleanse(psk, sizeof(psk));
    OPENSSL_cleanse(device1_send_key, sizeof(device1_send_key));
    OPENSSL_cleanse(device2_receive_key, sizeof(device2_receive_key));
    OPENSSL_cleanse(device2_send_key, sizeof(device2_send_key));
    OPENSSL_cleanse(device1_receive_key, sizeof(device1_receive_key));

    return result;
}
