
#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define KEY_SIZE 32
#define SALT_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define PUBLIC_KEY_SIZE 32
#define MAX_MESSAGE_SIZE 1024

static int generate_key_pair(EVP_PKEY **key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (ctx == NULL)
        return -1;

    int ok = EVP_PKEY_keygen_init(ctx) > 0 &&
             EVP_PKEY_keygen(ctx, key) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int export_public_key(
    EVP_PKEY *key,
    unsigned char public_key[PUBLIC_KEY_SIZE])
{
    size_t length = PUBLIC_KEY_SIZE;

    return EVP_PKEY_get_raw_public_key(
        key, public_key, &length) > 0 &&
        length == PUBLIC_KEY_SIZE;
}

static int import_public_key(
    const unsigned char public_key[PUBLIC_KEY_SIZE],
    EVP_PKEY **peer_key)
{
    *peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, public_key, PUBLIC_KEY_SIZE);

    return *peer_key != NULL;
}

static int derive_shared_secret(
    EVP_PKEY *private_key,
    EVP_PKEY *peer_key,
    unsigned char secret[KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    size_t length = KEY_SIZE;

    if (ctx == NULL)
        return 0;

    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer_key) > 0 &&
             EVP_PKEY_derive(ctx, secret, &length) > 0 &&
             length == KEY_SIZE;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int derive_aes_key(
    const unsigned char secret[KEY_SIZE],
    const unsigned char salt[SALT_SIZE],
    unsigned char aes_key[KEY_SIZE])
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx = NULL;

    char digest[] = "SHA256";
    char mode[] = "EXTRACT_AND_EXPAND";
    unsigned char info[] = "Secure Inline Communication Channel";

    OSSL_PARAM params[6];

    if (kdf == NULL)
        return 0;

    ctx = EVP_KDF_CTX_new(kdf);

    if (ctx == NULL) {
        EVP_KDF_free(kdf);
        return 0;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_MODE, mode, 0);
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)secret, KEY_SIZE);
    params[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, SALT_SIZE);
    params[4] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1);
    params[5] = OSSL_PARAM_construct_end();

    int ok = EVP_KDF_derive(ctx, aes_key, KEY_SIZE, params) > 0;

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);

    return ok;
}

static int encrypt_message(
    const unsigned char key[KEY_SIZE],
    const unsigned char nonce[NONCE_SIZE],
    const unsigned char *plaintext,
    int plaintext_length,
    unsigned char *ciphertext,
    unsigned char tag[TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0;
    int total = 0;

    if (ctx == NULL)
        return -1;

    int ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_SIZE, NULL) > 0 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &length,
                          plaintext, plaintext_length) > 0;

    if (ok) {
        total = length;

        ok = EVP_EncryptFinal_ex(ctx, ciphertext + total, &length) > 0;

        if (ok) {
            total += length;
            ok = EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) > 0;
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    return ok ? total : -1;
}

/* Returns plaintext length on success, -1 on failure. */
static int decrypt_message(
    const unsigned char key[KEY_SIZE],
    const unsigned char nonce[NONCE_SIZE],
    const unsigned char *ciphertext,
    int ciphertext_length,
    const unsigned char tag[TAG_SIZE],
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0;
    int total = 0;

    if (ctx == NULL)
        return -1;

    int ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_SIZE, NULL) > 0 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) > 0 &&
        EVP_DecryptUpdate(ctx, plaintext, &length,
                          ciphertext, ciphertext_length) > 0;

    if (ok) {
        total = length;

        ok = EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag) > 0;

        if (ok) {
            ok = EVP_DecryptFinal_ex(
                ctx, plaintext + total, &length) > 0;
        }

        if (ok)
            total += length;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
        return -1;

    plaintext[total] = '\0';
    return total;
}

static int send_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;

    while (length > 0) {
        ssize_t sent = send(fd, p, length, 0);

        if (sent <= 0)
            return 0;

        p += sent;
        length -= (size_t)sent;
    }

    return 1;
}

static int receive_all(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;

    while (length > 0) {
        ssize_t received = recv(fd, p, length, 0);

        if (received <= 0)
            return 0;

        p += received;
        length -= (size_t)received;
    }

    return 1;
}

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

#endif
