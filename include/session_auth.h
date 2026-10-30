
#ifndef SESSION_AUTH_H
#define SESSION_AUTH_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include "secure_crypto.h"

#define SESSION_PROOF_SIZE 32
#define SESSION_TRANSCRIPT_SIZE (PUBLIC_KEY_SIZE * 2 + SALT_SIZE)

/* DEMONSTRATION ONLY:
   In a real deployment, provision this PSK securely.
   Never hardcode a production secret in source code. */
static const unsigned char SESSION_PSK[KEY_SIZE] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00
};

static int session_send_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length > 0) {
        ssize_t n = send(fd, p, length, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return 0;
        p += n;
        length -= (size_t)n;
    }
    return 1;
}

static int session_receive_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;

    while (length > 0) {
        ssize_t n = recv(fd, p, length, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return 0;
        p += n;
        length -= (size_t)n;
    }
    return 1;
}

static int session_make_proof(
    const char *label,
    const unsigned char transcript[SESSION_TRANSCRIPT_SIZE],
    unsigned char proof[SESSION_PROOF_SIZE])
{
    unsigned char message[128 + SESSION_TRANSCRIPT_SIZE];
    size_t label_length = strlen(label);

    if (label_length + SESSION_TRANSCRIPT_SIZE > sizeof(message))
        return 0;

    memcpy(message, label, label_length);
    memcpy(message + label_length, transcript,
           SESSION_TRANSCRIPT_SIZE);

    unsigned int proof_length = 0;

    unsigned char *result = HMAC(
        EVP_sha256(),
        SESSION_PSK, KEY_SIZE,
        message, label_length + SESSION_TRANSCRIPT_SIZE,
        proof, &proof_length);

    OPENSSL_cleanse(message, sizeof(message));
    return result != NULL && proof_length == SESSION_PROOF_SIZE;
}

static int session_verify_proof(
    const char *label,
    const unsigned char transcript[SESSION_TRANSCRIPT_SIZE],
    const unsigned char received[SESSION_PROOF_SIZE])
{
    unsigned char expected[SESSION_PROOF_SIZE];

    if (!session_make_proof(label, transcript, expected))
        return 0;

    int valid = CRYPTO_memcmp(
        expected, received, SESSION_PROOF_SIZE) == 0;

    OPENSSL_cleanse(expected, sizeof(expected));
    return valid;
}

static int session_derive_key(
    const unsigned char secret[KEY_SIZE],
    const unsigned char salt[SALT_SIZE],
    const char *label,
    unsigned char output[KEY_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL)
        return 0;

    size_t output_length = KEY_SIZE;

    int ok =
        EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, SALT_SIZE) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, KEY_SIZE) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx, (const unsigned char *)label,
            (int)strlen(label)) > 0 &&
        EVP_PKEY_derive(ctx, output, &output_length) > 0;

    EVP_PKEY_CTX_free(ctx);
    return ok && output_length == KEY_SIZE;
}

#endif
