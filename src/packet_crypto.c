#include <string.h>
#include <limits.h>
#include <endian.h>
#include <openssl/evp.h>
#include "packet_crypto.h"

static void build_nonce(unsigned char iv[PC_NONCE_LEN], uint32_t prefix, uint64_t counter)
{
    uint32_t p = htobe32(prefix);
    uint64_t c = htobe64(counter);
    memcpy(iv, &p, 4);
    memcpy(iv + 4, &c, 8);
}

int protect_payload(const unsigned char key[32], uint64_t counter, uint32_t prefix,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *plaintext, size_t pt_len,
                    unsigned char *output, size_t out_cap, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[PC_NONCE_LEN];
    int len = 0, ct_len = 0;

    if (!key || !output || !out_len || (!plaintext && pt_len > 0)) return -1;
    if (counter == UINT64_MAX) return -1;               /* never reuse a nonce */
    if (pt_len > 60000 || aad_len > INT_MAX) return -1;
    if (out_cap < pt_len + PC_OVERHEAD) return -1;

    build_nonce(iv, prefix, counter);
    uint64_t be_counter = htobe64(counter);
    memcpy(output, &be_counter, PC_COUNTER_LEN);

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PC_NONCE_LEN, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;

    if (aad && aad_len > 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto err;

    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx, output + PC_COUNTER_LEN, &ct_len,
                          plaintext, (int)pt_len) != 1) goto err;

    if (EVP_EncryptFinal_ex(ctx, output + PC_COUNTER_LEN + ct_len, &len) != 1) goto err;
    ct_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, PC_TAG_LEN,
                            output + PC_COUNTER_LEN + ct_len) != 1) goto err;

    *out_len = PC_COUNTER_LEN + (size_t)ct_len + PC_TAG_LEN;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int unprotect_payload(const unsigned char key[32], uint32_t prefix,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *input, size_t in_len,
                      uint64_t *out_counter,
                      unsigned char *plaintext, size_t pt_cap, size_t *pt_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char iv[PC_NONCE_LEN];
    int len = 0, out = 0;

    if (!key || !input || !out_counter || !plaintext || !pt_len) return -1;
    if (in_len < PC_OVERHEAD || in_len > 65535 || aad_len > INT_MAX) return -1;

    size_t ct_len = in_len - PC_OVERHEAD;
    if (pt_cap < ct_len) return -1;

    uint64_t be_counter;
    memcpy(&be_counter, input, PC_COUNTER_LEN);
    uint64_t counter = be64toh(be_counter);
    build_nonce(iv, prefix, counter);

    const unsigned char *ct  = input + PC_COUNTER_LEN;
    const unsigned char *tag = ct + ct_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, PC_NONCE_LEN, NULL) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;

    if (aad && aad_len > 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto err;

    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx, plaintext, &out, ct, (int)ct_len) != 1) goto err;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, PC_TAG_LEN, (void *)tag) != 1) goto err;

    if (EVP_DecryptFinal_ex(ctx, plaintext + out, &len) != 1) goto err;   /* tag check */

    *pt_len = (size_t)out + (size_t)len;
    *out_counter = counter;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plaintext, pt_cap);      /* never leak unauthenticated data */
    return -1;
}