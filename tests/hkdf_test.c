
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int main(void)
{
    unsigned char shared_secret[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };

    unsigned char salt[16] = {
        10, 20, 30, 40, 50, 60, 70, 80,
        90, 100, 110, 120, 130, 140, 150, 160
    };

    unsigned char info[] = "Secure Inline Communication Channel";

    unsigned char key1[32];
    unsigned char key2[32];

    char digest1[] = "SHA256";
    char digest2[] = "SHA256";

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx1 = NULL;
    EVP_KDF_CTX *ctx2 = NULL;

    OSSL_PARAM params1[5];
    OSSL_PARAM params2[5];

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (kdf == NULL) {
        printf("ERROR: Could not load HKDF.\n");
        return 1;
    }

    ctx1 = EVP_KDF_CTX_new(kdf);
    ctx2 = EVP_KDF_CTX_new(kdf);

    if (ctx1 == NULL || ctx2 == NULL) {
        printf("ERROR: Could not create HKDF contexts.\n");
        goto cleanup;
    }

    params1[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest1, 0);
    params1[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, shared_secret, sizeof(shared_secret));
    params1[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params1[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1);
    params1[4] = OSSL_PARAM_construct_end();

    params2[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest2, 0);
    params2[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, shared_secret, sizeof(shared_secret));
    params2[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params2[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1);
    params2[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx1, key1, sizeof(key1), params1) <= 0) {
        printf("Device1 key derivation failed.\n");
        goto cleanup;
    }

    printf("Device1 derived a 256-bit key.\n");

    if (EVP_KDF_derive(ctx2, key2, sizeof(key2), params2) <= 0) {
        printf("Device2 key derivation failed.\n");
        goto cleanup;
    }

    printf("Device2 derived a 256-bit key.\n");

    if (memcmp(key1, key2, sizeof(key1)) == 0) {
        printf("SUCCESS: Both devices derived the same AES key!\n");
        printf("HKDF-SHA-256 test completed.\n");
    } else {
        printf("ERROR: Derived keys do not match.\n");
    }

cleanup:
    EVP_KDF_CTX_free(ctx1);
    EVP_KDF_CTX_free(ctx2);
    EVP_KDF_free(kdf);

    return 0;
}
