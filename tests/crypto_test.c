
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int main(void)
{
    EVP_PKEY_CTX *keygen1 = NULL;
    EVP_PKEY_CTX *keygen2 = NULL;
    EVP_PKEY_CTX *derive1 = NULL;
    EVP_PKEY_CTX *derive2 = NULL;

    EVP_PKEY *device1_key = NULL;
    EVP_PKEY *device2_key = NULL;

    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kdf_ctx1 = NULL;
    EVP_KDF_CTX *kdf_ctx2 = NULL;

    EVP_CIPHER_CTX *encrypt_ctx = NULL;
    EVP_CIPHER_CTX *decrypt_ctx = NULL;
    EVP_CIPHER_CTX *tamper_ctx = NULL;

    unsigned char tampered_ciphertext[128];
    unsigned char tampered_decrypted[128];

    int tampered_len = 0;
    int result = 1;

    unsigned char secret1[32];
    unsigned char secret2[32];

    unsigned char key1[32];
    unsigned char key2[32];

    unsigned char salt[16] = {0};
    unsigned char info[] = "Secure Inline Communication Channel";

    unsigned char nonce[12] = {0};

    unsigned char plaintext[] = "Hello from Device1!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char tag[16];

    size_t secret_len1 = sizeof(secret1);
    size_t secret_len2 = sizeof(secret2);

    int len = 0;
    int ciphertext_len = 0;
    int decrypted_len = 0;

    char digest1[] = "SHA256";
    char digest2[] = "SHA256";

    OSSL_PARAM params1[5];
    OSSL_PARAM params2[5];

    /* Generate Device1 X25519 key pair */

    keygen1 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (keygen1 == NULL ||
        EVP_PKEY_keygen_init(keygen1) <= 0 ||
        EVP_PKEY_keygen(keygen1, &device1_key) <= 0) {
        printf("Device1 key generation failed.\n");
        goto cleanup;
    }

    printf("Device1 X25519 key pair generated.\n");

    /* Generate Device2 X25519 key pair */

    keygen2 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (keygen2 == NULL ||
        EVP_PKEY_keygen_init(keygen2) <= 0 ||
        EVP_PKEY_keygen(keygen2, &device2_key) <= 0) {
        printf("Device2 key generation failed.\n");
        goto cleanup;
    }

    printf("Device2 X25519 key pair generated.\n");

    /* Device1 derives shared secret */

    derive1 = EVP_PKEY_CTX_new(device1_key, NULL);

    if (derive1 == NULL ||
        EVP_PKEY_derive_init(derive1) <= 0 ||
        EVP_PKEY_derive_set_peer(derive1, device2_key) <= 0 ||
        EVP_PKEY_derive(derive1, secret1, &secret_len1) <= 0) {
        printf("Device1 shared secret derivation failed.\n");
        goto cleanup;
    }

    printf("Device1 shared secret calculated.\n");

    /* Device2 derives shared secret */

    derive2 = EVP_PKEY_CTX_new(device2_key, NULL);

    if (derive2 == NULL ||
        EVP_PKEY_derive_init(derive2) <= 0 ||
        EVP_PKEY_derive_set_peer(derive2, device1_key) <= 0 ||
        EVP_PKEY_derive(derive2, secret2, &secret_len2) <= 0) {
        printf("Device2 shared secret derivation failed.\n");
        goto cleanup;
    }

    printf("Device2 shared secret calculated.\n");

    if (secret_len1 != secret_len2 ||
        memcmp(secret1, secret2, secret_len1) != 0) {
        printf("ERROR: Shared secrets do not match.\n");
        goto cleanup;
    }

    printf("SUCCESS: X25519 shared secrets match.\n");

    /* Prepare HKDF-SHA-256 */

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (kdf == NULL) {
        printf("Could not load HKDF.\n");
        goto cleanup;
    }

    kdf_ctx1 = EVP_KDF_CTX_new(kdf);
    kdf_ctx2 = EVP_KDF_CTX_new(kdf);

    if (kdf_ctx1 == NULL || kdf_ctx2 == NULL) {
        printf("Could not create HKDF contexts.\n");
        goto cleanup;
    }

    params1[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest1, 0);
    params1[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, secret1, secret_len1);
    params1[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params1[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1);
    params1[4] = OSSL_PARAM_construct_end();

    params2[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, digest2, 0);
    params2[1] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, secret2, secret_len2);
    params2[2] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
    params2[3] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, info, sizeof(info) - 1);
    params2[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kdf_ctx1, key1, sizeof(key1), params1) <= 0) {
        printf("Device1 HKDF derivation failed.\n");
        goto cleanup;
    }

    if (EVP_KDF_derive(kdf_ctx2, key2, sizeof(key2), params2) <= 0) {
        printf("Device2 HKDF derivation failed.\n");
        goto cleanup;
    }

    printf("Both devices derived AES-256 keys.\n");

    if (memcmp(key1, key2, sizeof(key1)) != 0) {
        printf("ERROR: AES keys do not match.\n");
        goto cleanup;
    }

    printf("SUCCESS: Derived AES keys match.\n");

    /* Encrypt message using Device1 key */

    encrypt_ctx = EVP_CIPHER_CTX_new();

    if (encrypt_ctx == NULL ||
        EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(encrypt_ctx, NULL, NULL,
                           key1, nonce) != 1 ||
        EVP_EncryptUpdate(encrypt_ctx, ciphertext, &len,
                          plaintext, (int)strlen((char *)plaintext)) != 1) {
        printf("Encryption failed.\n");
        goto cleanup;
    }

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(encrypt_ctx,
                            ciphertext + ciphertext_len, &len) != 1) {
        printf("Encryption finalization failed.\n");
        goto cleanup;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(encrypt_ctx, EVP_CTRL_GCM_GET_TAG,
                            sizeof(tag), tag) != 1) {
        printf("Could not obtain authentication tag.\n");
        goto cleanup;
    }

    printf("SUCCESS: AES-256-GCM encryption completed.\n");

    /* Decrypt and authenticate using Device2 key */

    decrypt_ctx = EVP_CIPHER_CTX_new();

    if (decrypt_ctx == NULL ||
        EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(decrypt_ctx, NULL, NULL,
                           key2, nonce) != 1 ||
        EVP_DecryptUpdate(decrypt_ctx, decrypted, &len,
                          ciphertext, ciphertext_len) != 1) {
        printf("Decryption setup failed.\n");
        goto cleanup;
    }

    decrypted_len = len;

    if (EVP_CIPHER_CTX_ctrl(decrypt_ctx, EVP_CTRL_GCM_SET_TAG,
                            sizeof(tag), tag) != 1) {
        printf("Could not set authentication tag.\n");
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(decrypt_ctx,
                            decrypted + decrypted_len, &len) != 1) {
        printf("ERROR: Authentication failed.\n");
        goto cleanup;
    }

    decrypted_len += len;
    decrypted[decrypted_len] = '\0';

    printf("SUCCESS: Authentication verified.\n");
    printf("Original message: %s\n", plaintext);
    printf("Decrypted message: %s\n", decrypted);

    if (strcmp((char *)plaintext, (char *)decrypted) != 0) {
        printf("ERROR: Messages do not match.\n");
        goto cleanup;
    }

    printf("SUCCESS: Original message matches decrypted message.\n");

    /* Tamper detection test */

    /* Copy the original ciphertext */
    memcpy(tampered_ciphertext, ciphertext, ciphertext_len);

    /* Change one bit of the ciphertext */
    tampered_ciphertext[0] ^= 0x01;

    printf("\nTesting AES-GCM tamper detection...\n");

    tamper_ctx = EVP_CIPHER_CTX_new();

    if (tamper_ctx == NULL ||
        EVP_DecryptInit_ex(tamper_ctx, EVP_aes_256_gcm(),
                        NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(tamper_ctx, NULL, NULL,
                        key2, nonce) != 1 ||
        EVP_DecryptUpdate(tamper_ctx, tampered_decrypted, &len,
                        tampered_ciphertext, ciphertext_len) != 1) {
        printf("Tamper test decryption setup failed.\n");
        goto cleanup;
    }

    tampered_len = len;

    /* Supply the original authentication tag */
    if (EVP_CIPHER_CTX_ctrl(tamper_ctx, EVP_CTRL_GCM_SET_TAG,
                            sizeof(tag), tag) != 1) {
        printf("Could not set authentication tag.\n");
        goto cleanup;
    }

    /* Authentication should fail because the ciphertext was modified */
    if (EVP_DecryptFinal_ex(tamper_ctx,
                            tampered_decrypted + tampered_len, &len) == 1) {
        printf("ERROR: Modified ciphertext was incorrectly accepted!\n");
        goto cleanup;
    }

    printf("SUCCESS: AES-GCM rejected the modified ciphertext!\n");
    printf("Tamper detection test passed.\n");

    printf("\nALL CRYPTOGRAPHIC AND TAMPER-DETECTION TESTS PASSED!\n");

    result = 0;

cleanup:
    EVP_PKEY_CTX_free(keygen1);
    EVP_PKEY_CTX_free(keygen2);
    EVP_PKEY_CTX_free(derive1);
    EVP_PKEY_CTX_free(derive2);

    EVP_PKEY_free(device1_key);
    EVP_PKEY_free(device2_key);

    EVP_KDF_CTX_free(kdf_ctx1);
    EVP_KDF_CTX_free(kdf_ctx2);
    EVP_KDF_free(kdf);

    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
    EVP_CIPHER_CTX_free(tamper_ctx);

    return result;
}
