
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(void)
{
    unsigned char key[32] = {0};
    unsigned char nonce[12] = {0};

    unsigned char plaintext[] = "Hello from Device1!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    unsigned char tag[16];

    int len = 0;
    int ciphertext_len = 0;
    int decrypted_len = 0;

    EVP_CIPHER_CTX *encrypt_ctx = NULL;
    EVP_CIPHER_CTX *decrypt_ctx = NULL;

    encrypt_ctx = EVP_CIPHER_CTX_new();
    decrypt_ctx = EVP_CIPHER_CTX_new();

    if (encrypt_ctx == NULL || decrypt_ctx == NULL) {
        printf("ERROR: Could not create encryption contexts.\n");
        goto cleanup;
    }

    /* AES-256-GCM encryption */
    if (EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto error;

    if (EVP_EncryptInit_ex(encrypt_ctx, NULL, NULL,
                           key, nonce) != 1)
        goto error;

    if (EVP_EncryptUpdate(encrypt_ctx, ciphertext, &len,
                          plaintext, (int)strlen((char *)plaintext)) != 1)
        goto error;

    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(encrypt_ctx,
                            ciphertext + ciphertext_len, &len) != 1)
        goto error;

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(encrypt_ctx, EVP_CTRL_GCM_GET_TAG,
                            16, tag) != 1)
        goto error;

    printf("Encryption successful!\n");
    printf("Ciphertext length: %d bytes\n", ciphertext_len);
    printf("Authentication tag: 16 bytes\n");

    /* AES-256-GCM decryption */
    if (EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto error;

    if (EVP_DecryptInit_ex(decrypt_ctx, NULL, NULL,
                           key, nonce) != 1)
        goto error;

    if (EVP_DecryptUpdate(decrypt_ctx, decrypted, &len,
                          ciphertext, ciphertext_len) != 1)
        goto error;

    decrypted_len = len;

    if (EVP_CIPHER_CTX_ctrl(decrypt_ctx, EVP_CTRL_GCM_SET_TAG,
                            16, tag) != 1)
        goto error;

    if (EVP_DecryptFinal_ex(decrypt_ctx,
                            decrypted + decrypted_len, &len) != 1) {
        printf("ERROR: Authentication failed!\n");
        goto cleanup;
    }

    decrypted_len += len;
    decrypted[decrypted_len] = '\0';

    printf("Decryption successful!\n");
    printf("Original message: %s\n", plaintext);
    printf("Decrypted message: %s\n", decrypted);

    goto cleanup;

error:
    printf("ERROR: AES-GCM operation failed.\n");

cleanup:
    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);

    return 0;
}
