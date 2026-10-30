#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int main(void)
{
	EVP_PKEY_CTX *ctx1 = NULL, *ctx2 = NULL;
	EVP_PKEY_CTX *derive1 = NULL, *derive2 = NULL;
	EVP_PKEY *key1 = NULL, *key2 = NULL;

	unsigned char secret1[32];
	unsigned char secret2[32];

	size_t len1 = sizeof(secret1);
	size_t len2 = sizeof(secret2);

	ctx1 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

	if (!ctx1 ||
		EVP_PKEY_keygen_init(ctx1) <= 0 ||
		EVP_PKEY_keygen(ctx1, &key1) <= 0) {
		printf("Device1 key generation failed\n");
		goto cleanup;
	}

        ctx2 = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

	if (!ctx2 ||
                EVP_PKEY_keygen_init(ctx2) <= 0 ||
                EVP_PKEY_keygen(ctx2, &key2) <= 0) {
                printf("Device2 key generation failed\n");
                goto cleanup;
        }

	derive1 = EVP_PKEY_CTX_new(key1, NULL);

	if (!derive1 ||
                EVP_PKEY_derive_init(derive1) <= 0 ||
                EVP_PKEY_derive_set_peer(derive1, key2) <= 0 ||
		EVP_PKEY_derive(derive1, secret1, &len1) <= 0) {
                printf("Device1 key generation failed\n");
                goto cleanup;
        }

	derive2 = EVP_PKEY_CTX_new(key2, NULL);

        if (!derive2 ||
                EVP_PKEY_derive_init(derive2) <= 0 ||
                EVP_PKEY_derive_set_peer(derive2, key1) <= 0 ||
                EVP_PKEY_derive(derive2, secret2, &len2) <= 0) {
                printf("Device2 key generation failed\n");
                goto cleanup;
        }

	if (len1 == len2 && memcmp(secret1, secret2, len1) == 0) {
		printf("SUCCESS: Shared secrets math!\n");
                printf("X25519 key exchange completed.\n");
	} else {
		printf("ERROR: Shared secrets do not match.\n");
	}

cleanup:
	EVP_PKEY_CTX_free(ctx1);
        EVP_PKEY_CTX_free(ctx2);
	EVP_PKEY_CTX_free(derive1);
        EVP_PKEY_CTX_free(derive2);
	EVP_PKEY_free(key1);
	EVP_PKEY_free(key2);

	OPENSSL_cleanse(secret1, sizeof(secret1));
	OPENSSL_cleanse(secret2, sizeof(secret2));

	return 0;
}


