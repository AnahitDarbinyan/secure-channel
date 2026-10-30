#include <stdio.h>
#include <openssl/evp.h>

int main(void)
{
	EVP_PKEY_CTX *ctx;
	EVP_PKEY *key = NULL;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

	if (!ctx) {
		printf("Error creating key context\n");
		return 1;
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &key) <=0) {
		printf("Key generation failed\n");
		EVP_PKEY_CTX_free(ctx);
		return 1;
	}

	printf("Device1 X25519 key pair generated successfully!\n");

	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(ctx);

	return 0;
}
