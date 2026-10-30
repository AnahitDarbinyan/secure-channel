#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define PC_NONCE_LEN   12
#define PC_COUNTER_LEN 8
#define PC_TAG_LEN     16
#define PC_OVERHEAD    (PC_COUNTER_LEN + PC_TAG_LEN)   /* 24 bytes added per packet */

/*
 * Output: counter(8, big-endian) || ciphertext || tag(16)
 * Returns 0 on success, -1 on failure.
 * output must not overlap plaintext. out_cap >= pt_len + PC_OVERHEAD.
 */
int protect_payload(const unsigned char key[32], uint64_t counter, uint32_t prefix,
                    const unsigned char *aad, size_t aad_len,
                    const unsigned char *plaintext, size_t pt_len,
                    unsigned char *output, size_t out_cap, size_t *out_len);

/*
 * Returns 0 only if the tag is valid. On success *out_counter holds the
 * packet counter. The caller must check it against the replay window
 * AFTER this succeeds, and only then update the window.
 * pt_cap >= in_len - PC_OVERHEAD.
 */
int unprotect_payload(const unsigned char key[32], uint32_t prefix,
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *input, size_t in_len,
                      uint64_t *out_counter,
                      unsigned char *plaintext, size_t pt_cap, size_t *pt_len);

#endif