#include <stdio.h>
#include <string.h>
#include "packet_crypto.h"

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

int main(void)
{
    unsigned char key[32] = {0};
    unsigned char pt[16]  = {0};
    unsigned char out[64], back[64];
    size_t out_len = 0, back_len = 0;
    uint64_t ctr = 99;

    /* NIST/McGrew-Viega AES-256-GCM test case 14:
       key=0, IV=0 (prefix 0 + counter 0), 16 zero bytes, no AAD. */
    static const unsigned char exp_ct[16] = {
        0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
        0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18 };
    static const unsigned char exp_tag[16] = {
        0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
        0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19 };

    CHECK(protect_payload(key, 0, 0, NULL, 0, pt, 16, out, sizeof out, &out_len) == 0);
    CHECK(out_len == 16 + PC_OVERHEAD);
    CHECK(memcmp(out + 8, exp_ct, 16) == 0);
    CHECK(memcmp(out + 8 + 16, exp_tag, 16) == 0);

    /* Round trip with AAD. */
    unsigned char aad[5] = {1,2,3,4,5};
    unsigned char msg[] = "hello secure channel";
    CHECK(protect_payload(key, 7, 1, aad, 5, msg, sizeof msg, out, sizeof out, &out_len) == 0);
    CHECK(unprotect_payload(key, 1, aad, 5, out, out_len, &ctr, back, sizeof back, &back_len) == 0);
    CHECK(ctr == 7 && back_len == sizeof msg && memcmp(back, msg, sizeof msg) == 0);

    /* Any modification must be rejected. */
    unsigned char bad[64];
    for (size_t i = 0; i < out_len; i++) {
        memcpy(bad, out, out_len);
        bad[i] ^= 0x01;
        CHECK(unprotect_payload(key, 1, aad, 5, bad, out_len, &ctr, back, sizeof back, &back_len) != 0);
    }
    unsigned char aad2[5] = {1,2,3,4,6};
    CHECK(unprotect_payload(key, 1, aad2, 5, out, out_len, &ctr, back, sizeof back, &back_len) != 0);
    CHECK(unprotect_payload(key, 2, aad, 5, out, out_len, &ctr, back, sizeof back, &back_len) != 0);
    unsigned char key2[32] = {1};
    CHECK(unprotect_payload(key2, 1, aad, 5, out, out_len, &ctr, back, sizeof back, &back_len) != 0);

    /* Counter exhaustion must refuse to encrypt (never reuse a nonce). */
    CHECK(protect_payload(key, UINT64_MAX, 1, NULL, 0, msg, sizeof msg, out, sizeof out, &out_len) != 0);

    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("packet crypto: all checks passed (incl. NIST AES-256-GCM vector)\n");
    return 0;
}
