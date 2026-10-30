#include <string.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include "packet_processor.h"
#include "packet_utils.h"

#define MAX_IP_PACKET 65535

/*
 * AAD = fields that no router on the path may change:
 *   src/dst address, protocol, ports, TCP seq, TCP ack, TCP flags.
 * TTL, IP checksum and TCP checksum are deliberately NOT included
 * (TTL is decremented by each hop, checksums are recomputed).
 * Binding seq/ack/ports stops a valid ciphertext from being moved to
 * another connection or another position in the stream.
 */
static void build_aad(unsigned char aad[PP_AAD_LEN],
                      const struct iphdr *ip, const struct tcphdr *tcp)
{
    memcpy(aad,      &ip->saddr, 4);
    memcpy(aad + 4,  &ip->daddr, 4);
    aad[8] = ip->protocol;
    memcpy(aad + 9,  &tcp->source, 2);
    memcpy(aad + 11, &tcp->dest, 2);
    memcpy(aad + 13, &tcp->seq, 4);
    memcpy(aad + 17, &tcp->ack_seq, 4);
    aad[21] = ((const unsigned char *)tcp)[13];       /* flags byte */
}

int pp_encrypt_packet(const unsigned char key[32], uint64_t *counter,
                      unsigned char *pkt, size_t len, size_t cap,
                      size_t *out_len)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    unsigned char *payload;
    int payload_len;

    if (!key || !counter || !pkt || !out_len || len > MAX_IP_PACKET)
        return PP_ERR_PARSE;

    if (parse_packet(pkt, (int)len, &ip, &tcp, &payload, &payload_len) != 0)
        return PP_ERR_PARSE;

    size_t total = ntohs(ip->tot_len);

    if (payload_len == 0) {
        *out_len = total;
        return PP_UNCHANGED;
    }

    if (total + PC_OVERHEAD > MAX_IP_PACKET || total + PC_OVERHEAD > cap)
        return PP_ERR_SIZE;

    unsigned char aad[PP_AAD_LEN];
    unsigned char out[MAX_IP_PACKET];
    size_t out_payload = 0;

    build_aad(aad, ip, tcp);

    uint64_t this_counter = (*counter)++;       /* consume the nonce first */

    if (protect_payload(key, this_counter, PP_NONCE_PREFIX,
                        aad, sizeof(aad),
                        payload, (size_t)payload_len,
                        out, sizeof(out), &out_payload) != 0)
        return PP_ERR_CRYPTO;

    memcpy(payload, out, out_payload);
    ip->tot_len = htons((uint16_t)(total + PC_OVERHEAD));
    recalculate_checksums(ip, tcp);

    *out_len = total + PC_OVERHEAD;
    OPENSSL_cleanse(out, out_payload);
    return PP_MODIFIED;
}

int pp_decrypt_packet(const unsigned char key[32], replay_window *window,
                      unsigned char *pkt, size_t len, size_t *out_len)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    unsigned char *payload;
    int payload_len;

    if (!key || !window || !pkt || !out_len || len > MAX_IP_PACKET)
        return PP_ERR_PARSE;

    if (parse_packet(pkt, (int)len, &ip, &tcp, &payload, &payload_len) != 0)
        return PP_ERR_PARSE;

    size_t total = ntohs(ip->tot_len);

    if (payload_len == 0) {
        *out_len = total;
        return PP_UNCHANGED;
    }

    /* A protected packet always carries counter + >=1 byte + tag. */
    if ((size_t)payload_len <= PC_OVERHEAD)
        return PP_ERR_SIZE;

    unsigned char aad[PP_AAD_LEN];
    unsigned char plain[MAX_IP_PACKET];
    size_t plain_len = 0;
    uint64_t counter = 0;

    build_aad(aad, ip, tcp);

    /* 1. Authenticate (tag check). Nothing is changed if this fails. */
    if (unprotect_payload(key, PP_NONCE_PREFIX, aad, sizeof(aad),
                          payload, (size_t)payload_len, &counter,
                          plain, sizeof(plain), &plain_len) != 0)
        return PP_ERR_CRYPTO;

    /* 2. Only an authentic packet may touch the replay window. */
    if (!replay_window_accept(window, counter)) {
        OPENSSL_cleanse(plain, plain_len);
        return PP_ERR_REPLAY;
    }

    /* 3. Restore original structure. */
    memcpy(payload, plain, plain_len);
    ip->tot_len = htons((uint16_t)(total - PC_OVERHEAD));
    recalculate_checksums(ip, tcp);

    *out_len = total - PC_OVERHEAD;
    OPENSSL_cleanse(plain, plain_len);
    return PP_MODIFIED;
}
