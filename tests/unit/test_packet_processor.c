#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "packet_processor.h"

static int failures;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

#define BUF 70000

/* ---- independent checksum code (big-endian word sum, RFC 1071) ---- */
static uint32_t sum16(uint32_t acc, const unsigned char *d, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2) acc += (d[i] << 8) | d[i + 1];
    if (n & 1) acc += d[n - 1] << 8;
    return acc;
}
static uint16_t fold(uint32_t a) { while (a >> 16) a = (a & 0xffff) + (a >> 16); return (uint16_t)a; }

static int checksums_valid(const unsigned char *p)
{
    const struct iphdr *ip = (const struct iphdr *)p;
    size_t ihl = ip->ihl * 4, tot = ntohs(ip->tot_len), tcp_len = tot - ihl;
    if (fold(sum16(0, p, ihl)) != 0xffff) return 0;
    unsigned char ph[12];
    memcpy(ph, &ip->saddr, 4); memcpy(ph + 4, &ip->daddr, 4);
    ph[8] = 0; ph[9] = 6; ph[10] = tcp_len >> 8; ph[11] = tcp_len & 0xff;
    uint32_t a = sum16(0, ph, 12);
    a = sum16(a, p + ihl, tcp_len);
    return fold(a) == 0xffff;
}

static void set_checksums(unsigned char *p)
{
    struct iphdr *ip = (struct iphdr *)p;
    size_t ihl = ip->ihl * 4, tot = ntohs(ip->tot_len), tcp_len = tot - ihl;
    struct tcphdr *t = (struct tcphdr *)(p + ihl);
    ip->check = 0; t->check = 0;
    uint16_t c = (uint16_t)~fold(sum16(0, p, ihl));
    ip->check = htons(c);
    unsigned char ph[12];
    memcpy(ph, &ip->saddr, 4); memcpy(ph + 4, &ip->daddr, 4);
    ph[8] = 0; ph[9] = 6; ph[10] = tcp_len >> 8; ph[11] = tcp_len & 0xff;
    uint32_t a = sum16(0, ph, 12);
    a = sum16(a, p + ihl, tcp_len);
    t->check = htons((uint16_t)~fold(a));
}

/* Build IP(20)+TCP(20 or 32 with options)+payload. Returns total length. */
static size_t make_packet(unsigned char *p, const unsigned char *pl, size_t n,
                          uint32_t seq, int with_options)
{
    memset(p, 0, 80);
    struct iphdr *ip = (struct iphdr *)p;
    size_t tcp_hl = with_options ? 32 : 20;
    ip->version = 4; ip->ihl = 5; ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("10.0.1.2"); ip->daddr = inet_addr("10.0.3.2");
    ip->id = htons(1234); ip->frag_off = htons(0x4000);
    ip->tot_len = htons((uint16_t)(20 + tcp_hl + n));
    struct tcphdr *t = (struct tcphdr *)(p + 20);
    t->source = htons(40000); t->dest = htons(5001);
    t->seq = htonl(seq); t->ack_seq = htonl(777);
    t->doff = (uint8_t)(tcp_hl / 4); t->ack = 1; t->psh = 1; t->window = htons(502);
    if (with_options) { p[40] = 1; p[41] = 1; p[42] = 8; p[43] = 10; p[44] = 0xAA; }
    if (n) memcpy(p + 20 + tcp_hl, pl, n);
    set_checksums(p);
    return 20 + tcp_hl + n;
}

int main(void)
{
    unsigned char key[32], other[32];
    for (int i = 0; i < 32; i++) { key[i] = (unsigned char)i; other[i] = (unsigned char)(i + 1); }

    static unsigned char orig[BUF], pkt[BUF], enc[BUF];
    const unsigned char msg[] = "GET /secret HTTP/1.1  attack at dawn  attack at dawn";
    size_t n = sizeof msg - 1, len, out;
    uint64_t counter = 0;
    replay_window win; replay_window_init(&win);

    /* ---------- 1. Round trip, headers preserved ---------- */
    for (int opt = 0; opt < 2; opt++) {
        counter = 0; replay_window_init(&win);
        len = make_packet(orig, msg, n, 1000, opt);
        CHECK(checksums_valid(orig));
        memcpy(pkt, orig, len);

        CHECK(pp_encrypt_packet(key, &counter, pkt, len, sizeof pkt, &out) == PP_MODIFIED);
        CHECK(out == len + PC_OVERHEAD);
        CHECK(ntohs(((struct iphdr *)pkt)->tot_len) == len + PC_OVERHEAD);
        CHECK(counter == 1);
        size_t hl = len - n;                                  /* IP+TCP header bytes */
        CHECK(memcmp(pkt + 12, orig + 12, 8) == 0);           /* src/dst IP kept     */
        CHECK(memcmp(pkt + 20, orig + 20, 12) == 0);          /* ports, seq, ack     */
        CHECK(memcmp(pkt + 32, orig + 32, 4) == 0);          /* offset,flags,window */
        CHECK(memcmp(pkt + 38, orig + 38, hl - 38) == 0);     /* urg ptr + options (36-37 = TCP checksum, changes) */
        CHECK(memcmp(pkt + hl, msg, 8) != 0);                 /* payload now hidden  */
        CHECK(memmem(pkt, out, "attack", 6) == NULL);         /* no plaintext leaks  */
        CHECK(checksums_valid(pkt));                          /* PC2 would accept    */
        memcpy(enc, pkt, out);

        size_t back;
        CHECK(pp_decrypt_packet(key, &win, pkt, out, &back) == PP_MODIFIED);
        CHECK(back == len);
        CHECK(memcmp(pkt, orig, len) == 0);                   /* bit-identical       */
        CHECK(checksums_valid(pkt));
    }

    /* ---------- 2. Replay of the same packet ---------- */
    memcpy(pkt, enc, len + PC_OVERHEAD);
    {
        size_t back;
        CHECK(pp_decrypt_packet(key, &win, pkt, len + PC_OVERHEAD, &back) == PP_ERR_REPLAY);
    }

    /* ---------- 3. Tampering: every protected byte & header field ---------- */
    {
        replay_window w2; size_t back, total = len + PC_OVERHEAD;
        size_t hl = len - n;
        for (size_t i = hl; i < total; i++) {                 /* counter, ct, tag */
            replay_window_init(&w2);
            memcpy(pkt, enc, total); pkt[i] ^= 0x80; set_checksums(pkt);
            CHECK(pp_decrypt_packet(key, &w2, pkt, total, &back) == PP_ERR_CRYPTO);
        }
        size_t fields[] = {12, 16, 20, 22, 24, 28, 33};       /* saddr daddr sport dport seq ack flags */
        for (size_t k = 0; k < sizeof fields / sizeof *fields; k++) {
            replay_window_init(&w2);
            memcpy(pkt, enc, total); pkt[fields[k]] ^= 0x01; set_checksums(pkt);
            CHECK(pp_decrypt_packet(key, &w2, pkt, total, &back) == PP_ERR_CRYPTO);
        }
        replay_window_init(&w2);                              /* wrong key */
        memcpy(pkt, enc, total);
        CHECK(pp_decrypt_packet(other, &w2, pkt, total, &back) == PP_ERR_CRYPTO);
        CHECK(w2.started == 0);                               /* forged data never moves window */
    }

    /* ---------- 4. A router between the devices decrements TTL ---------- */
    {
        replay_window w3; replay_window_init(&w3); size_t back;
        memcpy(pkt, enc, len + PC_OVERHEAD);
        ((struct iphdr *)pkt)->ttl--; set_checksums(pkt);
        CHECK(pp_decrypt_packet(key, &w3, pkt, len + PC_OVERHEAD, &back) == PP_MODIFIED);
    }

    /* ---------- 5. Nonce uniqueness: 5000 identical packets ---------- */
    {
        counter = 0;
        uint64_t prev = 0; int ok = 1, distinct = 1;
        static unsigned char first_ct[64]; 
        len = make_packet(orig, msg, n, 5000, 0);
        for (int i = 0; i < 5000; i++) {
            memcpy(pkt, orig, len);
            if (pp_encrypt_packet(key, &counter, pkt, len, sizeof pkt, &out) != PP_MODIFIED) { ok = 0; break; }
            uint64_t be; memcpy(&be, pkt + 40, 8);
            uint64_t c = be64toh(be);
            if (i > 0 && c != prev + 1) ok = 0;               /* strictly increasing */
            if (i == 0) memcpy(first_ct, pkt + 48, 32);
            else if (memcmp(first_ct, pkt + 48, 32) == 0) distinct = 0;
            prev = c;
        }
        CHECK(ok); CHECK(distinct); CHECK(counter == 5000);
    }

    /* ---------- 6. Out-of-order delivery is tolerated ---------- */
    {
        static unsigned char e[3][BUF]; size_t el[3], back;
        replay_window w4; replay_window_init(&w4); counter = 0;
        for (int i = 0; i < 3; i++) {
            len = make_packet(e[i], msg, n, 100 + i * 100, 0);
            pp_encrypt_packet(key, &counter, e[i], len, BUF, &el[i]);
        }
        int order[3] = {2, 0, 1};
        for (int i = 0; i < 3; i++)
            CHECK(pp_decrypt_packet(key, &w4, e[order[i]], el[order[i]], &back) == PP_MODIFIED);
    }

    /* ---------- 7. Packets without payload pass unchanged ---------- */
    {
        len = make_packet(orig, NULL, 0, 1, 0); memcpy(pkt, orig, len);
        counter = 0; replay_window w5; replay_window_init(&w5);
        CHECK(pp_encrypt_packet(key, &counter, pkt, len, BUF, &out) == PP_UNCHANGED);
        CHECK(out == len && memcmp(pkt, orig, len) == 0 && counter == 0);
        CHECK(pp_decrypt_packet(key, &w5, pkt, len, &out) == PP_UNCHANGED);
    }

    /* ---------- 8. Fail-closed cases ---------- */
    {
        len = make_packet(orig, msg, n, 1, 0); memcpy(pkt, orig, len);
        counter = UINT64_MAX;                                  /* exhausted counter */
        CHECK(pp_encrypt_packet(key, &counter, pkt, len, BUF, &out) < 0);

        counter = 0; memcpy(pkt, orig, len);
        CHECK(pp_encrypt_packet(key, &counter, pkt, len, len, &out) == PP_ERR_SIZE); /* no room */

        memcpy(pkt, orig, len); ((struct iphdr *)pkt)->frag_off = htons(0x2000); /* fragment */
        CHECK(pp_encrypt_packet(key, &counter, pkt, len, BUF, &out) == PP_ERR_PARSE);

        replay_window w6; replay_window_init(&w6);
        len = make_packet(orig, msg, 10, 1, 0);               /* "protected" packet too short */
        CHECK(pp_decrypt_packet(key, &w6, orig, len, &out) == PP_ERR_SIZE);
        len = make_packet(orig, msg, n, 1, 0);                /* plaintext injected into decrypt side */
        CHECK(pp_decrypt_packet(key, &w6, orig, len, &out) < 0);
    }

    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("packet processor: all checks passed\n");
    return 0;
}
