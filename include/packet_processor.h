#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <stddef.h>
#include <stdint.h>
#include "packet_crypto.h"
#include "replay_window.h"

/*
 * Whole-packet protection for IPv4/TCP.
 *
 * Encrypt side (Device1):
 *   IP hdr | TCP hdr | payload            (N bytes)
 *   -> IP hdr | TCP hdr | counter(8) | ciphertext(N) | tag(16)
 *
 * IP and TCP headers are kept as they are. Only tot_len and the IP/TCP
 * checksums change. No UDP encapsulation, no extra protocol header.
 *
 * Packets with an empty TCP payload (SYN, pure ACK, FIN...) carry no
 * application data and are passed through unchanged.
 *
 * Return values
 */
#define PP_UNCHANGED   0    /* packet left as it was (no payload)            */
#define PP_MODIFIED    1    /* packet rewritten, *out_len is the new length  */
#define PP_ERR_PARSE  (-1)  /* not a valid unfragmented IPv4/TCP packet      */
#define PP_ERR_CRYPTO (-2)  /* encryption failed or tag verification failed  */
#define PP_ERR_REPLAY (-3)  /* valid tag but counter already seen / too old  */
#define PP_ERR_SIZE   (-4)  /* packet too short/long for the operation       */

/* Working buffer size: biggest IPv4 packet + protection overhead. */
#define PP_MAX_BUF (65535 + PC_OVERHEAD)

/* Fixed nonce prefix. The key is unique per session (fresh X25519 keys +
 * random salt), and the 64-bit counter never repeats under that key. */
#define PP_NONCE_PREFIX 0x00000001u

/* Bytes of AAD: saddr, daddr, proto, sport, dport, seq, ack, tcp flags. */
#define PP_AAD_LEN 22

/*
 * pkt must have room for at least len + PC_OVERHEAD bytes (cap).
 * *counter is the per-session send counter; it is incremented BEFORE use,
 * so a nonce is never reused even if the packet is later dropped.
 * On any error the packet must be dropped (fail closed).
 */
int pp_encrypt_packet(const unsigned char key[32], uint64_t *counter,
                      unsigned char *pkt, size_t len, size_t cap,
                      size_t *out_len);

/* Verifies the tag, checks the replay window, restores the original packet. */
int pp_decrypt_packet(const unsigned char key[32], replay_window *window,
                      unsigned char *pkt, size_t len, size_t *out_len);

#endif
