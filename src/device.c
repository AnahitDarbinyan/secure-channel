/*
 * Secure inline channel device.
 *
 *   PC1 -> Device1 (--mode encrypt) -> Device2 (--mode decrypt) -> PC2
 *
 * 1. Authenticated X25519 handshake between the two devices (TCP, port 5006).
 * 2. Selected PC1->PC2 TCP packets arrive through NFQUEUE (iptables rule).
 *    Device1 encrypts the TCP payload with AES-256-GCM (tag appended).
 *    Device2 verifies the tag, decrypts, restores the packet and
 *    recalculates IP/TCP checksums.
 *
 * The device fails closed: if a packet cannot be processed, it is dropped,
 * never forwarded in clear.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <openssl/crypto.h>

#include "handshake.h"
#include "packet_processor.h"

#define DEFAULT_PEER_IP    "10.0.2.2"
#define HANDSHAKE_PORT     5006
#define ENCRYPT_QUEUE      2
#define DECRYPT_QUEUE      3

typedef enum { MODE_ENCRYPT, MODE_DECRYPT } device_mode;

typedef struct {
    device_mode   mode;
    unsigned char key[KEY_SIZE];
    uint64_t      send_counter;     /* Device1: next nonce counter        */
    replay_window window;           /* Device2: anti-replay state         */
    unsigned long forwarded, dropped;
} device_context;

static volatile sig_atomic_t stop_requested = 0;

static void on_signal(int sig)
{
    (void)sig;
    stop_requested = 1;
}

/* Large enough for the biggest IPv4 packet plus the 24 protection bytes. */
static unsigned char work[PP_MAX_BUF];

static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg,
                           struct nfq_data *nfa, void *user_data)
{
    (void)msg;
    device_context *ctx = user_data;

    struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(nfa);
    if (!hdr)
        return 0;
    uint32_t id = ntohl(hdr->packet_id);

    unsigned char *data = NULL;
    int len = nfq_get_payload(nfa, &data);

    if (len <= 0 || data == NULL || (size_t)len > 65535) {
        ctx->dropped++;
        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
    }

    memcpy(work, data, (size_t)len);

    size_t new_len = 0;
    int rc;
    uint64_t shown = ctx->send_counter;

    if (ctx->mode == MODE_ENCRYPT)
        rc = pp_encrypt_packet(ctx->key, &ctx->send_counter,
                               work, (size_t)len, sizeof(work), &new_len);
    else
        rc = pp_decrypt_packet(ctx->key, &ctx->window,
                               work, (size_t)len, &new_len);

    switch (rc) {
    case PP_UNCHANGED:
        ctx->forwarded++;
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);

    case PP_MODIFIED:
        ctx->forwarded++;
        if (ctx->mode == MODE_ENCRYPT)
            printf("[ENCRYPT] counter=%llu  %d -> %zu bytes\n",
                   (unsigned long long)shown, len, new_len);
        else
            printf("[DECRYPT] tag OK  %d -> %zu bytes\n", len, new_len);
        return nfq_set_verdict(queue, id, NF_ACCEPT,
                               (uint32_t)new_len, work);

    default: {
        const char *why =
            rc == PP_ERR_PARSE  ? "not a valid IPv4/TCP packet" :
            rc == PP_ERR_CRYPTO ? (ctx->mode == MODE_ENCRYPT
                                   ? "encryption failure"
                                   : "AUTHENTICATION FAILED (bad tag)") :
            rc == PP_ERR_REPLAY ? "REPLAY detected" :
                                  "bad packet size";
        printf("[DROP] %s\n", why);
        ctx->dropped++;
        return nfq_set_verdict(queue, id, NF_DROP, 0, NULL);
    }
    }
}

static int run_queue(device_context *ctx)
{
    int queue_number = ctx->mode == MODE_ENCRYPT ? ENCRYPT_QUEUE
                                                 : DECRYPT_QUEUE;
    struct nfq_handle *h = nfq_open();
    struct nfq_q_handle *q = NULL;
    static char buf[70000];
    int rc = 1;

    if (!h) {
        fprintf(stderr, "nfq_open failed (are you root?)\n");
        return 1;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "nfq_bind_pf failed\n");
        goto out;
    }

    q = nfq_create_queue(h, (uint16_t)queue_number, &packet_callback, ctx);
    if (!q) {
        fprintf(stderr, "Could not create NFQUEUE %d\n", queue_number);
        goto out;
    }

    if (nfq_set_mode(q, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "nfq_set_mode failed\n");
        goto out;
    }

    printf("Session established. Mode: %s, NFQUEUE %d. Waiting for packets...\n",
           ctx->mode == MODE_ENCRYPT ? "ENCRYPT (Device1)"
                                     : "DECRYPT (Device2)",
           queue_number);

    int fd = nfq_fd(h);
    rc = 0;

    while (!stop_requested) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n >= 0) {
            nfq_handle_packet(h, buf, (int)n);
        } else if (errno == EINTR) {
            continue;
        } else if (errno == ENOBUFS) {
            fprintf(stderr, "NFQUEUE overflow, packets lost\n");
            continue;
        } else {
            perror("recv");
            rc = 1;
            break;
        }
    }

    printf("\nStopping. forwarded=%lu dropped=%lu\n",
           ctx->forwarded, ctx->dropped);

out:
    if (q)
        nfq_destroy_queue(q);
    nfq_close(h);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  sudo %s --mode decrypt                 (Device2, start first)\n"
        "  sudo %s --mode encrypt [--peer IP]     (Device1, default peer %s)\n",
        prog, prog, DEFAULT_PEER_IP);
}

int main(int argc, char *argv[])
{
    const char *mode_arg = NULL;
    const char *peer = DEFAULT_PEER_IP;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc)
            mode_arg = argv[++i];
        else if (!strcmp(argv[i], "--peer") && i + 1 < argc)
            peer = argv[++i];
        else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!mode_arg) {
        usage(argv[0]);
        return 1;
    }

    static device_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    replay_window_init(&ctx.window);

    if (!strcmp(mode_arg, "encrypt"))
        ctx.mode = MODE_ENCRYPT;
    else if (!strcmp(mode_arg, "decrypt"))
        ctx.mode = MODE_DECRYPT;
    else {
        usage(argv[0]);
        return 1;
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;           /* no SA_RESTART: recv() returns */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (!device_handshake(ctx.mode == MODE_DECRYPT, peer,
                          HANDSHAKE_PORT, ctx.key)) {
        fprintf(stderr, "Handshake failed. No traffic will be forwarded.\n");
        return 1;
    }

    int rc = run_queue(&ctx);

    OPENSSL_cleanse(ctx.key, sizeof(ctx.key));
    return rc;
}
