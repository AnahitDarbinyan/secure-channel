#ifndef REPLAY_WINDOW_H
#define REPLAY_WINDOW_H

#include <stdint.h>

/*
 * Sliding anti-replay window (64 packets), as used by IPsec/DTLS.
 * Tolerates reordering inside the window, rejects duplicates and
 * counters that are too old.
 *
 * Call replay_window_accept() ONLY after the AES-GCM tag has been
 * verified, so that forged packets can never move the window.
 */
typedef struct {
    uint64_t highest;   /* highest counter accepted so far */
    uint64_t bitmap;    /* bit i set => (highest - i) already seen */
    int      started;
} replay_window;

static inline void replay_window_init(replay_window *w)
{
    w->highest = 0;
    w->bitmap  = 0;
    w->started = 0;
}

/* Returns 1 and records the counter if fresh; returns 0 if replayed/too old. */
static inline int replay_window_accept(replay_window *w, uint64_t counter)
{
    if (!w->started) {
        w->started = 1;
        w->highest = counter;
        w->bitmap  = 1;
        return 1;
    }

    if (counter > w->highest) {
        uint64_t shift = counter - w->highest;
        w->bitmap = (shift >= 64) ? 0 : (w->bitmap << shift);
        w->bitmap |= 1;
        w->highest = counter;
        return 1;
    }

    uint64_t diff = w->highest - counter;
    if (diff >= 64)
        return 0;                       /* too old */
    if (w->bitmap & ((uint64_t)1 << diff))
        return 0;                       /* duplicate */

    w->bitmap |= ((uint64_t)1 << diff);
    return 1;
}

#endif
