#ifndef GAZPACHO_WALLET_TX_INTERNAL_H
#define GAZPACHO_WALLET_TX_INTERNAL_H

/* Shared by the wallet transaction sources; not part of the interface. */

#include <string.h>

#include "gazpacho/wallet_tx.h"

/* A bounded writer: writes past cap set `over` and are dropped. */
typedef struct {
    uint8_t *p;
    size_t cap, len;
    int over;
} gzt_w;

static inline void gzt_put(gzt_w *w, const void *src, size_t n) {
    if (w->over || n > w->cap - w->len) {
        w->over = 1;
        return;
    }
    if (n) memcpy(w->p + w->len, src, n);
    w->len += n;
}

static inline void gzt_put_u8(gzt_w *w, uint8_t v) { gzt_put(w, &v, 1); }

static inline void gzt_put_le(gzt_w *w, uint64_t v, size_t n) {
    uint8_t b[8];
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(v >> (8 * i));
    gzt_put(w, b, n);
}

/* Bitcoin's compact size, minimal form. */
static inline void gzt_put_cs(gzt_w *w, uint64_t v) {
    if (v < 0xfd) {
        gzt_put_u8(w, (uint8_t)v);
    } else if (v <= 0xffff) {
        gzt_put_u8(w, 0xfd);
        gzt_put_le(w, v, 2);
    } else if (v <= 0xffffffffu) {
        gzt_put_u8(w, 0xfe);
        gzt_put_le(w, v, 4);
    } else {
        gzt_put_u8(w, 0xff);
        gzt_put_le(w, v, 8);
    }
}

static inline size_t gzt_cs_len(uint64_t v) {
    return v < 0xfd ? 1 : v <= 0xffff ? 3 : v <= 0xffffffffu ? 5 : 9;
}

/* SHA-256 helpers (libcrypto's one-shot SHA256). */
void gzt_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void gzt_sha256d(const uint8_t *data, size_t len, uint8_t out[32]);
/* BIP 340 tagged hash; len must be at most 512. */
void gzt_tagged_hash(const char *tag, const uint8_t *msg, size_t len, uint8_t out[32]);
/* Every count and length within the caps, and n_in, n_out at least 1. */
int gzt_tx_in_caps(const gzt_tx *tx);
int gzt_tx_has_witness(const gzt_tx *tx);

#endif /* GAZPACHO_WALLET_TX_INTERNAL_H */
