#ifndef GAZPACHO_WALLET_KEYS_INTERNAL_H
#define GAZPACHO_WALLET_KEYS_INTERNAL_H

/* Shared by the wallet key sources; not part of the public interface. */

#include "gazpacho/wallet_keys.h"

/* Store a reason through an optional pointer. */
static inline void gzw_set_reason(gzw_reason *why, gzw_reason reason) {
    if (why) *why = reason;
}

#endif /* GAZPACHO_WALLET_KEYS_INTERNAL_H */
