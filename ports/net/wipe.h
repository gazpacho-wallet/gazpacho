/* The transport's one way of wiping secrets.
 *
 * A separate object so that a test can link with --wrap=gz_net_wipe and see
 * exactly the transport's wipes, and not the crypto library's own (which a
 * static libcrypto would otherwise also send through a wrapped
 * OPENSSL_cleanse). */
#ifndef GAZPACHO_NET_WIPE_H
#define GAZPACHO_NET_WIPE_H

#include <stddef.h>

void gz_net_wipe(void *p, size_t n);

#endif
