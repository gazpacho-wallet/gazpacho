/* See wipe.h. OPENSSL_cleanse is not removed by the optimiser. */
#include "wipe.h"

#include <openssl/crypto.h>

void gz_net_wipe(void *p, size_t n)
{
    OPENSSL_cleanse(p, n);
}
