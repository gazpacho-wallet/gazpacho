/* SPDX-License-Identifier: MIT */
/* STAND-IN seed source (keys_standin.h). */
#include "keys_standin.h"

#include <stdio.h>
#include <string.h>

#include "gzp.h"

int gzp_seed_standin_from_entropy(gzp_seed_standin_t *s, const uint8_t entropy[32])
{
    char phrase[GZW_PHRASE_MAX];
    int ok;
    memset(s, 0, sizeof *s);
    ok = gzw_phrase_from_entropy(entropy, phrase) == 1 && gzw_phrase_to_seed(phrase, "", s->seed) == 1;
    gzw_wipe(phrase, sizeof phrase);
    if (!ok) {
        gzw_wipe(s, sizeof *s);
        return -1;
    }
    s->have = 1;
    return 0;
}

int gzp_seed_standin_open(gzp_seed_standin_t *s, const gzp_datadir_t *d)
{
    uint8_t entropy[32];
    int rc;
    memset(s, 0, sizeof *s);
    if ((rc = gzp_datadir_secret(d, "wallet-seed.standin", entropy, NULL, NULL)) != 0) {
        gzw_wipe(entropy, sizeof entropy);
        return rc;
    }
    rc = gzp_seed_standin_from_entropy(s, entropy);
    gzw_wipe(entropy, sizeof entropy);
    if (rc != 0) {
        fprintf(stderr, "gazpacho: cannot make the wallet's seed\n");
        return GZP_EXIT_DATA;
    }
    return 0;
}

static int standin_seed(void *ctx, uint8_t out[64])
{
    const gzp_seed_standin_t *s = ctx;
    if (!s || !s->have) {
        gzw_wipe(out, 64);
        return 0;
    }
    memcpy(out, s->seed, 64);
    return 1;
}

gzp_seed_source_t gzp_seed_standin_source(gzp_seed_standin_t *s)
{
    gzp_seed_source_t src;
    src.seed = standin_seed;
    src.ctx = s;
    return src;
}

void gzp_seed_standin_close(gzp_seed_standin_t *s)
{
    if (s) gzw_wipe(s, sizeof *s);
}
