#ifndef GZW_OFFICIAL_VECTORS_H
#define GZW_OFFICIAL_VECTORS_H

/* Runs the official BIP test vectors against gazpacho_wallet_keys.
   The vectors themselves are in official_vectors_data.h, generated from the
   published files by gen-official-vectors.py. */

#include <secp256k1.h>

/* One group of vectors and its result. */
typedef struct {
    const char *name;   /* what was checked */
    int cases;          /* vectors run */
    int failed;         /* vectors that did not give the published result */
} gzw_vector_group;

#define GZW_VECTOR_GROUPS 9

/* Run every group.  Fills groups[] and returns 1 only if every vector in
   every group passed and every group ran at least one vector.  Does no I/O. */
int gzw_official_vectors_run(const secp256k1_context *ctx,
                             gzw_vector_group groups[GZW_VECTOR_GROUPS]);

#endif /* GZW_OFFICIAL_VECTORS_H */
