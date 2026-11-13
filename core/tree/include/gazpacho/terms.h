/* The host terms record (spec/terms.md draft 2): decoding, encoding, digests,
 * the receipt checks of section 7, the version and freeze rule of sections 7
 * and 8, and the comparison of section 9.
 *
 * Pure C11: no allocation, no input or output, no global state. Every bound
 * of sections 2 to 5 is checked; a failure names exactly which rule broke
 * (gz_terms_err_t). Decoding is strict: the encoding is canonical (section
 * 2), so equal terms always have equal bytes and equal digests.
 *
 * Signatures and point validity need elliptic-curve arithmetic, which the
 * core does not contain: they go through the crypto provider of tree.h
 * (gz_tree_crypto_t), which the embedding supplies (core/tree/import gives
 * one built on secp256k1). */
#ifndef GAZPACHO_TERMS_H
#define GAZPACHO_TERMS_H

#include <stddef.h>
#include <stdint.h>

#define GZ_TERMS_OUTER_MAX   4096   /* section 2 rule 7 */
#define GZ_TERMS_CURRENT_MAX 1024
#define GZ_TERMS_MAX_SHAPES  250    /* 1,000 bytes of 4-byte entries at least */
#define GZ_TERMS_MAX_INTERIOR 6     /* section 4.1 */
#define GZ_TERMS_MAX_ADJ     36     /* 3 known even types and the 32 odd ones of 64..127 */
#define GZ_TERMS_LEAF_PS     3      /* the only leaf kind of 1.0.0 */

/* Known types (section 3). */
enum {
    GZ_TT_CHAIN = 2, GZ_TT_ALIAS = 3, GZ_TT_HOST_KEY = 4, GZ_TT_DESCRIPTION = 5, GZ_TT_SALT = 6,
    GZ_TT_PROFILE = 8, GZ_TT_TARGET = 10, GZ_TT_MINIMUM = 12, GZ_TT_DEADLINE = 14,
    GZ_TT_SHORTFALL = 16, GZ_TT_READY_WINDOW = 18, GZ_TT_SIGNING_BUDGET = 20, GZ_TT_STEP_TIMEOUT = 22,
    GZ_TT_SHAPES = 24, GZ_TT_LIFETIME = 26, GZ_TT_WINDDOWN = 28, GZ_TT_CHANNEL = 30,
    GZ_TT_FEERATE = 32, GZ_TT_SWITCHES = 34,
    GZ_TT_JOINING_FEE = 64, GZ_TT_FEE_BASE = 66, GZ_TT_FEE_PROP = 68,
    GZ_TC_OUTER_DIGEST = 2, GZ_TC_VERSION = 4     /* in the current record */
};

/* Why a record was refused. 0 is success. One code per rule, so that a test
 * can show that the refusal came from the rule it targets. */
typedef enum {
    GZ_TERMS_OK = 0,
    /* section 2: encoding */
    GZ_TERMS_E_TOO_LONG,          /* rule 7: 4,096 / 1,024 bytes */
    GZ_TERMS_E_TRUNCATED,         /* a BigSize or a value runs past the end */
    GZ_TERMS_E_NOT_MINIMAL,       /* rule 1: BigSize not minimally encoded */
    GZ_TERMS_E_ORDER,             /* rule 1: types not strictly increasing */
    GZ_TERMS_E_UNKNOWN_EVEN,      /* rule 3 (an even type of 1..127 this app does not know) */
    GZ_TERMS_E_RESERVED_TYPE,     /* rule 5: type 128 and up */
    GZ_TERMS_E_TYPE_NOT_ALLOWED,  /* rule 5: a type of 1..63 other than 2 and 4 in a current record */
    GZ_TERMS_E_LENGTH,            /* rule 2: a value of the wrong size */
    GZ_TERMS_E_MISSING,           /* a required type is absent */
    GZ_TERMS_E_UTF8,              /* display text that is not UTF-8 */
    /* section 3: bounds of the outer rules */
    GZ_TERMS_E_HOST_KEY,          /* not a valid point */
    GZ_TERMS_E_PROFILE,
    GZ_TERMS_E_TARGET,
    GZ_TERMS_E_MINIMUM,
    GZ_TERMS_E_SHORTFALL,
    GZ_TERMS_E_READY_WINDOW,
    GZ_TERMS_E_SIGNING_BUDGET,
    GZ_TERMS_E_STEP_TIMEOUT,
    GZ_TERMS_E_LIFETIME,
    GZ_TERMS_E_WINDDOWN,
    GZ_TERMS_E_CHANNEL,
    GZ_TERMS_E_FEERATE,
    GZ_TERMS_E_SWITCHES,
    GZ_TERMS_E_RANGE,             /* an adjustable range with min > max or above its ceiling */
    /* section 4: the shape table */
    GZ_TERMS_E_SHAPE_ENCODING,    /* entries do not fill the value exactly */
    GZ_TERMS_E_SHAPE_MAX_MEMBERS, /* below 3, above 1,000, or not increasing */
    GZ_TERMS_E_SHAPE_N_INTERIOR,  /* above 6 */
    GZ_TERMS_E_SHAPE_WIDTH,       /* an interior width outside 4..15 */
    GZ_TERMS_E_SHAPE_LEAF_KIND,   /* not 3 */
    GZ_TERMS_E_SHAPE_TARGET,      /* the last entry is below the target */
    GZ_TERMS_E_SHAPE_SPLIT,       /* section 4.3: some n makes a leaf with m <= a members */
    GZ_TERMS_E_UNFUNDABLE,        /* for some member count from minimum to target (at most 256),
                                     R(root) is above the money supply or 64 bits, or below the
                                     import's minimum funding 2 (2n - 1) fee + 1,092 n (review A, S3);
                                     or minimum above 256: no tree can ever be built (review B, B4) */
    /* Slice 1 profile (sections 3 and 7 step 4) */
    GZ_TERMS_E_CHAIN,             /* not signet */
    GZ_TERMS_E_SLICE1,            /* a value Slice 1 refuses: profile, shortfall, switches */
    /* section 5: the current record */
    GZ_TERMS_E_VERSION,           /* version 0 */
    GZ_TERMS_E_ADJ_SET,           /* not exactly the outer record's adjustable types */
    GZ_TERMS_E_ADJ_VALUE,         /* a value outside its range */
    /* section 7: receipt */
    GZ_TERMS_E_SCOPE,             /* step 2: digest differs from the message scope */
    GZ_TERMS_E_PINNED_KEY,        /* step 3: host_key is not the pinned BOLT 8 key */
    GZ_TERMS_E_OUTER_SIG,         /* step 3 */
    GZ_TERMS_E_CURRENT_SIG,       /* step 3 */
    GZ_TERMS_E_OUTER_DIGEST,      /* step 6: the current record names another outer digest */
    GZ_TERMS_E_ARGUMENT           /* a NULL pointer or a buffer too small */
} gz_terms_err_t;

typedef struct {
    uint16_t max_members;
    uint8_t n_interior;
    uint8_t interior[GZ_TERMS_MAX_INTERIOR];
    uint8_t leaf_kind;
} gz_shape_entry_t;

typedef struct {
    uint8_t type;                 /* 64..127 */
    uint64_t min, max;            /* outer: the range */
} gz_terms_range_t;

/* The outer rules, decoded. Display texts are kept as bytes. */
typedef struct {
    uint8_t chain[32];
    uint8_t host_key[33];
    uint8_t alias_len;            /* 0: absent */
    uint8_t alias[32];
    uint16_t description_len;     /* 0: absent */
    uint8_t description[280];
    uint8_t lobby_salt[16];
    uint8_t profile;
    uint16_t target, minimum;
    uint64_t deadline;
    uint8_t on_shortfall;
    uint32_t ready_window_ms, signing_budget_ms, step_timeout_ms;
    uint16_t n_shapes;
    gz_shape_entry_t shapes[GZ_TERMS_MAX_SHAPES];
    uint32_t lifetime_blocks, winddown_blocks;
    uint64_t channel_sat;
    uint32_t tree_feerate;        /* satoshis per 1,000 vbytes */
    uint8_t switches;
    uint8_t n_adj;                /* adjustable ranges, in type order */
    gz_terms_range_t adj[GZ_TERMS_MAX_ADJ];
    /* Odd types of 1..63 this app does not know (section 2 rule 4): skipped,
     * counted. They stay inside the digest because the digest is over the
     * received bytes, never over a re-encoding. */
    uint16_t n_unknown_odd;
} gz_terms_outer_t;

typedef struct {
    uint8_t outer_digest[32];
    uint32_t version;
    uint8_t n_values;
    struct { uint8_t type; uint64_t value; } val[GZ_TERMS_MAX_ADJ];
} gz_terms_current_t;

/* What a reader accepts. `slice1` = 1 applies the Slice 1 column of section 3
 * (signet only, profile 2, cancel on shortfall, switches 0). */
typedef struct {
    int slice1;
} gz_terms_policy_t;

/* Signet's genesis hash in internal order (section 3, type 2). A function, not
 * an exported object: the core holds no global objects (an AddressSanitizer
 * build gives every exported object a writable ODR indicator). */
const uint8_t *gz_terms_signet(void);

/* Section 7 step 1 for the outer record: the encoding of section 2 only
 * (canonical TLV, sizes, required types, UTF-8). Values may still be out of
 * bounds. */
gz_terms_err_t gz_terms_parse_outer(const uint8_t *b, size_t n, gz_terms_outer_t *out);
/* Steps 4 and 5 on a parsed record: the chain (signet, under the Slice 1
 * policy), then every bound of sections 3 and 4 including section 4.3. The
 * host key's prefix is checked here; that it is on the curve needs the
 * crypto provider (gz_terms_receive). Takes any struct, also one never
 * decoded: counts past the arrays are refused, never read. */
gz_terms_err_t gz_terms_check_outer(const gz_terms_outer_t *t, const gz_terms_policy_t *pol);
/* Section 5 on decoded structs (the part of step 6 that needs no bytes):
 * version at least 1, exactly the outer record's adjustable types in type
 * order, each value in its range. gz_terms_decode_current ends with it;
 * gz_tree_member_check runs it again on the frozen values (review B, B1). */
gz_terms_err_t gz_terms_check_current(const gz_terms_outer_t *outer, const gz_terms_current_t *c);
/* 1 if the two structs hold the same terms, field by field (counts and the
 * used part of each array only; padding and unused entries do not count). */
int gz_terms_outer_equal(const gz_terms_outer_t *a, const gz_terms_outer_t *b);
int gz_terms_current_equal(const gz_terms_current_t *a, const gz_terms_current_t *b);
/* parse, then check. */
gz_terms_err_t gz_terms_decode_outer(const uint8_t *b, size_t n, const gz_terms_policy_t *pol,
                                     gz_terms_outer_t *out);
/* Decode the current record against its decoded outer rules: section 2 and
 * section 5 (exactly the outer record's adjustable types, each in range,
 * version at least 1). Does not compare the outer digest (step 6 does).
 * With `outer` NULL, section 2 and the version only. */
gz_terms_err_t gz_terms_decode_current(const uint8_t *b, size_t n, const gz_terms_outer_t *outer,
                                       gz_terms_current_t *out);

/* Encode. Return the length written, or 0 if `cap` is too small or the
 * record breaks a rule of section 2 (types out of order are impossible
 * here; a value too long is not). Unknown odd types are not re-encoded:
 * encode only what this app writes as a host. */
size_t gz_terms_encode_outer(const gz_terms_outer_t *t, uint8_t *out, size_t cap);
size_t gz_terms_encode_current(const gz_terms_current_t *c, uint8_t *out, size_t cap);

/* Section 6. */
void gz_terms_outer_digest(const uint8_t *outer, size_t n, uint8_t out[32]);
void gz_terms_current_digest(const uint8_t *current, size_t n, uint8_t out[32]);

/* The section 4.3 check alone, on a decoded table (used by the decoder). */
gz_terms_err_t gz_terms_check_shapes(const gz_shape_entry_t *e, size_t n_entries, uint16_t target);

struct gz_tree_crypto;  /* tree.h */

/* Section 7 steps 1 to 6, in that order, on one terms_offer. `scope` is the
 * message's scope, `pinned_key` the BOLT 8 key the member connected to. On
 * success both records are decoded and both digests written. */
gz_terms_err_t gz_terms_receive(const uint8_t *outer, size_t outer_len, const uint8_t outer_sig[64],
                                const uint8_t *current, size_t current_len, const uint8_t current_sig[64],
                                const uint8_t scope[32], const uint8_t pinned_key[33],
                                const gz_terms_policy_t *pol, const struct gz_tree_crypto *crypto,
                                gz_terms_outer_t *outer_out, uint8_t outer_digest[32],
                                gz_terms_current_t *current_out, uint8_t current_digest[32]);

/* Section 7 steps 7 and 8, and section 8: what a member does with a newly
 * received, valid current record. `have` = 0 if none was accepted yet. */
typedef enum {
    GZ_TERMS_V_ACCEPT = 0,      /* higher version, not frozen: the new current values */
    GZ_TERMS_V_DUPLICATE,       /* equal version, identical bytes (same digest): nothing to do */
    GZ_TERMS_V_IGNORE_OLDER,    /* lower version, not frozen: ignored */
    GZ_TERMS_V_EQUIVOCATION,    /* equal version, other bytes: keep both as evidence, leave */
    GZ_TERMS_V_FROZEN_BREACH    /* frozen, and this is not the frozen record: evidence, leave */
} gz_terms_version_t;
gz_terms_version_t gz_terms_version_rule(int have, uint32_t have_version, const uint8_t have_digest[32],
                                         int frozen, uint32_t new_version, const uint8_t new_digest[32]);

/* Section 9: a member's own limits. A field left at its "no limit" value
 * (documented per field) does not constrain. */
typedef struct {
    uint64_t min_channel_sat;          /* fixed term 30 must be at least this (0: none) */
    uint32_t max_tree_feerate;         /* fixed term 32 at most (0: none) */
    uint32_t min_lifetime, max_lifetime; /* fixed term 26 (0: none) */
    uint16_t min_members;              /* the terms' `minimum` at least this (0: none) */
    uint8_t profiles;                  /* bit p = profile p accepted (0: any) */
    uint8_t n_max;                     /* adjustable limits: the value the member accepts at most */
    struct { uint8_t type; uint64_t max; } max[GZ_TERMS_MAX_ADJ];
} gz_terms_limits_t;

typedef enum {
    GZ_TERMS_FITS = 0,              /* every fixed term and every whole range fits */
    GZ_TERMS_FITS_ONLY_NOW,         /* fixed terms fit; some range does not, but its current value does */
    GZ_TERMS_DOES_NOT_FIT
} gz_terms_class_t;
/* Every adjustable term of draft 2 is a fee, so the value a member likes
 * least is the range's maximum (section 9). An adjustable type the limits do
 * not name has no limit. */
gz_terms_class_t gz_terms_classify(const gz_terms_outer_t *outer, const gz_terms_current_t *current,
                                   const gz_terms_limits_t *limits);

const char *gz_terms_err_name(gz_terms_err_t e);

#endif
