/* BOLT 8: Lightning's encrypted, authenticated connection, as a state machine.
 *
 * No input or output: the caller moves the bytes. The three acts are fixed
 * sizes; after them, each message is an 18-byte encrypted length followed by
 * the encrypted body and its 16-byte MAC. Ephemeral keys come from the
 * caller's randomness port. See spec/transport.md for the rules.
 *
 * After any error the state is dead: every later call returns
 * GZ_NOISE_ERR_STATE, and its keys have been wiped. The one exception is
 * gz_noise_remote_static, a query that changes nothing.
 *
 * NEVER COPY A READY STATE AND USE BOTH COPIES: each would encrypt with the
 * same key and nonces, which breaks ChaCha20-Poly1305. (The struct is visible
 * only so the tests can read intermediate values; the one copy in the suite,
 * in the fuzz target, uses throwaway keys.) */
#ifndef GAZPACHO_NET_NOISE_H
#define GAZPACHO_NET_NOISE_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

/* Randomness for ephemeral keys: `fill` writes `len` unpredictable bytes read
 * from the operating system at the call. Every draw is a one-time secret; the
 * transport never stores, logs or sends it. Cannot fail: a port that cannot
 * read the system's randomness ends the program (transport.md decision 12).
 * The transport's own type, so it includes no core header (contract v2,
 * section 12). */
typedef struct {
    void (*fill)(void *ctx, uint8_t *out, size_t len);
    void *ctx;
} gz_net_random_t;

#define GZ_NOISE_ACT1_LEN 50
#define GZ_NOISE_ACT2_LEN 50
#define GZ_NOISE_ACT3_LEN 66
#define GZ_NOISE_MAC_LEN 16
#define GZ_NOISE_HDR_LEN 18 /* encrypted 2-byte length and its MAC */
#define GZ_NOISE_MAX_MSG 65535
#define GZ_NOISE_ROTATE_AT 1000

typedef enum {
    GZ_NOISE_OK = 0,
    GZ_NOISE_ERR_STATE,   /* call out of order, or the state is dead */
    GZ_NOISE_ERR_LENGTH,  /* input not exactly the expected size */
    GZ_NOISE_ERR_VERSION, /* act version byte not 0 */
    GZ_NOISE_ERR_PUBKEY,  /* a key that is not a valid compressed point */
    GZ_NOISE_ERR_MAC,     /* authentication failed */
    GZ_NOISE_ERR_RANDOM,  /* randomness gave no valid secret key */
    GZ_NOISE_ERR_TOO_BIG, /* message over 65,535 bytes, or output too small */
    GZ_NOISE_ERR_KEY,     /* our own static key is invalid */
    GZ_NOISE_ERR_CRYPTO   /* the crypto library failed */
} gz_noise_err_t;

typedef enum {
    GZ_NOISE_DEAD = 0,
    GZ_NOISE_I_START, GZ_NOISE_I_SENT1, GZ_NOISE_I_GOT2,
    GZ_NOISE_R_START, GZ_NOISE_R_GOT1, GZ_NOISE_R_SENT2,
    GZ_NOISE_READY,     /* waiting for a length header */
    GZ_NOISE_READY_BODY /* header read, waiting for its body */
} gz_noise_phase_t;

/* Visible so tests can compare the intermediate values with BOLT 8's. Callers
 * use only the functions. */
typedef struct {
    const secp256k1_context *secp;
    gz_net_random_t random;
    gz_noise_phase_t phase;
    uint8_t ck[32], h[32], temp_k[32];
    uint8_t ls_priv[32], ls_pub[33];
    uint8_t e_priv[32], e_pub[33];
    uint8_t rs[33], re[33];
    uint8_t sk[32], rk[32], sck[32], rck[32];
    uint64_t sn, rn;
    uint16_t body_len; /* in READY_BODY: length from the header */
} gz_noise_t;

/* Both take our static secret key. The initiator also takes the responder's
 * static key, which it must know in advance (the member's pin). */
gz_noise_err_t gz_noise_init_initiator(gz_noise_t *st, const secp256k1_context *secp,
                                       const uint8_t ls_priv[32], const uint8_t rs[33],
                                       gz_net_random_t random);
gz_noise_err_t gz_noise_init_responder(gz_noise_t *st, const secp256k1_context *secp,
                                       const uint8_t ls_priv[32], gz_net_random_t random);

/* Initiator: write act one, read act two, write act three. */
gz_noise_err_t gz_noise_act1_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT1_LEN]);
gz_noise_err_t gz_noise_act2_read(gz_noise_t *st, const uint8_t *in, size_t len);
gz_noise_err_t gz_noise_act3_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT3_LEN]);

/* Responder: read act one, write act two, read act three. */
gz_noise_err_t gz_noise_act1_read(gz_noise_t *st, const uint8_t *in, size_t len);
gz_noise_err_t gz_noise_act2_write(gz_noise_t *st, uint8_t out[GZ_NOISE_ACT2_LEN]);
gz_noise_err_t gz_noise_act3_read(gz_noise_t *st, const uint8_t *in, size_t len);

/* After the handshake: the other side's static key. A query: before then it
 * returns GZ_NOISE_ERR_STATE without changing the state. */
gz_noise_err_t gz_noise_remote_static(const gz_noise_t *st, uint8_t out[33]);

/* Encrypt one message of up to 65,535 bytes. Writes 18 + len + 16 bytes. */
gz_noise_err_t gz_noise_encrypt(gz_noise_t *st, const uint8_t *msg, size_t len,
                                uint8_t *out, size_t out_cap, size_t *out_len);

/* Read a message in two steps: the 18-byte header gives the body length;
 * then exactly body_len + 16 bytes give the message, written to `out`
 * (at least body_len bytes). */
gz_noise_err_t gz_noise_decrypt_header(gz_noise_t *st, const uint8_t *in, size_t len,
                                       size_t *body_len);
gz_noise_err_t gz_noise_decrypt_body(gz_noise_t *st, const uint8_t *in, size_t len,
                                     uint8_t *out, size_t out_cap);

/* Wipe everything and mark the state dead. Safe to call more than once. */
void gz_noise_wipe(gz_noise_t *st);

/* Exposed for the test vectors: HKDF as BOLT 8 uses it (64 bytes, empty
 * info). Returns 1 on success. */
int gz_noise_hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t out1[32], uint8_t out2[32]);

const char *gz_noise_err_name(gz_noise_err_t e);

#endif
