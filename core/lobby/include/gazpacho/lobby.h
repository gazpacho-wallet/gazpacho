/* The lobby engine: spec/messages.md sections 4 to 6 and 8, spec/terms.md,
 * the lobby side of spec/signing-round.md section 6 step 1.
 *
 * Sans-I/O like the node (node.h): inputs in, actions out, and every save is
 * listed before the sends it justifies, so the runner's rule (runner.h) gives
 * "save before send". The engine holds no secret key. It signs and verifies
 * through a crypto port (gz_lobby_crypto_t) that the program supplies, so the
 * library itself calls nothing outside itself.
 *
 * Bytes on the wire are whole Lightning messages: the 2-byte type 52791, then
 * the envelope of messages.md section 4.
 *
 * WHAT IT DOES
 *   - Strict encoding and decoding of the lobby messages (kinds 16 to 34) and
 *     of `part` (kind 2, section 5), and of both terms records (terms.md 2 to
 *     6), with every bound of the specifications.
 *   - The member: checks terms on receipt (terms.md 7), compares them with its
 *     conditions (terms.md 9), joins, readies and unreadies, answers ready
 *     checks, keeps evidence of a host fault and leaves, takes `start`.
 *   - The host: seats, the limits on seat changes, the start rule, the ready
 *     check and its freeze, the choice of signers, `start`, cancel, removal
 *     before the start, standby seats.
 *   - The hand-off to the signing engine (gz_lobby_signing_t).
 *
 * ERRORS. An engine call that returns anything but GZ_OK (an action list too
 * small, a signature the port would not make) may already have changed the
 * engine's memory. Treat it like a refused list (runner.h): stop the node and
 * rebuild it from storage. Give the engines lists of at least 256 slots and
 * 512 KiB: a new current version is offered to every seat, about 5.4 KB each.
 *
 * WHAT IT DOES NOT DO
 *   - Build the tree (fee per transaction, funding amount): that is the
 *     creation-tree work. It computes the shape, the levels and D only.
 *   - Discovery, invitations as messages, names, chat: none in Slice 1. */
#ifndef GAZPACHO_LOBBY_H
#define GAZPACHO_LOBBY_H

#include "gazpacho/action.h"
#include "gazpacho/ports.h"

/* ---------------------------------------------------------------- limits */

#define GZ_LOBBY_MSG_TYPE      52791u   /* the Lightning message type, 0xce37 */
#define GZ_LOBBY_MAX_MSG       65535u   /* a whole Lightning message, type included */
#define GZ_LOBBY_MAX_RECORDS   65495u   /* records of one envelope */
#define GZ_TERMS_OUTER_MAX     4096u
#define GZ_TERMS_CURRENT_MAX   1024u
#define GZ_TERMS_MAX_SHAPES    250      /* 1,000 bytes of 4-byte entries */
#define GZ_TERMS_MAX_ADJ       36       /* 64 to 127: 3 known even + 32 odd + 1 */
#define GZ_LOBBY_MAX_SEATS     32       /* Slice 1 host: target + standbys */
#define GZ_LOBBY_MAX_CONNS     48
#define GZ_LOBBY_MAX_SAVED_MSG 256      /* a saved ready, start or ready_check */
#define GZ_LOBBY_STATUS_MAX    64       /* a lobby_status: 40 + 3 + 3 + 6 + 4 + 4 + 4 */
#define GZ_PART_DATA           65000u
#define GZ_PART_MAX_BODY       1048576u

/* ------------------------------------------------------- hashing (pure) */

typedef struct { uint32_t h[8]; uint64_t n; uint8_t buf[64]; } gz_lobby_sha256_t;
void gz_lobby_sha256_init(gz_lobby_sha256_t *s);
void gz_lobby_sha256_write(gz_lobby_sha256_t *s, const uint8_t *d, size_t len);
void gz_lobby_sha256_done(gz_lobby_sha256_t *s, uint8_t out[32]);
/* Start a BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || ...). */
void gz_lobby_tagged_init(gz_lobby_sha256_t *s, const char *tag);
void gz_lobby_tagged(const char *tag, const uint8_t *d, size_t len, uint8_t out[32]);

/* ----------------------------------------------------------- crypto port */

/* Which key signs. The program maps these to keys it holds: the host's
 * long-term key, or the member's per-lobby contribution and factory keys. */
#define GZ_LOBBY_KEY_HOST         1u
#define GZ_LOBBY_KEY_CONTRIBUTION 2u
#define GZ_LOBBY_KEY_FACTORY      3u

typedef struct {
    /* 1 if `sig` is a valid BIP 340 signature of `msg` under the x coordinate
     * of the 33-byte point `pub`, else 0. */
    int (*verify)(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64]);
    /* 1 if `pub` is a valid compressed point. */
    int (*point_ok)(void *ctx, const uint8_t pub[33]);
    /* BIP 340 signature of `msg` by key `which`; 1 on success. */
    int (*sign)(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64]);
    void *ctx;
} gz_lobby_crypto_t;

/* ---------------------------------------------------------------- terms */

typedef struct {
    uint16_t max_members;
    uint8_t n_interior;
    uint8_t interior[6];
    uint8_t leaf_kind;
} gz_lterms_shape_t;

typedef struct { uint8_t type; uint64_t min, max; } gz_lterms_range_t;

/* The outer rules, decoded (terms.md section 3). */
typedef struct {
    uint8_t chain[32], host_key[33], salt[16];
    const uint8_t *alias; size_t alias_len;          /* into the record; may be NULL */
    const uint8_t *description; size_t description_len;
    uint8_t profile, on_shortfall, switches;
    uint16_t target, minimum;
    uint64_t deadline;                               /* Unix seconds */
    uint32_t ready_window_ms, signing_budget_ms, step_timeout_ms;
    uint32_t lifetime_blocks, winddown_blocks, tree_feerate;
    uint64_t channel_sat;
    uint16_t n_shapes;
    gz_lterms_shape_t shapes[GZ_TERMS_MAX_SHAPES];
    uint8_t n_adj;                                   /* ranges, increasing type */
    gz_lterms_range_t adj[GZ_TERMS_MAX_ADJ];
} gz_lterms_outer_t;

/* The current values, decoded (terms.md section 5). */
typedef struct {
    uint8_t outer_digest[32];
    uint32_t version;
    uint8_t n_adj;
    uint8_t adj_type[GZ_TERMS_MAX_ADJ];
    uint64_t adj_value[GZ_TERMS_MAX_ADJ];
} gz_lterms_current_t;

/* Decode and check every bound of terms.md sections 2 to 4, the shape check
 * of 4.3 included. 1 if valid, 0 if refused. `out` points into `rec`. */
int gz_lterms_outer_decode(const uint8_t *rec, size_t len, gz_lterms_outer_t *out);
/* Decode against the outer rules (terms.md 7 step 6): the outer digest, the
 * exact set of adjustable types, each value inside its range. */
int gz_lterms_current_decode(const uint8_t *rec, size_t len, const gz_lterms_outer_t *outer,
                            const uint8_t outer_digest[32], gz_lterms_current_t *out);
/* Networks (messages.md section 2, contract v2 item 15): a party runs one,
 * signet or testnet4, and refuses terms for any other. */
#define GZ_LOBBY_NET_SIGNET   0
#define GZ_LOBBY_NET_TESTNET4 1
/* The network's block 0 hash in internal order, or NULL for another number. */
const uint8_t *gz_lterms_genesis(int network);
/* The values a Slice 1 app accepts: the party's own network (signet or
 * testnet4), Standard, cancel, switches 0. */
int gz_lterms_slice1_ok(const gz_lterms_outer_t *outer, int network);

/* Canonical encoders: one byte string per set of terms. Return the length,
 * or 0 if `cap` is short. They do not judge the values: decode the result. */
size_t gz_lterms_outer_encode(const gz_lterms_outer_t *o, uint8_t *out, size_t cap);
size_t gz_lterms_current_encode(const gz_lterms_current_t *c, const gz_lterms_outer_t *outer,
                               uint8_t *out, size_t cap);

void gz_lterms_outer_digest(const uint8_t *rec, size_t len, uint8_t out[32]);
void gz_lterms_current_digest(const uint8_t *rec, size_t len, uint8_t out[32]);

/* The tree for n members (terms.md 4.2): the applicable entry's level list
 * (interior || leaf kind) and D, the depth of the deepest leaf. 0 if no entry
 * covers n or the split meets an interior node with m <= its width. */
int gz_lterms_shape_for(const gz_lterms_outer_t *o, uint16_t n, uint8_t levels[8],
                       uint8_t *n_levels, uint8_t *depth);

/* A member's conditions (terms.md section 9). Kept on the device, never sent
 * except `min_members` in `ready`. */
typedef struct {
    uint8_t profiles;          /* bit p set: profile p is accepted */
    uint32_t life_min, life_max, wind_max, rate_max;
    uint64_t chan_min;
    uint64_t adj_max[3];       /* limits for types 64, 66, 68 */
    uint8_t current_only;      /* the looser option: compare current values only */
    uint16_t min_members;      /* 0: none */
} gz_lobby_conditions_t;

#define GZ_FIT_YES  1          /* fits: every fixed term and every whole range */
#define GZ_FIT_NOW  2          /* fits only now: a range does not, its value does */
#define GZ_FIT_NO   3          /* a fixed term or a current value does not fit */

/* The class, and in `*term` the type of the deciding term (0 for GZ_FIT_YES):
 * for GZ_FIT_NO the smallest failing fixed or current type, for GZ_FIT_NOW the
 * smallest adjustable type whose whole range does not fit. */
int gz_lterms_classify(const gz_lterms_outer_t *o, const gz_lterms_current_t *c,
                      const gz_lobby_conditions_t *cond, uint8_t *term);
/* 1 if a member with these conditions may be ready at these values. */
int gz_lterms_ready_ok(int cls, const gz_lobby_conditions_t *cond);

/* ------------------------------------------------------------- messages */

enum {
    GZ_KIND_PART = 2, GZ_KIND_HELLO = 16, GZ_KIND_TERMS_OFFER = 18, GZ_KIND_JOIN = 20,
    GZ_KIND_READY = 22, GZ_KIND_UNREADY = 24, GZ_KIND_LEAVE = 26, GZ_KIND_LOBBY_STATUS = 28,
    GZ_KIND_READY_CHECK = 30, GZ_KIND_START = 32, GZ_KIND_CANCEL = 34
};

/* What the decoder makes of a message. */
#define GZ_DEC_OK      0       /* a lobby message, or `part`, fully checked */
#define GZ_DEC_OTHER   1       /* a known kind of another engine (64 to 81): not decoded here */
#define GZ_DEC_IGNORE  2       /* not ours, an unknown odd kind, or discovery */
#define GZ_DEC_BADTAG  3       /* wrong protocol bytes: ignore, warn once per connection */
#define GZ_DEC_REFUSE  4       /* refuse: warning and close */

/* Every field of every lobby message; which are set depends on `kind` and
 * the `has_*` flags. Pointers point into the decoded bytes. */
typedef struct {
    uint16_t kind;
    uint8_t scope[32];
    size_t signed_len;               /* envelope bytes covered by msg_hash */
    const uint8_t *sig;              /* record 240, signed kinds */
    /* terms_offer */
    const uint8_t *outer, *outer_sig, *current, *current_sig;
    size_t outer_len, current_len;
    /* join */
    const uint8_t *factory_key, *bind_by_factory, *bind_by_contribution, *display_name;
    size_t display_name_len;
    /* ready, ready_check, start */
    const uint8_t *outer_digest, *current_digest, *check_id;
    uint32_t version, answer_within_ms;
    uint16_t min_members, signers;
    uint8_t role;
    int has_check_id, has_min_members;
    /* unready, leave, lobby_status, cancel */
    uint16_t reason;
    int has_reason;
    uint8_t lobby_state, seat_state;
    uint16_t joined, ready;
    /* part */
    const uint8_t *transfer_id, *data;
    uint16_t inner_kind, index, count;
    uint32_t total_len;
    size_t data_len;
} gz_lobby_msg_t;

/* Decode one whole Lightning message. Returns a GZ_DEC_* code; `m` is filled
 * only for GZ_DEC_OK. Checks the records of messages.md 4.2 and each kind's
 * table, but not signatures or direction (the engines do). */
int gz_lobby_decode(const uint8_t *msg, size_t len, gz_lobby_msg_t *m);

/* msg_hash = TH("gazpacho/msg", envelope bytes before record 240). */
void gz_lobby_msg_hash(const uint8_t *msg, const gz_lobby_msg_t *m, uint8_t out[32]);

/* A message being built. Records must be added in increasing type order. */
typedef struct { uint8_t *buf; size_t cap, len; int bad; } gz_lobby_enc_t;
void gz_lobby_enc_start(gz_lobby_enc_t *e, uint8_t *buf, size_t cap, uint16_t kind,
                        const uint8_t scope[32]);
void gz_lobby_enc_record(gz_lobby_enc_t *e, uint64_t type, const uint8_t *v, size_t len);
void gz_lobby_enc_u8(gz_lobby_enc_t *e, uint64_t type, uint8_t v);
void gz_lobby_enc_u16(gz_lobby_enc_t *e, uint64_t type, uint16_t v);
void gz_lobby_enc_u32(gz_lobby_enc_t *e, uint64_t type, uint32_t v);
/* Sign what is there with key `which` and add record 240. Returns the length,
 * or 0 on overflow or a failed signature. */
size_t gz_lobby_enc_sign(gz_lobby_enc_t *e, const gz_lobby_crypto_t *c, uint32_t which);
size_t gz_lobby_enc_done(gz_lobby_enc_t *e);

/* binding = TH("gazpacho/bind", scope || factory_key || contribution_key). */
void gz_lobby_binding(const uint8_t scope[32], const uint8_t fkey[33], const uint8_t ckey[33],
                      uint8_t out[32]);

/* BOLT 1 `warning` (type 1, channel_id all zero) with a short ASCII text. */
size_t gz_lobby_warning(const char *text, uint8_t *out, size_t cap);

/* ---------------------------------------------------- splitting (part) */

/* Number of parts for a body, 0 if it must not be split (fits) or is too large. */
uint16_t gz_part_count(size_t body_len);
/* Build part `index` of (kind, scope, body) into `out`. Returns its length or 0. */
size_t gz_part_build(uint16_t kind, const uint8_t scope[32], const uint8_t *body, size_t body_len,
                     uint16_t index, uint8_t *out, size_t cap);

/* One reassembly per connection and direction, in a caller-provided buffer
 * of GZ_PART_MAX_BODY bytes. */
typedef struct {
    uint8_t *buf; size_t cap;
    int open;
    uint8_t transfer_id[32], scope[32];
    uint16_t inner_kind, count;
    uint32_t total_len;
    uint8_t have[(GZ_PART_MAX_BODY / GZ_PART_DATA) + 2];
} gz_part_reasm_t;
void gz_part_reasm_init(gz_part_reasm_t *r, uint8_t *buf, size_t cap);
/* Feed a decoded part. Returns 1 when complete (`*kind`, `scope`, `*body`,
 * `*body_len` give the whole message), 0 when more is needed or the part was
 * a duplicate, -1 to refuse. */
int gz_part_feed(gz_part_reasm_t *r, const gz_lobby_msg_t *m, uint16_t *kind, uint8_t scope[32],
                 const uint8_t **body, size_t *body_len);

/* ----------------------------------------------------- engine plumbing */

/* Lobby states (messages.md section 6). */
enum { GZ_LOBBY_UNKNOWN = 0, GZ_LOBBY_OPEN, GZ_LOBBY_READY_CHECK, GZ_LOBBY_SIGNING,
       GZ_LOBBY_FUNDING, GZ_LOBBY_ACTIVE, GZ_LOBBY_CANCELLED, GZ_LOBBY_FAILED };
/* Seat states. */
enum { GZ_SEAT_NONE = 0, GZ_SEAT_JOINED, GZ_SEAT_READY, GZ_SEAT_CHOSEN, GZ_SEAT_NOT_CHOSEN,
       GZ_SEAT_LEFT, GZ_SEAT_REMOVED, GZ_SEAT_REFUSED };

/* Journal record types (journal.md section 9). 0x00010018 is this engine's
 * addition. Layouts are in host.c and member.c and in docs/notes/lobby.md. */
#define GZ_REC_LOBBY_OPENED   0x00010002u
#define GZ_REC_SEAT           0x00010006u
#define GZ_REC_FREEZE         0x00010008u
#define GZ_REC_LOBBY_ENDED    0x0001000au
#define GZ_REC_TERMS_RECEIVED 0x0001000cu
#define GZ_REC_JOINED         0x0001000eu
#define GZ_REC_READY_SENT     0x00010010u
#define GZ_REC_HOST_FAULT     0x00010012u
#define GZ_REC_START_SENT     0x00010014u
#define GZ_REC_START_RECEIVED 0x00010016u
#define GZ_REC_TERMS_VERSION  0x00010004u   /* host: a new current version, before it is sent */
#define GZ_REC_LOBBY_STATE    0x00010018u   /* host: Open after a retry, Funding, Active (new; docs/notes/lobby.md) */

/* Notification codes (GZ_ACTION_NOTIFY). Bytes: see each. */
#define GZ_NOTE_CLOSE      0x4c01u   /* close the connection: u64 peer id */
#define GZ_NOTE_REFUSED    0x4c02u   /* member does not take part: u8 class, u8 term */
#define GZ_NOTE_UNREADY    0x4c03u   /* member unreadied: u8 class, u8 term */
#define GZ_NOTE_HOST_FAULT 0x4c04u   /* member saw a host fault and left: u8 fault */
#define GZ_NOTE_ENDED      0x4c05u   /* the lobby ended: u8 lobby state, u16 reason */
#define GZ_NOTE_SEAT       0x4c06u   /* member's seat state: u8 lobby state, u8 seat state */
#define GZ_NOTE_STARTED    0x4c07u   /* a start: u8 role, u16 signers */
/* Host: a member's key holds a seat (1) or no longer does (0): contribution
 * key (33), u8. Given after the seat's save, and again for every seat by
 * gz_lobby_host_resume. The program applies it with gz_peers_set_seated_key
 * (transport PR 23) until contract v2's SET_SEATED action (P4) replaces this
 * notice; the engine itself calls nothing outside the core. */
#define GZ_NOTE_SEATED     0x4c08u

/* Host faults a member records (journal.md host_fault). */
#define GZ_FAULT_TWO_VALUES   1      /* two current records under one version */
#define GZ_FAULT_AFTER_FREEZE 2      /* a new version, or a check at other values, after the freeze */

/* Timer identifiers used by the engines. */
#define GZ_LOBBY_TIMER_DEADLINE 0x4c000001u
#define GZ_LOBBY_TIMER_WINDOW   0x4c000002u
#define GZ_LOBBY_TIMER_STATUS   0x4c000003u
#define GZ_LOBBY_TIMER_RETRY    0x4c000004u   /* member: join again after a refusal for a limit */
#define GZ_LOBBY_TIMER_IDLE     0x4c000005u   /* host: close connections silent for 60 s */
#define GZ_LOBBY_IDLE_MS        60000u        /* neither hello nor join within this: closed */
#define GZ_LOBBY_MAX_LINKS      64            /* member keys whose hello limits are kept */

/* An input to an engine. The time is read from the clock port, whose epoch
 * must be the Unix epoch (deadlines are Unix seconds). */
enum { GZ_LIN_CONNECTED = 1, GZ_LIN_DISCONNECTED, GZ_LIN_MESSAGE, GZ_LIN_TIMER };
typedef struct {
    int kind;
    uint64_t peer_id;
    const uint8_t *peer_key;         /* CONNECTED: the peer's BOLT 8 static key, 33 bytes */
    const uint8_t *bytes; size_t len;/* MESSAGE */
    uint64_t timer_id;               /* TIMER */
} gz_lobby_input_t;

/* ------------------------------------------------ hand-off to signing */

typedef struct {
    uint8_t factory_key[33], contribution_key[33];
    uint8_t bind_by_factory[64], bind_by_contribution[64];
} gz_lobby_participant_t;

/* What the lobby gives the signing engine when it starts (signing-round.md
 * section 6 step 1, messages.md 6.9, terms.md 10). Pointers are valid only
 * during the call. */
typedef struct {
    int role;                                  /* 1 chosen to sign (host: always 1) */
    const uint8_t *scope;                      /* = outer digest, 32 */
    const uint8_t *outer, *current;            /* the frozen records */
    size_t outer_len, current_len;
    const uint8_t *current_digest;             /* frozen, 32 */
    uint32_t version;                          /* frozen */
    const uint8_t *check_id;                   /* the check this start follows, 32 */
    const gz_lterms_outer_t *terms;             /* decoded outer rules */
    uint16_t signers;                          /* participants, host included */
    /* Host: every participant, host first, then chosen seats in order of
     * joining. Member: NULL (they arrive in round_propose). */
    const gz_lobby_participant_t *participants;
    uint16_t n_participants;
    /* Build parameters (messages.md 7.2) fixed or derived from the terms. */
    uint8_t levels[8], n_levels, fixed_levels; /* shape for signers - 1 members; D */
    uint8_t k, tree_anchors;                   /* 1, 1 */
    uint16_t layer_step, layer_states;         /* 144, 4 */
    uint16_t min_members;                      /* member: its own condition */
    const uint8_t *start_bytes; size_t start_len; /* member: the signed start, if any */
} gz_lobby_handoff_t;

/* The signing engine's side. `begin` appends its own actions after the
 * lobby's (round_propose comes after every start). It must not keep the
 * pointers. Returns GZ_OK or an error; an error fails the lobby's step.
 *
 * `cancel` (may be NULL) is called when the lobby ends by a `cancel`
 * (messages.md 6.10): on the host after its cancel is saved and listed for
 * every seat, on the member after the received cancel is saved. `scope` is
 * the lobby, `reason` the cancel's reason (1 deadline below the minimum,
 * 2 host's choice, 3 signing failed). It is called for every cancel, also one
 * before any start: the signing engine ignores a lobby it never began. Per
 * messages.md 6.10 the member's engine erases secret nonces and keeps its
 * round records; a cancel does not undo partial signatures already sent. */
typedef struct {
    gz_status_t (*begin)(void *ctx, const gz_lobby_handoff_t *h, gz_action_list_t *out);
    gz_status_t (*cancel)(void *ctx, const uint8_t scope[32], uint16_t reason, gz_action_list_t *out);
    void *ctx;
} gz_lobby_signing_t;

/* --------------------------------------------------------------- host */

typedef struct {
    uint8_t ckey[33], fkey[33], bind_f[64], bind_c[64];
    uint8_t state;
    uint16_t min_members;
    uint32_t ready_version;
    uint64_t join_seq;
    uint64_t changes[10];            /* times of the last saved changes, ring */
    uint8_t n_changes, changes_at;
    int answered;                    /* answered the open check */
    int chosen;                      /* chosen in the start of the current check */
    uint8_t ready_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t ready_len;
    uint8_t start_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t start_len;
} gz_lobby_seat_t;

typedef struct {
    int used;
    uint64_t peer_id;
    uint8_t key[33];
    int joins;                       /* seats created on this connection */
    uint64_t connected_ms; int spoke; /* when it came up; it has sent hello or join */
    int warned;                      /* sent the wrong-protocol warning */
    uint64_t status_ms; int status_pending;
    uint8_t status_msg[GZ_LOBBY_STATUS_MAX]; size_t status_len;   /* the last status sent */
} gz_lobby_conn_t;

/* The hello limits of one member key, kept across its connections
 * (messages.md 6.1: per link, not per connection). */
typedef struct {
    int used, answered;
    uint8_t key[33];
    uint64_t hello_ms, window_ms;    /* last answer; start of the ignored count's window */
    uint32_t ignored;
} gz_lobby_link_t;

typedef struct {
    uint8_t factory_key[33];         /* the host's own factory key */
    uint16_t standbys;               /* seats beyond the target */
    int listed;                      /* named in answers to scope-zero hello */
    int network;                     /* GZ_LOBBY_NET_*; 0 is signet */
} gz_lobby_host_config_t;

typedef struct {
    gz_ports_t ports;
    gz_lobby_crypto_t crypto;
    gz_lobby_signing_t signing;
    gz_lobby_host_config_t cfg;
    gz_lobby_participant_t me;
    int state;
    uint8_t outer[GZ_TERMS_OUTER_MAX]; size_t outer_len; uint8_t outer_sig[64];
    uint8_t current[GZ_TERMS_CURRENT_MAX]; size_t current_len; uint8_t current_sig[64];
    gz_lterms_outer_t terms;
    gz_lterms_current_t values;
    uint8_t scope[32], current_digest[32];
    int frozen;
    uint8_t check_id[32]; int check_open;
    uint8_t check_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t check_len;
    uint64_t check_ends_ms;
    int rule_dirty;
    uint16_t n_seats; uint64_t next_seq, created, last_create_ms;
    gz_lobby_seat_t seats[GZ_LOBBY_MAX_SEATS];
    gz_lobby_conn_t conns[GZ_LOBBY_MAX_CONNS];
    gz_lobby_link_t links[GZ_LOBBY_MAX_LINKS];
    int idle_armed;                  /* the idle timer is set */
    uint64_t zero_hello_window; uint32_t zero_hello_count;
    uint16_t end_reason;
    uint8_t cancel_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t cancel_len;
} gz_lobby_host_t;

/* Prepare a host. `outer`/`current` are the records the program composed;
 * they are checked like a member checks them (the host key must be the one
 * the crypto port signs with, which the caller states as `host_key` inside
 * the outer record). Nothing is saved until gz_lobby_host_open. */
gz_status_t gz_lobby_host_init(gz_lobby_host_t *h, const gz_ports_t *ports,
                               const gz_lobby_crypto_t *crypto, const gz_lobby_signing_t *signing,
                               const gz_lobby_host_config_t *cfg);
/* Open a new lobby: sign both records, save `lobby_opened`, set the deadline
 * timer. GZ_ERR_ARGUMENT if either record is refused. */
gz_status_t gz_lobby_host_open(gz_lobby_host_t *h, const uint8_t *outer, size_t outer_len,
                               const uint8_t *current, size_t current_len, gz_action_list_t *out);
/* Rebuild from stored records, oldest first; then gz_lobby_host_resume. */
gz_status_t gz_lobby_host_restore(gz_lobby_host_t *h, const gz_record_t *rec);
gz_status_t gz_lobby_host_resume(gz_lobby_host_t *h, gz_action_list_t *out);
gz_status_t gz_lobby_host_handle(gz_lobby_host_t *h, const gz_lobby_input_t *in, gz_action_list_t *out);
/* Host commands. */
gz_status_t gz_lobby_host_set_values(gz_lobby_host_t *h, const uint64_t *values, uint8_t n,
                                     gz_action_list_t *out);
gz_status_t gz_lobby_host_remove(gz_lobby_host_t *h, const uint8_t ckey[33], gz_action_list_t *out);
gz_status_t gz_lobby_host_cancel(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out);
/* The signing engine's outcome. */
#define GZ_ROUND_FUNDING 1
#define GZ_ROUND_ACTIVE  2
#define GZ_ROUND_RETRY   3           /* members named failed; the rest go back to Ready */
#define GZ_ROUND_FAILED  4           /* the signing budget is spent: cancel reason 3 */
gz_status_t gz_lobby_host_round_result(gz_lobby_host_t *h, int outcome, const uint8_t *failed_ckeys,
                                       size_t n_failed, gz_action_list_t *out);

/* Exposed for the model test: the choice of signers (messages.md 6.9) and
 * the start rule. `chosen` receives indices into `mins`; returns the count,
 * or -1 if fewer than `minimum` remain. */
int gz_lobby_choose(uint16_t target, uint16_t minimum, const uint16_t *mins, int n, int *chosen);
#define GZ_RULE_WAIT   0
#define GZ_RULE_CHECK  1
#define GZ_RULE_CANCEL 2
int gz_lobby_start_rule(uint16_t target, uint16_t minimum, uint64_t deadline_s, uint64_t now_s,
                        uint32_t ready);

/* ------------------------------------------------------------- member */

typedef struct {
    gz_ports_t ports;
    gz_lobby_crypto_t crypto;
    gz_lobby_signing_t signing;
    gz_lobby_conditions_t cond;
    uint8_t scope[32], host_key[33], factory_key[33], ckey[33];
    int auto_join;
    int have_terms, joined, ready, ended, left, frozen;
    int lobby_state, seat_state;
    uint64_t host_peer; int connected;
    uint8_t outer[GZ_TERMS_OUTER_MAX]; size_t outer_len; uint8_t outer_sig[64];
    gz_lterms_outer_t terms;
    /* the latest valid current record seen (memory only until readied) */
    uint8_t current[GZ_TERMS_CURRENT_MAX]; size_t current_len; uint8_t current_sig[64];
    gz_lterms_current_t values; uint8_t current_digest[32];
    uint32_t saved_version;          /* newest version saved in terms_received */
    uint32_t frozen_version; uint8_t frozen_digest[32];
    uint8_t join_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t join_len;
    uint8_t ready_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t ready_len;
    uint32_t ready_version;
    uint8_t answered_check[32]; int has_answered;
    uint8_t pending_check[GZ_LOBBY_MAX_SAVED_MSG]; size_t pending_len;
    uint8_t start_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t start_len; int role;
    int last_class; uint8_t last_term;
    int user_unready;                /* the user unreadied: do not ready by itself */
    int network;                     /* GZ_LOBBY_NET_*; signet unless set */
    int stale_seat;                  /* restoring: the saved seat is of other keys (an older epoch) */
    int resends;                     /* join/ready resent on lobby_status, this connection */
    int retries;                     /* joins again after a refusal for a limit, this connection */
    int sent_here;                   /* join or ready already sent on this connection */
} gz_lobby_member_t;

/* `scope` is the lobby identifier from the invitation; `host_key` the pinned
 * key; `ckey` the per-lobby contribution key (= BOLT 8 key) and `factory_key`
 * the factory key, both of which the crypto port signs with. */
gz_status_t gz_lobby_member_init(gz_lobby_member_t *m, const gz_ports_t *ports,
                                 const gz_lobby_crypto_t *crypto, const gz_lobby_signing_t *signing,
                                 const gz_lobby_conditions_t *cond, const uint8_t scope[32],
                                 const uint8_t host_key[33], const uint8_t ckey[33],
                                 const uint8_t factory_key[33], int auto_join);
/* The member's network, GZ_LOBBY_NET_SIGNET (the default) or _TESTNET4: terms
 * for another chain are refused. GZ_ERR_ARGUMENT for another value. */
gz_status_t gz_lobby_member_set_network(gz_lobby_member_t *m, int network);
/* Records whose saved join names a factory key other than the member's own
 * belong to a seat of an older restore epoch (safety-rule.md C12): that seat
 * is not resumed, and the member joins again with its current keys. */
gz_status_t gz_lobby_member_restore(gz_lobby_member_t *m, const gz_record_t *rec);
gz_status_t gz_lobby_member_handle(gz_lobby_member_t *m, const gz_lobby_input_t *in,
                                   gz_action_list_t *out);
/* User commands: unready (reason 2), leave (reason 2), ready again. */
gz_status_t gz_lobby_member_unready(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_leave(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_set_conditions(gz_lobby_member_t *m, const gz_lobby_conditions_t *c,
                                           gz_action_list_t *out);

#endif
