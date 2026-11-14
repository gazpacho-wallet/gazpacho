/* The lobby engine: spec/messages.md sections 4 to 6 and 8, spec/terms.md,
 * the lobby side of spec/signing-round.md section 6 step 1.
 *
 * Sans-I/O like the node (node.h): inputs in, actions out, and every save is
 * listed before the sends it justifies, so the runner's rule (runner.h) gives
 * "save before send". The engine holds no secret key. It signs and verifies
 * through a crypto port (gz_lobby_crypto_t) that the program supplies, so the
 * library itself calls nothing outside the core.
 *
 * Bytes on the wire are whole Lightning messages: the 2-byte type 52791, then
 * the envelope of messages.md section 4.
 *
 * WHAT IT DOES
 *   - Strict encoding and decoding of the lobby messages (kinds 16 to 34) and
 *     of `part` (kind 2, section 5), with every bound of the specification.
 *   - The terms are core/tree's (gazpacho/terms.h): one decoder, one set of
 *     acceptance rules (gz_terms_receive with the Slice 1 policy), one
 *     comparison (gz_terms_classify). The lobby adds only the deciding term
 *     for its notices (gz_lobby_classify) and its SHA-256 is core/tree's.
 *   - The member: checks terms on receipt (terms.md 7), compares them with its
 *     conditions (terms.md 9), joins, readies and unreadies, answers ready
 *     checks, keeps evidence of a host fault and leaves, takes `start`.
 *   - The host: seats, the limits on seat changes, joins and connections, the
 *     start rule, the ready check and its freeze, the choice of signers,
 *     `start`, the signing budget, cancel, removal before the start, standby
 *     seats.
 *   - The hand-off to the signing engine (gazpacho/lobby_handoff.h).
 *
 * ERRORS. An engine call that returns anything but GZ_OK (an action list too
 * small, a signature the port would not make, a NULL argument) may already
 * have changed the engine's memory. Treat it like a refused list (runner.h):
 * stop the node and rebuild it from storage. A user command that is merely
 * too late or too early (unready when not ready, removal once Signing, new
 * values after the freeze) is not an error: it returns GZ_OK, changes
 * nothing and gives GZ_NOTE_COMMAND_REFUSED. Give the engines lists of at
 * least 256 slots and 512 KiB: a new current version is offered to every
 * seat, about 5.4 KB each.
 *
 * WHAT IT DOES NOT DO
 *   - Build the tree (fee per transaction, funding amount): that is core/tree.
 *     It takes the shape, the levels and D from gz_tree_params.
 *   - Discovery, invitations as messages, names, chat: none in Slice 1. */
#ifndef GAZPACHO_LOBBY_H
#define GAZPACHO_LOBBY_H

#include "gazpacho/action.h"
#include "gazpacho/ports.h"
#include "gazpacho/terms.h"
#include "gazpacho/lobby_handoff.h"

/* ---------------------------------------------------------------- limits */

#define GZ_LOBBY_MSG_TYPE      52791u   /* the Lightning message type, 0xce37 */
#define GZ_LOBBY_MAX_MSG       65535u   /* a whole Lightning message, type included */
#define GZ_LOBBY_MAX_RECORDS   65495u   /* records of one envelope */
#define GZ_LOBBY_MAX_SEATS     32       /* Slice 1 host: target + standbys */
#define GZ_LOBBY_MAX_CONNS     48
#define GZ_LOBBY_MAX_UNSEATED  16       /* connections whose key holds no seat */
#define GZ_LOBBY_MAX_SAVED_MSG 256      /* a saved ready, start, ready_check or cancel */
#define GZ_LOBBY_STATUS_MAX    64       /* a lobby_status: 40 + 3 + 3 + 6 + 4 + 4 + 4 */
#define GZ_PART_DATA           65000u
#define GZ_PART_MAX_BODY       1048576u

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

/* ---------------------------------------------------- terms (core/tree) */

/* The policy both sides apply: core/tree's Slice 1 column of terms.md 3
 * (signet, Standard, cancel on shortfall, switches 0, a fundable tree for
 * every member count). Networks are settled there, in gz_terms_policy_t. */
const gz_terms_policy_t *gz_lobby_policy(void);

/* A member's conditions (terms.md section 9). Kept on the device; only
 * `min_members` is ever sent, as the hint of `ready`.
 *   limits        core/tree's limits: what gz_terms_classify compares, and what
 *                 the signing engine checks the real tree against. Their
 *                 min_members is the fixed-term rule (the terms' `minimum` at
 *                 least this); 0 means no limit for a fixed term.
 *   current_only  the looser option: ready while the current values fit.
 *   min_members   the hint of `ready` (messages.md 6.4): the smallest number
 *                 of members this member signs with, host not counted; 0 none. */
typedef struct {
    gz_terms_limits_t limits;
    uint8_t current_only;
    uint16_t min_members;
} gz_lobby_conditions_t;

#define GZ_FIT_YES  1          /* fits: every fixed term and every whole range */
#define GZ_FIT_NOW  2          /* fits only now: a range does not, its value does */
#define GZ_FIT_NO   3          /* a fixed term or a current value does not fit */

/* gz_terms_classify, and in `*term` the type of the deciding term (0 for
 * GZ_FIT_YES): the smallest type whose limit alone gives that class (8
 * profile, 12 minimum, 26 lifetime, 30 channel, 32 fee rate, then the
 * adjustable types). Every comparison is core/tree's. */
int gz_lobby_classify(const gz_terms_outer_t *o, const gz_terms_current_t *c,
                      const gz_lobby_conditions_t *cond, uint8_t *term);
/* 1 if a member with these conditions may be ready at these values. */
int gz_lobby_ready_ok(int cls, const gz_lobby_conditions_t *cond);

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
#define GZ_REC_LOBBY_STATE    0x00010018u   /* the signing outcome: host and member (new; docs/notes/lobby.md) */

/* Notification codes (GZ_ACTION_NOTIFY). Bytes: see each. */
#define GZ_NOTE_CLOSE      0x4c01u   /* close the connection: u64 peer id */
#define GZ_NOTE_REFUSED    0x4c02u   /* member does not ready: u8 class, u8 term */
#define GZ_NOTE_UNREADY    0x4c03u   /* member unreadied: u8 class, u8 term */
#define GZ_NOTE_HOST_FAULT 0x4c04u   /* member saw a host fault and left: u8 fault */
#define GZ_NOTE_ENDED      0x4c05u   /* the lobby ended: u8 lobby state, u16 reason */
#define GZ_NOTE_SEAT       0x4c06u   /* member's seat state: u8 lobby state, u8 seat state */
#define GZ_NOTE_STARTED    0x4c07u   /* a start: u8 role, u16 signers */
/* Host: a member's key holds a seat (1) or no longer does (0): contribution
 * key (33), u8. Given after the seat's save, and again for every seat by
 * gz_lobby_host_resume. A chosen seat that leaves while Signing stays seated
 * until the round is resolved. The program applies it with
 * gz_peers_set_seated_key (transport PR 23) until contract v2's SET_SEATED
 * action (P4) replaces this notice; the engine itself calls nothing outside
 * the core. */
#define GZ_NOTE_SEATED     0x4c08u
/* A user command refused now, with nothing changed: u8 command (GZ_CMD_*),
 * u8 the lobby state as this side knows it. Not an error (see ERRORS). */
#define GZ_NOTE_COMMAND_REFUSED 0x4c09u
#define GZ_CMD_SET_VALUES   1
#define GZ_CMD_REMOVE       2
#define GZ_CMD_CANCEL       3
#define GZ_CMD_ROUND_RESULT 4
#define GZ_CMD_UNREADY      5
#define GZ_CMD_LEAVE        6

/* Host faults a member records (journal.md host_fault). */
#define GZ_FAULT_TWO_VALUES   1      /* two current records under one version */
#define GZ_FAULT_AFTER_FREEZE 2      /* a new version, or a check at other values, after the freeze */

/* Timer identifiers used by the engines. */
#define GZ_LOBBY_TIMER_DEADLINE 0x4c000001u
#define GZ_LOBBY_TIMER_WINDOW   0x4c000002u
#define GZ_LOBBY_TIMER_STATUS   0x4c000003u
#define GZ_LOBBY_TIMER_RETRY    0x4c000004u   /* member: join again after a refusal for a limit */
#define GZ_LOBBY_TIMER_IDLE     0x4c000005u   /* host: close idle and unseated connections */
#define GZ_LOBBY_TIMER_BUDGET   0x4c000006u   /* host: the signing budget (terms.md 3) is spent, before a hand-off */
#define GZ_LOBBY_IDLE_MS        60000u        /* neither hello nor join within this: closed */
#define GZ_LOBBY_UNSEATED_MS    600000u       /* no seat within this of connecting: closed */
#define GZ_LOBBY_MAX_LINKS      64            /* member keys whose hello limits are kept */
#define GZ_LOBBY_BAD_JOINS      3             /* joins refused as invalid on one connection: closed */
#define GZ_LOBBY_REFUSED_JOINS  32            /* joins refused for a limit on one connection: closed */

/* A SEND from the lobby, until P4.2 puts it on links (docs/notes/lobby.md,
 * decision 23). The lobby still names a peer by the number the program gave
 * it and sends whole Lightning messages. In contract v2's SEND (action.h)
 * that is: kind GZ_LOBBY_SEND_WHOLE, scope zero, the whole message in
 * `records`, and the peer's number in bytes 1 to 8 of the link's remote key,
 * big-endian (byte 0 is zero, so it is no public key). No program carries
 * these out yet. gz_lobby_sent_peer reads the number back. */
#define GZ_LOBBY_SEND_WHOLE 0xffffu
uint64_t gz_lobby_sent_peer(const gz_action_t *send);

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
    int bad_joins, refused_joins;    /* joins refused as invalid, and for a limit */
    uint64_t connected_ms; int spoke; /* when it came up; it has sent hello or join */
    uint64_t seq;                    /* order of coming up: the oldest is pushed out first */
    int closed;                      /* the engine asked for it to be closed */
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
    gz_terms_outer_t terms;
    gz_terms_current_t values;
    uint8_t scope[32], current_digest[32];
    int frozen;
    uint8_t check_id[32]; int check_open;
    uint8_t check_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t check_len;
    int rule_dirty;
    /* Seat events, and their count when the last check began: after a check
     * that ended without a start, the next needs a seat event since (decision
     * 8), so that nothing loops. */
    uint64_t seat_epoch, failed_epoch; int check_failed;
    uint16_t n_seats; uint64_t next_seq, created;
    uint64_t create_credit_ms, credit_at_ms;   /* creations: a bucket of `target`, one a second */
    gz_lobby_seat_t seats[GZ_LOBBY_MAX_SEATS];
    gz_lobby_conn_t conns[GZ_LOBBY_MAX_CONNS];
    gz_lobby_link_t links[GZ_LOBBY_MAX_LINKS];
    int idle_armed;                  /* the idle timer is set */
    uint64_t conn_seq;
    uint64_t budget_ms;              /* Unix ms the signing budget began (the first start); 0 none */
    uint64_t zero_hello_window; uint32_t zero_hello_count;
    uint16_t end_reason;
    uint8_t cancel_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t cancel_len;
} gz_lobby_host_t;

/* Prepare a host. Nothing is saved until gz_lobby_host_open. */
gz_status_t gz_lobby_host_init(gz_lobby_host_t *h, const gz_ports_t *ports,
                               const gz_lobby_crypto_t *crypto, const gz_lobby_signing_t *signing,
                               const gz_lobby_host_config_t *cfg);
/* Open a new lobby: `outer`/`current` are the records the program composed;
 * they are checked like a member checks them (core/tree's policy; the host
 * key must be the one the crypto port signs with), signed, saved as
 * `lobby_opened`, and the deadline timer is set. GZ_ERR_ARGUMENT if refused. */
gz_status_t gz_lobby_host_open(gz_lobby_host_t *h, const uint8_t *outer, size_t outer_len,
                               const uint8_t *current, size_t current_len, gz_action_list_t *out);
/* Rebuild from stored records, oldest first; then gz_lobby_host_resume, which
 * re-announces the seats, sets the timers again and, in Signing, hands the
 * saved start to the signing engine again (resume = 1). */
gz_status_t gz_lobby_host_restore(gz_lobby_host_t *h, const gz_record_t *rec);
gz_status_t gz_lobby_host_resume(gz_lobby_host_t *h, gz_action_list_t *out);
gz_status_t gz_lobby_host_handle(gz_lobby_host_t *h, const gz_lobby_input_t *in, gz_action_list_t *out);
/* Host commands. A command refused now gives GZ_NOTE_COMMAND_REFUSED. */
gz_status_t gz_lobby_host_set_values(gz_lobby_host_t *h, const uint64_t *values, uint8_t n,
                                     gz_action_list_t *out);
gz_status_t gz_lobby_host_remove(gz_lobby_host_t *h, const uint8_t ckey[33], gz_action_list_t *out);
gz_status_t gz_lobby_host_cancel(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out);
/* The signing engine's outcome (GZ_LOBBY_ROUND_*, lobby_handoff.h), saved
 * (lobby_state) before anything shows it. For GZ_LOBBY_ROUND_RETRY,
 * `failed_ckeys` lists the failed seats' contribution keys, 33 bytes each;
 * Retry and Failed are taken only while Signing (Failed also in Funding).
 * Funding and Active are always taken once a round was handed over, also
 * after the lobby ended by a cancel (lobby_handoff.h, the signing budget). */
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
    gz_terms_outer_t terms;
    /* the latest valid current record seen (memory only until readied) */
    uint8_t current[GZ_TERMS_CURRENT_MAX]; size_t current_len; uint8_t current_sig[64];
    gz_terms_current_t values; uint8_t current_digest[32];
    uint32_t saved_version;          /* newest version saved in terms_received */
    uint32_t frozen_version; uint8_t frozen_digest[32];
    uint8_t join_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t join_len;
    uint8_t ready_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t ready_len;
    uint32_t ready_version;
    uint8_t answered_check[32]; int has_answered;   /* the check its saved ready answers */
    uint8_t withdrawn_check[32]; int has_withdrawn; /* a check it answered, then unreadied */
    uint8_t pending_check[GZ_LOBBY_MAX_SAVED_MSG]; size_t pending_len;
    uint8_t start_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t start_len; int role;
    int last_class; uint8_t last_term;
    int user_unready;                /* the user unreadied: do not ready by itself */
    uint16_t unready_reason, leave_reason;   /* of the saved unready and leave, for resends */
    int stale_seat;                  /* restoring: the saved seat is of other keys (an older epoch) */
    int round_state;                 /* the saved signing outcome: 0, or GZ_LOBBY_FUNDING or _ACTIVE */
    int resends;                     /* state messages resent on lobby_status, this connection */
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
/* Records whose saved join names a factory key other than the member's own
 * belong to a seat of an older restore epoch (safety-rule.md C12): that seat
 * is not resumed, and the member joins again with its current keys. After
 * the records, gz_lobby_member_resume: a saved start with role 1 for a check
 * the member is still ready for is handed to the signing engine again
 * (resume = 1), so a restart between `start` and `round_propose` costs
 * nothing (messages.md 6.9). */
gz_status_t gz_lobby_member_restore(gz_lobby_member_t *m, const gz_record_t *rec);
gz_status_t gz_lobby_member_resume(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_handle(gz_lobby_member_t *m, const gz_lobby_input_t *in,
                                   gz_action_list_t *out);
/* User commands: unready (reason 2), leave (reason 2), new conditions. */
gz_status_t gz_lobby_member_unready(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_leave(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_set_conditions(gz_lobby_member_t *m, const gz_lobby_conditions_t *c,
                                           gz_action_list_t *out);
/* 1 if the member may sign for this check: it answered it and is still ready
 * for the frozen values (not unreadied since). The signing engine asks before
 * it takes a round_propose, also one that comes without a `start`
 * (messages.md 7.2), and answers with round_abort when it may not. */
int gz_lobby_member_may_sign(const gz_lobby_member_t *m, const uint8_t check_id[32]);
/* The signing engine's outcome for this member (GZ_LOBBY_ROUND_*), saved
 * (lobby_state) so that gz_lobby_member_resume never hands a finished check
 * over again: Funding and Active are shown (GZ_NOTE_SEAT), also after a
 * cancel; Retry spends the start so that the next check's start is taken;
 * Failed waits for the host's cancel. `check_id` is the check of the round
 * that ended (the hand-off's check_id), required for GZ_LOBBY_ROUND_RETRY and
 * not read otherwise: a Retry acts only if it names the check of the start
 * the member holds; a Retry for another (older) check is ignored. */
gz_status_t gz_lobby_member_round_result(gz_lobby_member_t *m, int outcome, const uint8_t *check_id,
                                         gz_action_list_t *out);

#endif
