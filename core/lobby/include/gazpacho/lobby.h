/* The lobby engine: spec/messages.md sections 4 to 6 and 8, spec/terms.md,
 * the lobby side of spec/signing-round.md section 6 step 1.
 *
 * Sans-I/O like the node (node.h): inputs in, actions out, and every save is
 * listed before the sends it justifies, so the runner's rule (runner.h) gives
 * "save before send". The engine holds no secret key. It signs and verifies
 * through a crypto port (gz_lobby_crypto_t) that the program supplies, so the
 * library itself calls nothing outside the core.
 *
 * Contract v2 (docs/notes/composite-node.md): a message is (kind, scope,
 * records) on a link, and a link is derived from keys the engine holds: the
 * host speaks to a seat on (host key, the seat's contribution key), a member
 * to its host on (its contribution key, the pinned host key). The engine
 * emits SEND, CONNECT, DISCONNECT and SET_SEATED itself. A refusal is a
 * DISCONNECT with `why` GZ_DISCONNECT_REFUSED, never a SEND: the transport
 * sends the warning. A message the engine SAVES is kept as an envelope
 * (envelope.h: tag, kind, scope, records), so a resend is byte for byte.
 *
 * WHAT IT DOES
 *   - Strict encoding and decoding of the lobby messages (kinds 16 to 34),
 *     with every bound of the specification. Splitting (`part`, kind 2) is
 *     the transport's.
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
 * ERRORS (the engine rule, composite-node.md 8.1). An engine call returns
 * an error only for a bug: an action list too small, a NULL argument, a
 * value outside its range. Nothing a peer, the key port or a user command
 * can cause is an error: a bad message is a DISCONNECT `refused` or a
 * counted drop, a signature the port would not make gives GZ_NOTE_NO_KEY
 * and nothing else, and a user command that is too late or too early
 * (unready when not ready, removal once Signing, new values after the
 * freeze) returns GZ_OK, changes nothing and gives GZ_NOTE_COMMAND_REFUSED.
 * An error may already have changed the engine's memory: the node is
 * poisoned and rebuilt from storage. Two calls validate what a person
 * composed, gz_lobby_host_open and gz_lobby_host_set_values: they return
 * GZ_ERR_ARGUMENT with nothing appended and nothing changed, which their
 * caller answers as a refused command. Give the engines lists of at least
 * 256 slots and 512 KiB: a new current version is offered to every seat,
 * about 5.4 KB each.
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

#define GZ_LOBBY_ENV_HDR       38u      /* an envelope's header: tag 4, kind 2, scope 32 */
#define GZ_LOBBY_MAX_RECORDS   65495u   /* records of one envelope */
#define GZ_LOBBY_MAX_ENV       (GZ_LOBBY_ENV_HDR + GZ_LOBBY_MAX_RECORDS)
#define GZ_LOBBY_MAX_SEATS     32       /* Slice 1 host: target + standbys */
/* The host's connections: the one table size the node part, the program's
 * adapter and the transport share (GZ_NODE_MAX_CONNS, node.h; core/node
 * asserts they are equal). Which connection without a seat is pushed out or
 * closed as idle is the node part's rule (composite-node.md section 3); the
 * lobby sees only connections bound to it. */
#define GZ_LOBBY_MAX_CONNS     64
#define GZ_LOBBY_MAX_SAVED_MSG 256      /* a saved ready, start, ready_check or cancel, as an envelope */
#define GZ_LOBBY_STATUS_MAX    64       /* a lobby_status envelope: 38 + 3 + 3 + 6 + 4 + 4 + 4 */
#define GZ_LOBBY_MAX_ADDRESS   64       /* a host address, "host:port" (GZ_CONNECT_MAX_ADDRESS) */

/* THE LARGEST RECORD OF EACH TYPE. One table: every buffer a record is built
 * in, and every reader's bound, comes from these, with static assertions in
 * act.c, so that a record the engine can save is never one its reader (the
 * engine's own restore, the node part, the journal) refuses. A field of n
 * bytes costs at most n + 4 with its type and length. */
#define GZ_LOBBY_FIELD(n)             ((n) + 4u)
#define GZ_LOBBY_REC_SCOPE            GZ_LOBBY_FIELD(32u)
#define GZ_LOBBY_REC_MAX_OPENED       (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(GZ_TERMS_OUTER_MAX) + GZ_LOBBY_FIELD(64u) + \
                                       GZ_LOBBY_FIELD(GZ_TERMS_CURRENT_MAX) + GZ_LOBBY_FIELD(64u))
#define GZ_LOBBY_REC_MAX_VERSION      (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(GZ_TERMS_CURRENT_MAX) + GZ_LOBBY_FIELD(64u))
#define GZ_LOBBY_REC_MAX_SEAT         (GZ_LOBBY_REC_SCOPE + 2u * GZ_LOBBY_FIELD(33u) + 2u * GZ_LOBBY_FIELD(64u) + \
                                       GZ_LOBBY_FIELD(1u) + GZ_LOBBY_FIELD(2u) + GZ_LOBBY_FIELD(4u) + \
                                       GZ_LOBBY_FIELD(8u) + GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG))
#define GZ_LOBBY_REC_MAX_FREEZE       (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(32u) + GZ_LOBBY_FIELD(4u) + \
                                       GZ_LOBBY_FIELD(32u) + GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG))
#define GZ_LOBBY_REC_MAX_ENDED        (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(1u) + GZ_LOBBY_FIELD(2u) + \
                                       GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG) + GZ_LOBBY_FIELD(1u))
#define GZ_LOBBY_REC_MAX_TERMS        GZ_LOBBY_REC_MAX_OPENED
#define GZ_LOBBY_REC_MAX_JOINED       (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG))
#define GZ_LOBBY_REC_MAX_READY_SENT   (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG))
#define GZ_LOBBY_EVIDENCE_MAX         (GZ_TERMS_CURRENT_MAX + 64u)
#define GZ_LOBBY_REC_MAX_HOST_FAULT   (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(1u) + 2u * GZ_LOBBY_FIELD(GZ_LOBBY_EVIDENCE_MAX))
#define GZ_LOBBY_START_ITEM           (33u + 2u + GZ_LOBBY_MAX_SAVED_MSG)
#define GZ_LOBBY_REC_MAX_START_SENT   (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(32u) + GZ_LOBBY_FIELD(8u) + \
                                       GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SEATS * GZ_LOBBY_START_ITEM))
#define GZ_LOBBY_REC_MAX_START_RECEIVED (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(GZ_LOBBY_MAX_SAVED_MSG))
#define GZ_LOBBY_REC_MAX_STATE        (GZ_LOBBY_REC_SCOPE + GZ_LOBBY_FIELD(1u) + GZ_LOBBY_FIELD(32u))
#define GZ_LOBBY_REC_MAX              GZ_LOBBY_REC_MAX_START_SENT   /* the largest of all (asserted) */
/* The table itself, for readers and tests: `*n` rows of (type, largest size). */
typedef struct { uint32_t type; uint32_t max; const char *name; } gz_lobby_rec_max_t;
const gz_lobby_rec_max_t *gz_lobby_rec_table(size_t *n);
/* The largest size of a record type; 0 for a type that is not the lobby's. */
uint32_t gz_lobby_rec_max(uint32_t type);
/* The scope a Lobby record carries as its first field (composite-node.md
 * 7.3): 1 and `scope` set, or 0 if the record is no well-formed Lobby record. */
int gz_lobby_rec_scope(const gz_record_t *rec, uint8_t scope[32]);

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
    GZ_KIND_HELLO = 16, GZ_KIND_TERMS_OFFER = 18, GZ_KIND_JOIN = 20,
    GZ_KIND_READY = 22, GZ_KIND_UNREADY = 24, GZ_KIND_LEAVE = 26, GZ_KIND_LOBBY_STATUS = 28,
    GZ_KIND_READY_CHECK = 30, GZ_KIND_START = 32, GZ_KIND_CANCEL = 34
};

/* What the decoder makes of a message. */
#define GZ_DEC_OK      0       /* a lobby message, fully checked */
#define GZ_DEC_OTHER   1       /* a known kind of another engine (64 to 81): not decoded here */
#define GZ_DEC_IGNORE  2       /* an unknown odd kind, or discovery */
#define GZ_DEC_BADTAG  3       /* a saved envelope that does not start with the protocol tag */
#define GZ_DEC_REFUSE  4       /* refuse: DISCONNECT `refused` */

/* Every field of every lobby message; which are set depends on `kind` and
 * the `has_*` flags. Pointers point into the decoded bytes. */
typedef struct {
    uint16_t kind;
    uint8_t scope[32];
    const uint8_t *records;          /* the TLV stream decoded */
    size_t records_len;
    size_t signed_len;               /* records covered by msg_hash: those before record 240 */
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
} gz_lobby_msg_t;

/* Decode one message (kind, scope, records). Returns a GZ_DEC_* code; `m` is
 * filled only for GZ_DEC_OK, and points into `records`. Checks the records
 * of messages.md 4.2 and each kind's table, but not signatures or direction
 * (the engines do). */
int gz_lobby_decode(uint16_t kind, const uint8_t scope[32], const uint8_t *records, size_t len,
                    gz_lobby_msg_t *m);
/* The same for a saved envelope (tag, kind, scope, records). */
int gz_lobby_decode_env(const uint8_t *env, size_t len, gz_lobby_msg_t *m);

/* msg_hash = TH("gazpacho/msg", 67 7a 66 01 || kind || scope || the records
 * before record 240) (messages.md 4.3; contract v2 section 7). */
void gz_lobby_msg_hash(const gz_lobby_msg_t *m, uint8_t out[32]);

/* A message being built, as an envelope (tag, kind, scope, records).
 * Records must be added in increasing type order. */
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

/* The node part's answers for lobbies it holds no engine for
 * (composite-node.md sections 2.4 and 4), appended as SENDs on `link`:
 *   gz_lobby_host_unknown  `lobby_status` with lobby state 0 alone, for a
 *                          `hello` naming a scope this host does not know;
 *   gz_lobby_host_ended    for a late `hello` to an ended lobby (a tombstone
 *                          or the index of ended lobbies): `lobby_status`
 *                          with the final state and the reason, then the
 *                          saved signed `cancel` envelope if there is one
 *                          (`cancel` NULL or `cancel_len` 0: none). */
gz_status_t gz_lobby_host_unknown(const gz_link_t *link, const uint8_t scope[32], gz_action_list_t *out);
gz_status_t gz_lobby_host_ended(const gz_link_t *link, const uint8_t scope[32], uint8_t final_state,
                                uint16_t reason, const uint8_t *cancel, size_t cancel_len,
                                gz_action_list_t *out);
/* What a `lobby_ended` record holds, for the node part's tombstones: 1 and
 * the fields set (`*cancel` points into the record; `*cancel_len` 0 if it
 * holds none), or 0 if the record is malformed. */
int gz_lobby_rec_ended(const gz_record_t *rec, uint8_t scope[32], uint8_t *state, uint16_t *reason,
                       const uint8_t **cancel, size_t *cancel_len);

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

/* Notification codes (GZ_ACTION_NOTIFY). Bytes: see each. 0x4c01 (close)
 * and 0x4c08 (seated) are gone: DISCONNECT and SET_SEATED replace them. */
#define GZ_NOTE_REFUSED    0x4c02u   /* member does not ready: u8 class, u8 term */
#define GZ_NOTE_UNREADY    0x4c03u   /* member unreadied: u8 class, u8 term */
#define GZ_NOTE_HOST_FAULT 0x4c04u   /* member saw a host fault and left: u8 fault */
#define GZ_NOTE_ENDED      0x4c05u   /* the lobby ended: u8 lobby state, u16 reason */
#define GZ_NOTE_SEAT       0x4c06u   /* member's seat state: u8 lobby state, u8 seat state */
#define GZ_NOTE_STARTED    0x4c07u   /* a start: u8 role, u16 signers */
/* SEATS. The host emits SET_SEATED for a member's key after the seat's save,
 * and again for every seat in gz_lobby_host_resume, before any member
 * reconnects. A chosen seat that leaves while Signing stays seated until the
 * round is resolved. */
/* A user command refused now, with nothing changed: u8 command (GZ_CMD_*),
 * u8 the lobby state as this side knows it. Not an error (see ERRORS). */
#define GZ_NOTE_COMMAND_REFUSED 0x4c09u
/* The crypto port would not sign (a key the key port does not hold): u8 the
 * key (GZ_LOBBY_KEY_*). What needed the signature did not happen; nothing
 * was saved or sent for it. Never an error (the engine rule). */
#define GZ_NOTE_NO_KEY     0x4c0au
/* Member: its signing gate is closed (composite-node.md 12.2), so it is not
 * ready: "unlock to take part". No bytes. Given once per closing. */
#define GZ_NOTE_LOCKED     0x4c0bu
#define GZ_CMD_SET_VALUES   1
#define GZ_CMD_REMOVE       2
#define GZ_CMD_CANCEL       3
#define GZ_CMD_ROUND_RESULT 4
#define GZ_CMD_UNREADY      5
#define GZ_CMD_LEAVE        6
#define GZ_CMD_READY        7
#define GZ_CMD_START        8   /* host: the person's early start */
#define GZ_CMD_CONDITIONS   9   /* member: the person's conditions changed (the copying rule) */

/* Host faults a member records (journal.md host_fault). */
#define GZ_FAULT_TWO_VALUES   1      /* two current records under one version */
#define GZ_FAULT_AFTER_FREEZE 2      /* a new version, or a check at other values, after the freeze */

/* Timer identifiers used by the engines. */
#define GZ_LOBBY_TIMER_DEADLINE 0x4c000001u
#define GZ_LOBBY_TIMER_WINDOW   0x4c000002u
#define GZ_LOBBY_TIMER_STATUS   0x4c000003u
#define GZ_LOBBY_TIMER_RETRY    0x4c000004u   /* member: join again after a refusal for a limit, or
                                                 * hello again when a hello got no answer */
/* A member asks again when its hello got no answer on that connection: the
 * host answers one hello a second per member key, across its connections
 * (messages.md 6.1), so a reconnect within that second gets none. */
#define GZ_LOBBY_HELLO_AGAIN_MS  1500
#define GZ_LOBBY_HELLO_AGAIN_MAX 5
/* 0x4c000005 was the host's idle timer: idle and unseated connections are
 * the node part's now (composite-node.md section 3). Not reused. */
#define GZ_LOBBY_TIMER_BUDGET   0x4c000006u   /* host: the signing budget (terms.md 3) is spent, with no round in flight */
#define GZ_LOBBY_MAX_TIMERS     6             /* the ids above: a slot's timer budget (composite-node.md 7.1) */
#define GZ_LOBBY_MAX_LINKS      64            /* member keys whose hello limits are kept */
#define GZ_LOBBY_BAD_JOINS      3             /* joins refused as invalid on one connection: closed */
#define GZ_LOBBY_REFUSED_JOINS  32            /* joins refused for a limit on one connection: closed */

/* An input to an engine. The time is read from the clock port, whose epoch
 * must be the Unix epoch (deadlines are Unix seconds). `link` is the link
 * the event came on (local: our key, remote: the peer's BOLT 8 static key). */
enum { GZ_LIN_CONNECTED = 1, GZ_LIN_DISCONNECTED, GZ_LIN_MESSAGE, GZ_LIN_TIMER };
typedef struct {
    int kind;
    gz_link_t link;                  /* CONNECTED, DISCONNECTED, MESSAGE */
    uint16_t msg_kind;               /* MESSAGE: the kind, */
    const uint8_t *scope;            /*   the scope (32), */
    const uint8_t *records; size_t len; /* and the records */
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
    /* The seat said `unready` reason 3 (its signing gate is closed). Its next
     * `ready` is not counted against the change limit, once per check window
     * (`free_window` is the window that used it, plus one). Memory only. */
    int locked;
    uint64_t free_window;
    uint8_t ready_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t ready_len;
    uint8_t start_msg[GZ_LOBBY_MAX_SAVED_MSG]; size_t start_len;
    /* The member refused (an unready or leave with reason 1, its own
     * conditions): the reason, and the stage (1 Open, 2 a ready check, 3 Signing), until
     * it readies or joins again (local-api.md 15.3). Memory only. */
    /* (and until the lobby's next ready check: decision K21) */
    uint16_t refused;
    uint8_t refused_stage;
} gz_lobby_seat_t;

typedef struct {
    int used;
    gz_link_t link;                  /* (host key, the member's key) */
    uint8_t key[33];                 /* = link.remote */
    int joins;                       /* seats created on this connection */
    int bad_joins, refused_joins;    /* joins refused as invalid, and for a limit */
    int closed;                      /* the engine asked for it to be closed */
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
    /* Room for a seat for `key` beyond the lobby's own limits: the node's
     * connection table, which all its lobbies share. NULL: no such limit.
     * A join that finds no room is refused like one to a full lobby. */
    int (*seat_room)(void *ctx, const uint8_t key[33]);
    /* 1 while the person's pause is on (local-api.md 11.3): no ready check
     * by the start rule; at the deadline the lobby is cancelled, reason 2.
     * NULL: never paused. Called with seat_ctx. */
    int (*paused)(void *ctx);
    /* 1 if the host's wallet can fund this lobby now (local-api.md 15.2): asked
     * before the start rule's ready check, the automatic start. 0: no check;
     * before the deadline the lobby stays Open and is asked again at its next
     * seat event, or when its node asks the rule again (a tip); at or after
     * it the lobby is cancelled, reason 5, the host could not fund it by the
     * deadline (review B of #55, M-2; messages.md 6.10). NULL: always. With seat_ctx. */
    int (*funds_ok)(void *ctx);
    /* The rule applied and asked for no start (paused, or not CHECK): nothing
     * waits for funds now. NULL: not told. With seat_ctx. */
    void (*funds_idle)(void *ctx);
    void *seat_ctx;
    /* The most tree transactions its signer signs (0: no limit): terms whose target needs more do not
     * open (terms.md 7, gz_terms_policy_t.max_tree_nodes). */
    uint32_t max_tree_nodes;
} gz_lobby_host_config_t;

typedef struct {
    gz_ports_t ports;
    gz_lobby_crypto_t crypto;
    gz_lobby_signing_t signing;
    gz_lobby_host_config_t cfg;
    gz_lobby_participant_t me;
    int bound;                       /* `me` holds the host's own signed binding */
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
    /* Members blamed by a failed attempt (a refusal, silence, an abort), by contribution key, whatever
     * they send or however they leave and join again: left out of the next check that starts, then
     * free again, so a member one block behind once is not locked out (review A of PR 52, M1). */
    struct { uint8_t key[33]; uint8_t left; } skip[GZ_LOBBY_MAX_SEATS];
    uint16_t n_seats; uint64_t next_seq, created;
    uint64_t create_credit_ms, credit_at_ms;   /* creations: a bucket of `target`, one a second */
    gz_lobby_seat_t seats[GZ_LOBBY_MAX_SEATS];
    gz_lobby_conn_t conns[GZ_LOBBY_MAX_CONNS];
    gz_lobby_link_t links[GZ_LOBBY_MAX_LINKS];
    uint64_t window_no;              /* ready checks begun: names a check window */
    int started;                     /* a start was ever sent (round kinds may pass) */
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
 * `lobby_opened`, and the deadline timer is set. GZ_ERR_ARGUMENT if refused:
 * nothing was appended, and the engine is as gz_lobby_host_init left it. */
gz_status_t gz_lobby_host_open(gz_lobby_host_t *h, const uint8_t *outer, size_t outer_len,
                               const uint8_t *current, size_t current_len, gz_action_list_t *out);
/* Rebuild from stored records, oldest first; then gz_lobby_host_resume, which
 * re-announces the seats, sets the timers again and, in Signing, hands the
 * saved start to the signing engine again (resume = 1). */
gz_status_t gz_lobby_host_restore(gz_lobby_host_t *h, const gz_record_t *rec);
gz_status_t gz_lobby_host_resume(gz_lobby_host_t *h, gz_action_list_t *out);
gz_status_t gz_lobby_host_handle(gz_lobby_host_t *h, const gz_lobby_input_t *in, gz_action_list_t *out);
/* A scope-zero `hello` on `link` (messages.md 6.1), which the node part
 * gives to each listed lobby in turn: a listed, open lobby answers with its
 * `terms_offer`, at most 4 times a second across all links. The link need
 * not be one of the lobby's connections. */
gz_status_t gz_lobby_host_listing(gz_lobby_host_t *h, const gz_link_t *link, gz_action_list_t *out);
/* 1 once the lobby has sent a `start`: round kinds under its scope may reach
 * the signing engine (composite-node.md section 4). */
int gz_lobby_host_round_ok(const gz_lobby_host_t *h);
/* The pause changed (cfg.paused): the start rule is applied again. */
gz_status_t gz_lobby_host_pause_changed(gz_lobby_host_t *h, gz_action_list_t *out);
/* 1 if the start rule asks for a ready check now: Open, not paused, and the
 * rule's CHECK at this time and these seats. A query; it changes nothing. The
 * rule itself is applied only at some seat events (a leave does not apply
 * it), so the node asks this to end a wait for funds that no start needs. */
int gz_lobby_host_start_due(const gz_lobby_host_t *h);
/* Host commands. A command refused now gives GZ_NOTE_COMMAND_REFUSED.
 * gz_lobby_host_set_values returns GZ_ERR_ARGUMENT, with nothing appended
 * or changed, for values outside the terms' ranges. */
gz_status_t gz_lobby_host_set_values(gz_lobby_host_t *h, const uint64_t *values, uint8_t n,
                                     gz_action_list_t *out);
gz_status_t gz_lobby_host_remove(gz_lobby_host_t *h, const uint8_t ckey[33], gz_action_list_t *out);
gz_status_t gz_lobby_host_cancel(gz_lobby_host_t *h, uint16_t reason, gz_action_list_t *out);
/* The person's early start (local-api.md 15.2, "start now"): the ready check
 * begins now, before the start rule would begin it, exactly as the rule
 * begins it (the freeze saved before the first check). Only while Open, not
 * paused (cfg.paused), with at least the terms' minimum counted as the
 * start rule counts them (gz_lobby_host_ready_count), and, as for the rule,
 * not again after a check that ended without a start until a seat event
 * (the failed-check guard, decision 8). Otherwise
 * GZ_NOTE_COMMAND_REFUSED (GZ_CMD_START) and nothing else. A check that ends
 * without a start returns the lobby to Open, under the rule again. */
gz_status_t gz_lobby_host_start(gz_lobby_host_t *h, gz_action_list_t *out);
/* The seats the start rule counts now: Ready for the current values,
 * connected, and with a min_members a start could meet. */
uint32_t gz_lobby_host_ready_count(const gz_lobby_host_t *h);
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

/* The member's signing gate (composite-node.md 12.2). `may_answer` returns 1
 * if the member may be ready and answer a check for `scope` now, 0 if its
 * gate is closed. NULL: always open (member_signing AUTO). The composite
 * owns the gates; the lobby only asks, and is told when one opens or closes
 * (gz_lobby_member_gate_opened, gz_lobby_member_gate_closed). */
typedef struct {
    int (*may_answer)(void *ctx, const uint8_t scope[32]);
    void *ctx;
} gz_lobby_gate_t;

/* What a member needs of its slot (composite-node.md 2.4, 2.5): where its
 * host is, and which of its keys it uses there. */
typedef struct {
    uint8_t scope[32];               /* the lobby identifier from the invitation */
    uint8_t host_key[33];            /* the pinned key */
    uint8_t ckey[33];                /* the per-lobby contribution key (= BOLT 8 key) */
    uint8_t factory_key[33];
    uint8_t address[GZ_LOBBY_MAX_ADDRESS]; uint8_t address_len;   /* "host:port", numeric */
    uint32_t key_epoch, key_index;   /* of the contribution key: CONNECT names them */
    int auto_join;
    uint32_t max_tree_nodes;         /* as the host's: terms past it are refused before any seat */
} gz_lobby_member_config_t;

typedef struct {
    gz_ports_t ports;
    gz_lobby_crypto_t crypto;
    gz_lobby_signing_t signing;
    gz_lobby_gate_t gate;
    gz_lobby_conditions_t cond;
    uint8_t scope[32], host_key[33], factory_key[33], ckey[33];
    uint8_t address[GZ_LOBBY_MAX_ADDRESS]; uint8_t address_len;
    uint32_t key_epoch, key_index;
    gz_link_t link;                  /* (ckey, host_key) */
    int auto_join;
    int have_terms, joined, ready, ended, left, frozen;
    int never_joined;                /* ended without ever holding a seat (slot_closed state 0) */
    int end_how;                     /* GZ_LOBBY_END_*, 0 otherwise */
    int lobby_state, seat_state;
    int connected;
    int locked_told;                 /* GZ_NOTE_LOCKED given for this closing */
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
    int sent_here;                   /* the join was already sent on this connection */
    uint32_t max_tree_nodes;         /* the config's (M2) */
    int heard_here;                  /* the host sent this lobby a message on this connection */
    int hello_tries;                 /* hellos asked again on this connection, unanswered */
    int retry_join;                  /* the retry timer is for a join refused for a limit */
} gz_lobby_member_t;

/* The crypto port signs with the contribution and factory keys `cfg` names.
 * `gate` may be NULL (always open). Nothing is saved or sent. */
gz_status_t gz_lobby_member_init(gz_lobby_member_t *m, const gz_ports_t *ports,
                                 const gz_lobby_crypto_t *crypto, const gz_lobby_signing_t *signing,
                                 const gz_lobby_gate_t *gate, const gz_lobby_conditions_t *cond,
                                 const gz_lobby_member_config_t *cfg);
/* CONNECT to the host with the slot's contribution key: issued when the slot
 * opens (after the save of the key's index, which the composite lists
 * before it) and by gz_lobby_member_resume at every start. */
gz_status_t gz_lobby_member_connect(gz_lobby_member_t *m, gz_action_list_t *out);
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
/* User commands: ready (the person's own, which ends a user's unready; with
 * a gate it is given after the gate was opened), unready (reason 2), leave
 * (reason 2), new conditions. */
gz_status_t gz_lobby_member_ready(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_unready(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_leave(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_set_conditions(gz_lobby_member_t *m, const gz_lobby_conditions_t *c,
                                           gz_action_list_t *out);
/* The person's conditions changed while this lobby holds its copy
 * (local-api.md 13.2, the copying rule). The copy stays the one in force
 * (`m->cond`: the ready check and the signing check compare against it, so
 * a loosening changes nothing here). If the lobby's latest values (the
 * frozen ones after the freeze) fit `person` worse than they fit the copy
 * (gz_lobby_member_misfits), the member leaves before its round: `leave`
 * reason 1, saved first, and GZ_NOTE_REFUSED with the class and the
 * deciding term under `person`. A lobby whose round was handed over
 * (gz_lobby_member_in_round) or is signed (a saved Funding or Active) is
 * never left for this: GZ_NOTE_COMMAND_REFUSED (GZ_CMD_CONDITIONS), nothing
 * changed; so is an ended lobby. A lobby that fits as well gets nothing. */
gz_status_t gz_lobby_member_tighten(gz_lobby_member_t *m, const gz_lobby_conditions_t *person,
                                    gz_action_list_t *out);
/* 1 if `person` fits this lobby worse than its copy does: it has terms, has
 * not ended, and its latest values move down under `person` from "a plain
 * ready may be given" to "joined, not ready by itself" (fits only now, the
 * default option) or "does not fit", or from the second to the third. */
int gz_lobby_member_misfits(const gz_lobby_member_t *m, const gz_lobby_conditions_t *person);
/* 1 while the lobby's round was handed over and its outcome is not saved:
 * a start with role 1 for the check the member answered and still holds
 * (gz_lobby_member_check_in_flight), that no Retry spent. */
int gz_lobby_member_in_round(const gz_lobby_member_t *m);
/* The signing gate changed (composite-node.md 12.2).
 *   opened  the member readies again if it was unready only for the lock:
 *           before the freeze for the latest values, after it the plain
 *           ready for the frozen version (messages.md 6.4).
 *   closed  a member that is Ready and has no answered check in flight
 *           sends `unready` reason 3, "locked" (saved first), and
 *           GZ_NOTE_LOCKED. A check already answered runs to its end: its
 *           answer is not withdrawn. The same happens by itself in
 *           gz_lobby_member_resume (every gate is closed at a start) and
 *           when a ready_check arrives while the gate is closed. */
gz_status_t gz_lobby_member_gate_opened(gz_lobby_member_t *m, gz_action_list_t *out);
gz_status_t gz_lobby_member_gate_closed(gz_lobby_member_t *m, gz_action_list_t *out);
/* THE ACCEPTED RECORD (composite-node.md 9.2, 13). Returns 1, and fills the
 * whole hand-off (frozen records and signatures, pinned key, frozen digest
 * and version, limits; pointers into `m`, valid until its next call), only
 * when all of these hold:
 *   - `check_id` is the newest check the member answered, and not withdrawn
 *     (no unready since);
 *   - there is no saved `start` with role 2 for that attempt;
 *   - that attempt is not spent (no saved outcome for it);
 *   - no higher attempt of that check is known.
 * Otherwise 0, and the signing engine ignores the proposal (no round_abort).
 * `attempt` is round_propose's record 7; until P4.7 makes it required, every
 * check has the one attempt 1, and 0 is read as 1. The signing engine asks
 * for every round_propose, also one that comes without a `start`
 * (messages.md 7.2); the hand-off's `signers` is then 0 and its shape empty:
 * the count is the proposal's. Replaces gz_lobby_member_may_sign. `out` may
 * be NULL. */
int gz_lobby_member_accepted(const gz_lobby_member_t *m, const uint8_t check_id[32], uint32_t attempt,
                             gz_lobby_handoff_t *out);
/* 1 while a check the member answered may still lead to a round for it: it
 * is Ready, answered, not withdrawn, not told "not chosen" (a role-2 start),
 * with no outcome yet, and the lobby has not ended. The composite keeps a
 * per-lobby gate (AT_JOIN) open exactly this long after the answer, and
 * calls gz_lobby_member_gate_closed when it turns 0 (composite-node.md
 * 12.2: the gate closes when that check's last attempt ends). */
int gz_lobby_member_check_in_flight(const gz_lobby_member_t *m);
/* How a member's lobby ended without a cancel and without its own leave
 * (saved in lobby_ended, field 10, so that a restart does not forget). */
#define GZ_LOBBY_END_REMOVED       1   /* the host removed its seat */
#define GZ_LOBBY_END_REFUSED       2   /* its join was refused as invalid */
#define GZ_LOBBY_END_BAD_TERMS     3   /* the host's terms were refused before any seat */
/* 1 once the member has answered a check: round kinds under its scope may
 * reach the signing engine (composite-node.md section 4). */
int gz_lobby_member_round_ok(const gz_lobby_member_t *m);
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
