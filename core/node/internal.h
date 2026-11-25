/* core/node internals: the composite's state and the pieces that share it.
 * See docs/notes/composite-node.md. Files:
 *   composite.c  init, the stepped start, handle, poison and rollback
 *   route.c      routing by kind, then scope, then link (sections 3 to 5)
 *   timers.c     timer ids packed with area and slot generation (7.1)
 *   watches.c    the watch registry (7.2)
 *   handoff.c    engine calls, brackets and merges, confirmations (7.4, 7.5)
 *   nodepart.c   the node part: restore batch, connections, slots, limits
 *   test_engine.c, test_slot.c  test builds only */
#ifndef GZ_NODE_INTERNAL_H
#define GZ_NODE_INTERNAL_H

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/node.h"
#include "gazpacho/view.h"
#include "engine.h"
#include "gazpacho/lobby.h"
#include "gazpacho/signing.h"
#include "gazpacho/tree.h"

#ifdef GZ_TEST_KINDS
#define GZ_NODE_CHECKS 1        /* the test-build checks of 7.4 and 8.3 */
#define GZ_NODE_N_TEST 2
#else
#define GZ_NODE_CHECKS 0
#define GZ_NODE_N_TEST 0
#endif

/* The highest key_index a slot_opened may name. Allocation counts up from 1
 * (highest_index + 1) and never comes near it; an index above it is damage:
 * the factory index (key_index + 1) would wrap, or the pair would meet the
 * indexes the program reserves at the top. A second defence after the sealed
 * journal (L4; core-slot-index-bounds). Allocation stops once highest_index
 * reaches it, so it never gives an index the next start would refuse (review
 * of PR 87, L1); the load refuses anything above it. */
#define GZ_LS_KEY_INDEX_MAX 0xfffffff0u

/* ---- the test engine (test builds) -------------------------------------- */

#define TE_MAX_PENDING     512       /* unacknowledged replies held in memory */
#define TE_MAX_PENDING_LINK 128      /* of them, on one link: no key fills the table for the others */
#define TE_MAX_WATCHES     16        /* distinct watches one test engine may ask for (7.2) */
#define TE_MAX_TARGETS     4         /* saved CONNECT targets (member) */
#define TE_MAX_LIMITS      16        /* links with a hello limit */
#define TE_MAX_SEND        70000u    /* records of a test SEND command */
#define TE_MAX_SEND_PAD    200000u   /* and a pad record after them: a message the transport splits */
#define TE_MAX_SEND_TOTAL  210000u   /* records and pad together */
#define TE_MAX_PAD         60000u    /* big-reply padding: the test kind is never split */
#define TE_CHUNK_BYTES     (70u * 1024u)
#define TE_MAX_STEP_ACTIONS 24
#define TE_MAX_STEP_BYTES  (TE_MAX_SEND_TOTAL + 8u * 1024u)
#define TE_MAX_TIMERS      4          /* ids 1 (command), 2 (continuation), 3 (hand-off), 4 (deferred hello) */

typedef struct {
    int used;
    uint64_t serial;
    gz_link_t link;
    uint8_t len;
    uint8_t payload[64];
} te_pending_t;

typedef struct {
    gz_node_id_t host;
    uint32_t epoch, index;
    uint8_t addr_len;
    uint8_t addr[64];
} te_target_t;

/* A link the engine has answered: its hello limit, and the answer still
 * going out (one chunk per step). */
typedef struct {
    gz_link_t link;
    uint64_t last_ms;
    int used;
    int resending;                         /* replies after `after` still to send */
    int deferred;                          /* a hello inside the second: answered when it is over */
    uint64_t after;
} te_limit_t;

/* The hooks the composite gives a test engine: a hand-off to another engine
 * (or to itself), bracketed and, when the target is running, deferred until
 * its call returns; and the same without deferral, which only the re-entry
 * check's test uses. */
typedef struct {
    void *ctx;
    gz_status_t (*handoff)(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out);
    gz_status_t (*handoff_now)(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out);
} te_hooks_t;

typedef struct {
    uint16_t area;
    int host;
    gz_ports_t ports;
    gz_key_port_t keys;
    te_hooks_t hooks;
    uint64_t incarnation;                  /* the high half of every serial it issues */
    uint64_t next_serial, saved;           /* saved: pings this engine ever saved (the view's version) */
    te_pending_t pending[TE_MAX_PENDING];
    size_t n_pending;
    te_target_t targets[TE_MAX_TARGETS];
    size_t n_targets;
    te_limit_t limits[TE_MAX_LIMITS];
    size_t resend_turn;                    /* round-robin over the links being answered */
    uint32_t pad;                          /* big-reply padding */
    uint32_t fail_in;                      /* fail at the fail_in-th next step; 0: never */
    uint64_t handoff_tag;
    uint64_t batches;                      /* confirmations seen (per merged batch) */
    uint64_t dropped;                      /* pings not saved: the table, or the link's share, was full */
    uint64_t skipped_targets;              /* saved CONNECT targets not issued: a bad address */
    uint8_t watches[TE_MAX_WATCHES][37];   /* the watches asked for: kind (1 tx, 0 outpoint), txid, vout */
    uint32_t watch_depth[TE_MAX_WATCHES]; /* the largest depth asked for each */
    size_t n_watches;
} te_t;

gz_status_t te_init(te_t *t, uint16_t area, int host, const gz_ports_t *ports, const gz_key_port_t *keys,
                    const te_hooks_t *hooks, uint64_t incarnation);
gz_status_t te_take_handoff(te_t *t, uint64_t tag, gz_action_list_t *out);
const gz_engine_ops_t *gz_te_ops(void);

/* ---- the slot stand-in (test builds): what a slot's lobby will be -------- */

#define TS_MAX_STEP_ACTIONS 8
#define TS_MAX_STEP_BYTES  (4u * 1024u)
#define TS_MAX_TIMERS      6           /* the lobby's: 0x4c000001 to 0x4c000006 */
#define TS_MAX_WATCHES     4           /* watches a slot's engine may ask for (7.2) */

typedef struct {
    uint16_t gen;
    int host;
    uint8_t scope[32];
    uint32_t timer_ms;
} ts_t;

gz_status_t ts_open(ts_t *s, uint16_t gen, int host, const uint8_t scope[32], uint32_t timer_ms,
                    gz_action_list_t *out);
gz_status_t ts_seat(ts_t *s, const gz_node_id_t *member, int seated, gz_action_list_t *out);
gz_status_t ts_watch(ts_t *s, const uint8_t txid[32], uint32_t depth, gz_action_list_t *out);
gz_status_t ts_save(ts_t *s, gz_action_list_t *out);
const gz_engine_ops_t *gz_ts_ops(void);

/* ---- a slot's lobby (lobbyslot.c) ---------------------------------------- */

/* The lobby's worst step (lobby.h: 256 actions; a new current version to
 * every seat), with the stand-in's records and notices. */
#define LS_MAX_STEP_ACTIONS 264
#define LS_MAX_STEP_BYTES  (320u * 1024u)
#define LS_MAX_TIMERS      GZ_LOBBY_MAX_TIMERS
#define SLOT_KIND_STANDIN 0            /* test builds: the stand-in of test_slot.c */
#define SLOT_KIND_LOBBY   1

typedef union {
    gz_lobby_host_t h;
    gz_lobby_member_t m;
} slot_lobby_t;

const gz_engine_ops_t *gz_ls_ops(void);

/* The signing stand-in (test builds): the rounds handed to it. */
#define SS_MAX 32
typedef struct {
    int used, ended;
    int partials;                      /* GZ_TEST_SIGN_PARTIALS: counted as having sent partial signatures */
    uint64_t seq, due_ms;              /* due_ms 0: no outcome is coming */
    uint8_t scope[32], check[32];
} ss_round_t;
typedef struct {
    ss_round_t r[SS_MAX];
    uint64_t seq;
    int arm, cur, force;
} ss_t;

/* ---- engines and slots -------------------------------------------------- */

/* Engine indices: one bit each in a confirmation mask. */
enum {
    ENG_NODE = 0,
    ENG_TEST0 = 1,
    ENG_TEST1 = 2,
    ENG_SIGN = 3,        /* the signing engine (signslot.c), node-wide */
    ENG_SLOT0 = 4,
    ENG_N = ENG_SLOT0 + GZ_NODE_MAX_SLOTS
};

/* ---- the view and the local-API engine (P6a; view.c, api.c) --------------- */
typedef struct {
    char local_id[GZ_LOCAL_ID_MAX + 1]; /* "lob_..." (local-api.md 7.3); empty: none saved */
    uint64_t hash;                  /* of the object last emitted */
    uint64_t since_ms, gate_ms, locked_ms;
    uint32_t key;                   /* stage, seat and doing when since_ms was taken */
    int gate;
    uint8_t att_code;               /* the attention item emitted, 0 none */
    uint16_t att_count;
} slot_view_t;

/* A member's conditions as LOBBY_JOIN, slot_opened and the conditions
 * record carry them (lobbyslot.c, gz_ls_cond_decode). */
#define COND_HEAD 27u
#define COND_MAX (COND_HEAD + 9u * GZ_TERMS_MAX_ADJ)
#define API_MAX_PRESET 16
#define API_MAX_IDS (GZ_NODE_MAX_SLOTS + GZ_NODE_MAX_TOMBSTONES + 256)
#define API_MAX_METHOD 16
#define API_MAX_PATH 192
#define API_MAX_ERROR 32
/* A lobby's local id; ended_ms: when its slot ended (0 while it holds one,
 * or not yet known: an ended lobby counts from the start that loads it). */
typedef struct { int used; uint64_t seq, ended_ms; uint8_t scope[32]; char id[GZ_LOCAL_ID_MAX + 1]; } api_lid_t;
typedef struct {
    int used;
    uint64_t seq;
    char rid[GZ_CMD_MAX_REQUEST_ID + 1];
    char method[API_MAX_METHOD]; uint8_t method_len;
    char path[API_MAX_PATH]; uint16_t path_len;
    uint8_t digest[32];
    uint16_t status;
    uint64_t created_ms;
    char object[GZ_LOCAL_ID_MAX + 1];
    char error[API_MAX_ERROR + 1];  /* the first answer's error code, "" on success */
} api_req_t;
typedef struct {
    int pause;                      /* GZ_PAUSE_* */
    uint64_t pause_since;
    uint32_t pause_version;         /* the person's pause changes, saved: a resume names it (M1 of PR 75's review) */
    uint8_t held[GZ_NODE_MAX_SLOTS][32];
    int n_held;
    int have_signing;
    uint8_t signing_saved, host_funding_saved;
    uint32_t signing_version;
    /* The person's conditions (local-api.md 13; record 0x000d0008): in force
     * for every member lobby against its own copy (lobbyslot.c, cond_apply)
     * and copied into a join that names none. */
    int have_cond;
    gz_lobby_conditions_t cond;
    uint8_t cond_bytes[COND_MAX];
    size_t cond_len;
    uint32_t cond_version;
    uint32_t cond_tightened;        /* the version of the last save that tightened anything (record field 8) */
    char preset[API_MAX_PRESET + 1];
    unsigned cond_left;             /* the slots a conditions change left (bit i) */
    api_lid_t ids[API_MAX_IDS];
    uint64_t id_seq;
    api_req_t reqs[GZ_API_MAX_REQUESTS]; /* ids with an object (a lobby): each lobby's share, kept by 7.4 */
    api_req_t ring[GZ_API_RING];    /* ids with none (pause, signing): the newest, a ring */
    int ring_next;
    uint64_t req_seq;
    /* The clock the 30 days are counted on: never back. Wall time while the
     * wall clock runs ahead of it, else the monotonic clock's progress; at a
     * load it starts at the newest time the journal holds (api.c, keep_clock). */
    uint64_t keep_now, keep_mono;
    int keep_mono_set;
    int opened;                     /* the slot a command opened, plus one */
    unsigned left, aborted;         /* a pause's answer: the slots it left, and aborted (bit i) */
    int status_dirty;               /* the pause changed inside a slot's step: the status object follows it */
    char pids[GZ_NODE_MAX_SLOTS][GZ_LOCAL_ID_MAX + 1]; /* their ids, before the pause */
    uint8_t res[2400], rec[640];
    char params[2048];              /* a pause's three lists of at most 8 ids each, or a 409's first call */
} api_t;
_Static_assert(GZ_API_MAX_REQUESTS == GZ_NODE_MAX_SLOTS * (GZ_API_LOBBY_SHARE + GZ_API_LOBBY_RESERVE),
               "request ids: every slot's lobby its share and its reserve (7.4; review A of PR 55, N1)");
_Static_assert(sizeof(((api_t *)0)->rec) >= COND_MAX + 4u + API_MAX_PRESET + 12u, "the conditions record fits api.rec");

/* ---- a query to a host for its lobbies (discovery.c) ---------------------- */
#define DQ_MAX_OFFERS 16
#define DQ_QUIET_MS 1500u              /* answered this long after the last offer */
#define DQ_LIMIT_MS 10000u             /* failed when nothing came in this long */
#define DQ_ASKING 1
#define DQ_ANSWERED 2
#define DQ_FAILED 3
typedef struct {
    uint8_t scope[32];
    uint8_t outer[GZ_TERMS_OUTER_MAX]; size_t outer_len; uint8_t outer_sig[64];
    uint8_t current[GZ_TERMS_CURRENT_MAX]; size_t current_len; uint8_t current_sig[64];
    gz_terms_outer_t terms;
    gz_terms_current_t values;
    uint64_t hash;                  /* of its view object, last emitted */
} dq_offer_t;
/* A lobby seen in a query, not joined: its local id for the run (7.3), in a
 * table of its own, so that queries never fill or churn the saved ids of
 * api.ids (review of #79, M2). One query's worth; the oldest not in the
 * current query goes. */
typedef struct {
    int used;
    uint32_t seq;
    uint8_t scope[32];
    char id[GZ_LOCAL_ID_MAX + 1];
} dq_seen_t;
typedef struct {
    int state;                      /* 0 none yet, DQ_* */
    const char *why;                /* failed: no_answer, unreachable */
    uint32_t serial;
    char id[16];                    /* "q_" and the serial */
    gz_node_id_t host;
    uint8_t address[GZ_LOBBY_MAX_ADDRESS]; uint8_t address_len;
    uint32_t key_epoch, key_index;
    gz_link_t link;
    int link_wanted, connected;
    uint64_t asked_ms, ended_ms;    /* wall clock */
    uint64_t deadline, quiet;       /* the monotonic clock */
    dq_offer_t offers[DQ_MAX_OFFERS];
    int n;
    uint64_t hash;                  /* of the query's view object */
    dq_seen_t seen[DQ_MAX_OFFERS];
    uint32_t seen_seq;
} dq_t;

#define VIEW_BODY 12288
typedef struct {
    uint8_t head[VIEW_BODY + 128];
    uint8_t body[VIEW_BODY];
    uint8_t seats[GZ_LOBBY_MAX_SEATS * GZ_VHL_SEAT_LEN + GZ_NODE_MAX_SLOTS * (11 + GZ_LOCAL_ID_MAX)];
    uint8_t list[GZ_NODE_MAX_SLOTS * (GZ_LOCAL_ID_MAX + 1)];
    uint64_t counter, status_hash;
    size_t start_step;
} view_t;

/* ---- the signing engine (signslot.c) -------------------------------------- */

/* Its timing (composite-node.md 8.3, R12): one tick a second; a round's
 * resends every 5 s, so that with every slot's round visited in turn
 * (GZ_NODE_MAX_SLOTS ticks) a resend still comes well inside the shortest
 * step timeout, 60 s; a member's Unfinished creation is Abandoned after an
 * hour (the funding engine's own deadline, P4.5, comes from the chain).
 * node.h's sign_tick_ms shortens the tick in tests: the rest follows. */
#define SG_TICK_MS 1000u
#define SG_RESEND_MS 5000u
#define SG_STEP_MS 60000u
#define SG_UNFINISHED_MS 3600000u
_Static_assert((uint64_t)GZ_NODE_MAX_SLOTS * SG_RESEND_MS < SG_STEP_MS,
               "a round's resend must come inside the step timeout with every slot's round in turn (R12)");
_Static_assert(GZ_SIGN_MAX_ROUNDS >= GZ_NODE_MAX_SLOTS, "one Active round for each lobby (H8)");
/* Its worst step (8.3): a message to every member and the saves, or a
 * failed attempt's aborts with one round's resends and the abandoned rounds
 * that left memory. 2 MB holds a tier's nonce sets to every member of a
 * 32-member tree; a host begins no round whose own steps could pass the
 * bytes (signslot.c, sg_step_bytes). */
#define SG_MAX_STEP_ACTIONS (3u * GZ_SIGN_MAX_PARTICIPANTS + GZ_SIGN_MAX_ROUNDS + 8u)
#define SG_MAX_STEP_BYTES (2048u * 1024u)
#define SG_MAX_QUEUED GZ_NODE_MAX_SLOTS     /* outcomes waiting for a lobby's call to return */

/* The caller's memory for the signing engine (node.h sign_mem): the engine and the builders' work
 * space, so that a node with no engine carries none of it. */
typedef struct {
    gz_sign_t sign;
    gz_tree_t tree;
    gz_tree_import_t imp;
} sg_mem_t;

typedef struct {
    int kind;
    uint8_t scope[32], check[32];
    uint16_t attempt;
    uint8_t blamed[GZ_SIGN_MAX_PARTICIPANTS * 33];
    size_t n_blamed;
} sg_queued_t;

#define SLOT_FREE    0
#define SLOT_OPEN    1
#define SLOT_CLOSING 2
/* Left out at this start: the key port could not give its keys. It keeps
 * its place and its scope and does nothing else, so that no command opens
 * a second slot for the scope or one place too many, and the next start
 * loads the same journal the same way (review B of PR 44, H1). */
#define SLOT_LEFT_OUT 3
#define SLOT_MAX_SEATS 32
#define SLOT_MAX_TIMERS 8

typedef struct {
    int state;
    uint32_t serial;
    uint16_t gen;
    int host;
    uint8_t scope[32];
    gz_node_id_t host_key;          /* member: the pinned host key */
    uint32_t key_epoch, key_index;  /* member: its contribution key */
    int listed;                     /* host: answers a scope-zero hello */
    int round_ok;                   /* its lobby answered a check (member) or sent a start (host) */
    gz_node_id_t seated[SLOT_MAX_SEATS];
    size_t n_seated;
    uint64_t timers[SLOT_MAX_TIMERS]; /* packed ids set and not yet fired or cancelled */
    size_t n_timers;
#ifdef GZ_TEST_KINDS
    ts_t ts;
#endif
    /* A slot's lobby (SLOT_KIND_LOBBY). */
    int kind;
    struct gz_node *node;           /* the lobby's ports reach the node through the slot */
    gz_link_t link;                 /* member: (its contribution key, the pinned host key) */
    uint8_t address[GZ_LOBBY_MAX_ADDRESS];
    uint8_t address_len;
    uint16_t standbys;
    int auto_join;
    gz_lobby_conditions_t cond;
    int gate_open, gate_flight;     /* the per-lobby signing gate (12.2), and: its check was seen in flight */
    /* AT_JOIN: the scoped factory secret the person's ready made, for the
     * values digest it readied for (12.2); wiped when the gate closes. */
    int gate_have;
    uint8_t gate_digest[32], gate_secret[32];
    int told;                       /* the lobby's log line was given, with `last` */
    uint32_t last[5];
    int have_end;                   /* at load: the lobby's own end record was seen */
    uint8_t end_cancel[GZ_LOBBY_MAX_SAVED_MSG];
    size_t end_cancel_len;
    slot_lobby_t lobby;
    slot_view_t view;               /* P6a */
    int awake;                      /* resumed at this start, or opened in this run: the pause acts on it */
    uint64_t set_aside;             /* host: gz_fund_set_aside_sat of its terms, once known */
    uint32_t cond_seen;             /* member: the saved conditions' version when it joined (slot_opened 24) */
    int set_aside_known;
    int stale;                      /* member: left out as a seat of an older epoch (BD2): nothing is sent for it */
} slot_t;

_Static_assert(SLOT_MAX_SEATS >= GZ_LOBBY_MAX_SEATS, "a slot notes every seat its lobby can mark (T-P42-2)");
_Static_assert(GZ_LOBBY_MAX_CONNS == GZ_NODE_MAX_CONNS, "one size for the connection tables (section 3)");
_Static_assert(LS_MAX_TIMERS <= TS_MAX_TIMERS, "a lobby's timers are within a slot's budget (7.1)");

/* ---- the node part ------------------------------------------------------ */

/* CONNECTIONS (composite-node.md section 3). The table holds what the
 * transport can have open at once (GZ_NODE_MAX_CONNS, node.h: the program's
 * and the transport's tables are held to it). A connection whose key holds a
 * seat in an Open host slot is SEATED; every other one is UNSEATED, whether a
 * message has bound it to a slot or not. The one rule for the unseated: at
 * most NP_MAX_UNSEATED of them, a newcomer pushing out the oldest silent one
 * first, and each closed after NP_IDLE_MS without a message. A seated one is
 * never pushed out and never closed as idle. */
#define NP_MAX_CONNS GZ_NODE_MAX_CONNS
#define NP_MAX_UNSEATED 16            /* the lobby's numbers, moved up (reviewer B, B7) */
/* The keys the host's lobbies hold seated together, Open and Closing: the
 * entries the table keeps beside the unseated places, so that a seated
 * member always finds one (review A of PR 44, M1). A join for a key that
 * holds no seat yet is refused while this many are held. */
#define NP_MAX_SEATED (NP_MAX_CONNS - NP_MAX_UNSEATED)
#define NP_IDLE_MS 60000u
/* However much it sends, a connection without a seat goes this long after it
 * came up, or lost its seat (T-P42-7: the lobby's ten-minute rule, kept by
 * the node part; chatter does not hold a place). And for its first moments a
 * newcomer is not yet "silent": it is not pushed out before those that have
 * had the time to speak and did not. */
#define NP_UNSEATED_MAX_MS 600000u
#define NP_SILENT_GRACE_MS 2000u
/* Drop notices are rate-limited (T-P42-8): the first NP_DROP_NOTICES of a
 * reason are told, then every time the count reaches a power of two. The
 * counts themselves are exact. */
#define NP_DROP_NOTICES 64u
#define NP_HELLO_GAP_MS 1000u          /* one answer a second per link */
#define NP_HELLO_WINDOW_MS 600000u     /* 20 ignored hellos in 10 minutes close it */
#define NP_HELLO_IGNORED_MAX 20
#define NP_MAX_LISTED 4
/* The node part's worst step: every connection closed at once (the idle
 * timer, or a slot's close putting its connections over the cap), with the
 * step's notices, timer and result. Test builds hold every step to it. */
#define NP_MAX_STEP_ACTIONS (NP_MAX_CONNS + SLOT_MAX_SEATS + SLOT_MAX_TIMERS + 16)
#define NP_MAX_STEP_BYTES (16u * 1024u)
#define NP_MAX_TIMERS 4                /* the unbound idle timer, the continuation timer, ... */
#define NP_TIMER_IDLE 1u
#define NP_TIMER_CONTINUE 2u           /* the next thing due later: a Closing slot's end */
#define NP_TIMER_SIGN 3u               /* test builds: the signing stand-in's outcome */
#define NP_TIMER_DISCOVERY 4u          /* a query to a host for its lobbies (discovery.c) */
#define NP_MAX_ENDED 256               /* ended lobbies answered from the index (2.4) */

/* An ended lobby in the index: what a late hello is answered with. */
typedef struct {
    int used;
    uint64_t seq;
    uint8_t scope[32];
    uint8_t state;
    uint16_t reason, cancel_len;
    uint8_t cancel[GZ_LOBBY_MAX_SAVED_MSG];
} np_ended_t;

/* A lobby that has ended, with its keys: a round of it may still need them
 * (a status request, a resent ack, an abort) after its slot is freed, also
 * across a start (2.5: the key hook works for a closing slot's old round).
 * The newest NP_MAX_ENDED. */
typedef struct {
    int used, host;
    uint64_t seq;
    uint8_t scope[32];
    uint32_t epoch, index;
} np_keyed_t;

/* A Closing slot (2.4): what it keeps while a round's last news may come. */
typedef struct {
    int used, host;
    uint64_t seq, until_ms;         /* the monotonic clock */
    uint8_t scope[32];
    gz_link_t link;                 /* member: its CONNECT stands */
    gz_node_id_t seated[SLOT_MAX_SEATS]; /* host: its members' seats stay */
    size_t n_seated;
} np_closing_t;

typedef struct {
    int used;
    int connected;                  /* between its PEER_CONNECTED and its PEER_DISCONNECTED */
    int closing;                    /* the node part asked for its close: nothing more is taken from it */
    int seated;                     /* its key holds a seat in an Open host slot */
    int slot;                       /* bound slot, or -1 */
    gz_link_t link;
    uint64_t since_ms;              /* connected, or last message (the monotonic clock) */
    uint64_t unseated_ms;           /* connected, or lost its seat: the hard limit counts from here */
    int spoke;
    uint64_t hello_last_ms, hello_window_ms; /* the monotonic clock */
    uint32_t hello_ignored;
} np_conn_t;

/* Counted drops, by reason. */
enum {
    DROP_KIND = 0,       /* a kind no engine takes */
    DROP_DISCOVERY,
    DROP_FUNDED,         /* factory_funded: counted, nothing acted on */
    DROP_NO_SLOT,        /* a lobby or round kind for a scope with no slot or round */
    DROP_SCOPE_ZERO,
    DROP_LINK,           /* the wrong link: dropped and refused */
    DROP_REBIND,         /* a bound link sent another scope: refused */
    DROP_HELLO_LIMIT,
    DROP_NO_ENGINE,      /* routed to an engine this build does not have yet */
    DROP_TIMER,          /* a timer of a slot generation no longer in use */
    DROP_CONFIRM,        /* a confirmation with no batch awaiting */
    DROP_UNCONNECTED,    /* host: a message on a link not held as connected (closed, refused, never reported) */
    DROP_N
};

/* Epochs before the current one, oldest first, for the guard record
 * (journal.md 8.3). Past this many the oldest is forgotten. */
#define NP_MAX_OLD_EPOCHS 15
#define NP_GUARD_HEAD 58        /* magic 8, chain 32, counter 8, count 2, rounds started 8 */

typedef struct {
    uint32_t epoch;
    int have_epoch;
    uint64_t guard_counter, rounds_started;
    uint32_t highest_index;
    uint32_t old_epochs[NP_MAX_OLD_EPOCHS][2]; /* epoch, its highest index */
    uint32_t n_old_epochs;
    /* The guard file as storage gave it with the restore marker (ports.h):
     * its counter, rounds started, and its newest NP_MAX_OLD_EPOCHS + 1
     * epochs, oldest first. */
    int have_file;
    uint64_t file_counter, file_rounds;
    uint32_t file_epochs[NP_MAX_OLD_EPOCHS + 1][2];
    uint32_t n_file_epochs;
    uint64_t newest_incarnation;    /* of the newest batch storage held at load */
    np_conn_t conns[NP_MAX_CONNS];
    uint64_t idle_due_ms;           /* 0: the idle timer is not set (the monotonic clock) */
    int idle_check;                 /* a seat was given up in this bracket: look at the idle timer at its end */
    uint64_t drops[DROP_N];
    np_ended_t ended[NP_MAX_ENDED];
    uint64_t ended_seq;
    np_keyed_t keyed[NP_MAX_ENDED];
    uint64_t keyed_seq;
    np_closing_t closing[GZ_NODE_MAX_TOMBSTONES];
    uint64_t closing_due_ms;        /* 0: the closing timer is not set */
    uint64_t skipped_slots;         /* slots left out at load: keys the port could not give */
    gz_node_id_t seat_key;          /* test builds: a slot-seat command being carried out */
    int seat_val;
} np_t;

/* ---- the watch registry ------------------------------------------------- */

#define MAX_WATCHES GZ_NODE_MAX_WATCHES

typedef struct {
    int used, is_tx;
    uint8_t key[36];                /* txid, or txid and vout */
    uint32_t depth;
    uint16_t mask;                  /* engines that asked */
} watch_t;

/* Each engine's budget of distinct watches (7.2), as for timers: an engine
 * that asks for more broke its own cap (GZ_ERR_BUG), so the registry can
 * never be full. A slot's watches are forgotten when it closes. */
_Static_assert(2 * TE_MAX_WATCHES + GZ_NODE_MAX_SLOTS * TS_MAX_WATCHES + GZ_NODE_FUNDING_WATCHES <= MAX_WATCHES,
               "the engines' watch budgets must fit the registry (7.2)");

/* ---- hand-offs ---------------------------------------------------------- */

#define MAX_DEFERRED 4
#define CQ_MAX 96

typedef struct {
    int from, to;
    uint64_t tag;
} deferred_t;

/* ---- the composite ------------------------------------------------------ */

/* Timers a node-wide engine may have set at once, at most (the table that
 * holds them; each engine's own budget is below it). */
#define NW_MAX_TIMERS 4

struct gz_node {
    gz_ports_t ports;
    gz_node_config_t cfg;
    uint64_t incarnation;
    int poisoned;
    uint16_t err_area;
    gz_status_t err_status;

    /* the start */
    int fenced, loaded, started, restored;
    gz_batch_id_t fence;
    int resume_at, resume_restore_done;
    int resumed[ENG_N];
    uint32_t held[ENG_N];           /* confirmations held for an engine not yet resumed (7.5) */

    /* engines */
    int n_test;
#ifdef GZ_TEST_KINDS
    te_t test[GZ_NODE_N_TEST];
#endif
    slot_t slots[GZ_NODE_MAX_SLOTS];
    uint32_t slot_serial;
    np_t np;
    watch_t watches[MAX_WATCHES];
    uint64_t nw_timers[ENG_SLOT0][NW_MAX_TIMERS]; /* node-wide engines: packed ids set, not yet fired or cancelled */
    size_t n_nw_timers[ENG_SLOT0];
    int unlocked;                   /* the node-wide signing gate (12.2): memory only, closed at a start */
    api_t api;                      /* the local-API engine (P6a) */
    dq_t dq;                        /* a query to a host for its lobbies (discovery.c, W12) */
    view_t view;                    /* the view objects (P6a) */
    struct {                        /* a lobby command being carried out */
        uint16_t code;
        int refused;
        gz_bytes_t a, b;
    } lc;
#ifdef GZ_TEST_KINDS
    ss_t ss;
#endif

    /* the signing engine (signslot.c) */
    int sign_on;                    /* built with a secp256k1 context: the engine runs */
    gz_sign_t *sign;                /* the engine, in the caller's memory (node.h sign_mem), or NULL */
    uint32_t tip;                   /* the newest tip the chain (or the configuration) gave */
    sg_queued_t sq[SG_MAX_QUEUED];
    size_t n_sq, sq_cur;
    uint32_t sg_touched;            /* slots an outcome reached in the signing call under way */
    int sg_defer;                   /* a lobby called the engine: its outcomes wait (U1) */
    uint64_t sg_lost, sg_refused;   /* outcomes for a lobby that has ended; proposals the checks refused */
    uint32_t sg_refused_check;
    gz_action_list_t *sg_out;       /* the list of the engine call under way (the builder's notices) */
    gz_status_t sg_line_st;
    uint8_t sg_begin_scope[32];
    uint8_t sg_guard[NP_GUARD_HEAD + 8 * (NP_MAX_OLD_EPOCHS + 1)];
    uint8_t sg_blamed[GZ_SIGN_MAX_PARTICIPANTS * 33];
    uint8_t sg_keys[GZ_SIGN_MAX_PARTICIPANTS][33];
    gz_tree_participant_t sg_parts[GZ_SIGN_MAX_PARTICIPANTS];
    gz_tree_proposal_t sg_prop;
    uint8_t sg_ftx[GZ_SIGN_MAX_FUNDING_TX]; /* the proposal's funding transaction: a real plan's, up to the engine's limit */
    gz_tree_t *sg_tree;             /* the builder's work space (large), in the engine's memory */
    gz_tree_import_t *sg_imp;

    /* one call */
    int busy[ENG_N];
    int8_t owner[GZ_NODE_LIST_ACTIONS];
    size_t base;                    /* the list's count when the call began */
    int bracket_on, bracket_handoff, bracket_top;
    size_t bracket_from;
    deferred_t deferred[MAX_DEFERRED];
    int n_deferred;
    size_t nested_bytes;            /* test builds: bytes appended by nested calls */

    /* confirmations (7.5): per SAVE returned, the engines whose records it holds */
    uint16_t cq[CQ_MAX];
    size_t cq_head, cq_n;
};

/* handoff.c */
uint16_t gz_c_area(const gz_node_t *c, int eng);
gz_status_t gz_c_bug(gz_node_t *c, int eng);
gz_status_t gz_c_call(gz_node_t *c, int eng, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t gz_c_bracket(gz_node_t *c, int eng, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t gz_c_node_bracket_begin(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_c_node_bracket_end(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_c_handoff(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out);
gz_status_t gz_c_handoff_now(void *ctx, uint16_t from, uint16_t to, uint64_t tag, gz_action_list_t *out);
void gz_c_confirmed(gz_node_t *c, gz_action_list_t *out, gz_status_t *st);
gz_status_t gz_c_postprocess(gz_node_t *c, size_t from, int merge_all, gz_action_list_t *out);
gz_status_t gz_c_resume(gz_node_t *c, int eng, gz_action_list_t *out, int *more);
gz_status_t gz_c_release_held(gz_node_t *c, int eng, gz_action_list_t *out);
void gz_c_engine_opened(gz_node_t *c, int eng);
void gz_c_engine_closed(gz_node_t *c, int eng);
gz_status_t gz_c_slot_inline(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                             gz_action_list_t *out);

/* timers.c */
#define TIMER_ID_MAX UINT64_C(0xffffffff)
uint64_t gz_timer_pack(uint16_t area, uint16_t gen, uint32_t id);
void gz_timer_unpack(uint64_t packed, uint16_t *area, uint16_t *gen, uint32_t *id);
int gz_timer_track(slot_t *s, uint64_t packed, int set);
gz_status_t gz_timer_cancel_slot(slot_t *s, gz_action_list_t *out);
int gz_timer_route(const gz_node_t *c, uint64_t packed, int *eng, uint32_t *id);
/* Every engine is held to its own timer budget (7.1, T-P42-6): note a timer of
 * engine `eng` set (1) or cancelled or fired (0). 0 if a set would pass the
 * engine's budget: the engine broke its own cap, a bug. */
int gz_timer_note(gz_node_t *c, int eng, uint64_t packed, int set);
size_t gz_timer_budget(const gz_node_t *c, int eng);

/* watches.c */
int gz_watch_note(gz_node_t *c, const gz_action_t *a, int eng); /* 1 keep, 0 drop, -1 over the engine's budget */
uint16_t gz_watch_mask(const gz_node_t *c, const gz_chain_event_t *ev);
void gz_watch_forget(gz_node_t *c, int eng);
/* An engine's UNWATCH: its bit leaves the entry. 1 if nobody asks for the
 * watch any more (the entry is free and the UNWATCH goes out), 0 if others
 * still ask or it held no such watch (the UNWATCH is dropped). */
int gz_watch_unnote(gz_node_t *c, const gz_action_t *a, int eng);

/* route.c */
typedef enum {
    RT_DROP = 0,         /* counted (`drop`) */
    RT_REFUSE,           /* counted and DISCONNECT refused */
    RT_SLOT,             /* to slot `slot`'s engine */
    RT_BIND,             /* host: bind the unbound link to `slot`, then RT_SLOT */
    RT_SIGNING,          /* to the signing engine */
    RT_TEST,             /* to test engine `eng` */
    RT_LISTING,          /* host: a scope-zero hello, to every listed slot */
    RT_UNKNOWN_HELLO,    /* host: lobby_status state 0 for an unknown scope */
    RT_ENDED_HELLO,      /* host: a late hello for ended lobby `slot` of the index: its final state and cancel */
    RT_DISCOVERY         /* member: a message on the link of a query for a host's lobbies */
} rt_kind_t;

typedef struct {
    rt_kind_t kind;
    int slot, eng, drop;
} rt_t;

typedef enum { FAM_NONE = 0, FAM_LOBBY, FAM_ROUND, FAM_FUNDED, FAM_TEST, FAM_DISCOVERY } rt_family_t;

rt_family_t gz_route_family(uint16_t kind, int test_build);
rt_t gz_route_message(const gz_node_t *c, int conn, const gz_link_t *link, uint16_t kind,
                      const uint8_t scope[32], gz_bytes_t records);
int gz_route_slot_by_scope(const gz_node_t *c, const uint8_t scope[32]);
int gz_route_slot_link(const gz_node_t *c, int slot, gz_link_t *link);
int gz_route_member_slot_of_link(const gz_node_t *c, const gz_link_t *link);
int gz_route_slot_seated(const gz_node_t *c, const gz_node_id_t *key);
int gz_route_closing_seated(const gz_node_t *c, const gz_node_id_t *key);
int gz_route_key_seated(const gz_node_t *c, const gz_node_id_t *key);
size_t gz_route_seats_held(const gz_node_t *c);

/* nodepart.c */
gz_status_t np_load(gz_node_t *c, const gz_record_t *rec, gz_batch_id_t at);
void np_guard_file(gz_node_t *c, gz_bytes_t guard);
void np_seat_changed(gz_node_t *c, int slot, const gz_node_id_t *member, int seated);
gz_status_t np_idle_check(gz_node_t *c, gz_action_list_t *out);
gz_status_t np_restore_batch(gz_node_t *c, gz_action_list_t *out);
gz_status_t np_resume(gz_node_t *c, gz_action_list_t *out);
gz_status_t np_message(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t np_peer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t np_timer(gz_node_t *c, uint32_t id, gz_action_list_t *out);
gz_status_t np_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out);
gz_status_t np_log(gz_node_t *c, gz_action_list_t *out, const char *text);
gz_status_t np_drop(gz_node_t *c, int why, uint16_t kind, gz_action_list_t *out);
gz_status_t np_command_result(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error);
gz_status_t np_command_result_o(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error,
                                const char *params, const char *object);
gz_status_t np_command_result_p(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error,
                                const char *params);
int np_conn_find(const gz_node_t *c, const gz_link_t *link);
int np_same_key(const gz_node_id_t *a, const gz_node_id_t *b);
int np_same_link(const gz_link_t *a, const gz_link_t *b);
uint64_t np_mono(gz_node_t *c);
gz_status_t np_set_timer(gz_action_list_t *out, uint32_t id, uint64_t delay);
gz_status_t np_disconnect(gz_action_list_t *out, const gz_link_t *link, uint16_t why);
gz_status_t np_slot_freed(gz_node_t *c, int i, gz_action_list_t *out);
gz_status_t np_save_pair(gz_node_t *c, uint32_t first, const gz_record_t *extra, gz_action_list_t *out);
uint32_t np_next_first(const gz_node_t *c, uint32_t from);

/* lobbyslot.c */
int gz_ls_init(gz_node_t *c, int i);
gz_status_t gz_ls_after(gz_node_t *c, int i, gz_action_list_t *out);
gz_status_t gz_ls_load_opened(gz_node_t *c, const gz_record_t *rec);
gz_status_t gz_ls_load_closed(gz_node_t *c, const gz_record_t *rec);
gz_status_t gz_ls_load_record(gz_node_t *c, const gz_record_t *rec);
gz_status_t gz_ls_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out);
int gz_ls_ended_find(const gz_node_t *c, const uint8_t scope[32]);
gz_status_t gz_ls_ended_answer(const gz_node_t *c, int idx, const gz_link_t *link, gz_action_list_t *out);
gz_status_t gz_ls_closing_timer(gz_node_t *c, gz_action_list_t *out);
int gz_ls_closing_count(const gz_node_t *c);
gz_status_t gz_ls_pause_changed(gz_node_t *c, gz_action_list_t *out);
int gz_ls_cond_decode(const uint8_t *p, size_t n, gz_lobby_conditions_t *c);
size_t gz_ls_cond_encode(const gz_lobby_conditions_t *c, uint8_t *p, size_t cap);
int gz_ls_conditions_blocked(const gz_node_t *c, const gz_lobby_conditions_t *person, unsigned *slots);
gz_status_t gz_ls_conditions_changed(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_ls_merge_saves(gz_node_t *c, gz_action_list_t *out, size_t from);
uint64_t gz_ls_set_aside(slot_t *s);

/* discovery.c */
gz_status_t gz_dq_command(gz_node_t *c, gz_bytes_t cmd, gz_action_list_t *out);
int gz_dq_link(const gz_node_t *c, const gz_link_t *link);
gz_status_t gz_dq_peer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t gz_dq_message(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t gz_dq_timer(gz_node_t *c, gz_action_list_t *out);

/* view.c */
gz_status_t gz_view_query(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_view_seen(gz_node_t *c, int k, gz_action_list_t *out);
gz_status_t gz_view_gone(gz_node_t *c, uint8_t kind, const char *id, uint64_t *last, gz_action_list_t *out);
gz_status_t gz_view_status(gz_node_t *c, int force, gz_action_list_t *out);
gz_status_t gz_view_slot(gz_node_t *c, int i, int force, gz_action_list_t *out);
gz_status_t gz_view_start(gz_node_t *c, gz_action_list_t *out, int *done);

/* api.c */
gz_status_t gz_api_load(gz_node_t *c, const gz_record_t *rec);
gz_status_t gz_api_loaded(gz_node_t *c);
const char *gz_api_local_id(gz_node_t *c, const uint8_t scope[32]);
int gz_api_held(const gz_node_t *c, const uint8_t scope[32]);
int gz_api_paused(const gz_node_t *c);
gz_status_t gz_api_slot_opened(gz_node_t *c, int i, gz_action_list_t *out);
gz_status_t gz_api_seen_id(gz_node_t *c, const uint8_t scope[32]);
int gz_api_seen_only(gz_node_t *c, const uint8_t scope[32]);
const gz_lobby_conditions_t *gz_api_conditions(const gz_node_t *c);
void gz_api_slot_ended(gz_node_t *c, const uint8_t scope[32]);
gz_status_t gz_api_resume(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_api_save_pause(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_api_release(gz_node_t *c, const uint8_t scope[32], gz_action_list_t *out);
int gz_api_req_kept(gz_node_t *c, const char *rid);
gz_status_t gz_api_precheck(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out, int *done);
gz_status_t gz_api_after(gz_node_t *c, gz_bytes_t cmd, size_t from, gz_action_list_t *out);
gz_status_t gz_api_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out);
size_t gz_api_loosens(const gz_lobby_conditions_t *from, const gz_lobby_conditions_t *to, uint8_t *l);
gz_status_t gz_ls_left_out_note(gz_node_t *c, int i, gz_action_list_t *out);
int gz_ls_stale(const gz_node_t *c, int i);
gz_status_t gz_ls_stale_out(gz_node_t *c, int i, gz_action_list_t *out);
gz_status_t gz_c_slot_bracket(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                              gz_action_list_t *out);
/* signslot.c */
gz_status_t gz_sg_init(gz_node_t *c);
void gz_sg_started(gz_node_t *c);   /* at a start, after the engine resumed */
/* The proposal's funding transaction, copied into the node: 1, or 0 (nothing set) if it is empty or
 * longer than GZ_SIGN_MAX_FUNDING_TX. */
int gz_sg_set_funding(gz_node_t *c, gz_tree_proposal_t *p, const uint8_t *tx, size_t len, const uint8_t txid[32],
                      uint32_t vout);
void gz_ls_wipe32(uint8_t *p);      /* 32 secret bytes, wiped */
/* The engine's key hook (signing.h `keys`), for the node's tests too. */
int gz_sg_keys(void *ctx, const uint8_t scope[32], const uint8_t *terms_digest, secp256k1_keypair *f, secp256k1_keypair *kc);
int gz_sg_may_ack(void *ctx, const gz_sign_round_t *r, uint32_t *ack_tip);   /* 1 ack, 0 no, -1 not yet */
/* GZ_SIGN_OUT_THIS if the member's round in lobby `scope` has partial signatures out and is not resolved,
 * GZ_SIGN_OUT_UNKNOWN for such a round whose lobby is not known, else GZ_SIGN_OUT_NONE (the signing
 * engine's fact, gz_sign_partials_out): the person's leave is then refused, Slice 1 blocker C1. The pause
 * (local-api.md 11.3, PR 55) and a conditions change (PR 77) must ask the same. */
int gz_ls_partials_out(const gz_node_t *c, const uint8_t scope[32]);
const gz_engine_ops_t *gz_sg_ops(void);
gz_status_t gz_sg_after(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_sg_drain(gz_node_t *c, gz_action_list_t *out);
void gz_sg_keyed_add(gz_node_t *c, const slot_t *s);
void gz_sg_signing(slot_t *s, gz_lobby_signing_t *sg);
size_t np_guard_for_round(gz_node_t *c, uint8_t *buf);

#ifdef GZ_TEST_KINDS
gz_status_t gz_ss_load(gz_node_t *c, const gz_record_t *rec);
gz_status_t gz_ss_timer(gz_node_t *c, gz_action_list_t *out);
gz_status_t gz_ss_resume(gz_node_t *c, gz_action_list_t *out, int *more);
#endif

#endif
