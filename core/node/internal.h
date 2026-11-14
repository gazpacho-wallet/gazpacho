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
#include "engine.h"

#ifdef GZ_TEST_KINDS
#define GZ_NODE_CHECKS 1        /* the test-build checks of 7.4 and 8.3 */
#define GZ_NODE_N_TEST 2
#else
#define GZ_NODE_CHECKS 0
#define GZ_NODE_N_TEST 0
#endif

/* ---- the test engine (test builds) -------------------------------------- */

#define TE_MAX_PENDING     512       /* unacknowledged replies held in memory */
#define TE_MAX_TARGETS     4         /* saved CONNECT targets (member) */
#define TE_MAX_LIMITS      16        /* links with a hello limit */
#define TE_MAX_SEND        70000u    /* records of a test SEND command */
#define TE_MAX_PAD         60000u    /* big-reply padding: the test kind is never split */
#define TE_CHUNK_BYTES     (70u * 1024u)
#define TE_MAX_STEP_ACTIONS 24
#define TE_MAX_STEP_BYTES  (80u * 1024u)
#define TE_MAX_TIMERS      4

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
    uint64_t dropped;                      /* pings not saved: the pending table was full */
} te_t;

gz_status_t te_init(te_t *t, uint16_t area, int host, const gz_ports_t *ports, const gz_key_port_t *keys,
                    const te_hooks_t *hooks, uint64_t incarnation);
gz_status_t te_take_handoff(te_t *t, uint64_t tag, gz_action_list_t *out);
const gz_engine_ops_t *gz_te_ops(void);

/* ---- the slot stand-in (test builds): what a slot's lobby will be -------- */

#define TS_MAX_STEP_ACTIONS 8
#define TS_MAX_STEP_BYTES  (4u * 1024u)
#define TS_MAX_TIMERS      6           /* the lobby's: 0x4c000001 to 0x4c000006 */

typedef struct {
    uint16_t gen;
    int host;
    uint8_t scope[32];
    uint32_t timer_ms;
} ts_t;

gz_status_t ts_open(ts_t *s, uint16_t gen, int host, const uint8_t scope[32], uint32_t timer_ms,
                    gz_action_list_t *out);
gz_status_t ts_seat(ts_t *s, const gz_node_id_t *member, int seated, gz_action_list_t *out);
const gz_engine_ops_t *gz_ts_ops(void);

/* ---- engines and slots -------------------------------------------------- */

/* Engine indices: one bit each in a confirmation mask. */
enum {
    ENG_NODE = 0,
    ENG_TEST0 = 1,
    ENG_TEST1 = 2,
    ENG_SLOT0 = 3,
    ENG_N = ENG_SLOT0 + GZ_NODE_MAX_SLOTS
};

#define SLOT_FREE    0
#define SLOT_OPEN    1
#define SLOT_CLOSING 2
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
} slot_t;

/* ---- the node part ------------------------------------------------------ */

#define NP_MAX_CONNS 96
#define NP_MAX_UNBOUND 16             /* the lobby's numbers, moved up (reviewer B, B7) */
#define NP_IDLE_MS 60000u
#define NP_HELLO_GAP_MS 1000u          /* one answer a second per link */
#define NP_HELLO_WINDOW_MS 600000u     /* 20 ignored hellos in 10 minutes close it */
#define NP_HELLO_IGNORED_MAX 20
#define NP_MAX_LISTED 4
#define NP_MAX_STEP_ACTIONS 40
#define NP_MAX_STEP_BYTES (16u * 1024u)
#define NP_MAX_TIMERS 2                /* the unbound idle timer, the continuation timer */
#define NP_TIMER_IDLE 1u
#define NP_TIMER_CONTINUE 2u

typedef struct {
    int used, connected;
    int slot;                       /* bound slot, or -1 */
    gz_link_t link;
    uint64_t since_ms;              /* connected, or last message */
    int spoke;
    uint64_t hello_last_ms, hello_window_ms;
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
    uint64_t newest_incarnation;    /* of the newest batch storage held at load */
    np_conn_t conns[NP_MAX_CONNS];
    uint32_t n_unbound;
    uint64_t idle_due_ms;           /* 0: the idle timer is not set */
    uint64_t drops[DROP_N];
    gz_node_id_t seat_key;          /* test builds: a slot-seat command being carried out */
    int seat_val;
} np_t;

/* ---- the watch registry ------------------------------------------------- */

#define MAX_WATCHES 64

typedef struct {
    int used, is_tx;
    uint8_t key[36];                /* txid, or txid and vout */
    uint32_t depth;
    uint16_t mask;                  /* engines that asked */
} watch_t;

/* ---- hand-offs ---------------------------------------------------------- */

#define MAX_DEFERRED 4
#define CQ_MAX 96

typedef struct {
    int from, to;
    uint64_t tag;
} deferred_t;

/* ---- the composite ------------------------------------------------------ */

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
gz_status_t gz_c_slot_inline(gz_node_t *c, int eng, gz_status_t (*fn)(gz_node_t *, int, gz_action_list_t *),
                             gz_action_list_t *out);

/* timers.c */
#define TIMER_ID_MAX UINT64_C(0xffffffff)
uint64_t gz_timer_pack(uint16_t area, uint16_t gen, uint32_t id);
void gz_timer_unpack(uint64_t packed, uint16_t *area, uint16_t *gen, uint32_t *id);
int gz_timer_track(slot_t *s, uint64_t packed, int set);
gz_status_t gz_timer_cancel_slot(slot_t *s, gz_action_list_t *out);
int gz_timer_route(const gz_node_t *c, uint64_t packed, int *eng, uint32_t *id);

/* watches.c */
int gz_watch_note(gz_node_t *c, const gz_action_t *a, int eng); /* 1 keep, 0 drop, -1 full */
uint16_t gz_watch_mask(const gz_node_t *c, const gz_chain_event_t *ev);

/* route.c */
typedef enum {
    RT_DROP = 0,         /* counted (`drop`) */
    RT_REFUSE,           /* counted and DISCONNECT refused */
    RT_SLOT,             /* to slot `slot`'s engine */
    RT_BIND,             /* host: bind the unbound link to `slot`, then RT_SLOT */
    RT_SIGNING,          /* to the signing engine */
    RT_TEST,             /* to test engine `eng` */
    RT_LISTING,          /* host: a scope-zero hello, to every listed slot */
    RT_UNKNOWN_HELLO     /* host: lobby_status state 0 for an unknown scope */
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

/* nodepart.c */
gz_status_t np_load(gz_node_t *c, const gz_record_t *rec, gz_batch_id_t at);
gz_status_t np_restore_batch(gz_node_t *c, gz_action_list_t *out);
gz_status_t np_resume(gz_node_t *c, gz_action_list_t *out);
gz_status_t np_message(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t np_peer(gz_node_t *c, const gz_event_t *ev, gz_action_list_t *out);
gz_status_t np_timer(gz_node_t *c, uint32_t id, gz_action_list_t *out);
gz_status_t np_command(gz_node_t *c, uint16_t code, gz_bytes_t cmd, gz_action_list_t *out);
gz_status_t np_log(gz_node_t *c, gz_action_list_t *out, const char *text);
gz_status_t np_drop(gz_node_t *c, int why, uint16_t kind, gz_action_list_t *out);
gz_status_t np_command_result(gz_action_list_t *out, gz_bytes_t cmd, uint16_t status, const char *error);
int np_conn_find(const gz_node_t *c, const gz_link_t *link);
int np_same_key(const gz_node_id_t *a, const gz_node_id_t *b);
int np_same_link(const gz_link_t *a, const gz_link_t *b);

#endif
