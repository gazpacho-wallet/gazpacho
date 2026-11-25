/* SPDX-License-Identifier: MIT */
/* TEST ONLY. A fake backend for the local API server (spec/local-api.md
 * draft 4): spec-shaped answers for every Slice 1 call, so the interface
 * (stream S10) can be built against it before the program (S11) exists.
 *
 * It is NOT a wallet. Its passphrase check is a plain constant-time comparison
 * with a passphrase held in memory, with no key derivation and no files; its
 * 24 words are a fixed test phrase. It is compiled only into the tests and
 * the gz-api-fake tool, never into the program: building it without
 * GZ_API_FAKE_BACKEND defined is an error. */
#ifndef GAZPACHO_API_FAKE_BACKEND_H
#define GAZPACHO_API_FAKE_BACKEND_H

#ifndef GZ_API_FAKE_BACKEND
#error "fake_backend is test-only: it is compiled only into tests and gz-api-fake"
#endif

#include <pthread.h>
#include <stdint.h>

#include "gazpacho/api.h"

/* The fixed test passphrase of the LOCKED scenario (test-only fixture). */
#define GZ_FAKE_PASSPHRASE "fake test passphrase, not a wallet"

enum gz_fake_scenario {
    GZ_FAKE_FIRST_RUN = 0,   /* no wallet */
    GZ_FAKE_LOCKED           /* a wallet exists with GZ_FAKE_PASSPHRASE; the program starts locked */
};

typedef struct gz_fake {
    pthread_mutex_t mu;
    gz_api_server *srv;               /* set after gz_api_server_new, for events */
    int wallet;                       /* enum gz_api_wallet */
    int setup_ready;                  /* finish-setup done */
    int restoring;
    char pass[1100];
    size_t pass_len;
    char words[24][16];
    int64_t words_checked_at;
    int64_t check_times[3];
    int64_t now_override;             /* tests: Unix seconds, 0 = real */
    /* test switches */
    int files_behind_next;            /* the next unlock finds the files behind */
    int derivation_fails_next;        /* the next derivation fails (passphrase_not_checked) */
    int pp_delay_ms;                  /* each derivation takes this long */
    int fault_next;                   /* the next create, restore or start-as-restore is done with a fault */
    int hold;                         /* acting calls are held until gz_fake_release (contract-v2 11) */
    int hold_forever;                 /* ... and gz_fake_release releases nothing (node_busy tests) */
    int64_t acted;                    /* acting calls carried out (not replays) */
    /* the engine's request ids and held outcomes (fake_backend.c) */
    struct gz_fake_rid **rids;
    int nrids;
    struct gz_fake_held **held;
    int nheld;
    int partials_out;                 /* a round with partial signatures out: a lock is held */
    int chain_state;                  /* enum gz_api_chain_state */
    int has_factory;                  /* an awaiting-funding factory (something to watch) */
    int doing_extra_n;
    gz_api_doing doing_extra[8];      /* extra doing candidates, for the priority tests */
    int attention_extra_n;
    gz_api_attention attention_extra[8];
    /* state */
    int64_t cond_version;
    int64_t cond_max_joining_fee_sat, cond_min_members, cond_min_confirmations, cond_max_fee_ppm;
    char cond_preset[16];
    int pause_on;
    int64_t pause_since;
    int joined;                       /* lob_7k2q joined */
    int joining_answer;
    int ready;
    int left;
    int host_open;                    /* lob_4c08 hosted, open */
    int host_cancelled;
    int host_seat_removed;
    int64_t set_aside_sat;
    int64_t address_no;
    int64_t query_no;
    int64_t query_last_at;
    int64_t derivations;              /* how many passphrase operations ran */
    int64_t installs;                 /* how many results were installed (pp_done) */
    int max_inside;                   /* the most that ran at once (23.2 item 46) */
    int inside;
    /* The interface's story (gz-api-fake --story, stream S10): the lobbies move
     * on, one step per gz_fake_cmd("step"), through a whole start. Off (0), the
     * fake answers the one fixed picture the server's tests expect. */
    int story;
    /* gz-api-fake --loosen-extra-after N: from the N-th conditions preview on, a change
     * that loosens anything also loosens max_fee_ppm (the save-time preview then differs
     * from the one on screen: the interface must show the new list and ask again). */
    int loosen_extra_after, previews;
    int m_stage, m_round, m_outcome;  /* the member in lob_7k2q (fake_backend.c: MS_, MO_) */
    int m_refuse_next;                /* the app's own check fails at the next signing */
    int m_refuse_kind;                /* 0 on min_members, 1 on a list and a range, 2 at a safety check */
    int join_list_fail;               /* the next join is refused on a list and a range */
    int m_conf;                       /* funding confirmations seen */
    int joined2, ready2, left2;       /* lob_b19d: several lobbies at once (owner decision 16b) */
    /* draft 5, 14.3: the signing gates, in the story only (the fixed picture
     * keeps draft 4's joins, as auto). gz_fake_cmd("restart") closes every
     * gate: a Ready seat under at_join becomes locked (rule 3). */
    int member_signing;               /* 0 at_join (the default), 1 auto */
    int signing_pending;              /* -1, or the value saved for the next start */
    int64_t signing_version;
    int gate1, gate2;                 /* the per-lobby gate is open (lob_7k2q, lob_b19d) */
    int64_t gate1_at, gate2_at;
    int locked1, locked2;             /* Ready, then the gate closed: unready reason 3 sent */
    int h_locked;                     /* the hosted lobby's seats shown locked (15.3) */
    int m_removed;                    /* the host removed this member's seat (14.6) */
    int m_terms_bump;                 /* lob_7k2q's host moved its joining fee: version 4, a new digest */
    int acc_counts;                   /* 14.6 counts: 0 none (Slice 1), 1 unsigned, 2 signed (1.0.0) */
    int h_stage, h_round, h_ready, h_conf, h_left_seen;   /* the hosted lobby */
    int64_t h_target, h_minimum, h_channel, h_funded_sat;
    char h_name[121];
    char st_buf[5][400];              /* status params, stable until the next status call */
} gz_fake;

void gz_fake_init(gz_fake *f, int scenario);
void gz_fake_free(gz_fake *f);
/* Confirm every held save: held calls (f->hold) are answered. Any thread. */
void gz_fake_release(gz_fake *f);
/* One line of the story's script: step, member-refuse, member-refuse-list,
 * member-refuse-safety, join-refuse-list, member-unfinished,
 * member-cancel, host-seats N, host-leave, chain STATE, hold on|off|forever,
 * release, restore-done, files-behind, pp-delay MS, fail-derivation,
 * restart, host-locked N, member-removed, host-moves-fee, join-second,
 * host-counts-unsigned, host-counts-signed.
 * Any thread. 0, or -1 for a line it does not know. */
int gz_fake_cmd(gz_fake *f, const char *line);
extern const gz_api_backend gz_fake_backend;

#endif
