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
} gz_fake;

void gz_fake_init(gz_fake *f, int scenario);
void gz_fake_free(gz_fake *f);
/* Confirm every held save: held calls (f->hold) are answered. Any thread. */
void gz_fake_release(gz_fake *f);
extern const gz_api_backend gz_fake_backend;

#endif
