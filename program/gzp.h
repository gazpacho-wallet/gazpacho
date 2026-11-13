/* SPDX-License-Identifier: MIT */
/* The `gazpacho` program: shared definitions. See docs/notes/program.md.
 *
 * Everything under program/ is the surrounding program of the core: it is
 * the only code that touches storage, the network, the chain, the clock and
 * the user. The core (core/gazpacho) never calls it. */
#ifndef GZP_H
#define GZP_H

#include <stddef.h>
#include <stdint.h>



/* Exit statuses. */
#define GZP_EXIT_OK        0
#define GZP_EXIT_FAILED    1  /* a failure at run time: fatal errors past the restart limit */
#define GZP_EXIT_USAGE     2  /* bad arguments, or a refused configuration (mainnet) */
#define GZP_EXIT_LOCKED    3  /* another gazpacho holds this data folder */
#define GZP_EXIT_DATA      4  /* the data folder or a file in it is unusable */
#define GZP_EXIT_CHAIN     5  /* a chain server is on another network, or unreachable at start */
#define GZP_EXIT_STORAGE   6  /* a failed journal write could not be undone: not restarted (store.h) */
#define GZP_EXIT_TEST      70 /* a --test-crash-* hook fired (tests only) */

#define GZP_ROLE_HOST   1
#define GZP_ROLE_MEMBER 2

#define GZP_MAX_CHAIN_URLS 4
#define GZP_ADDR_MAX 64

typedef struct {
    const char *data_dir;
    int role;                      /* GZP_ROLE_* */
    const char *network;           /* "signet" (default) or "testnet4" */
    /* host */
    char listen_host[GZP_ADDR_MAX];
    uint16_t listen_port;          /* 0: any free port (tests) */
    /* member: <host key, 66 hex>@<numeric address>:<port> (messages.md section 2) */
    int have_connect;
    uint8_t connect_key[33];
    char connect_host[GZP_ADDR_MAX];
    uint16_t connect_port;
    /* the local interface (local-api.md); served once PR 26 is merged */
    int no_interface;
    uint16_t interface_port;       /* 0: the default for the network */
    /* chain */
    int no_chain;
    const char *chain_urls[GZP_MAX_CHAIN_URLS];
    int n_chain_urls;
    uint32_t chain_poll_ms;
    int check_chain;               /* --check-chain: the start-up chain check, read-only, then stop */
    /* transport (peers.h) */
    int handshake_ms, recv_ms, send_ms, ping_ms, pong_ms, reconnect_ms;
    int max_per_address;           /* -1: the transport's default */
    const char *name;              /* label in output lines and test pings */
    /* tests only: accepted by gazpacho-test (GZP_TEST_BUILD), refused by gazpacho */
    int test_pings;                /* pings this program sends each peer, outside the node */
    int test_ping_ms;
    int test_crash_at_ping;        /* _exit after the batch holding the K-th ping record is durable */
    int test_storage_fail_at;      /* the K-th append of the first incarnation fails */
    int test_start_delay_ms;       /* keep the start open this long, the loop running (inputs queued) */
    int test_listen_during_start;  /* host: listen before the start, so its queue is exercised */
    const char *test_restore_from; /* put this journal in place as a restore (sets the marker) */
    int test_sync_fail_at;         /* the K-th batch is written, then its sync reports failure */
    int test_cut_fail;             /* ... and cutting it back fails too (the store is poisoned) */
    int test_crash_after_counter;  /* exit between the start counter and the incarnation entry */
    int test_timer_ms;             /* a test timer every MS, in the executor's table, logged when it fires */
    int test_burst_n, test_burst_bytes; /* at each connection, send N messages of BYTES (test kind) */
    int test_oversize_send;        /* pad every node SEND to this many bytes (too big: fatal) */
    int test_node_error_at;        /* the K-th event delivered is treated as a node error */
} gzp_options_t;

/* Parses argv into `o` (defaults first). Returns 0, or GZP_EXIT_USAGE after
 * printing why to stderr. Refuses mainnet here, before anything is opened. */
int gzp_options_parse(gzp_options_t *o, int argc, char **argv);
void gzp_usage(void);

/* Output lines: one event per line on standard output, "<name> <what> k=v ...".
 * Tests parse them. Never a secret. */
void gzp_log(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;
void gzp_log_set_name(const char *name);

/* Milliseconds: monotonic (timers) and wall clock (the core's clock port). */
uint64_t gzp_mono_ms(void);
uint64_t gzp_wall_ms(void);

/* The operating system's random source, read at each call. Aborts the program
 * if it cannot be read: the port cannot report failure, and weak keys are
 * worse than stopping. Keeps no state and never logs what it returns. */
void gzp_os_random(uint8_t *out, size_t len);

/* Lowercase hex of `n` bytes into out (2n+1 bytes). */
void gzp_hex(const uint8_t *p, size_t n, char *out);
/* Exactly 2n hex digits into out. 1 on success. */
int gzp_unhex(const char *s, size_t slen, uint8_t *out, size_t n);

#endif
