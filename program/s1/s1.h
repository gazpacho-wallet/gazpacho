/* slice1-attempt glue: one host and members as separate processes, driving
 * the lobby engine, the signing engine with trees from terms, the wallet's
 * funding and the chain view. THROWAWAY: never merged. Three translation
 * units because lobby.h, signing.h and tree.h cannot be included together
 * (see PROGRESS.md, mismatches). */
#ifndef GZ_S1_H
#define GZ_S1_H

#include <stddef.h>
#include <stdint.h>
#include "gazpacho/action.h"
#include "gazpacho/event.h"
#include "gazpacho/ports.h"

#define S1_MAX_PARTS 20

void s1_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void s1_hex(char *out, const uint8_t *b, size_t n);
void s1_hex_rev(char *out, const uint8_t *b, size_t n);
void s1_die(const char *why) __attribute__((noreturn));

/* Shared state read by the pieces. */
typedef struct {
    int host;
    int fake_chain;               /* loopback test: no chain servers, fake funding */
    uint32_t tip;                 /* chain tip height (fake: --fake-tip) */
    const char *dir;
    const char *phrase_in;        /* host: wallet phrase file path, passed through */
    uint32_t change_index;
    const char *gate;             /* host: broadcast only once this file exists */
    uint8_t host_sk[32], host_pk[33];      /* host: BOLT 8 = terms host key = contribution */
    uint8_t ckey_sk[32], ckey_pk[33];      /* member: BOLT 8 = contribution key */
    uint8_t fkey_sk[32], fkey_pk[33];      /* factory key */
    gz_ports_t ports;
    void *secp;                   /* secp256k1_context * */
    uint64_t host_conn;           /* member: connection to the host */
    int member_bad;               /* member: conditions the terms do not meet */
} s1_global_t;
extern s1_global_t G;

/* Action lists. */
gz_action_list_t *s1_list(void);          /* a fresh empty list */
void s1_exec(gz_action_list_t *l);        /* carry out every action, in order */
uint64_t s1_conn_for_key(const uint8_t key[33]);   /* host: connection of a member key, 0 none */

/* ---- lobby (s1_lobby.c) ---- */
void s1_lobby_host_open(uint16_t target, uint16_t minimum, uint64_t channel_sat, uint8_t scope_out[32]);
void s1_lobby_member_init(const uint8_t scope[32], const uint8_t host_key[33]);
void s1_lobby_connected(uint64_t conn, const uint8_t key[33]);
void s1_lobby_disconnected(uint64_t conn);
void s1_lobby_message(uint64_t conn, const uint8_t *msg, size_t len);
void s1_lobby_timer(uint64_t id);
void s1_lobby_round_result(int outcome);   /* 1 funding, 2 active, 4 failed */
/* member: the stored records with the host's signatures (for the tree checks) */
int s1_lobby_member_records(const uint8_t **outer, size_t *outer_len, const uint8_t **outer_sig,
                            const uint8_t **current, size_t *current_len, const uint8_t **current_sig);

/* What the lobby hands the signing side (a plain copy of gz_lobby_handoff_t). */
typedef struct {
    uint8_t fkey[33], ckey[33], bind_f[64], bind_c[64];
} s1_part_t;
typedef struct {
    int role;
    uint8_t scope[32], current_digest[32];
    uint32_t version;
    const uint8_t *outer, *current; size_t outer_len, current_len;
    uint16_t n_parts;             /* host only */
    s1_part_t parts[S1_MAX_PARTS];
} s1_handoff_t;

/* ---- signing (s1_sign.c) ---- */
int s1_sign_begin(const s1_handoff_t *h, gz_action_list_t *out);   /* lobby's begin */
void s1_sign_event(const gz_event_t *ev);
void s1_sign_poll(void);          /* host: funding steps; both: chain watch */
void s1_sign_timer(uint64_t id);

/* ---- funding and chain (s1_fund.c) ---- */
int s1_chain_open(void);
int s1_chain_tip(uint32_t *tip);
int s1_fund_prepare(void);        /* host: scan the wallet's coins */
int s1_fund_build(const uint8_t script[34], uint64_t amount, uint8_t *utx, size_t cap, size_t *len,
                  uint8_t txid[32], uint32_t *vout);
int s1_fund_release(const uint8_t txid[32], uint8_t *raw, size_t cap, size_t *len);
int s1_broadcast(const uint8_t *raw, size_t len);
/* confirmations of txid as each operator reports it; returns the agreed
 * value or -1, and logs every operator's answer */
int s1_tx_confirmations(const uint8_t txid[32], uint32_t *height);
/* the output txid:vout as the chain view gives it (34-byte scripts only) */
int s1_tx_output(const uint8_t txid[32], uint32_t vout, uint64_t *amount, uint8_t script[34]);

#endif
