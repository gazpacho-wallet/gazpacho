/* The watch registry (composite-node.md section 7.2).
 *
 * For each (WATCH_TX, txid) or (WATCH_OUTPOINT, outpoint): the engines that
 * asked and the largest depth asked. The first request issues the action; a
 * later request with a larger depth issues it again with that depth; other
 * repeats issue nothing. Reports go to every engine in the set, and each
 * ignores what it no longer needs. Memory only: every engine sets its watches
 * again at start (node.h rule 4).
 *
 * BUDGETS. An engine cannot see how full the registry is, so it is never
 * full: each engine has a budget of distinct watches (internal.h), their sum
 * fits the registry, and an engine keeps its own cap below its budget and
 * answers a request past it with a refusal. One that asks for more anyway
 * broke that cap (GZ_ERR_BUG, as for timers). There is no "unwatch" action
 * (action.h), but the registry forgets: when a slot closes, its engine's bit
 * leaves every entry, and an entry nobody asks for any more is free. The
 * program goes on reporting it; the report then reaches nobody. */
#include "internal.h"
#include <string.h>

static void key_of_action(const gz_action_t *a, int *is_tx, uint8_t key[36], uint32_t *depth)
{
    memset(key, 0, 36);
    if (a->kind == GZ_ACTION_WATCH_TX) {
        *is_tx = 1;
        memcpy(key, a->u.watch_tx.txid, 32);
        *depth = a->u.watch_tx.depth;
    } else {
        *is_tx = 0;
        memcpy(key, a->u.watch_outpoint.outpoint.txid, 32);
        gz_put_u32(key + 32, a->u.watch_outpoint.outpoint.vout);
        *depth = a->u.watch_outpoint.depth;
    }
}

static int find(const gz_node_t *c, int is_tx, const uint8_t key[36])
{
    for (int i = 0; i < MAX_WATCHES; i++)
        if (c->watches[i].used && c->watches[i].is_tx == is_tx && memcmp(c->watches[i].key, key, 36) == 0)
            return i;
    return -1;
}

static size_t budget(int eng)
{
    if (eng == ENG_TEST0 || eng == ENG_TEST1) return TE_MAX_WATCHES;
    if (eng >= ENG_SLOT0 && eng < ENG_N) return TS_MAX_WATCHES;
    return 0;
}

static size_t held_by(const gz_node_t *c, int eng)
{
    size_t n = 0;
    for (int i = 0; i < MAX_WATCHES; i++)
        if (c->watches[i].used && (c->watches[i].mask & (1u << eng))) n++;
    return n;
}

int gz_watch_note(gz_node_t *c, const gz_action_t *a, int eng)
{
    int is_tx, i;
    uint8_t key[36];
    uint32_t depth;
    key_of_action(a, &is_tx, key, &depth);
    i = find(c, is_tx, key);
    /* One more watch for this engine: within its budget. */
    if ((i < 0 || !(c->watches[i].mask & (1u << eng))) && held_by(c, eng) >= budget(eng)) return -1;
    if (i >= 0) {
        c->watches[i].mask |= (uint16_t)(1u << eng);
        if (depth <= c->watches[i].depth) return 0;
        c->watches[i].depth = depth;
        return 1;
    }
    for (i = 0; i < MAX_WATCHES; i++) {
        if (c->watches[i].used) continue;
        c->watches[i].used = 1;
        c->watches[i].is_tx = is_tx;
        memcpy(c->watches[i].key, key, 36);
        c->watches[i].depth = depth;
        c->watches[i].mask = (uint16_t)(1u << eng);
        return 1;
    }
    return -1;
}

uint16_t gz_watch_mask(const gz_node_t *c, const gz_chain_event_t *ev)
{
    uint8_t key[36];
    int i;
    memset(key, 0, sizeof key);
    if (ev->kind == GZ_CHAIN_TX_CONFIRMED || ev->kind == GZ_CHAIN_TX_UNCONFIRMED) {
        memcpy(key, ev->txid, 32);
        i = find(c, 1, key);
    } else if (ev->kind == GZ_CHAIN_OUTPOINT_SPENT) {
        memcpy(key, ev->outpoint.txid, 32);
        gz_put_u32(key + 32, ev->outpoint.vout);
        i = find(c, 0, key);
    } else {
        return 0;
    }
    return i < 0 ? 0 : c->watches[i].mask;
}

int gz_watch_unnote(gz_node_t *c, const gz_action_t *a, int eng)
{
    uint8_t key[36];
    int i;
    memset(key, 0, sizeof key);
    memcpy(key, a->u.unwatch.what.txid, 32);
    if (!a->u.unwatch.is_tx) gz_put_u32(key + 32, a->u.unwatch.what.vout);
    i = find(c, a->u.unwatch.is_tx, key);
    if (i < 0 || !(c->watches[i].mask & (1u << eng))) return 0;
    c->watches[i].mask &= (uint16_t)~(1u << eng);
    if (c->watches[i].mask) return 0;
    c->watches[i].used = 0;
    return 1;
}

/* An engine has ended (its slot closed): nothing is reported to it again,
 * and what only it watched is forgotten. */
void gz_watch_forget(gz_node_t *c, int eng)
{
    for (int i = 0; i < MAX_WATCHES; i++) {
        if (!c->watches[i].used) continue;
        c->watches[i].mask &= (uint16_t)~(1u << eng);
        if (!c->watches[i].mask) c->watches[i].used = 0;
    }
}
