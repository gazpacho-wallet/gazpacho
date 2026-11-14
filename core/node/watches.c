/* The watch registry (composite-node.md section 7.2).
 *
 * For each (WATCH_TX, txid) or (WATCH_OUTPOINT, outpoint): the engines that
 * asked and the largest depth asked. The first request issues the action; a
 * later request with a larger depth issues it again with that depth; other
 * repeats issue nothing. Reports go to every engine in the set, and each
 * ignores what it no longer needs. Memory only: every engine sets its watches
 * again at start (node.h rule 4). */
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

int gz_watch_note(gz_node_t *c, const gz_action_t *a, int eng)
{
    int is_tx, i;
    uint8_t key[36];
    uint32_t depth;
    key_of_action(a, &is_tx, key, &depth);
    i = find(c, is_tx, key);
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
