/* The watch registry's release (UNWATCH, step P4.5): a release frees the
 * engine's place, an entry two engines share stays until both release it,
 * and a report for a released watch reaches nobody. */
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static gz_action_t watch_tx(uint8_t tag)
{
    gz_action_t a = {.kind = GZ_ACTION_WATCH_TX};
    memset(a.u.watch_tx.txid, tag, 32);
    a.u.watch_tx.depth = 3;
    return a;
}
static gz_action_t unwatch_tx(uint8_t tag)
{
    gz_action_t a = {.kind = GZ_ACTION_UNWATCH};
    a.u.unwatch.is_tx = 1;
    memset(a.u.unwatch.what.txid, tag, 32);
    return a;
}
static gz_chain_event_t report(uint8_t tag)
{
    gz_chain_event_t e;
    memset(&e, 0, sizeof e);
    e.kind = GZ_CHAIN_TX_CONFIRMED;
    memset(e.txid, tag, 32);
    e.confirmations = 1;
    return e;
}

int main(void)
{
    gz_node_t *c = (gz_node_t *)calloc(1, sizeof *c);
    gz_action_t a;
    gz_chain_event_t e;
    if (!c) return 2;
    /* A test engine fills its budget. */
    for (int i = 0; i < TE_MAX_WATCHES; i++) {
        a = watch_tx((uint8_t)(i + 1));
        CHECK(gz_watch_note(c, &a, ENG_TEST0) == 1);
    }
    a = watch_tx(0x77);
    CHECK(gz_watch_note(c, &a, ENG_TEST0) == -1);   /* over its budget: a bug */
    /* Released: its place is free again, and the UNWATCH goes out. */
    a = unwatch_tx(1);
    CHECK(gz_watch_unnote(c, &a, ENG_TEST0) == 1);
    a = watch_tx(0x77);
    CHECK(gz_watch_note(c, &a, ENG_TEST0) == 1);
    /* A report for the released watch reaches nobody. */
    e = report(1);
    CHECK(gz_watch_mask(c, &e) == 0);
    e = report(0x77);
    CHECK(gz_watch_mask(c, &e) == (1u << ENG_TEST0));
    /* Released twice, or never held: dropped. */
    a = unwatch_tx(1);
    CHECK(gz_watch_unnote(c, &a, ENG_TEST0) == 0);
    CHECK(gz_watch_unnote(c, &a, ENG_TEST1) == 0);
    /* Watched again after its release: a new entry, so the WATCH goes out. */
    a = watch_tx(1);
    CHECK(gz_watch_note(c, &a, ENG_TEST1) == 1);
    e = report(1);
    CHECK(gz_watch_mask(c, &e) == (1u << ENG_TEST1));
    /* Shared by two engines: the entry stays until the last lets go. */
    a = watch_tx(2);
    CHECK(gz_watch_note(c, &a, ENG_TEST1) == 0);    /* already watched: nothing new goes out */
    a = unwatch_tx(2);
    CHECK(gz_watch_unnote(c, &a, ENG_TEST0) == 0);
    e = report(2);
    CHECK(gz_watch_mask(c, &e) == (1u << ENG_TEST1));
    CHECK(gz_watch_unnote(c, &a, ENG_TEST1) == 1);
    CHECK(gz_watch_mask(c, &e) == 0);
    /* An outpoint watch is released by its outpoint, not its txid. */
    {
        gz_action_t w = {.kind = GZ_ACTION_WATCH_OUTPOINT}, u = {.kind = GZ_ACTION_UNWATCH};
        memset(w.u.watch_outpoint.outpoint.txid, 9, 32);
        w.u.watch_outpoint.outpoint.vout = 4;
        w.u.watch_outpoint.depth = 1;
        CHECK(gz_watch_note(c, &w, ENG_TEST1) == 1);
        memset(u.u.unwatch.what.txid, 9, 32);
        u.u.unwatch.what.vout = 5;
        CHECK(gz_watch_unnote(c, &u, ENG_TEST1) == 0);
        u.u.unwatch.is_tx = 1;
        CHECK(gz_watch_unnote(c, &u, ENG_TEST1) == 0);
        u.u.unwatch.is_tx = 0;
        u.u.unwatch.what.vout = 4;
        CHECK(gz_watch_unnote(c, &u, ENG_TEST1) == 1);
    }
    free(c);
    if (fails) return 1;
    printf("watch release: all passed\n");
    return 0;
}
