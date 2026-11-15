/* Fuzz target for the signing engine's start and what follows it: a journal
 * of any records, read by a fresh engine, then messages and ticks.
 *
 * Input: byte 0 chooses the party (bit 0: the host; else member 1 + (bits 1
 * and 2) % 3) and byte 1 whether a guard hook runs. Then chunks:
 *   0x00                         a new batch
 *   0x01 type(4, LE) len(2, LE) bytes   a record of the current batch
 *   0x02 from(1) len(2, LE) bytes       a message, delivered after the start
 *   0x03                         a timer tick
 * Unknown chunks end the input. tests/signing/test_signing.c's "replay-seeds"
 * writes real journals in this form (fuzz/corpus/signing_replay/).
 *
 * Properties, beyond "no crash, no undefined behaviour, no read outside the
 * input" (the sanitizers and libFuzzer judge those):
 *   - the start returns GZ_OK or GZ_ERR_CORRUPT, nothing else;
 *   - the library's illegal-argument callback never fires (every value is
 *     parsed before it reaches the library);
 *   - S1 at start: every round_nonces the start sends follows, in the same
 *     action list, a save holding a round_started for its round and tier;
 *   - S3 at start: every round_partial_sigs the start sends is exactly the
 *     bytes of a saved exposure record (the start never signs anew);
 *   - no secret nonce survives into a round the journal shows as signed. */
#include "world.h"
#include <stdlib.h>

#define REQUIRE(c) do { if (!(c)) abort(); } while (0)

typedef struct { gz_record_t recs[64]; uint8_t batch[64]; size_t n, at; } fr_store_t;

static int fr_next(void *ctx, gz_stored_batch_t *b)
{
    fr_store_t *s = ctx;
    size_t k = s->at;
    if (s->at >= s->n) return 0;
    while (k < s->n && s->batch[k] == s->batch[s->at]) k++;
    b->id.incarnation = 1; b->id.sequence = (uint64_t)s->batch[s->at] + 1;
    b->records = &s->recs[s->at]; b->n_records = k - s->at;
    s->at = k;
    return 1;
}
static void fr_rewind(void *ctx) { ((fr_store_t *)ctx)->at = 0; }
static uint64_t g_fr;
static void fr_fill(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len)
{
    (void)ctx; (void)p;
    for (size_t i = 0; i < len; i++) { g_fr = g_fr * 6364136223846793005ull + 1442695040888963407ull; out[i] = (uint8_t)(g_fr >> 56); }
}
static uint64_t fr_now(void *ctx) { (void)ctx; return 0; }

/* The field `type` of a record (one-byte types and lengths up to 0xfd..), or NULL. */
static const uint8_t *field(const gz_record_t *r, uint8_t type, size_t *len)
{
    const uint8_t *b = r->bytes.data;
    size_t n = r->bytes.len, at = 0;
    while (at + 2 <= n) {
        uint64_t t = b[at++], l = b[at++];
        if (t >= 0xfd) return NULL;
        if (l == 0xfd) { if (at + 2 > n) return NULL; l = (uint64_t)b[at] << 8 | b[at + 1]; at += 2; }
        else if (l == 0xfe) { if (at + 4 > n) return NULL; l = (uint64_t)b[at] << 24 | (uint64_t)b[at + 1] << 16 | (uint64_t)b[at + 2] << 8 | b[at + 3]; at += 4; }
        else if (l == 0xff) return NULL;
        if (l > n - at) return NULL;
        if (t == type) { *len = (size_t)l; return b + at; }
        at += (size_t)l;
    }
    return NULL;
}

static gz_sign_t g_eng;
static fr_store_t g_store;
static w_builder_t g_builder;
static gz_action_t g_slots[512];
static uint8_t g_bytes[1u << 22];

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    gz_sign_config_t c;
    gz_ports_t ports = {{fr_fill, NULL}, {fr_now, NULL}};
    gz_action_list_t list;
    gz_storage_reader_t reader = {fr_next, fr_rewind, &g_store, 2, 0};
    const uint8_t *msgs = NULL;
    size_t at = 2, msgs_len = 0;
    uint8_t batch = 0;
    uint32_t party;
    int more = 1;
    gz_status_t st;
    if (n < 2) return 0;
    party = (d[0] & 1u) ? 0 : 1 + ((d[0] >> 1) & 3u) % 3;
    memset(&g_store, 0, sizeof g_store);
    /* the journal */
    while (at < n) {
        if (d[at] == 0x00) { batch++; at++; continue; }
        if (d[at] != 0x01 || n - at < 7 || g_store.n == 64) break;
        uint32_t type = (uint32_t)d[at + 1] | (uint32_t)d[at + 2] << 8 | (uint32_t)d[at + 3] << 16 | (uint32_t)d[at + 4] << 24;
        size_t len = (size_t)d[at + 5] | (size_t)d[at + 6] << 8;
        if (n - at - 7 < len) break;
        g_store.recs[g_store.n].type = type;
        g_store.recs[g_store.n].bytes.data = d + at + 7;
        g_store.recs[g_store.n].bytes.len = len;
        g_store.batch[g_store.n++] = batch;
        at += 7 + len;
    }
    msgs = d + at; msgs_len = n - at;
    /* a fresh engine */
    memset(&c, 0, sizeof c);
    c.host = party == 0; c.ctx = w_ctx();
    w_secret("test/factory", party, c.factory_secret);
    w_secret("test/contribution", party, c.contribution_secret);
    c.build = w_build; c.retry = w_retry; c.build_ctx = &g_builder;
    c.tick_ms = 1; c.resend_ticks = 2; c.deadline_ticks = 6; c.status_ticks = 2; c.max_attempts = 3; c.unfinished_ticks = 4;
    if (d[1] & 1u) w_hooks(&g_builder, &c);
    g_fr = 0x9e3779b97f4a7c15ull ^ n;
    REQUIRE(gz_sign_init(&g_eng, &c, &ports, 2) == GZ_OK);
    gz_action_list_init(&list, g_slots, 512, g_bytes, sizeof g_bytes);
    int illegal = g_illegal;
    st = gz_sign_start(&g_eng, &reader, &list, &more);
    REQUIRE(st == GZ_OK || st == GZ_ERR_CORRUPT);
    REQUIRE(g_illegal == illegal);
    if (st == GZ_OK) {
        REQUIRE(more == 0);
        for (size_t k = 0; k < list.count; k++) {
            const gz_action_t *a = &list.slots[k];
            gz_sign_msg_t m;
            if (a->kind != GZ_ACTION_SEND || !gz_sign_decode(a->u.send.bytes.data, a->u.send.bytes.len, &m)) continue;
            if (m.kind == GZ_SIGN_MSG_NONCES) {               /* S1: saved first, in this list */
                int saved = 0;
                for (size_t q = 0; q < k && !saved; q++) {
                    const gz_action_t *s = &list.slots[q];
                    if (s->kind != GZ_ACTION_SAVE) continue;
                    for (size_t r = 0; r < s->u.save.n_records && !saved; r++) {
                        size_t il, tl;
                        const uint8_t *id = field(&s->u.save.records[r], 2, &il), *tier = field(&s->u.save.records[r], 10, &tl);
                        saved = s->u.save.records[r].type == GZ_SIGN_REC_ROUND_STARTED && id && il == 32 && tier && tl == 1 &&
                                memcmp(id, m.round_id, 32) == 0 && tier[0] == m.tier;
                    }
                }
                REQUIRE(saved);
            } else if (m.kind == GZ_SIGN_MSG_PARTIALS) {      /* S3: the saved bytes, byte for byte */
                int found = 0;
                for (size_t r = 0; r < g_store.n && !found; r++) {
                    size_t pl;
                    const uint8_t *pm;
                    if (g_store.recs[r].type != GZ_SIGN_REC_EXPOSURE || !(pm = field(&g_store.recs[r], 14, &pl))) continue;
                    found = pl == a->u.send.bytes.len && memcmp(pm, a->u.send.bytes.data, pl) == 0;
                }
                REQUIRE(found);
            }
        }
        /* no secret nonce in a tier the journal shows as signed (exposure) */
        for (int k = 0; k < GZ_SIGN_MAX_ROUNDS; k++) {
            const gz_sign_round_t *r = &g_eng.rounds[k];
            if (r->state == GZ_SIGN_ROUND_FREE) continue;
            for (int i = 0; i < r->def.n_items; i++)
                if (r->tier_state[r->def.items[i].tier] >= GZ_SIGN_TIER_SIGNED && !c.host) REQUIRE(r->secnonce_serial[i] == 0);
        }
        /* then messages and ticks */
        at = 0;
        while (at < msgs_len) {
            gz_event_t ev;
            memset(&ev, 0, sizeof ev);
            if (msgs[at] == 0x03) { ev.kind = GZ_EVENT_TIMER_FIRED; ev.u.timer.timer_id = 0x5347u; at++; }
            else if (msgs[at] == 0x02 && msgs_len - at >= 4) {
                size_t len = (size_t)msgs[at + 2] | (size_t)msgs[at + 3] << 8;
                if (msgs_len - at - 4 < len) break;
                ev.kind = GZ_EVENT_MESSAGE_RECEIVED; ev.u.message.peer_id = msgs[at + 1] % W_MAX_NODES;
                ev.u.message.bytes.data = msgs + at + 4; ev.u.message.bytes.len = len;
                at += 4 + len;
            } else break;
            gz_action_list_init(&list, g_slots, 512, g_bytes, sizeof g_bytes);
            st = gz_sign_handle(&g_eng, &ev, &list);
            REQUIRE(st == GZ_OK || st == GZ_ERR_NO_SPACE);
            REQUIRE(g_illegal == illegal);
        }
    }
    gz_sign_wipe(&g_eng);
    return 0;
}
