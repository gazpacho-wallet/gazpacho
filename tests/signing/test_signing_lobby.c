/* The signing engine's outcome into the lobby host (core/signing/lobby_outcome.c),
 * against the real gz_lobby_host_round_result: built only with the lobby
 * engine. The host's state is set directly, as the lobby's own tests
 * reach Signing only through a whole lobby; the transitions themselves are
 * the lobby's (its tests cover cancel reason 3, which FAILED maps to). */
#include "gazpacho/lobby.h"
#include "gazpacho/signing_outcome.h"
#include "../check.h"
#include <string.h>

static uint64_t now_ms(void *ctx) { (void)ctx; return 1000000; }
static void fill(void *ctx, gz_random_purpose_t p, uint8_t *out, size_t len) { (void)ctx; (void)p; memset(out, 7, len); }

static int c_verify(void *ctx, const uint8_t pub[33], const uint8_t msg[32], const uint8_t sig[64]) { (void)ctx; (void)pub; (void)msg; (void)sig; return 1; }
static int c_point(void *ctx, const uint8_t pub[33]) { (void)ctx; return pub[0] == 2 || pub[0] == 3; }
static int c_sign(void *ctx, uint32_t which, const uint8_t msg[32], uint8_t sig[64]) { (void)ctx; (void)which; memcpy(sig, msg, 32); memset(sig + 32, 0, 32); return 1; }

static size_t saves_of(const gz_action_list_t *l, uint32_t type)
{
    size_t n = 0;
    for (size_t k = 0; k < l->count; k++)
        if (l->slots[k].kind == GZ_ACTION_SAVE)
            for (size_t r = 0; r < l->slots[k].u.save.n_records; r++) n += l->slots[k].u.save.records[r].type == type;
    return n;
}

int main(void)
{
    static gz_lobby_host_t h;
    static gz_action_t slots[64];
    static uint8_t bytes[1u << 16];
    gz_action_list_t l;
    uint8_t keys[2][33], id[32] = {1};
    gz_sign_outcome_t o;
    memset(&h, 0, sizeof h);
    h.ports.clock.now_ms = now_ms; h.ports.random.fill = fill;
    h.terms.deadline = 2000000;                    /* not passed */
    h.terms.target = 3; h.terms.minimum = 3;       /* too few ready after the retry: the lobby waits */
    h.crypto.verify = c_verify; h.crypto.point_ok = c_point; h.crypto.sign = c_sign;
    memset(keys, 0, sizeof keys);
    keys[0][0] = 2; keys[0][1] = 0xa1; keys[1][0] = 3; keys[1][1] = 0xb2;
    h.n_seats = 2;
    for (int i = 0; i < 2; i++) { memcpy(h.seats[i].ckey, keys[i], 33); h.seats[i].state = GZ_SEAT_READY; h.seats[i].chosen = 1; }
    memset(&o, 0, sizeof o);
    o.round_id = id;

    /* FUNDING: Signing to Funding, saved */
    h.state = GZ_LOBBY_SIGNING;
    h.budget_ms = 1;                               /* a round was handed over (lobby_handoff.h) */
    o.kind = GZ_SIGN_OUTCOME_FUNDING;
    gz_action_list_init(&l, slots, 64, bytes, sizeof bytes);
    CHECK(gz_sign_lobby_outcome(&h, &o, &l) == GZ_OK && h.state == GZ_LOBBY_FUNDING && saves_of(&l, GZ_REC_LOBBY_STATE) == 1);

    /* RETRY with one blamed seat: it must ready again (Joined); the lobby goes back to Open */
    h.state = GZ_LOBBY_SIGNING;
    o.kind = GZ_SIGN_OUTCOME_RETRY;
    o.blamed = (const uint8_t (*)[33])keys[1]; o.n_blamed = 1;
    gz_action_list_init(&l, slots, 64, bytes, sizeof bytes);
    CHECK(gz_sign_lobby_outcome(&h, &o, &l) == GZ_OK && h.state == GZ_LOBBY_OPEN);
    CHECK(h.seats[1].state == GZ_SEAT_JOINED && h.seats[0].state == GZ_SEAT_READY && !h.seats[0].chosen);
    CHECK(saves_of(&l, GZ_REC_LOBBY_STATE) == 1);

    /* not while the lobby is not signing: the lobby refuses the command with a notice and changes
     * nothing; a blamed count without keys; an unknown kind */
    o.kind = GZ_SIGN_OUTCOME_FUNDING; o.blamed = NULL; o.n_blamed = 0;
    gz_action_list_init(&l, slots, 64, bytes, sizeof bytes);
    CHECK(gz_sign_lobby_outcome(&h, &o, &l) == GZ_OK && h.state == GZ_LOBBY_OPEN && saves_of(&l, GZ_REC_LOBBY_STATE) == 0);
    h.state = GZ_LOBBY_SIGNING;
    o.kind = GZ_SIGN_OUTCOME_RETRY; o.n_blamed = 1;
    CHECK(gz_sign_lobby_outcome(&h, &o, &l) == GZ_ERR_ARGUMENT);
    o.kind = (gz_sign_outcome_kind_t)9;
    CHECK(gz_sign_lobby_outcome(&h, &o, &l) == GZ_ERR_ARGUMENT);
    CHECK(gz_sign_lobby_outcome(NULL, &o, &l) == GZ_ERR_ARGUMENT);
    return check_done();
}
