/* SPDX-License-Identifier: MIT */
/* The program's view: GET /api/v1/status's attention list (local-api.md 11.4)
 * from the core's kind 7 items (gzp_view_attention). Each code's name, the
 * lobby's role (the item's own record, else the lobby's view kind, else the
 * code), the params of host_funds_short and member_refused, the order, and the
 * items left out: an unknown code, a lobby with no role, a malformed record. */
#include <stdio.h>
#include <string.h>

#include "gazpacho/command.h"
#include "gazpacho/envelope.h"
#include "gazpacho/view.h"
#include "view.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

static gzp_view_t V;

/* A kind 7 item: id, code, lobby, since, then role (0: none), need/have, count. */
static void item(const char *id, uint8_t code, const char *lobby, uint64_t since, uint8_t role, uint64_t need, uint64_t have,
                 uint16_t count)
{
    uint8_t b[256], v[8];
    size_t at = 0;
    char out[GZP_VIEW_ID_MAX + 1];
    gz_rec_put(b, sizeof b, &at, GZ_VIEW_REC_ID, (const uint8_t *)id, strlen(id));
    gz_rec_put(b, sizeof b, &at, GZ_VAT_CODE, &code, 1);
    gz_rec_put(b, sizeof b, &at, GZ_VAT_LOBBY, (const uint8_t *)lobby, strlen(lobby));
    gz_put_u64(v, since);
    gz_rec_put(b, sizeof b, &at, GZ_VAT_SINCE, v, 8);
    if (count) {
        gz_put_u16(v, count);
        gz_rec_put(b, sizeof b, &at, GZ_VAT_COUNT, v, 2);
    }
    if (need || have) {
        gz_put_u64(v, need);
        gz_rec_put(b, sizeof b, &at, GZ_VAT_NEED, v, 8);
        gz_put_u64(v, have);
        gz_rec_put(b, sizeof b, &at, GZ_VAT_HAVE, v, 8);
    }
    if (role) gz_rec_put(b, sizeof b, &at, GZ_VAT_ROLE, &role, 1);
    CHECK(gzp_view_apply(&V, GZ_VIEW_ATTENTION, b, at, out) == 1);
}

static void lobby_view(uint32_t kind, const char *id)
{
    uint8_t b[64];
    size_t at = 0;
    char out[GZP_VIEW_ID_MAX + 1];
    gz_rec_put(b, sizeof b, &at, GZ_VIEW_REC_ID, (const uint8_t *)id, strlen(id));
    CHECK(gzp_view_apply(&V, kind, b, at, out) == 1);
}

static const gz_api_attention *find(const gzp_attention_t *a, const char *id)
{
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->item[i].id, id) == 0) return &a->item[i];
    return NULL;
}

int main(void)
{
    static gzp_attention_t a;
    const gz_api_attention *x;
    /* the item's own role wins over the lobby's view kind */
    lobby_view(GZ_VIEW_LOBBY, "lob_00000000000000a1");
    item("att_00000000000000a1", GZ_ATT_HOST_FUNDS_SHORT, "lob_00000000000000a1", 30, GZ_ROLE_HOSTED, 900, 400, 0);
    /* no role record: the lobby's view kind says it */
    lobby_view(GZ_VIEW_HOST_LOBBY, "lob_00000000000000b2");
    item("att_00000000000000b2", GZ_ATT_MEMBER_REFUSED, "lob_00000000000000b2", 10, 0, 0, 0, 2);
    /* a left-out lobby has no view: its role comes from the item */
    item("att_00000000000000c3", GZ_ATT_LOBBY_LEFT_OUT, "lob_00000000000000c3", 20, GZ_ROLE_JOINED, 0, 0, 0);
    /* no role anywhere, and a code that says none: left out */
    item("att_00000000000000d4", GZ_ATT_LOBBY_LEFT_OUT, "lob_00000000000000d4", 5, 0, 0, 0, 0);
    /* an unknown code: left out */
    item("att_00000000000000e5", 99, "lob_00000000000000e5", 5, GZ_ROLE_JOINED, 0, 0, 0);
    /* a member's locked seat with no role record and no view: the code says joined */
    item("att_00000000000000f6", GZ_ATT_UNLOCK_TO_TAKE_PART, "lob_00000000000000f6", 10, 0, 0, 0, 0);
    gzp_view_attention(&V, &a);
    CHECK(a.n == 4 && a.skipped == 2);
    /* oldest first, then by id */
    CHECK(a.n == 4 && strcmp(a.item[0].id, "att_00000000000000b2") == 0 && strcmp(a.item[1].id, "att_00000000000000f6") == 0 &&
          strcmp(a.item[2].id, "att_00000000000000c3") == 0 && strcmp(a.item[3].id, "att_00000000000000a1") == 0);
    x = find(&a, "att_00000000000000a1");
    CHECK(x && strcmp(x->code, "host_funds_short") == 0 && strcmp(x->lobby_id, "lob_00000000000000a1") == 0 &&
          strcmp(x->lobby_role, "hosted") == 0 &&
          strcmp(x->params_json, "{\"lobby_id\":\"lob_00000000000000a1\",\"lobby_role\":\"hosted\",\"need_sat\":900,\"have_sat\":400}") == 0);
    x = find(&a, "att_00000000000000b2");
    CHECK(x && strcmp(x->code, "member_refused") == 0 && strcmp(x->lobby_role, "hosted") == 0 &&
          strcmp(x->params_json, "{\"lobby_id\":\"lob_00000000000000b2\",\"lobby_role\":\"hosted\",\"count\":2}") == 0);
    x = find(&a, "att_00000000000000c3");
    CHECK(x && strcmp(x->code, "lobby_left_out") == 0 && strcmp(x->lobby_role, "joined") == 0 &&
          strcmp(x->params_json, "{\"lobby_id\":\"lob_00000000000000c3\",\"lobby_role\":\"joined\"}") == 0);
    x = find(&a, "att_00000000000000f6");
    CHECK(x && strcmp(x->code, "unlock_to_take_part") == 0 && strcmp(x->lobby_role, "joined") == 0);
    CHECK(!find(&a, "att_00000000000000d4") && !find(&a, "att_00000000000000e5"));
    /* host_funds_short without its amounts is left out, never shown with made-up numbers */
    gzp_view_clear(&V);
    item("att_00000000000000a7", GZ_ATT_HOST_FUNDS_SHORT, "lob_00000000000000a7", 1, GZ_ROLE_HOSTED, 0, 0, 0);
    gzp_view_attention(&V, &a);
    CHECK(a.n == 0 && a.skipped == 1);
    gzp_view_clear(&V);
    if (failures) fprintf(stderr, "%d failures\n", failures);
    else printf("program_view: ok\n");
    return failures != 0;
}
