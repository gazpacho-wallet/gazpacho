/* Routing a received message (composite-node.md section 4; layer 1 of 13).
 *
 * The transport has already checked the protocol bytes, the direction, the
 * record table, and put parts back together; kind 2 never reaches the core.
 *
 * 1. BY KIND, to an engine family: 16 to 63 lobby; 64 to 80 signing; 81
 *    (factory_funded) counted, nothing acted on; 32767 test (test builds
 *    only); 128 to 159 discovery, dropped and counted (never worth a
 *    disconnect); anything else dropped and counted.
 * 2. BY SCOPE, to a slot, or for round kinds to the signing engine while it
 *    holds a round under the scope (P4.3), or while the scope's Open slot has
 *    answered a check (member) or sent a start (host). A scope with no slot
 *    is dropped and counted; on the host an unknown scope's `hello` is
 *    answered with lobby state 0, and a scope-zero `hello` with the listing.
 * 3. THE LINK is checked. Member: the slot's link, derived from its keys
 *    (its contribution key, the pinned host key), or the message is dropped
 *    and the connection refused. Host: a lobby message's connection must be
 *    bound to the slot (section 3): an unbound connection's first nonzero
 *    scope binds it, and a bound one that sends another scope is refused.
 *    A round message's remote key is checked by the signing engine.
 *
 * Every decision is a pure function of the composite's state: no action is
 * taken here (nodepart.c carries it out). */
#include "internal.h"
#include <string.h>

int np_same_key(const gz_node_id_t *a, const gz_node_id_t *b)
{
    return memcmp(a->key, b->key, GZ_NODE_ID_LEN) == 0;
}

int np_same_link(const gz_link_t *a, const gz_link_t *b)
{
    return np_same_key(&a->local, &b->local) && np_same_key(&a->remote, &b->remote);
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

rt_family_t gz_route_family(uint16_t kind, int test_build)
{
    if (kind >= GZ_MSG_KIND_LOBBY_FIRST && kind <= GZ_MSG_KIND_LOBBY_LAST) return FAM_LOBBY;
    if (kind >= GZ_MSG_KIND_ROUND_FIRST && kind <= GZ_MSG_KIND_ROUND_LAST) return FAM_ROUND;
    if (kind == GZ_MSG_KIND_FACTORY_FUNDED) return FAM_FUNDED;
    if (kind == GZ_MSG_KIND_TEST && test_build) return FAM_TEST;
    if (kind >= GZ_MSG_KIND_DISCOVERY_FIRST && kind <= GZ_MSG_KIND_DISCOVERY_LAST) return FAM_DISCOVERY;
    return FAM_NONE;
}

int gz_route_slot_by_scope(const gz_node_t *c, const uint8_t scope[32])
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_OPEN && memcmp(c->slots[i].scope, scope, 32) == 0) return i;
    return -1;
}

/* A member slot's link, derived from its keys: (its contribution key, the
 * pinned host key). 0 if the key port has no key for it. */
int gz_route_slot_link(const gz_node_t *c, int slot, gz_link_t *link)
{
    const slot_t *s = &c->slots[slot];
    if (s->host || !c->cfg.keys.pub) return 0;
    if (!c->cfg.keys.pub(c->cfg.keys.ctx, s->key_epoch, s->key_index, link->local.key)) return 0;
    link->remote = s->host_key;
    return 1;
}

int gz_route_member_slot_of_link(const gz_node_t *c, const gz_link_t *link)
{
    gz_link_t l;
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++)
        if (c->slots[i].state == SLOT_OPEN && !c->slots[i].host && gz_route_slot_link(c, i, &l) &&
            np_same_link(&l, link))
            return i;
    return -1;
}

int gz_route_slot_seated(const gz_node_t *c, const gz_node_id_t *key)
{
    for (int i = 0; i < GZ_NODE_MAX_SLOTS; i++) {
        const slot_t *s = &c->slots[i];
        if (s->state != SLOT_OPEN || !s->host) continue;
        for (size_t j = 0; j < s->n_seated; j++)
            if (np_same_key(&s->seated[j], key)) return i;
    }
    return -1;
}

static rt_t mk(rt_kind_t kind, int slot, int eng, int drop)
{
    rt_t r;
    r.kind = kind;
    r.slot = slot;
    r.eng = eng;
    r.drop = drop;
    return r;
}

/* The test family: the engine record 3 names (0x7e57 if absent). */
static rt_t route_test(const gz_node_t *c, gz_bytes_t records)
{
    (void)c;
    (void)records;
#ifdef GZ_TEST_KINDS
    gz_bytes_t v;
    uint16_t area = (uint16_t)GZ_AREA_TEST;
    int f = gz_rec_find(records, 3, &v);
    if (f < 0) return mk(RT_DROP, -1, -1, DROP_KIND);
    if (f == 1) {
        if (v.len != 2) return mk(RT_DROP, -1, -1, DROP_KIND);
        area = gz_get_u16(v.data);
    }
    for (int i = 0; i < c->n_test; i++)
        if (c->test[i].area == area) return mk(RT_TEST, -1, ENG_TEST0 + i, 0);
#endif
    return mk(RT_DROP, -1, -1, DROP_KIND);
}

static rt_t route_lobby(const gz_node_t *c, int conn, const gz_link_t *link, uint16_t kind, const uint8_t scope[32])
{
    int zero = all_zero(scope, 32), s;
    if (c->cfg.host) {
        if (zero) return kind == GZ_MSG_KIND_HELLO ? mk(RT_LISTING, -1, -1, 0) : mk(RT_DROP, -1, -1, DROP_SCOPE_ZERO);
        s = gz_route_slot_by_scope(c, scope);
        int bound = conn >= 0 ? c->np.conns[conn].slot : -1;
        if (bound >= 0) return s == bound ? mk(RT_SLOT, s, -1, 0) : mk(RT_REFUSE, -1, -1, DROP_REBIND);
        if (s >= 0) return mk(RT_BIND, s, -1, 0);
        return kind == GZ_MSG_KIND_HELLO ? mk(RT_UNKNOWN_HELLO, -1, -1, 0) : mk(RT_DROP, -1, -1, DROP_NO_SLOT);
    }
    if (zero) return mk(RT_DROP, -1, -1, DROP_SCOPE_ZERO);
    s = gz_route_slot_by_scope(c, scope);
    if (s < 0) return mk(RT_DROP, -1, -1, DROP_NO_SLOT);
    gz_link_t l;
    if (!gz_route_slot_link(c, s, &l) || !np_same_link(&l, link)) return mk(RT_REFUSE, -1, -1, DROP_LINK);
    return mk(RT_SLOT, s, -1, 0);
}

static rt_t route_round(const gz_node_t *c, const gz_link_t *link, const uint8_t scope[32])
{
    int s;
    if (all_zero(scope, 32)) return mk(RT_DROP, -1, -1, DROP_SCOPE_ZERO);
    /* (P4.3: first, any round the signing engine holds under the scope,
     * resolved rounds included, with its link from the saved round.) */
    s = gz_route_slot_by_scope(c, scope);
    if (s < 0 || !c->slots[s].round_ok) return mk(RT_DROP, -1, -1, DROP_NO_SLOT);
    if (!c->cfg.host) {
        gz_link_t l;
        if (!gz_route_slot_link(c, s, &l) || !np_same_link(&l, link)) return mk(RT_REFUSE, -1, -1, DROP_LINK);
    }
    return mk(RT_SIGNING, s, -1, 0);
}

rt_t gz_route_message(const gz_node_t *c, int conn, const gz_link_t *link, uint16_t kind,
                      const uint8_t scope[32], gz_bytes_t records)
{
    switch (gz_route_family(kind, GZ_NODE_N_TEST > 0)) {
    case FAM_LOBBY:     return route_lobby(c, conn, link, kind, scope);
    case FAM_ROUND:     return route_round(c, link, scope);
    case FAM_FUNDED:    return mk(RT_DROP, -1, -1, DROP_FUNDED);
    case FAM_TEST:      return route_test(c, records);
    case FAM_DISCOVERY: return mk(RT_DROP, -1, -1, DROP_DISCOVERY);
    case FAM_NONE:      break;
    }
    return mk(RT_DROP, -1, -1, DROP_KIND);
}
