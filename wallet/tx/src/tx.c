/* Transactions: serialisation, strict parsing, txid, weight; networks, fee
 * rates and dust.  See docs/notes/wallet-tx.md sections 1.1, 1.2, 1.5, 1.6. */

#include <openssl/sha.h>

#include "internal.h"

const char *gzt_err_text(gzt_err e) {
    switch (e) {
    case GZT_OK: return "ok";
    case GZT_ERR_ARG: return "invalid argument";
    case GZT_ERR_MAINNET: return "mainnet is refused in this version";
    case GZT_ERR_PARSE: return "not a canonical transaction";
    case GZT_ERR_LIMIT: return "transaction beyond this library's limits";
    case GZT_ERR_SCRIPT: return "destination script not accepted";
    case GZT_ERR_DUST: return "amount below the dust limit";
    case GZT_ERR_FEE_CEILING: return "fee rate above the caller's ceiling";
    case GZT_ERR_FUNDS: return "not enough funds for amount and fee";
    case GZT_ERR_KEY: return "key does not match the coin's script";
    case GZT_ERR_SIGN: return "signing or signature verification failed";
    case GZT_ERR_STATE: return "funding not built, or another txid";
    case GZT_ERR_BUFFER: return "output buffer too small";
    case GZT_ERR_INTERNAL: return "internal self-check failed";
    }
    return "unknown error";
}

/* ---- networks ------------------------------------------------------------ */

/* Names held in the table itself, so that it has no pointers to relocate and
   lives in read-only data. */
static const struct { char name[10]; uint8_t id; gzw_network keys; } NETS[] = {
    {"signet", 1, GZW_NET_SIGNET},     /* the ids of GZT_NET_* */
    {"testnet", 2, GZW_NET_TESTNET},
    {"testnet4", 3, GZW_NET_TESTNET4},
    {"regtest", 4, GZW_NET_REGTEST},
};
#define N_NETS (sizeof NETS / sizeof NETS[0])

gzt_err gzt_network_from_name(const char *name, gzt_network *out) {
    if (!name || !out) return GZT_ERR_ARG;
    if (strcmp(name, "mainnet") == 0) return GZT_ERR_MAINNET;
    for (size_t i = 0; i < N_NETS; i++) {
        if (strcmp(name, NETS[i].name) == 0) {
            out->id = NETS[i].id;
            return GZT_OK;
        }
    }
    return GZT_ERR_ARG;
}

gzt_err gzt_network_to_keys(gzt_network net, gzw_network *out) {
    if (!out) return GZT_ERR_ARG;
    for (size_t i = 0; i < N_NETS; i++) {
        if (NETS[i].id == net.id) {
            *out = NETS[i].keys;
            return GZT_OK;
        }
    }
    return GZT_ERR_ARG;
}

/* ---- fee rates and dust ---------------------------------------------------- */

uint64_t gzt_fee_for_vsize(gzt_feerate rate, uint64_t vsize) {
    if (rate.sat_per_kvb > GZT_FEERATE_MAX_SAT_PER_KVB || vsize > 1000000) return UINT64_MAX;
    return (vsize * rate.sat_per_kvb + 999) / 1000;
}

gzt_err gzt_feerate_from_server(uint64_t server_sat_per_kvb, gzt_feerate ceiling,
                                gzt_feerate *out) {
    if (!out) return GZT_ERR_ARG;
    out->sat_per_kvb = 0;
    if (ceiling.sat_per_kvb == 0 || ceiling.sat_per_kvb > GZT_FEERATE_MAX_SAT_PER_KVB ||
        server_sat_per_kvb == 0)
        return GZT_ERR_ARG;
    if (server_sat_per_kvb > ceiling.sat_per_kvb) return GZT_ERR_FEE_CEILING;
    out->sat_per_kvb = server_sat_per_kvb;
    return GZT_OK;
}

int gzt_is_witness_program(const uint8_t *s, size_t len) {
    if (!s || len < 4 || len > 42) return 0;
    if (s[1] != len - 2) return 0;
    if (s[0] == 0x00) return len == 22 || len == 34;
    return s[0] >= 0x51 && s[0] <= 0x60;
}

uint64_t gzt_dust_limit(const uint8_t *s, size_t len) {
    if (!gzt_is_witness_program(s, len)) return 0;
    return (8 + 1 + (uint64_t)len + 67) * 3;
}

/* ---- hashing ----------------------------------------------------------- */

void gzt_sha256(const uint8_t *data, size_t len, uint8_t out[32]) { SHA256(data, len, out); }

void gzt_sha256d(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t h[32];
    SHA256(data, len, h);
    SHA256(h, 32, out);
}

void gzt_tagged_hash(const char *tag, const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint8_t buf[64 + 512];
    uint8_t t[32];
    SHA256((const uint8_t *)tag, strlen(tag), t);
    memcpy(buf, t, 32);
    memcpy(buf + 32, t, 32);
    if (len > 512) len = 512; /* callers never pass more; keeps the copy in bounds */
    if (len) memcpy(buf + 64, msg, len);
    SHA256(buf, 64 + len, out);
}

/* ---- serialisation --------------------------------------------------------- */

int gzt_tx_in_caps(const gzt_tx *tx) {
    if (tx->n_in == 0 || tx->n_in > GZT_MAX_INPUTS) return 0;
    if (tx->n_out == 0 || tx->n_out > GZT_MAX_OUTPUTS) return 0;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_txin *in = &tx->in[i];
        if (in->script_sig_len > GZT_MAX_SCRIPT || in->witness_count > GZT_MAX_WITNESS_ITEMS)
            return 0;
        for (unsigned j = 0; j < in->witness_count; j++)
            if (in->witness[j].len > GZT_MAX_WITNESS_ITEM) return 0;
    }
    for (uint32_t i = 0; i < tx->n_out; i++)
        if (tx->out[i].script_len > GZT_MAX_SCRIPT) return 0;
    return 1;
}

int gzt_tx_has_witness(const gzt_tx *tx) {
    for (uint32_t i = 0; i < tx->n_in; i++)
        if (tx->in[i].witness_count) return 1;
    return 0;
}

static void write_tx(gzt_w *w, const gzt_tx *tx, int witness) {
    gzt_put_le(w, tx->version, 4);
    if (witness) {
        gzt_put_u8(w, 0x00);
        gzt_put_u8(w, 0x01);
    }
    gzt_put_cs(w, tx->n_in);
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_txin *in = &tx->in[i];
        gzt_put(w, in->prev_txid, 32);
        gzt_put_le(w, in->prev_vout, 4);
        gzt_put_cs(w, in->script_sig_len);
        gzt_put(w, in->script_sig, in->script_sig_len);
        gzt_put_le(w, in->sequence, 4);
    }
    gzt_put_cs(w, tx->n_out);
    for (uint32_t i = 0; i < tx->n_out; i++) {
        gzt_put_le(w, tx->out[i].value, 8);
        gzt_put_cs(w, tx->out[i].script_len);
        gzt_put(w, tx->out[i].script, tx->out[i].script_len);
    }
    if (witness) {
        for (uint32_t i = 0; i < tx->n_in; i++) {
            const gzt_txin *in = &tx->in[i];
            gzt_put_cs(w, in->witness_count);
            for (unsigned j = 0; j < in->witness_count; j++) {
                gzt_put_cs(w, in->witness[j].len);
                gzt_put(w, in->witness[j].data, in->witness[j].len);
            }
        }
    }
    gzt_put_le(w, tx->locktime, 4);
}

gzt_err gzt_tx_serialize(const gzt_tx *tx, gzt_ser_form form, uint8_t *out, size_t cap,
                         size_t *len_out) {
    if (!tx || !out || !len_out) return GZT_ERR_ARG;
    *len_out = 0;
    if (form != GZT_SER_NO_WITNESS && form != GZT_SER_WITNESS) return GZT_ERR_ARG;
    if (!gzt_tx_in_caps(tx)) return GZT_ERR_ARG;
    gzt_w w = {out, cap, 0, 0};
    write_tx(&w, tx, form == GZT_SER_WITNESS && gzt_tx_has_witness(tx));
    if (w.over) return GZT_ERR_BUFFER;
    *len_out = w.len;
    return GZT_OK;
}

static gzt_err hash_form(const gzt_tx *tx, gzt_ser_form form, uint8_t out[32]) {
    uint8_t buf[GZT_MAX_TX_BYTES];
    size_t len;
    if (!out) return GZT_ERR_ARG;
    gzt_err e = gzt_tx_serialize(tx, form, buf, sizeof buf, &len);
    if (e) return e;
    gzt_sha256d(buf, len, out);
    gzw_wipe(buf, len); /* a wtxid serialises the signatures */
    return GZT_OK;
}

gzt_err gzt_tx_txid(const gzt_tx *tx, uint8_t out[32]) {
    return hash_form(tx, GZT_SER_NO_WITNESS, out);
}

gzt_err gzt_tx_wtxid(const gzt_tx *tx, uint8_t out[32]) {
    return hash_form(tx, GZT_SER_WITNESS, out);
}

gzt_err gzt_tx_weight(const gzt_tx *tx, uint64_t *weight_out, uint64_t *vsize_out) {
    /* Counted, not serialised, so that no copy of a signed transaction is
       left on the stack.  The tests compare it with real serialisations. */
    if (!weight_out || !vsize_out) return GZT_ERR_ARG;
    if (!tx || !gzt_tx_in_caps(tx)) return GZT_ERR_ARG;
    uint64_t base = 4 + gzt_cs_len(tx->n_in) + gzt_cs_len(tx->n_out) + 4, wit = 0;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        const gzt_txin *in = &tx->in[i];
        base += 32 + 4 + gzt_cs_len(in->script_sig_len) + in->script_sig_len + 4;
        wit += gzt_cs_len(in->witness_count);
        for (unsigned j = 0; j < in->witness_count; j++)
            wit += gzt_cs_len(in->witness[j].len) + in->witness[j].len;
    }
    for (uint32_t i = 0; i < tx->n_out; i++)
        base += 8 + gzt_cs_len(tx->out[i].script_len) + tx->out[i].script_len;
    *weight_out = 4 * base + (gzt_tx_has_witness(tx) ? 2 + wit : 0);
    *vsize_out = (*weight_out + 3) / 4;
    return GZT_OK;
}

uint64_t gzt_keypath_vsize(size_t n_in, const size_t *lens, size_t n_out) {
    if (n_in == 0 || n_in > GZT_MAX_INPUTS || n_out == 0 || n_out > GZT_MAX_OUTPUTS || !lens)
        return 0;
    uint64_t base = 4 + gzt_cs_len(n_in) + n_in * (32 + 4 + 1 + 4) + gzt_cs_len(n_out) + 4;
    for (size_t i = 0; i < n_out; i++) {
        if (lens[i] > GZT_MAX_SCRIPT) return 0;
        base += 8 + gzt_cs_len(lens[i]) + lens[i];
    }
    uint64_t wit = 2 + n_in * (1 + 1 + 64);
    return (4 * base + wit + 3) / 4;
}

/* ---- strict parsing ------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    size_t len, pos;
} gzt_r;

static int get(gzt_r *r, void *dst, size_t n) {
    if (n > r->len - r->pos) return 0;
    memcpy(dst, r->p + r->pos, n);
    r->pos += n;
    return 1;
}

static int get_le(gzt_r *r, size_t n, uint64_t *v) {
    uint8_t b[8];
    if (!get(r, b, n)) return 0;
    *v = 0;
    for (size_t i = 0; i < n; i++) *v |= (uint64_t)b[i] << (8 * i);
    return 1;
}

/* Compact size, minimal encoding only. */
static int get_cs(gzt_r *r, uint64_t *v) {
    uint64_t first;
    if (!get_le(r, 1, &first)) return 0;
    if (first < 0xfd) {
        *v = first;
        return 1;
    }
    size_t n = first == 0xfd ? 2 : first == 0xfe ? 4 : 8;
    uint64_t min = first == 0xfd ? 0xfd : first == 0xfe ? 0x10000 : UINT64_C(0x100000000);
    if (!get_le(r, n, v)) return 0;
    return *v >= min;
}

/* A length-prefixed field of at most cap bytes. */
static gzt_err get_bytes(gzt_r *r, uint8_t *dst, uint16_t *len, size_t cap) {
    uint64_t n;
    if (!get_cs(r, &n)) return GZT_ERR_PARSE;
    if (n > r->len - r->pos) return GZT_ERR_PARSE;
    if (n > cap) return GZT_ERR_LIMIT;
    get(r, dst, (size_t)n);
    *len = (uint16_t)n;
    return GZT_OK;
}

static gzt_err parse(gzt_r *r, gzt_tx *tx) {
    uint64_t v, n;
    gzt_err e;
    int segwit = 0;
    if (!get_le(r, 4, &v)) return GZT_ERR_PARSE;
    tx->version = (uint32_t)v;
    if (r->pos < r->len && r->p[r->pos] == 0x00) {
        if (r->len - r->pos < 2 || r->p[r->pos + 1] != 0x01) return GZT_ERR_PARSE;
        r->pos += 2;
        segwit = 1;
    }
    if (!get_cs(r, &n) || n == 0) return GZT_ERR_PARSE;
    if (n > GZT_MAX_INPUTS) return GZT_ERR_LIMIT;
    tx->n_in = (uint32_t)n;
    for (uint32_t i = 0; i < tx->n_in; i++) {
        gzt_txin *in = &tx->in[i];
        if (!get(r, in->prev_txid, 32) || !get_le(r, 4, &v)) return GZT_ERR_PARSE;
        in->prev_vout = (uint32_t)v;
        if ((e = get_bytes(r, in->script_sig, &in->script_sig_len, GZT_MAX_SCRIPT))) return e;
        if (!get_le(r, 4, &v)) return GZT_ERR_PARSE;
        in->sequence = (uint32_t)v;
    }
    if (!get_cs(r, &n) || n == 0) return GZT_ERR_PARSE;
    if (n > GZT_MAX_OUTPUTS) return GZT_ERR_LIMIT;
    tx->n_out = (uint32_t)n;
    uint64_t sum = 0;
    for (uint32_t i = 0; i < tx->n_out; i++) {
        gzt_txout *o = &tx->out[i];
        if (!get_le(r, 8, &o->value)) return GZT_ERR_PARSE;
        if (o->value > GZT_MAX_MONEY) return GZT_ERR_PARSE;
        sum += o->value;
        if (sum > GZT_MAX_MONEY) return GZT_ERR_PARSE;
        if ((e = get_bytes(r, o->script, &o->script_len, GZT_MAX_SCRIPT))) return e;
    }
    if (segwit) {
        for (uint32_t i = 0; i < tx->n_in; i++) {
            gzt_txin *in = &tx->in[i];
            if (!get_cs(r, &n)) return GZT_ERR_PARSE;
            if (n > GZT_MAX_WITNESS_ITEMS) return GZT_ERR_LIMIT;
            in->witness_count = (uint8_t)n;
            for (unsigned j = 0; j < in->witness_count; j++)
                if ((e = get_bytes(r, in->witness[j].data, &in->witness[j].len,
                                   GZT_MAX_WITNESS_ITEM)))
                    return e;
        }
        if (!gzt_tx_has_witness(tx)) return GZT_ERR_PARSE; /* superfluous witness record */
    }
    if (!get_le(r, 4, &v)) return GZT_ERR_PARSE;
    tx->locktime = (uint32_t)v;
    if (r->pos != r->len) return GZT_ERR_PARSE;
    return GZT_OK;
}

gzt_err gzt_tx_parse(const uint8_t *raw, size_t len, gzt_tx *out) {
    if (!out) return GZT_ERR_ARG;
    memset(out, 0, sizeof *out);
    if (!raw) return GZT_ERR_ARG;
    gzt_r r = {raw, len, 0};
    gzt_err e = parse(&r, out);
    if (e) memset(out, 0, sizeof *out);
    return e;
}
