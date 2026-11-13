#!/usr/bin/env python3
"""Break-checks for the chain port.

For each safety behaviour: remove it from the source, rebuild, and require
that at least one test now fails. A behaviour whose removal no test notices
is reported as SURVIVED and makes the run fail. The source is restored after
every change (git checkout of that file).

  python3 -I ports/chain/tests/break_checks.py BUILD_DIR [NAME-PREFIX ...]

BUILD_DIR is a configured build of this repository. Checks marked "slow"
also run the local-server test (label "slow"); the others run every chain_
test except that one. Not part of ctest: it edits the working tree while it
runs, so it refuses to start with uncommitted changes in ports/chain.
"""
import os
import subprocess
import sys

P = "ports/chain/"
C, H, V, J, E, M, T, G = (P + "chain.c", P + "headers.c", P + "verify.c", P + "json.c",
                          P + "esplora.c", P + "multi.c", P + "http_curl.c", P + "tools/gz-chain.c")
SLOW = True

CHECKS = [
    # ---------------------------------------------------------------- strict parsing
    ("p1 accept a field the interface does not define", E,
     "return false; /* a field this interface does not define */", "(void)0;"),
    ("p2 accept an object with the same key twice", J,
     "if (same_bytes(p, &p->toks[i], &p->toks[key])) return false;", "(void)same_bytes;"),
    ("p3 accept text after the JSON value", J, "if (p.pos != p.len) return false;", ""),
    ("p4 accept an amount above 21 million bitcoin", E,
     "|| o.value > GZ_MAX_MONEY) goto done;", ") goto done;"),
    ("p5 accept a confirmed status without a block", E,
     "if (seen != (F_CONFIRMED | F_HEIGHT | F_HASH | F_TIME)) return false;", ""),
    ("p6 accept a Merkle position outside the tree (parser)", E,
     "if (p.depth < 32 && (p.pos >> p.depth) != 0) return false;", ""),
    ("p7 accept more Merkle nodes than the limit", E,
     "val->type != GZ_JSON_ARRAY || val->size > GZ_MERKLE_MAX_DEPTH", "val->type != GZ_JSON_ARRAY"),
    ("p8 accept the same outpoint listed twice", E,
     "if (output_cmp(&out[k - 1], &out[k]) == 0) goto done; /* same outpoint twice */", ""),
    ("p9 accept upper-case hex", C,
     "if (c >= 'a' && c <= 'f') return c - 'a' + 10;",
     "if (c >= 'a' && c <= 'f') return c - 'a' + 10;\n  if (c >= 'A' && c <= 'F') return c - 'A' + 10;"),
    ("p10 accept a non-canonical length inside a transaction", C,
     "if (v < min) return false;", "(void)min;"),
    ("p11 accept a transaction with bytes left over", C,
     "if (!rd_skip(&r, 4) || r.pos != len) return false;", "if (!rd_skip(&r, 4)) return false;"),
    ("p12 accept a header shorter than 160 characters (review e10)", E,
     "if (s == NULL || len != 2 * GZ_HEADER_LEN) return false;",
     "if (s == NULL || len > 2 * GZ_HEADER_LEN) return false;"),
    ("p13 proof height bound raised to 32 bits (review e25)", E,
     "if (!tok_u32(s, val, GZ_MAX_HEIGHT, &p.block_height)) return false;",
     "if (!tok_u32(s, val, UINT32_MAX, &p.block_height)) return false;"),
    ("p14 fee answer accepted with any status (review e29)", E,
     "if (status != 200 && status != 203)\n    return status == 404 ? GZ_CHAIN_MALFORMED : status_meaning(status);",
     ""),
    ("p15 single-server fee bound back at 21 million bitcoin (item 3)", E,
     "rate > GZ_FEE_MAX_SAT_PER_KVB) return false;", "rate > GZ_MAX_MONEY) return false;"),
    ("p16 block with zero transactions accepted", E,
     "if (!tok_u32(s, val, GZ_MAX_BLOCK_TXS, &b.tx_count) || b.tx_count == 0) return false;",
     "if (!tok_u32(s, val, UINT32_MAX, &b.tx_count)) return false;"),
    # ---------------------------------------------------------------- transactions
    ("x1 accept a transaction with no inputs (review c1)", C,
     "if (!rd_varint(&r, &n_in) || n_in == 0) return false;", "if (!rd_varint(&r, &n_in)) return false;"),
    ("x2 accept a transaction with no outputs (review c2)", C,
     "if (!rd_varint(&r, &n_out) || n_out == 0) return false;", "if (!rd_varint(&r, &n_out)) return false;"),
    ("x3 reader skips without a bound (review c6)", C, "if (n > r->len - r->pos) return false;", ""),
    ("x4 accept a 64-byte transaction (item 6)", C,
     "if (4 + (body_end - body_start) + 4 == 64) return false;", ""),
    ("x5 anything with one input is a coinbase", C,
     "return memcmp(raw + pos + 1, null_outpoint, sizeof null_outpoint) == 0;",
     "(void)null_outpoint;\n  return true;"),
    # ---------------------------------------------------------------- interface front
    ("f1 no height bound on block_header (review c7)", C,
     "if (!usable(c) || out == NULL || height > GZ_MAX_HEIGHT) return GZ_CHAIN_INVALID_ARG;\n  memset(out, 0, GZ_HEADER_LEN);",
     "if (!usable(c) || out == NULL) return GZ_CHAIN_INVALID_ARG;\n  memset(out, 0, GZ_HEADER_LEN);"),
    ("f2 broadcast does not parse the transaction first (review c8)", C,
     "  if (!gz_txid_from_raw(raw, len, txid)) return GZ_CHAIN_INVALID_ARG;\n  if (c->ops->broadcast == NULL)",
     "  (void)txid;\n  if (c->ops->broadcast == NULL)"),
    ("f3 no size limit on what is broadcast (review e17)", C,
     "  if (len > GZ_TX_MAX_BYTES) return GZ_CHAIN_INVALID_ARG;\n", ""),
    ("f4 a backend missing a call is jumped into", C,
     "  if (c->ops->tx_status == NULL) return GZ_CHAIN_INVALID_ARG;\n", ""),
    # ---------------------------------------------------------------- networks (item 2)
    ("n1 a server on another network passes the network check", C,
     "return found == network ? GZ_CHAIN_OK : GZ_CHAIN_WRONG_NETWORK;", "return GZ_CHAIN_OK;"),
    ("n2 no network at all accepted by the network check", C,
     "  if (!gz_network_valid(network)) return GZ_CHAIN_INVALID_ARG;\n  gz_chain_result r = gz_chain_identify_network",
     "  gz_chain_result r = gz_chain_identify_network"),
    ("n3 comparing backend never checks a server's network", M,
     "static bool ready(multi *m, size_t i) {\n  if (m->net[i] == NET_RIGHT) return true;",
     "static bool ready(multi *m, size_t i) {\n  if (m->net[i] == NET_RIGHT || 1) return true;"),
    ("n4 broadcast sent to a server on another network", M,
     "    if (!ready(m, i)) {\n      a->u.broadcast.result = a->result;\n      continue;\n    }\n", ""),
    ("n5 comparing backend made without a network", M,
     "if (!gz_network_valid(cfg->network)) return GZ_CHAIN_INVALID_ARG;", ""),
    ("n6 confirm_tx does not check the network first", V,
     "  if (r != GZ_CHAIN_OK) return r;\n\n  gz_tx_status status;", "  (void)r;\n\n  gz_tx_status status;"),
    ("n7 proof of work for no network falls back to a default", H,
     "if (!gz_network_valid(network)) return GZ_POW_BAD_NETWORK;", ""),
    # ---------------------------------------------------------------- answers checked against what they must match
    ("a1 raw transaction not checked against the txid asked for", E,
     "if (memcmp(check, txid, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;", ""),
    ("a2 header not checked against the block hash for its height", E,
     "if (memcmp(check, hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;", ""),
    ("a3 confirmation above the server's own tip accepted", E,
     "if (tip < st.height) return GZ_CHAIN_MALFORMED;", ""),
    ("a4 broadcast answer naming another txid accepted", E,
     "if (!gz_hash_from_hex(body, len, got) || memcmp(got, want, GZ_HASH_LEN) != 0) {",
     "if (!gz_hash_from_hex(body, len, got)) {"),
    ("a5 block summary describing another block accepted", E,
     "if (memcmp(block.id, hash, GZ_HASH_LEN) != 0 || block.height != height) return GZ_CHAIN_MALFORMED;", ""),
    # ---------------------------------------------------------------- broadcast (item 8)
    ("b1 broadcast answer not trimmed", E,
     "    while (len > 0 && is_blank(body[len - 1])) len--;\n", ""),
    ("b2 'already known' believed without seeing the transaction", E,
     "      if (es_tx_status(es, want, &st) == GZ_CHAIN_OK &&\n          (st.state == GZ_TX_MEMPOOL || st.state == GZ_TX_CONFIRMED)) {",
     "      if (1) {"),
    ("b3 'already known' not recognised", E,
     "if (gz_es_reason_is_already_known(out->reason)) {", "if (0) {"),
    # ---------------------------------------------------------------- size caps, time limits, retries, rate
    ("s1 no per-call size cap", E,
     "if (cap > es->cfg.max_response_bytes) cap = es->cfg.max_response_bytes;",
     "cap = es->cfg.max_response_bytes;"),
    ("s2 the transport's reported length trusted", E,
     "if (resp.len > cap) return GZ_CHAIN_TOO_LARGE; /* a transport that broke its promise */", ""),
    ("s3 no cap on the number of outputs", E, "if (toks[0].size > cap) {", "if (0) {"),
    ("s4 backend allowed without a time limit", E, "cfg->timeout_ms == 0 || ", ""),
    ("s5 retries without bound", E,
     "attempt < es->cfg.max_attempts; attempt++", "attempt < es->cfg.max_attempts + 3; attempt++"),
    ("s6 broadcast repeated after a timeout", E, "if (post && hr != GZ_HTTP_E_CONNECT) break;", ""),
    ("s7 no minimum interval between requests", E,
     "now - es->last_ms < es->cfg.min_interval_ms) {",
     "now - es->last_ms < es->cfg.min_interval_ms && es->cfg.max_attempts == 0) {"),
    ("s8 backoff not capped (review e22)", E,
     "if (wait > ES_MAX_BACKOFF_MS) wait = ES_MAX_BACKOFF_MS;", ""),
    # ---------------------------------------------------------------- addresses and operators (items 1, 10)
    ("o1 plain http to any host (backend)", E,
     "if (!https && !gz_host_is_loopback(info->host)) return false;", ""),
    ("o2 host names not normalised to lower case", C,
     "if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');", ""),
    ("o3 every host name its own operator", C,
     "} else if (!canonical_ipv4(norm, strlen(norm))) {", "} else if (0) {"),
    ("o10 a trailing dot kept: one host, two spellings (review A)", C,
     "if (len > 0 && in[len - 1] == '.') len--; /* the DNS root: one trailing dot */", ""),
    ("o11 numeric host forms other than dotted IPv4 accepted", C,
     "if (is_digit(out[last_label]) && !canonical_ipv4(out, len)) return false;", "(void)last_label;"),
    ("o12 empty labels accepted", C,
     "if (label == 0 || out[i - 1] == '-') return false;", "if (label > 63) return false;"),
    ("o13 this machine's names counted as separate operators", C,
     "start = LOOPBACK_OPERATOR; /* one machine is one operator, by any name */", "start = norm;"),
    ("o14 hosts a backend describes not normalised", M,
     "if (!gz_host_normalise(info[i].host, strlen(info[i].host), host)) return GZ_CHAIN_INVALID_ARG;\n        memcpy(info[i].host, host, sizeof host);",
     "(void)host;"),
    ("o15 operator names in any spelling", C,
     "if (edge || (c == '.' && id[i - 1] == '.')) return false;", "(void)edge;"),
    ("o16 requests sent to the address as given", E,
     "memcpy(es->base, info.endpoint, strlen(info.endpoint) + 1);",
     "memcpy(es->base, cfg->base_url, strlen(cfg->base_url) + 1);"),
    ("o17 user information accepted by the backend", C,
     "return false; /* not part of a host name: '@', '%', ':', '/', non-ASCII... */",
     "if (c != '@') return false;"),
    ("o4 the same handle twice accepted", M,
     "if (servers[j].ctx == servers[i].ctx) return GZ_CHAIN_INVALID_ARG;", ""),
    ("o5 the same host twice accepted", M,
     "if (info[i].host[0] != '\\0' && strcmp(info[i].host, info[j].host) == 0)\n        return GZ_CHAIN_INVALID_ARG;",
     ""),
    ("o6 servers counted instead of operators", M,
     "if (in[i] && !seen[m->op[i]]) {", "if (in[i] && (seen[m->op[i]] || 1)) {"),
    ("o7 more servers than the array holds (review m23)", M,
     "if (count < 1 || count > GZ_MULTI_MAX_SERVERS) return GZ_CHAIN_INVALID_ARG;",
     "if (count < 1) return GZ_CHAIN_INVALID_ARG;"),
    ("o8 quorum of one allowed", M,
     "if (cfg->quorum < 2 || cfg->quorum > GZ_MULTI_MAX_SERVERS ||",
     "if (cfg->quorum < 1 || cfg->quorum > GZ_MULTI_MAX_SERVERS ||"),
    ("o9 tip slack unbounded (review m24)", M, " || cfg->tip_slack > GZ_MULTI_LAG_MAX_BLOCKS)", ")"),
    ("o18 comparing backend made without a clock", M,
     "if (cfg->now_ms == NULL) return GZ_CHAIN_INVALID_ARG; /* lag must be timed */", ""),
    # ---------------------------------------------------------------- disagreement detection
    ("d1 different positive answers accepted", M,
     "return GZ_CHAIN_DISAGREE; /* two different positive answers */", "(void)0;"),
    ("d2 one server has it, another not: answer anyway", M,
     "if (first_ok != m->n && first_missing != m->n) {", "if (0) {"),
    ("d3 answer from fewer operators than the quorum", M,
     "if (operators_among(m, in) < m->cfg.quorum) return no_quorum(m);\n  *which = ",
     "*which = "),
    ("d4 block hashes not compared (review m21)", M,
     "return hash_eq(a->u.block_hash, b->u.block_hash);", "(void)a;\n  (void)b;\n  return true;"),
    ("d5 headers not compared (review m20)", M,
     "return memcmp(a->u.header, b->u.header, GZ_HEADER_LEN) == 0;", "(void)a;\n  (void)b;\n  return true;"),
    ("d6 proof position not compared (review m11)", M, "  if (x->pos != y->pos) return false;\n", ""),
    ("d7 proof nodes not compared (review m12)", M,
     "return memcmp(x->nodes, y->nodes, (size_t)x->depth * GZ_HASH_LEN) == 0;", "return true;"),
    ("d8 proof height not compared (review m13)", M,
     "if (x->block_height != y->block_height) return false;", ""),
    ("d9 raw transactions compared by length only (witness)", M,
     "return a->u.raw_tx.len == b->u.raw_tx.len && hash_eq(a->u.raw_tx.digest, b->u.raw_tx.digest);",
     "return a->u.raw_tx.len == b->u.raw_tx.len;"),
    ("d10 comparing layer does not recheck the txid (review m14)", M,
     "if (got > cap || !gz_txid_from_raw(buf, got, check) || !hash_eq(check, txid)) {",
     "(void)check;\n    if (got > cap) {"),
    ("d11 buffer left by a failing server handed on (review m15)", M,
     "if (last_len != a->u.raw_tx.len || !hash_eq(digest, a->u.raw_tx.digest)) {", "if (0) {"),
    ("d12 broadcast accepted under another txid (review m16)", M,
     "if (a->result == GZ_CHAIN_OK && !hash_eq(a->u.broadcast.txid, txid)) {", "if (0) {"),
    ("d13 confirmed in two different places accepted", M,
     "        conflict = true; /* confirmed in two different places */", "        (void)0;"),
    ("d14 two different confirmed spends accepted", M,
     "        conflict = true; /* two different confirmed spends */", "        (void)0;"),
    ("d15 confirmed outputs compared without their data (review m10)", M,
     "x->vout == y->vout && x->value == y->value &&\n         x->confirmed == y->confirmed && x->height == y->height &&\n         hash_eq(x->block_hash, y->block_hash);",
     "x->vout == y->vout && x->value == y->value;"),
    ("d16 confirmed output lists compared by count only (review m22)", M,
     "if (!output_eq(&x[i], &y[j])) return false;", ""),
    ("d17 claimed confirmations: highest instead of lowest", M,
     "if (in[i] && a[i].u.tx_status.claimed_confirmations < out->claimed_confirmations) {",
     "if (in[i] && a[i].u.tx_status.claimed_confirmations > out->claimed_confirmations) {"),
    # ---------------------------------------------------------------- tip and lag (item 7)
    ("t1 tip: the highest reported instead of the lowest (review m27)", M,
     "if (lowest == m->n || a[i].u.tip.height < a[lowest].u.tip.height) lowest = i;",
     "if (lowest == m->n || a[i].u.tip.height > a[lowest].u.tip.height) lowest = i;"),
    ("t2 tip: server ahead with no block at the lower height only dropped (review m5)", M,
     "return finish(m, GZ_CHAIN_DISAGREE); /* ahead, yet no block at the lower height */", "in[i] = false;"),
    ("t3 tip: any distance apart accepted", M,
     "if (t->height - low->height > m->cfg.tip_slack) return finish(m, GZ_CHAIN_DISAGREE);", ""),
    ("t4 tip: server ahead not checked to hold the lower tip", M,
     "if (!hash_eq(at_low, low->hash)) return finish(m, GZ_CHAIN_DISAGREE);", ""),
    ("t5 lag never reported", M,
     "  if (height == 0 || !tips_show_lag(m, in, tips)) return false;",
     "  if (height == 0 || !tips_show_lag(m, in, tips) || 1) return false;"),
    ("t6 lag of any size", M, "if (high - tips[low].height > m->cfg.tip_slack) return false;", ""),
    ("t7 lag across two chains", M,
     "               !hash_eq(at_low, tips[low].hash)) {", "               !hash_eq(at_low, at_low)) {"),
    ("t8 lag judged from the tips alone (review B)", M,
     "    if (has[i] ? tips[i].height < height : tips[i].height >= height) return false;\n",
     "    (void)has[i];\n    (void)height;\n"),
    ("t10 lag without a time limit (review B)", M,
     "return now - m->lag_since_ms <= GZ_MULTI_LAG_MAX_MS;", "return now >= m->lag_since_ms;"),
    ("t11 lag period not ended by level tips (comparison)", M,
     "  if (high == tips[low].height) { /* nobody is behind */\n    lag_over(m);",
     "  if (high == tips[low].height) { /* nobody is behind */\n    (void)lag_over;"),
    ("t12 lag period not ended by level tips (tip call)", M,
     "if (all_level) lag_over(m); /* every server at one tip: nobody is behind */", "(void)all_level;"),
    ("t13 outputs: lag without a confirmed spend above the lister's tip", M,
     "if (sp.spent && sp.confirmed && sp.height > tips[i].height && sp.height <= tips[j].height)",
     "if (sp.spent)"),
    ("t14 outputs: a new output taken as lag at any height", M,
     "if (o->height > tips[j].height && o->height <= tips[i].height) continue; /* new */",
     "continue; /* new */"),
    ("t15 outputs: one outpoint with two sets of details taken as lag", M,
     "          if (!output_eq(p, o)) return false;\n", ""),
    ("t16 confirmation: headers followed past the agreed tip (review D)", V,
     "if (height > GZ_MAX_HEIGHT - k || height + k > tip.height) break;",
     "if (height > GZ_MAX_HEIGHT - k) break;"),
    # ---------------------------------------------------------------- unconfirmed data (item 7)
    ("u1 transaction: a mempool difference blanks the view", M,
     "  if (n_confirmed == 0) {\n    /* nothing confirmed anywhere: that much is agreed */\n    memset(out, 0, sizeof *out);\n    if (n_mempool == n_ok) {",
     "  if (n_confirmed == 0 && n_mempool == n_ok) {\n    /* nothing confirmed anywhere: that much is agreed */\n    memset(out, 0, sizeof *out);\n    if (n_mempool == n_ok) {"),
    ("u2 outputs: unconfirmed ones compared as if confirmed", M,
     "    while (i < nx && !x[i].confirmed) i++;\n    while (j < ny && !y[j].confirmed) j++;\n", ""),
    ("u3 outputs: an unconfirmed one from a single server kept", M,
     "    if (everywhere) out[kept++] = *o;", "    if (everywhere || 1) out[kept++] = *o;"),
    ("u5 outputs: differences not flagged (review m22', m49)", M,
     "    if (in[i] && a[i].u.outputs.count != kept) differs = true;\n", ""),
    ("u6 outputs: a list naming one outpoint twice accepted", M,
     "if (output_cmp(&mine[k - 1], &mine[k]) == 0) a[i].result = GZ_CHAIN_MALFORMED; /* listed twice */",
     "(void)0;"),
    ("u4 spend: different unconfirmed spenders taken as agreed", M,
     "      } else if (!same_spender(&a[first_pending].u.outspend, o)) {",
     "      } else if (0) {"),
    # ---------------------------------------------------------------- fees (item 3)
    ("e1 fees: highest instead of lowest", M,
     "combined.entries[combined.count].sat_per_kvb = lowest;",
     "combined.entries[combined.count].sat_per_kvb = highest;"),
    ("e2 fees: no disagreement however far apart", M,
     "if (highest > lowest * m->cfg.fee_disagree_factor + m->cfg.fee_disagree_slack_sat_per_kvb)\n      return finish(m, GZ_CHAIN_DISAGREE);",
     ""),
    ("e3 fees: comparing backend's ceiling ignored", M,
     "if (lowest > m->cfg.fee_ceiling_sat_per_kvb) lowest = m->cfg.fee_ceiling_sat_per_kvb;", ""),
    ("e4 fees: answer from one operator", M,
     "if (operators_among(m, in) < m->cfg.quorum) return finish(m, no_quorum(m));\n\n  /* Every target",
     "/* Every target"),
    ("e5 fees: a target fewer than a quorum answer for kept (review C)", M,
     "if (operators_among(m, answered) < m->cfg.quorum) continue;", "(void)answered;"),
    ("e10 fees: a server answers for a faster target with a slower one's rate (review C)", M,
     "if (e->target <= target && (best == NULL || e->target > best->target)) best = e;\n  }\n  return best;",
     "if (best == NULL || e->target > best->target) best = e;\n  }\n  (void)target;\n  return best;"),
    ("e11 fees: a slower target chosen when no faster one is listed (review C)", C,
     "if (pick == NULL) return GZ_CHAIN_NOT_FOUND;", "if (pick == NULL) pick = &est.entries[0];"),
    ("e6 fees: servers asked on test networks", C, "if (gz_network_is_test(network)) {", "if (0) {"),
    ("e7 fees: no floor", C, "if (rate < GZ_FEE_MIN_SAT_PER_KVB) rate = GZ_FEE_MIN_SAT_PER_KVB;", ""),
    ("e8 fees: caller's ceiling ignored", C,
     "if (rate > ceiling_sat_per_kvb) {\n    rate = ceiling_sat_per_kvb;", "if (0) {\n    rate = ceiling_sat_per_kvb;"),
    ("e9 fees: no ceiling required", C, "|| ceiling_sat_per_kvb == 0)", ")"),
    # ---------------------------------------------------------------- proofs and confirmation counts (items 5, 6)
    ("v1 confirm: a server that cannot show the block gives a clean 'no' (review v1)", V,
     "return r == GZ_CHAIN_NOT_FOUND ? GZ_CHAIN_BAD_PROOF : r;", "return r;"),
    ("v2 confirm: Merkle proof not checked against the header", V,
     "if (!gz_merkle_verify(txid, &out->proof, out->header)) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v3 confirm: neither header nor summary tied to the stated block", V,
     [("if (memcmp(hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;", ""),
      ("if (memcmp(out->block.hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;", "")], None),
    ("v4 confirm: proof height not checked", V,
     "if (out->proof.block_height != height) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v5 confirm: proof of work not checked", V,
     "if (gz_header_check_pow(out->header, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;", "(void)0;"),
    ("v6 confirm: proof depth not checked against the transaction count", V,
     "if (out->proof.depth != depth) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v7 confirm: no coinbase cross-check", V,
     "    if (cb_proof.block_height != height || cb_proof.pos != 0 || cb_proof.depth != depth)\n      return GZ_CHAIN_BAD_PROOF;\n    if (!gz_merkle_verify(out->block.coinbase_txid, &cb_proof, out->header))\n      return GZ_CHAIN_BAD_PROOF;\n",
     ""),
    ("v8 confirm: the coinbase position may hold any transaction", V,
     "    if (memcmp(txid, out->block.coinbase_txid, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;\n    if (!tx_is_coinbase) return GZ_CHAIN_BAD_PROOF;\n",
     ""),
    ("v9 confirm: later headers not checked to link", V,
     "if (!gz_header_links(prev, next)) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v10 confirm: more confirmations counted than asked for", V,
     "for (uint32_t k = 1; k < want; k++) {", "for (uint32_t k = 1; k < want + 5; k++) {"),
    ("v11 confirm: half-checked result left in the output", V,
     "    memset(out, 0, sizeof *out);\n  }\n  return r;", "  }\n  return r;"),
    # review F: each coinbase step and the other confirmation checks on their own
    ("v19 confirm: transaction bytes not rechecked against the txid (review v2)", V,
     "if (!gz_txid_from_raw(txbuf, tx_len, check) || memcmp(check, txid, GZ_HASH_LEN) != 0)\n    return GZ_CHAIN_BAD_PROOF;\n  bool tx_is_coinbase",
     "bool tx_is_coinbase"),
    ("v20 confirm: position not below the count (review v4)", V,
     "if (out->proof.pos >= out->block.tx_count) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v21 confirm: summary not tied to the status block (review v5)", V,
     "if (memcmp(out->block.hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v22 confirm: coinbase branch depth not compared (review v6)", V,
     "cb_proof.pos != 0 || cb_proof.depth != depth)", "cb_proof.pos != 0)"),
    ("v23 confirm: coinbase not checked to be a coinbase (review v7)", V,
     "    if (!gz_tx_is_coinbase(txbuf, tx_len)) return GZ_CHAIN_BAD_PROOF;\n    r = must_exist",
     "    r = must_exist"),
    ("v24 confirm: coinbase branch not verified (review v8)", V,
     "if (!gz_merkle_verify(out->block.coinbase_txid, &cb_proof, out->header))\n      return GZ_CHAIN_BAD_PROOF;", ""),
    ("v25 confirm: a coinbase accepted at a later position (review v9)", V,
     "if (tx_is_coinbase) return GZ_CHAIN_BAD_PROOF; /* a coinbase anywhere but first */", ""),
    ("v26 confirm: later headers' proof of work not checked (review v11)", V,
     "if (gz_header_check_pow(next, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;", ""),
    ("v27 confirm: no cap on depth (review v14)", V,
     "if (want_confirmations > GZ_CONFIRM_MAX_DEPTH) want_confirmations = GZ_CONFIRM_MAX_DEPTH;", ""),
    ("x6 64-byte rule measured with the witness (review c13)", C,
     "if (4 + (body_end - body_start) + 4 == 64) return false;", "if (len == 64) return false;"),
    ("x7 coinbase: more than one input allowed (review c14)", C,
     "if (raw[pos] != 0x01) return false; /* exactly one input */", ""),
    ("v12 Merkle: any root accepted", H,
     "return memcmp(root, header + 36, GZ_HASH_LEN) == 0;", "(void)root;\n  return true;"),
    ("v13 Merkle: position ignored", H, "if (pos & 1) {", "if (0) {"),
    ("v14 Merkle: duplicated last node accepted (item 6)", H,
     "if (memcmp(proof->nodes[i], cur, GZ_HASH_LEN) == 0) return false;", ""),
    ("v15 proof of work: hash not compared with the target", H,
     "if (memcmp(hash_be, target, GZ_HASH_LEN) > 0) return GZ_POW_HASH_ABOVE;", "(void)hash_be;"),
    ("v16 proof of work: any target however easy", H,
     "if (memcmp(target, limit, GZ_HASH_LEN) > 0) return GZ_POW_TOO_EASY;", ""),
    ("v17 signet limit made as easy as regtest (review h5)", H,
     "case GZ_NET_SIGNET: return 0x1e0377ae;", "case GZ_NET_SIGNET: return 0x207fffff;"),
    ("v18 header link check always passes", H,
     "return memcmp(h, next + 4, GZ_HASH_LEN) == 0;", "(void)next;\n  return true;"),
    # ---------------------------------------------------------------- transport (review t1-t6), local servers
    ("h1 TLS certificate not verified (review t1)", T,
     "CURLOPT_SSL_VERIFYPEER, 1L)", "CURLOPT_SSL_VERIFYPEER, 0L)", SLOW),
    ("h2 TLS host name not verified (review t2)", T,
     "CURLOPT_SSL_VERIFYHOST, 2L)", "CURLOPT_SSL_VERIFYHOST, 0L)", SLOW),
    ("h3 redirects followed (review t3)", T,
     "CURLOPT_FOLLOWLOCATION, 0L)", "CURLOPT_FOLLOWLOCATION, 1L)", SLOW),
    ("h4 body size cap not enforced while reading, nor by libcurl (review t4)", T,
     [("if (n > s->cap - s->len) {", "if (0) {"),
      ("  ok = ok && curl_easy_setopt(e, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)cap) == CURLE_OK;\n", "")],
     None, SLOW),
    ("h5 plain http to any host (review t5)", T,
     "if (!https && !local_http) return GZ_HTTP_E_FAILED;", "(void)local_http;", SLOW),
    ("h6 no time limit (review t6)", T,
     "  ok = ok && curl_easy_setopt(e, CURLOPT_TIMEOUT_MS, (long)req->timeout_ms) == CURLE_OK;\n", "", SLOW),
    # The strict authority parser and libcurl's own parse each refuse user
    # information; removing one leaves the other, so the check removes both.
    ("h8 transport: user information in the authority accepted (review E)", T,
     [("      if (!is_alnum(c) && c != '.' && c != '-') return false;", "      (void)c;"),
      ("  ok = ok && curl_url_get(u, CURLUPART_USER, &got, 0) == CURLUE_NO_USER;\n"
       "  ok = ok && curl_url_get(u, CURLUPART_PASSWORD, &got, 0) == CURLUE_NO_PASSWORD;\n"
       "  ok = ok && curl_url_get(u, CURLUPART_HOST, &got, 0) == CURLUE_OK && got != NULL &&\n"
       "       strcmp(got, host) == 0;\n",
       "  (void)host;\n")],
     None, SLOW),
    ("h9 transport: loopback recognised by prefix (review E)", T,
     "  bool local_http = !https && is_loopback_host(host);",
     "  (void)is_loopback_host;\n  bool local_http = !https && strncmp(req->url, \"http://localhost\", 16) == 0;", SLOW),
    ("h10 proxy from the environment followed", T,
     '  ok = ok && curl_easy_setopt(e, CURLOPT_PROXY, c->proxy != NULL ? c->proxy : "") == CURLE_OK;\n',
     "", SLOW),
    ("h7 User-Agent not set", T,
     "  ok = ok && curl_easy_setopt(e, CURLOPT_USERAGENT, GZ_HTTP_USER_AGENT) == CURLE_OK;\n", "", SLOW),
    # ---------------------------------------------------------------- the tool (review g1-g4)
    ("g1 tool: mainnet flag not refused", G,
     'strcmp(cmd, "broadcast") == 0 && a.network == GZ_NET_MAINNET)',
     'strcmp(cmd, "broadcast") == 0 && a.network == GZ_NET_MAINNET && 0)', SLOW),
    ("g2 tool: broadcast to a server found to be on mainnet", G,
     "found == GZ_NET_MAINNET) {", "found == GZ_NET_MAINNET && 0) {", SLOW),
    ("g3 tool: exit status 0 on disagreement (review g2)", G,
     'case GZ_CHAIN_DISAGREE: printf(" (the servers contradict each other: NOT confirmed)\\n"); return 1;',
     'case GZ_CHAIN_DISAGREE: printf(" (the servers contradict each other: NOT confirmed)\\n"); return 0;',
     SLOW),
    ("g4 tool: proof exits 0 for an unconfirmed transaction (review g3)", G,
     "if (conf.status.state != GZ_TX_CONFIRMED) return 1; /* nothing was proved */", "", SLOW),
    ("g5 tool: no warning with one operator (review g4)", G,
     "if (operators < 2)\n    printf(", "if (0)\n    printf(", SLOW),
    ("g6 tool: duplicate servers not refused", M,
     "if (servers[j].ctx == servers[i].ctx) return GZ_CHAIN_INVALID_ARG;\n      if (!described[i] || !described[j]) continue;",
     "if (!described[i] || !described[j] || 1) continue;", SLOW),
    ("g7 tool: fee exits 0 on disagreement (review g6)", G,
     "return r == GZ_CHAIN_OK ? 0 : 1;", "return 0;", SLOW),
    ("g8 tool: lag exits 0 (review g7)", G,
     "             GZ_MULTI_LAG_MAX_BLOCKS);\n      return 1;", "             GZ_MULTI_LAG_MAX_BLOCKS);\n      return 0;", SLOW),
    ("g9 tool: proof exits 0 when the comparing check fails (review g8)", G,
     "  if (r != GZ_CHAIN_OK) return rc;\n  printf(\"transaction: \");", "  (void)rc;\n  printf(\"transaction: \");", SLOW),
    ("g10 tool: default servers not named by operator", G,
     "    cfg.operator_id = a.operators[made];\n", "", SLOW),
]


def sh(cmd, cwd, timeout=900):
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    build = os.path.abspath(sys.argv[1])
    only = sys.argv[2:]
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    rc, out = sh("git diff --quiet -- ports/chain", root)
    if rc != 0:
        sys.exit("ports/chain has uncommitted changes; commit or stash them first")
    counts = {"caught": 0, "SURVIVED": 0, "ERROR": 0}
    for entry in CHECKS:
        name, path, old, new = entry[:4]
        slow = len(entry) > 4 and entry[4]
        if only and not any(name.startswith(o) for o in only):
            continue
        full = os.path.join(root, path)
        src = open(full).read()
        pairs = old if isinstance(old, list) else [(old, new)]
        bad = [o for o, _ in pairs if src.count(o) != 1]
        if bad:
            print("ERROR    %s: pattern found %d times in %s" % (name, src.count(bad[0]), path), flush=True)
            counts["ERROR"] += 1
            continue
        for o, n in pairs:
            src = src.replace(o, n)
        open(full, "w").write(src)
        rc, out = sh("cmake --build %s -j4" % build, root)
        if rc != 0:
            errs = [l for l in out.splitlines() if "error" in l][:2]
            print("ERROR    %s: does not compile: %s" % (name, " | ".join(errs)), flush=True)
            counts["ERROR"] += 1
        else:
            sel = "-R '^chain_'" if slow else "-R '^chain_' -LE slow"
            rc, out = sh("ctest %s --timeout 300" % sel, build)
            failed = sorted(set(l.split(" - ")[1].split(" ")[0] for l in out.splitlines()
                                if " - chain_" in l))
            if rc != 0:
                print("caught   %s -> %s" % (name, " ".join(failed)), flush=True)
                counts["caught"] += 1
            else:
                print("SURVIVED %s" % name, flush=True)
                counts["SURVIVED"] += 1
        sh("git checkout -q -- %s" % path, root)
    sh("git checkout -q -- ports/chain", root)
    rc, out = sh("cmake --build %s -j4 && cd %s && ctest -R '^chain_' -LE slow" % (build, build), root)
    print("restored and rebuilt; tests on the unchanged source: %s" %
          ("pass" if rc == 0 else "FAIL\n" + out[-2000:]))
    total = sum(counts.values())
    print("%d behaviours removed in turn: caught %d, survived %d, errors %d" %
          (total, counts["caught"], counts["SURVIVED"], counts["ERROR"]), flush=True)
    sys.exit(0 if counts["SURVIVED"] == 0 and counts["ERROR"] == 0 and rc == 0 else 1)


if __name__ == "__main__":
    main()
