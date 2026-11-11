#!/usr/bin/env bash
# Break-checks for the chain port: for each safety behaviour, remove it from
# the source, rebuild, and require that at least one test now fails. A
# behaviour whose removal no test notices is reported as SURVIVED and makes
# this script fail. The source is restored after every change.
#
#   ports/chain/tests/break-checks.sh BUILD_DIR
#
# BUILD_DIR is an already configured build of this repository (Release or
# sanitizer). Needs python3 and git. Not part of ctest: it edits the working
# tree while it runs, so do not run it with uncommitted changes in ports/chain.
set -u
build=${1:?usage: break-checks.sh BUILD_DIR}
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root" || exit 2
if ! git diff --quiet -- ports/chain; then
  echo "ports/chain has uncommitted changes; commit or stash them first" >&2
  exit 2
fi

survived=0
count=0

# check NAME FILE OLD NEW: replace the one occurrence of OLD in FILE by NEW.
check() {
  local name=$1 file=$2 old=$3 new=$4 failed
  count=$((count + 1))
  if ! python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1:4]
src = open(path).read()
if src.count(old) != 1:
    sys.stderr.write("pattern found %d times in %s (want 1)\n" % (src.count(old), path))
    sys.exit(1)
open(path, "w").write(src.replace(old, new))
PY
  then
    echo "ERROR    $name: the source no longer matches this check"
    survived=$((survived + 1))
    return
  fi
  if ! cmake --build "$build" -j4 >"$build/break-check.log" 2>&1; then
    echo "ERROR    $name: does not compile with the change (see $build/break-check.log)"
    survived=$((survived + 1))
  else
    failed=$(cd "$build" && ctest -R '^chain_' 2>&1 | sed -n 's/.*- \(chain_[a-z_]*\) (.*/\1/p' | sort -u | tr '\n' ' ')
    if [ -n "$failed" ]; then
      echo "caught   $name -> failing: $failed"
    else
      echo "SURVIVED $name: no test failed"
      survived=$((survived + 1))
    fi
  fi
  git checkout -q -- "$file"
}

E=ports/chain/esplora.c
J=ports/chain/json.c
M=ports/chain/multi.c
H=ports/chain/headers.c
V=ports/chain/verify.c
C=ports/chain/chain.c
G=ports/chain/tools/gz-chain.c

echo "== strict parsing"
check "accept a field the interface does not define (status object)" $E \
  'return false; /* a field this interface does not define */' '(void)0;'
check "accept an object with the same key twice" $J \
  'if (same_bytes(p, &p->toks[i], &p->toks[key])) return false;' '(void)same_bytes;'
check "accept text after the JSON value" $J \
  'if (p.pos != p.len) return false;' ''
check "accept an amount above 21 million bitcoin" $E \
  '|| o.value > GZ_MAX_MONEY) goto done;' ') goto done;'
check "accept a confirmed status without a block" $E \
  'if (seen != (F_CONFIRMED | F_HEIGHT | F_HASH | F_TIME)) return false;' ''
check "accept a Merkle position outside the tree" $E \
  'if (p.depth < 32 && (p.pos >> p.depth) != 0) return false;' ''
check "accept more Merkle nodes than the limit (trust the server's count)" $E \
  'val->type != GZ_JSON_ARRAY || val->size > GZ_MERKLE_MAX_DEPTH' 'val->type != GZ_JSON_ARRAY'
check "accept the same outpoint listed twice" $E \
  'if (output_cmp(&out[k - 1], &out[k]) == 0) goto done; /* same outpoint twice */' ''
check "accept upper-case or non-canonical hex" $C \
  "if (c >= 'a' && c <= 'f') return c - 'a' + 10;" \
  "if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10;"
check "accept a non-canonical length inside a transaction" $C \
  'if (v < min) return false;' '(void)min;'
check "accept a transaction with bytes left over" $C \
  'if (!rd_skip(&r, 4) || r.pos != len) return false;' 'if (!rd_skip(&r, 4)) return false;'

echo "== answers checked against what they must match"
check "do not check that a raw transaction hashes to the txid asked for" $E \
  'if (memcmp(check, txid, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;' ''
check "do not check that a header hashes to the block hash for its height" $E \
  'if (memcmp(check, hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_MALFORMED;' ''
check "accept a confirmation above the server's own tip" $E \
  'if (tip < st.height) return GZ_CHAIN_MALFORMED;' ''
check "accept a broadcast answer naming another txid" $E \
  '|| memcmp(got, want, GZ_HASH_LEN) != 0) {' ') {'

echo "== size caps, time limits, retries, request rate"
check "no per-call size cap (every call may fill the whole buffer)" $E \
  'if (cap > es->cfg.max_response_bytes) cap = es->cfg.max_response_bytes;' \
  'cap = es->cfg.max_response_bytes;'
check "trust the transport's reported length" $E \
  'if (resp.len > cap) return GZ_CHAIN_TOO_LARGE; /* a transport that broke its promise */' ''
check "no cap on the number of outputs returned" $E \
  'if (toks[0].size > cap) {' 'if (0) {'
check "allow a backend without a time limit" $E \
  'cfg->timeout_ms == 0 || ' ''
check "retry without bound on a failing server" $E \
  'attempt < es->cfg.max_attempts; attempt++' 'attempt < es->cfg.max_attempts + 3; attempt++'
check "repeat a broadcast after a timeout" $E \
  'if (post && hr != GZ_HTTP_E_CONNECT) break;' ''
check "no minimum interval between requests" $E \
  'now - es->last_ms < es->cfg.min_interval_ms) {' \
  'now - es->last_ms < es->cfg.min_interval_ms && es->cfg.max_attempts == 0) {'

echo "== disagreement detection"
check "return an answer although servers differ" $M \
  'if (a->result == GZ_CHAIN_OK && !same(f, a)) return GZ_CHAIN_DISAGREE;' '(void)same;'
check "return an answer although one says found and another not found" $M \
  'if (a->result != f->result) return GZ_CHAIN_DISAGREE;' ''
check "answer from a single server (no quorum)" $M \
  'if (count < m->cfg.quorum) return no_quorum(m);
  *which = first;' '*which = first;'
check "ignore where a spend confirmed when comparing" $M \
  'return hash_eq(x->spender_txid, y->spender_txid) && x->spender_vin == y->spender_vin &&
         x->confirmed == y->confirmed && x->height == y->height &&
         hash_eq(x->block_hash, y->block_hash);' \
  'return hash_eq(x->spender_txid, y->spender_txid) && x->spender_vin == y->spender_vin;'
check "treat spent and unspent as the same answer" $M \
  'if (x->spent != y->spent) return false;' ''
check "compare confirmed transactions by height only, not block hash" $M \
  'return x->height == y->height && hash_eq(x->block_hash, y->block_hash);' \
  'return x->height == y->height;'
check "accept tips any distance apart" $M \
  'if (t->height - low->height > m->cfg.tip_slack) return finish(m, GZ_CHAIN_DISAGREE);' ''
check "do not check that a server ahead has the lower tip in its chain" $M \
  'if (!hash_eq(at_low, low->hash)) return finish(m, GZ_CHAIN_DISAGREE);' ''
check "compare raw transactions by txid only (witness not compared)" $M \
  'return a->u.raw_tx.len == b->u.raw_tx.len && hash_eq(a->u.raw_tx.digest, b->u.raw_tx.digest);' \
  'return a->u.raw_tx.len == b->u.raw_tx.len;'
check "compare output lists by count only" $M \
  'if (!output_eq(&a->u.outputs.items[i], &b->u.outputs.items[i])) return false;' '(void)output_eq;'
check "no ceiling on fee rates" $M \
  'a[i].result = GZ_CHAIN_MALFORMED; /* absurd rate: discard the whole answer */' '(void)0;'

echo "== proof verification"
check "confirm without checking the Merkle proof against the header" $V \
  'if (!gz_merkle_verify(txid, &out->proof, out->header)) return GZ_CHAIN_BAD_PROOF;' ''
check "confirm without checking the header is the block in the status" $V \
  'if (memcmp(hash, out->status.block_hash, GZ_HASH_LEN) != 0) return GZ_CHAIN_BAD_PROOF;' ''
check "confirm without checking the proof is for the same height" $V \
  'if (out->proof.block_height != out->status.height) return GZ_CHAIN_BAD_PROOF;' ''
check "confirm without checking proof of work" $V \
  'if (gz_header_check_pow(out->header, network) != GZ_POW_OK) return GZ_CHAIN_BAD_PROOF;' ''
check "confirm although the server offers no proof" $V \
  'if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_BAD_PROOF; /* confirmed but no proof offered */' \
  'if (r == GZ_CHAIN_NOT_FOUND) return GZ_CHAIN_OK;'
check "Merkle check that accepts any root" $H \
  'return memcmp(root, header + 36, GZ_HASH_LEN) == 0;' '(void)root; return true;'
check "Merkle fold that ignores the position" $H \
  'if (pos & 1) {' 'if (0) {'
check "proof of work: do not compare the hash with the target" $H \
  'if (memcmp(hash_be, target, GZ_HASH_LEN) > 0) return GZ_POW_HASH_ABOVE;' '(void)hash_be;'
check "proof of work: allow any target however easy" $H \
  'if (memcmp(target, limit, GZ_HASH_LEN) > 0) return GZ_POW_TOO_EASY;' ''
check "header link check that always passes" $H \
  'return memcmp(h, next + 4, GZ_HASH_LEN) == 0;' '(void)h; return true;'

echo "== the tool"
check "gz-chain does not refuse broadcast on mainnet" $G \
  'strcmp(cmd, "broadcast") == 0 && a.network == GZ_NET_MAINNET' \
  'strcmp(cmd, "broadcast") == 0 && a.network == GZ_NET_MAINNET && 0'

echo "== restoring and rebuilding the unchanged source"
git checkout -q -- ports/chain
cmake --build "$build" -j4 >"$build/break-check.log" 2>&1 || { echo "rebuild failed"; exit 2; }
(cd "$build" && ctest -R '^chain_' 2>&1 | tail -3)
echo "$count behaviours removed in turn; not caught: $survived"
[ "$survived" -eq 0 ]
