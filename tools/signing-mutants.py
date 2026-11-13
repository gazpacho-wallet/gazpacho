#!/usr/bin/env python3
"""Rule-removed runs and mutation testing of the signing engine.

usage:
  signing-mutants.py rules   SRC BUILD...     each safety rule removed in turn: the tests must fail
  signing-mutants.py mutants SRC BUILD... [--limit N] [--file F] [--names FILE]
                                              (--names: only the mutants named, one per line, e.g. earlier survivors)

SRC is a checkout; each BUILD is a configured CMake build directory of its own
copy of SRC (one per parallel worker: the copy is given as BUILD/../src).
Every variant is written into a worker's copy, test_signing is rebuilt and
run, and the original is put back. A variant that does not compile is
reported apart. Wrong versions live only here, never in the library.
"""
import os, re, subprocess, sys, threading, queue, time

ENGINE = ["core/signing/signing.c", "core/signing/sign_tx.c", "core/signing/round_msg.c"]

# rule -> (file, text on the marked line, replacement). The line is found by
# its RULE marker; the text must occur in it.
RULES = {
    "S1_SAVE_FIRST": ("emit_batch(em, recs, n);", "{}"),
    "S2_KNOWN_ROUND": ("if (r) {", "if (0) {"),
    "S2_ONE_NONCE": ("if (s < 0 || r->secnonce_serial[i] || (r->have_nonce[i] >> s & 1u)) return 0;", "if (s < 0) return 0;"),
    "S2_ONE_PARTIAL": ("if (s < 0 || !r->secnonce_serial[i] || (r->have_psig[i] >> s & 1u)) return 0;", "if (s < 0) return 0;"),
    "S3_RESEND_SAVED": ("emit_send(em, host, r->nonces_msg, r->nonces_len);", "{}"),
    "S4_FRESH_ID": ("gz_sign_sha256_write(&s, host_random, 32);", "(void)host_random;"),
    "HOST_RANDOM_MIX": ("hw.n = 32; put64(&hw, e->incarnation); put64(&hw, e->attempt_counter++);", "hw.n = 32;"),
    "RESTART_ANSWERS_ABORT": ("member_fail(e, r, GZ_SIGN_WHY_RESTARTED, &em);", "member_begin_tier(e, r, r->tier, &em);"),
    "ABORT_ONLY_BEFORE_PARTIAL": ("if (!r->ever_partial) {", "if (1) {"),
    "SIGNED_NEVER_ABORTED": ("r->state = GZ_SIGN_ROUND_UNFINISHED;", "r->state = GZ_SIGN_ROUND_ABORTED;"),
    "NONCE_SIG_COVERS_ITEM": ("gz_rmsg_nonce_hash(r->id, it->tier, (uint32_t)i, r->nonce[i][s], d);", "gz_rmsg_nonce_hash(r->id, 0, 0, r->nonce[i][s], d);"),
    "CHECK_NONCE_SIGS": ("if (!verify33(e, r->def.participants[it->signers[s]].contribution_key, nd, sig)) {", "if ((void)nd, (void)sig, 0) {"),
    "SLOT_NONCE": ("if (r->have_nonce[i] >> s & 1u) {", "if (0) {"),
    "SLOT_PSIG": ("if (r->have_psig[i] >> s & 1u) {", "if (0) {"),
    "PARSE_NONCE_FIRST": ("!secp256k1_musig_pubnonce_parse(e->cfg.ctx, &pn, nonce)) {", "((void)pn, 0)) {"),
    "PARSE_PSIG_FIRST": ("!secp256k1_musig_partial_sig_parse(e->cfg.ctx, &ps, p + 4) ||", ""),
    "VERIFY_PARTIAL": ("!secp256k1_musig_partial_sig_verify(e->cfg.ctx, &ps, &pn, &pk, &r->cache[i], &r->session[i])) {", "0) {"),
    "VERIFY_FINAL": ("if (!n || !gz_sign_tx_verify(e->cfg.ctx, e->work_tx, n, it->spent_amount, it->spent_script)) return 0;", "if (!n) return 0;"),
    "C10_UNRESOLVED": ("return GZ_SIGN_WHY_BUSY;", "{}"),
    "C7_OTHER_TREE": ("!same(e->exposures[i].tree_digest, r->def.tree_digest, 32)) return GZ_SIGN_WHY_OTHER_TREE;", "0) return GZ_SIGN_WHY_OTHER_TREE;"),
    "EXPOSURE_FIRST": ("save_exposure(e, r, t, em);", "if (0) save_exposure(e, r, t, em);"),
    "MAY_ACK": ("if (e->cfg.may_ack && !e->cfg.may_ack(e->cfg.hook_ctx, r, &tip)) {", "if (0) {"),
    "OLD_EPOCH_REFUSED": ("return refuse_id(e, id);", "return 1;"),
    "UNFINISHED_ABANDONED": ("r->state = GZ_SIGN_ROUND_ABANDONED;", "r->state = GZ_SIGN_ROUND_UNFINISHED;"),
    "PER_ITEM_ANSWER": ("wr32(q, (uint32_t)i); q += 4;", "wr32(q, 0u); q += 4;"),
    "HOST_VERIFY_FINAL": ("if (!len || !gz_sign_tx_verify(e->cfg.ctx, tx, len, it->spent_amount, it->spent_script)) {", "if (!len) {"),
    "DUPLICATE_KEYS": ("for (int j = 0; j < i; j++)", "for (int j = 0; j < 0; j++)"),
    "DUPLICATE_SIGNERS": ("if (s > 0 && it->signers[s] <= it->signers[s - 1]) return GZ_SIGN_WHY_INVALID_ROUND;", ""),
    "FIXED_MODE": ("if (it->mode != GZ_SIGN_MODE_KEYPATH || it->has_merkle_root > 1) return GZ_SIGN_WHY_INVALID_ROUND;", "if (it->has_merkle_root > 1) return GZ_SIGN_WHY_INVALID_ROUND;"),
    "SCRIPT_MATCH": ("if (it->spent_script[0] != 0x51 || it->spent_script[1] != 0x20 || !same(it->spent_script + 2, ser, 32)) return GZ_SIGN_WHY_INVALID_ROUND;", ""),
    "WIPE_ON_ABORT": ("wipe(r->secnonce, sizeof r->secnonce);", ""),
    "WIPE_AFTER_SIGN": ("wipe(&r->secnonce[i], sizeof r->secnonce[i]);", ""),
    "INCARNATION_MIX": ("put(&w, rnd, 32); put64(&w, e->incarnation); put64(&w, counter);", "put(&w, rnd, 32); (void)counter;"),
    "S5_CURRENT_KEY": ("if (me < 0 || (me == 0) != (e->cfg.host != 0)) return GZ_SIGN_WHY_NOT_MY_KEY;", "if (me < 0) me = e->cfg.host ? 0 : 1;"),
    "FUNDING_MATCH": ("if (it->spent_amount != d->funding_amount || !same(it->spent_script, d->funding_script, 34)) return GZ_SIGN_WHY_INVALID_ROUND;", ""),
    "HOST_SIG": ("if (!verify33(e, pr->p.participants[0].contribution_key, d32, pr->sig)) return GZ_SIGN_WHY_BAD_HOST_SIG;", ""),
    "FUNDING_TX": ("if (!same(d32, pr->p.funding_txid, 32) ||", "if (0 ||"),
    "NO_UNSET_SLOT": ("if (r->have_nonce[i] != all_bits(it)) return 0;", ""),
    # review A: F2 (refused identifiers beyond the exact list), F3 (eviction order), F1 (failed until a start)
    "KNOWN_FILTER": ("for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++)", "for (int k = 0; k < GZ_SIGN_KNOWN_FILTER_K; k++) if (k >= 0) return 0; else"),
    "EVICT_SETTLED_FIRST": ("settled(r) > settled(best) ||", "0 ||"),
    "FAIL_ON_ERROR": ("e->failed = 1;", "(void)0;"),
    # review A: F7 (C1: the root needs everyone), F4 (who a member's abort blames)
    "C1_ROOT_ALL": ("if (it->n_signers != d->n_participants) return GZ_SIGN_WHY_INVALID_ROUND;", ""),
    "BLAME_SECOND_RESTART": ("if (same(e->restarted[k], key, 33)) return bit(j);", "if (same(e->restarted[k], key, 33)) return 0;"),
    "BLAME_FALSE_SUPERSEDED": ("return bit(j);", "return 0;"),
}


def rule_variants(src):
    path = os.path.join(src, "core/signing/signing.c")
    text = open(path).read().split("\n")
    out = []
    for name, (old, new) in RULES.items():
        lines = [i for i, l in enumerate(text) if re.search(r"RULE:" + name + r"\b", l)]
        if len(lines) != 1 or old not in text[lines[0]]:
            out.append((name, None, None))
            continue
        t = list(text)
        t[lines[0]] = t[lines[0]].replace(old, new, 1)
        out.append((name, "core/signing/signing.c", "\n".join(t)))
    return out


OPS = [(r"==", "!="), (r"!=", "=="), (r"<=", "<"), (r">=", ">"), (r"(?<![<>=!-])<(?![<=])", "<="),
       (r"(?<![<>=-])>(?![>=])", ">="), (r"&&", "||"), (r"\|\|", "&&"), (r"return 1;", "return 0;"),
       (r"return 0;", "return 1;"), (r"\+ 1\b", "- 1"), (r"- 1\b", "+ 1"), (r"!(?=[a-z(])", "")]


def code_lines(text):
    """Indexes of lines that hold executable code worth mutating."""
    out, depth = [], 0
    for i, l in enumerate(text):
        s = l.strip()
        if depth > 0 and s and not s.startswith(("/*", "*", "//", "#")) and "RULE-SKIP" not in s:
            out.append(i)
        depth += l.count("{") - l.count("}")
    return out


def mutant_variants(src, only=None):
    out = []
    for f in ENGINE:
        if only and only not in f:
            continue
        text = open(os.path.join(src, f)).read().split("\n")
        for i in code_lines(text):
            line = text[i]
            code = line.split("/*")[0]
            for pat, rep in OPS:
                m = re.search(pat, code)
                if m:
                    t = list(text)
                    t[i] = code[:m.start()] + rep + code[m.end():] + line[len(code):]
                    out.append(("%s:%d %s->%s" % (f, i + 1, pat, rep), f, "\n".join(t)))
            s = code.strip()
            if s.endswith(";") and not s.startswith(("return", "if", "for", "while", "else", "case", "default", "uint", "int ",
                                                      "size_t", "const", "gz_", "secp256k1_", "wr_t", "emit_t", "static", "volatile")):
                t = list(text)
                t[i] = ""
                out.append(("%s:%d delete" % (f, i + 1), f, "\n".join(t)))
    return out


def run_variant(build, rel, text, args, timeout):
    src = os.path.join(build, "..", "src")
    path = os.path.join(src, rel)
    orig = open(path).read()
    try:
        open(path, "w").write(text)
        b = subprocess.run(["cmake", "--build", build, "--target", "test_signing", "test_signing_wb", "test_round_msg"], capture_output=True, timeout=600)
        if b.returncode != 0:
            return "no-compile", ""
        try:
            env = dict(os.environ, GZ_STOP_ON_FAIL="1")
            # the white-box guards first (seconds), then the whole suite
            for exe, a in (("test_round_msg", []), ("test_signing_wb", []), ("test_signing", args)):
                t = subprocess.run([os.path.join(build, exe)] + a, capture_output=True, timeout=timeout, env=env)
                if t.returncode != 0:
                    fails = sorted(set(re.findall(r"FAIL \S+/(\w+\.[ch]:\d+)", t.stdout.decode(errors="replace"))))
                    return "killed", ",".join(fails[:6]) or exe
            return "survived", ""
        except subprocess.TimeoutExpired:
            return "killed", "timeout"
    finally:
        open(path, "w").write(orig)


def main():
    mode, src, builds = sys.argv[1], sys.argv[2], []
    limit, only, args, names = None, None, [], None
    rest = sys.argv[3:]
    while rest:
        a = rest.pop(0)
        if a == "--limit": limit = int(rest.pop(0))
        elif a == "--file": only = rest.pop(0)
        elif a == "--names": names = set(l.strip() for l in open(rest.pop(0)) if l.strip())
        else: builds.append(a)
    if mode == "rules":
        variants, args, timeout = rule_variants(src), [], 5400
    else:
        variants, args, timeout = mutant_variants(src, only), [], 5400   # the full suite, stopping at the first failing section
        if names is not None: variants = [v for v in variants if v[0] in names]
        if limit: variants = variants[:limit]
    q = queue.Queue()
    for v in variants: q.put(v)
    results, lock = [], threading.Lock()

    def worker(build):
        while True:
            try: name, rel, text = q.get_nowait()
            except queue.Empty: return
            if rel is None:
                r = ("marker-missing", "")
            else:
                r = run_variant(build, rel, text, args, timeout)
            with lock:
                results.append((name, r))
                print("%-60s %s %s" % (name, r[0], r[1]), flush=True)

    start = time.time()
    threads = [threading.Thread(target=worker, args=(b,)) for b in builds]
    for t in threads: t.start()
    for t in threads: t.join()
    counts = {}
    for _, (k, _) in results: counts[k] = counts.get(k, 0) + 1
    print("SUMMARY %s: %s in %.0f s" % (mode, counts, time.time() - start))
    for name, (k, _) in sorted(results):
        if k in ("survived", "marker-missing"): print("SURVIVOR" if k == "survived" else "MISSING", name)


if __name__ == "__main__":
    main()
