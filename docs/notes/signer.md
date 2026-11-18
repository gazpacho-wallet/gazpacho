# The signer boundary

Design note, draft 1, 2026-11-18. **Not itself reviewed.** The owner approved the research recommendation of 2026-11-18. This note turns it into a design. It changes no code. Paths and names refer to `main` at `9a9d910` and to the open drafts #52 (`composite-p4-3`), #53 (`keys-p8`), #56 (`funding-p45`) and #59 (`k1-ready-binding`).

## 0. The rule, in one paragraph

Gazpacho never signs a hash or bytes that someone else supplies. One library, `signer/`, is the only code that holds a long-term or per-lobby secret key and the only code that calls a signing function. It offers **typed operations** that name objects, such as "my partial signature for item k of round R". Each operation computes what it signs from data it has checked itself. No operation takes a 32-byte digest. No other code ever sees a secret key.

Why this matters for us: the host's per-lobby factory key is the only key in the tree's timeout leaves (`<h> CLTV DROP <host> CHECKSIG`, `core/tree/model.c`; the key is `participants[0].factory_key`, `core/tree/checks.c`). A BIP 340 signature by that key over the right 32 bytes is a spend of a tree node by the timeout path, to outputs the requester chose. Today a generic `sign(msg32)` hook can reach that key (`gz_node_crypto_t.sign` in `node.h`, `gz_lobby_crypto_t.sign` in `lobby.h`, `ls_sign` in `core/node/lobbyslot.c`, `port_sign` in `program/executor.c`, `gzp_net_sign` in `program/net.c`). Every caller passes a tagged hash it computed itself, so nothing is exploitable now. This design removes the hook, so that no future caller can make it exploitable.

An "inventory" in this note (the table in section 3) is a design and audit list of which key signs what. It is not a place where keys are kept.

## 1. What is decided

| # | Decision |
|---|---|
| D1 | One library, `signer/` (target `gazpacho_signer`), holds every long-term and per-lobby secret key and makes every signature and every static-key ECDH. |
| D2 | Its interface is a set of typed operations (section 2). There is no operation that takes a digest, a sighash type or a free-form message. |
| D3 | Each key may sign only the tags and sighashes of section 3. The signer enforces the table. Anything else is refused. |
| D4 | `gz_key_port_t.secret`, `host_secret` (PR #52), the slot's `gate_secret` (PR #52), `gz_sign_config_t.factory_secret` and `contribution_secret`, `gz_node_crypto_t.sign`, `gz_lobby_crypto_t.sign(msg32)`, `gzp_net_sign` and `gzp_net_sign_host` (PR #53) all go (section 4). |
| D5 | The wallet port of PR #56 signs by plan txid, never by bytes. The master key never leaves the signer (section 6). |
| D6 | Two CI checks: no signing symbol outside `signer/`, and no unregistered tag (section 7). Each signer check has a named mutation (section 8). |
| D7 | Slice 1: a library in the same process. 1.0.0: the same library inside a separate signer process with capability masks and seccomp, like Core Lightning's `hsmd` (section 10). |
| D8 | Open: whether to split the host factory key (O2, section 11). |
| D9 | Slice 1's `round_open` re-checks scripts, amounts, C6 and C10, but not the full C1 rebuild, which moves into the signer at 1.0.0 (section 10); this departs from the research recommendation, which put the C1 rebuild inside `round_open`, and is pending the owner. Slice 1 holds no balance. |

## 2. The library and its operations

### 2.1 Shape

`signer/` sits beside `wallet/` and follows its rules:

- It does no I/O.
- It keeps no global or static state; all state is in a `gz_signer_t` the program allocates.
- It reads randomness only through the random port, with `GZ_RANDOM_SECRET` for nonce material.
- It gets the seed only through the seed source of PR #53 (`gzp_seed_source_t`), which gives a seed only while storage is unlocked.

It is checked by `tools/check-core-isolation.sh` with its own allow list, as `core/signing` is today (section 7).

It links:

- `secp256k1-zkp` (signing, MuSig2, ECDH);
- `wallet/` and `wallet/tx` (BIP 32, BIP 86, transactions, the held funding);
- the pure helpers it needs to recompute what it signs: `core/signing/sign_tx.c` (parse, txid, TapSighash, TapTweak), `core/signing/round_msg.c` (`gz_rmsg_hash`, `gz_rmsg_nonce_hash`) and `core/tree/terms.c` (the terms decoder and digests).

Nothing else links the secret-key calls.

What lives inside `gz_signer_t`:

- **Role:** host or member, fixed per data folder. The epoch and the restore freeze (PR #53 `keys.h` policy, safety rule C12/R3).
- **Network:** never mainnet; `gzw_network` as `wallet/` refuses it.
- **Slots:** for each open slot, its scope, epoch, `key_index`, its gate (AT_JOIN), and the saved factory public key (`seat_key`, PR #59 BD3).
- **Rounds:** for each open round, the round id, the terms digest it was opened under, and the per-item sighash, tweak and spent output the signer computed itself. It also holds the MuSig2 secret nonces, which live only here.
- **Held funding plans** (host): `gzt_funding` objects, keyed by txid.
- **The host's long-term key**, while the program runs. The transport needs it for every handshake.

Seeds, master keys and intermediate BIP 32 nodes are never kept. Each derivation asks the seed source, walks the path, keeps the one result it needs, and wipes the rest. PR #53's `gzp_keys_*` already works this way and becomes the signer's derivation layer.

**Errors.** Every operation returns `GZ_SG_OK` (0) or a refusal reason from section 2.4. On any refusal every output buffer is zeroed and the signer's state is unchanged. A refusal is an outcome, never a node error: the engine answers as its state requires, as the key port's 0 does today.

**Session secrets are not signer business.** The BOLT 8 ephemeral key, the transport cipher keys and the storage cipher keys protect one connection or one file, and stay where they are (`ports/net`, `ports/storage`). The rule covers keys that sign or that identify this wallet on the wire.

### 2.2 Common inputs

```c
typedef struct gz_signer gz_signer_t;            /* opaque */

typedef struct {                                 /* a slot, as the node part names it */
    uint8_t scope[32];                           /* the lobby id: TH("gazpacho/terms/outer", outer) */
    uint32_t epoch, key_index;                   /* contribution key at key_index, factory at +1 */
} gz_sg_slot_t;

typedef enum {                                   /* which of the slot's keys, or the host's */
    GZ_SG_KEY_HOST = 1,                          /* the host's long-term key (host only) */
    GZ_SG_KEY_CONTRIBUTION,                      /* the member's per-lobby key (member only) */
    GZ_SG_KEY_FACTORY                            /* the slot's factory key (both) */
} gz_sg_key_t;
```

A slot must be registered with `gz_sg_slot_add` (the node part already saves `key_index` and `slot_opened` in one batch, `composite-node.md` 2.5) before any operation names it. An operation that names an unknown slot, or a slot of another epoch, is refused.

### 2.3 The operations

Each operation lists its exact inputs, what it computes itself, and the checks it runs **before** signing, in order. "Recompute" means the signer builds the bytes it signs from the inputs with its own code. The caller never passes a digest.

#### Slots and gates

**`gz_sg_slot_add(sg, const gz_sg_slot_t *slot, uint8_t contribution_pub[33], uint8_t factory_pub[33] /* may be NULL */)`**

1. The epoch is current and not frozen (C12, R3).
2. `key_index + 1` is below 2^31, so both keys of the pair are hardened indexes. (Draft 1 also required `key_index` to be even. No specification says so: `contract-v2.md` 13 allocates pairs (i, i + 1), not even i. The check is dropped until a specification adds the rule.)
3. The slot is not already held.
4. The table has room.

Returns the public keys. Before PR #59 lands it also returns the factory public key. After PR #59 the factory public key comes from `gate_open` (BD2).

**`gz_sg_gate_open(sg, scope, const uint8_t digest[32], uint8_t factory_pub[33])`**

This is the AT_JOIN ready, and under PR #59 the first ready in every mode.

1. The slot is held.
2. The epoch is current and not frozen.
3. The seed source gives a seed (the person's passphrase unlocked it).

It derives the factory key at `(epoch, key_index + 1)` and keeps it bound to `(scope, digest)`, replacing and wiping any earlier binding for that scope. If the slot already has a `seat_key`, the derived public key must equal it (BD5a, at a later ready under AT_JOIN); otherwise `GZ_SG_E_SEAT_KEY`: the ready is not sent, `seat_key` stays unchanged, and the person is told the passphrase differs (`messages.md` 6.4, BD5a). In a round the same mismatch is `round_open` check 3, `round_abort` reason 12. Returns the public key so the node can save `seat_key` before it sends the ready (BD3).

Under AUTO and WHEN_UNLOCKED the node calls it too. The binding then has `digest` set to all zeros, meaning "any terms of this scope".

**`gz_sg_gate_close(sg, scope)`** wipes the scope's factory secret and its binding. **`gz_sg_gate_close_all(sg)`** wipes every gate, at every start and on "lock signing" (`composite-node.md` 12.2).

**`gz_sg_seat_key(sg, scope, const uint8_t seat_key[33])`** gives the signer the saved `seat_key` after a restart (from the journal), so that BD5 holds across restarts.

#### Messages

**`gz_sg_sign_envelope(sg, gz_sg_key_t key, scope, uint16_t kind, const uint8_t *records, size_t len, int fresh, uint8_t sig[64])`**

The signer computes `msg_hash = TH("gazpacho/msg", protocol ‖ kind ‖ scope ‖ records)` (`messages.md` 4.3, the same code as `gz_rmsg_hash`).

1. `kind` is in the key's row of the kind table (3.2), for this party's role.
2. `scope` is a held slot (member) or a lobby this host has open (host).
3. `key` matches the role: HOST only on a host, CONTRIBUTION only on a member, never FACTORY. The factory key signs no message (PR #59).
4. `records` ends before record 240, and no record 240 is present (the signature record is the signer's to append).
5. `len ≤ GZ_LOBBY_MAX_ENV`.

`fresh` = 1 draws `aux_rand` from the random port. `fresh` = 0 uses 32 zero bytes, BIP 340's deterministic variant, which only the messages the engine rebuilds may ask for (`signing.c`, `sign_digest`, today). The signer checks the kind is one of those: `round_tier_result` and `round_abort` from the host.

The signer does not decode the records of every kind in Slice 1. These signatures move no coins. What they could be misused for is a cross-context signature, and the tag, the kind check and the key check close that. Decoding moves into the signer process at 1.0.0 for the kinds that commit a party (section 10).

**`gz_sg_sign_terms(sg, const uint8_t *outer, size_t olen, const uint8_t *current, size_t clen, uint8_t outer_sig[64], uint8_t current_sig[64])`** (host)

1. Both records decode under `terms.md` with core/tree's decoder.
2. `host_key` in the outer terms is this host's long-term public key.
3. The chain is this signer's network.
4. The current values are within the outer ranges.

It computes both digests (`gazpacho/terms/outer`, `gazpacho/terms/current`) and signs both with the host key. `gz_lobby_host_open` and `set_values` call it in place of their three `crypto.sign` calls (`host.c`). A `current` that differs from what the host last signed under the same outer is allowed; its version must be higher.

**`gz_sg_sign_binding(sg, scope, uint8_t sig[64])`**

The signer computes `binding = TH("gazpacho/bind", scope ‖ factory_pub ‖ contribution_pub)` from the slot's own two public keys and signs it with the contribution key (member) or the host key (host). Under PR #59 there is only this one signature, `bind_by_contribution`, carried in the first ready. **It is made once per seat**, at the seat's first ready (BD3): the node saves it in `seat_key` field 10 together with the factory public key, and every later ready sends the saved bytes, with no call to this operation and no seed (`messages.md` 6.4, `journal.md` 9.1). The host accepts any valid signature over the same binding and keeps the first it saved, so a re-signature after a crash before the save is harmless; the signer need not reproduce the bytes. Before PR #59 a second call with `GZ_SG_KEY_FACTORY` gives `bind_by_factory`. That call is removed when PR #59's code lands (section 9).

1. The slot is held.
2. Its factory public key is known (gate opened, or before PR #59, slot added).
3. Member: the gate is open for this scope (true at the first ready, the only time it is called).

#### Rounds

The signing engine (core/signing) keeps doing everything public: decoding, the builder and C1 to C11, nonce aggregation, partial verification, combining, and the final checks. The signer re-checks what binds a signature and keeps the secret nonces.

**`gz_sg_round_open(sg, scope, const gz_sign_def_t *def, const uint8_t round_id[32], const uint8_t host_random[32], gz_sg_round_t *handle)`**

The `def` is what the engine checked (`check_def` passed).

1. `scope` is a held slot. Member: its gate is open, and the gate's digest equals `def->terms_digest`, or the gate is any-terms (AUTO and WHEN_UNLOCKED).
2. This party is in `def->participants` with exactly the slot's factory public key and contribution (or host) public key, at one position only (PR #59 BD4).
3. Member, after PR #59: the factory public key equals the saved `seat_key` (BD5); otherwise reason 12.
4. For each item:
   - `tx` parses as an unsigned one-input transaction (`gz_sign_tx_parse`, no witness).
   - Its signers are increasing positions among the participants.
   - The signer aggregates their factory keys (BIP 327 KeyAgg), applies the TapTweak with the item's merkle root, and checks the spent script is `OP_1 <that key>`.
   - The spent output is either the funding output with exactly `def->funding_amount` and `def->funding_script`, needing all participants, or an output of another item in `def`, with that amount and script, in the same or an earlier tier (C6).
   - The signer computes the item's BIP 341 sighash itself, with `SIGHASH_DEFAULT`, key path, input 0.
5. The signer recomputes the round id from `def`, its own digests and tweaks, and `host_random` (`gz_sign_round_id`). It must equal `round_id`.
6. No other open round of this signer spends the same funding outpoint with a different tree digest (C10, defence in depth: the engine also checks it).

It stores per item the sighash, the KeyAgg cache and the tweak, and returns a handle. The `def` bytes are not kept.

**`gz_sg_nonce(sg, handle, uint16_t item, uint8_t pubnonce[66], uint8_t attest_sig[64])`**

1. The handle is open.
2. `item` is one this party signs.
3. No secret nonce was ever made for `(round, item)` under this signer's incarnation.

It generates the nonce exactly as `make_nonce` does today:

- `session_id = TH("gazpacho/session-id", 32 secret random ‖ incarnation ‖ counter)`;
- `extra = TH("gazpacho/nonce-extra", round_id ‖ tier ‖ item)`;
- `secp256k1_musig_nonce_gen` with the factory secret, the factory public key, the item's own sighash and the KeyAgg cache.

It keeps the secret nonce inside and signs `TH("gazpacho/nonce", round_id ‖ tier ‖ item ‖ pubnonce)` with the contribution key (member) or host key (host). The inputs are wiped.

**`gz_sg_partial(sg, handle, uint16_t item, const uint8_t (*nonces)[66], uint8_t n, uint8_t psig[32])`**

1. The handle is open.
2. A secret nonce exists for the item and has not been used.
3. `n` equals the item's number of signers.
4. `nonces[pos]` equals this party's own public nonce for the item, where `pos` is its position among the item's signers.
5. Every nonce parses.

It aggregates the nonces and processes the session with the signer's own sighash for the item (never a caller's), then signs. The secret nonce is wiped whether signing succeeds or fails. A second call for the item is refused. The caller verifies the partial with `secp256k1_musig_partial_sig_verify`, as now.

**`gz_sg_round_close(sg, handle)`** wipes every secret nonce of the round. The engine calls it when the round ends, aborts or is cancelled (`RULE:CANCEL_WIPES`, PR #52), and `gz_sg_gate_close` calls it for every round under that scope. At a start there are no rounds: secret nonces never outlive the process (`RULE:RESTART_ANSWERS_ABORT`).

#### Transport

**`gz_sg_ecdh(sg, gz_sg_key_t key, const gz_sg_slot_t *slot /* NULL for HOST */, const uint8_t point[33], uint8_t shared[32])`**

1. `point` parses as a valid point.
2. `key` is HOST on a host, or CONTRIBUTION of a held slot on a member, never FACTORY.

It computes BOLT 8's `ecdh(k, point)` (SHA-256 of the compressed shared point, libsecp256k1's default hash, as `ports/net/noise.c` does now). `noise.c` calls it through the transport's key hook in place of `secp256k1_ecdh(..., priv, ...)`. The transport no longer receives its static secret (`gzp_net_cfg_t.static_key` goes).

#### The on-chain wallet (host funding)

**`gz_sg_fund_plan(sg, const gzt_funding_request *req, const gzt_coin *coins, size_t n, gzt_funding_info *info, uint8_t *unsigned_tx, size_t cap, size_t *len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev)`**

1. Every coin's script is the BIP 86 output of its `(change, index)`, derived here.
2. `req->funding_script` is `OP_1 <32 bytes>`.
3. The fee rate is at most the request's ceiling.
4. The change index is not among the used ones.

It runs `gzt_funding_build` with the master key, derived and wiped inside the call, and holds the plan under its txid. It returns the plan's public parts: `gzt_funding_unsigned` and `gzt_funding_prevout`.

**`gz_sg_fund_sign(sg, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *len)`**

1. A plan is held under `txid`.
2. The checks `gzt_funding_release` already makes: the txid recomputed from the plan equals `txid` and the plan's own, and the amounts agree.

It signs every input, verifies each signature, and returns the signed bytes.

**`gz_sg_fund_spend_back(sg, const uint8_t txid[32], uint32_t input, uint64_t fee, uint8_t *out, size_t cap, size_t *len)`**

1. A plan is held under `txid`.
2. `input` is one of its inputs.
3. `fee` ≤ the spend-back's fee cap, which admits the whole fee ladder of the funding engine (`funding.md` 2; PR #56) and nothing above it. With the spend-back's own virtual size `v` (`gzt_keypath_vsize`), the held plan's fee `F` and size `V` (computed by the signer from the plan it built or adopted, inputs minus outputs, never taken from the caller), the policy's ceiling rate `c` and `I` = 1,000 sat/kvB (the incremental relay fee of Core 28.x and 29.0, a signer constant), the cap is the larger of:
   - `ceil(c × v / 1000)`, the ceiling on the spend-back's own size (level 0: the funding was never seen, so the spend-back pays the ordinary rate);
   - `F + ceil(I × v / 1000)`, raised if needed to `F × v / V + 1` (Core's rule 6: a higher rate than the transaction it replaces), which is the top of the ladder (level 2; level 1 is the same with Core 29.1's 100 sat/kvB and is always below it).

   `F` was itself checked against the ceiling when the plan was made (`fund_plan` check 3, `fund_adopt` check 5), so the cap is bounded by the policy alone. When a fee child of the funding exists (H16; none in Slice 1), `F` and `V` are the evicted package's, counting only a child this signer signed. "Ceiling × `v`" alone, as draft 1 had it, refuses level 2: a 16 sat funding of 154 vB and a 111 vB spend-back give 127 sat against a cap of 111 at 1 sat/vB (review B of #56, M-3). The formula is `gz_sg_spend_back_fee_cap` in `signer/` (stage 1, PR #71), with its vectors.
4. What is left is above the dust limit.

The destination is the next unused receive script of this wallet, chosen here and never taken from the caller (`composite-node.md` 14.3).

**`gz_sg_fund_adopt(sg, const uint8_t *unsigned_tx, size_t len, const uint8_t txid[32], const uint8_t funding_script[34], uint64_t amount)`**

After a restart, it takes back a plan from the funding engine's journal record (it replaces `hold`).

1. The bytes parse, and their txid is `txid`.
2. Output 0 is exactly `amount` to `funding_script`.
3. Every other output is a change output to this wallet's BIP 86 change branch, at an index the signer derives and finds.
4. Every input spends a coin of this wallet, given with its derivation in the journal record and checked by deriving its script.
5. The fee rate is at most the ceiling.

The journal is our own encrypted storage. The check makes adopted bytes as trustworthy as built ones, and costs little.

**`gz_sg_fund_release(sg, const uint8_t txid[32])`** drops and wipes a plan.

Later typed wallet operations (sends the person confirmed, exits, timeout sweeps, penalties) are added the same way when their features land. Each gets its own section in this note and its own rows in section 3. **There is never a "sign this transaction" operation.** The penalty operation, if `safety-rule.md` C12's proposed exception is adopted, is the only operation that may use an earlier epoch, and only in the revocation-basepoint family (`exit.md` CH-18, PR #61, pending the owner); every other operation refuses another epoch (`GZ_SG_E_EPOCH`).

### 2.4 Refusal reasons

| Code | Meaning |
|---|---|
| `GZ_SG_E_ARG` | NULL, a length out of range, a malformed point |
| `GZ_SG_E_NO_SEED` | Locked: the seed source has no seed |
| `GZ_SG_E_EPOCH` | Another epoch than the current one, or frozen |
| `GZ_SG_E_SLOT` | Unknown slot, or slot table full |
| `GZ_SG_E_GATE` | AT_JOIN gate closed, or opened for another digest |
| `GZ_SG_E_SEAT_KEY` | Derived factory key differs from `seat_key`. At a `ready`: the ready is not sent (#59 BD5a). In a round: `round_abort` reason 12 |
| `GZ_SG_E_KIND` | A kind or tag outside the key's row (section 3) |
| `GZ_SG_E_ROUND` | A round check of 2.3 failed: the round id, a script, an amount, C6, C10, or this party missing or present twice |
| `GZ_SG_E_NONCE` | No secret nonce, already used, or our own nonce missing from the set |
| `GZ_SG_E_PLAN` | No plan under that txid, or the plan check failed |
| `GZ_SG_E_FEE` | Above the ceiling, or above the spend-back's fee cap (2.3) |
| `GZ_SG_E_INTERNAL` | A self-check failed |

## 3. Keys and what each may sign

### 3.1 The table

| Key | Path (`docs/notes/keys.md`, PR #53; no specification yet) | May sign | May do | Never |
|---|---|---|---|---|
| Host long-term | `m/254315617'/net'/1'/k'` | BIP 340 over `gazpacho/msg` for the host kinds of 3.2; `gazpacho/terms/outer`; `gazpacho/terms/current`; `gazpacho/bind` (as the host's contribution key); `gazpacho/nonce` (the host is a signer of every item). Later, by its own typed operations: `gazpacho/listing`, `gazpacho/withdrawal`, `gazpacho/index`, `gazpacho/anchor`, `gazpacho/beacon` | BOLT 8 ECDH | Any TapSighash; any untagged value |
| Host factory, per lobby | `m/254315617'/net'/2'/epoch'/(i+1)'`, i the lobby's pair index on the host's own branch 2' (`program/keys.h`, PR #53: "its own pairs"); the host's contribution role is taken by its long-term key | MuSig2 partial signatures over the signer's own TapSighash for tree items, `SIGHASH_DEFAULT`, key path. Before PR #59's code: also `gazpacho/bind` (`bind_by_factory`) | — | Any BIP 340 single-key signature after PR #59; any script-path sighash until a typed timeout-sweep operation exists (O2) |
| Member contribution, per lobby | `m/254315617'/net'/0'/epoch'/i'` | BIP 340 over `gazpacho/msg` for the member kinds of 3.2; `gazpacho/bind`; `gazpacho/nonce` | BOLT 8 ECDH (one link per lobby) | Any TapSighash; any untagged value |
| Member factory, per lobby | `m/254315617'/net'/0'/epoch'/(i+1)'` | MuSig2 partial signatures as for the host. Before PR #59's code: also `gazpacho/bind` | — | Anything else |
| Wallet BIP 86 | `m/86'/coin'/0'/{0,1}/j` | BIP 341 key-path `SIGHASH_DEFAULT` signatures of a held funding plan (`fund_sign`) and its spend-backs (`fund_spend_back`) | — | NONE, SINGLE or ANYONECANPAY; any transaction not built or adopted by the signer |

Rows 2 and 4 assume `exit.md` 3.4 (`docs/DECISIONS-WITHOUT-OWNER.md` K10, pending owner) and `exit.md` CH-OP-1 (proposed). The import still pays distribution and penalty outputs to the factory key (`signing-round.md` 2). Row 2's script-path exception is the typed timeout sweep of O2.

No sighash type is ever an input. `SIGHASH_DEFAULT` is the only one any signing operation produces. `gzt_sigmsg` keeps its other types for tests and cross-checks, but no signer operation reaches them, and the CI check of section 7 forbids `gzt_sigmsg` and `gzt_sighash_keypath` with a non-zero type in `signer/`.

### 3.2 Kinds per key

Kind numbers are from `lobby.h` and `round_msg.h`.

The envelope signature is record 240 of `messages.md` 4.3. A kind marked "— (unsigned)" carries no record 240 in the specification, so the signer refuses `sign_envelope` for it under every key.

| Kind | Host long-term | Member contribution |
|---|---|---|
| 2 `part` | — (unsigned; `messages.md` 5) | — (unsigned) |
| 16 `hello` | — (unsigned: no records, `messages.md` 6.1) | — (unsigned) |
| 18 `terms_offer` | — (unsigned as a message; its two records are signed by `sign_terms`, `messages.md` 6.2) | — |
| 20 `join` | — | — (unsigned: no record 240 in 6.3; after PR #59 no keys and no signatures at all) |
| 22 `ready` | — | yes |
| 24 `unready`, 26 `leave` | — | — (unsigned: no record 240, `messages.md` 6.5, 6.6) |
| 28 `lobby_status` | — (unsigned, `messages.md` 6.7) | — |
| 30 `ready_check`, 32 `start`, 34 `cancel` | yes | — |
| 64 `round_propose`, 72 `round_tier_result` (deterministic allowed), 74 `round_complete` | yes | — |
| 66 `round_nonces` | — | — (no record 240; each entry's `nonce_sig` is made by the round operation under `gazpacho/nonce`, `messages.md` 7.3) |
| 68 `round_all_nonces` | — (unsigned: "No signature record", `messages.md` 7.4; `signing-round.md` 4, "Carried signatures only") | — |
| 70 `round_partial_sigs`, 76 `round_ack` | — | yes |
| 78 `round_abort` | yes (deterministic allowed) | yes |
| 80 `round_status_request` | — | — (unsigned: no record 240, `messages.md` 7.10) |
| 81 `factory_funded` | — (odd and unsigned, `messages.md` 7.11) | — |
| 32767 `test` | — (test builds only; never signed by a real key) | — |

The engines' code is the reference for who sends what. Drafting this table showed one gap: `messages.md` 4.1 lists who sends each kind, but no table says which kinds are signed. Add a 'Signed' column there. (Checked on `main`: the lobby wire table, `core/lobby/wire.c` `ROWS`, gives record 240 only to 22, 30, 32 and 34, and `send_hello` and `send_reason` in `core/lobby/member.c` send 16, 24 and 26 without one.) Step S4 (section 9) builds the table from `messages.md` and fails a test if the code sends a kind the table does not allow.

### 3.3 Tags

Every tag is registered in `spec/PROTOCOL.md` 8.2 before use. This note adds a column there, "signed directly, by which key", filled from 3.1.

These tags are in the code but missing from 8.2, and are added by this PR's follow-up (S1):

- `gazpacho/session-id`
- `gazpacho/allnonces`
- `gazpacho/host-random`
- `gazpacho/known-filter`
- `gazpacho/test`, reserved for tests (registered by PR #60), and `gazpacho/test-funding`, reserved for tests, which is not on `main`: PR #52 adds it (`core/node/signslot.c`), and it is registered when #52 merges

`gazpacho/tree` is in use, not "name reserved". The derivation string `gazpacho keys` goes in 8.2's plain-strings table.

## 4. The key port and the crypto hooks, after

### 4.1 What goes

| Today | Where | After |
|---|---|---|
| `gz_key_port_t.secret(epoch, index, sec32)` | `ports.h` | Gone |
| `gz_key_port_t.host_secret(sec32)` | PR #52 | Gone, before PR #52 merges or right after (section 9) |
| `gz_key_port_t` `forget(scope)` on `gz_node_crypto_t` | `node.h` | `gz_signer_port_t.gate_close` |
| `gz_node_crypto_t.sign(host, epoch, index, msg32, sig)` | `node.h` | Gone; replaced by typed calls |
| `gz_lobby_crypto_t.sign(which, msg32, sig)` | `lobby.h` | Replaced by `sign_envelope`, `sign_binding`, `sign_terms` hooks of the same shape as 2.3 |
| Slot `gate_secret[32]`, `gate_digest`, `gate_have` | PR #52 `core/node/internal.h` | Gone; the gate's secret is in the signer, and the slot keeps only `gate_open` (a flag) |
| `gz_sign_config_t.factory_secret`, `contribution_secret` | `signing.h` (main) | Gone (PR #52 already replaces them with the `keys` hook) |
| `gz_sign_config_t.keys(scope, terms_digest, factory_kp, contribution_kp)` | PR #52 | Gone; the engine calls `round_open`, `nonce`, `partial`, `round_close` and `sign_envelope` |
| `gzp_net_sign`, `gzp_net_sign_host`, `gzp_net_key(..., sec, ...)` | `program/net.c`, PR #53 | Gone; `noise.c` calls `gz_sg_ecdh` |
| `gzp_net_cfg_t.static_key` | `program/net.h` | Gone; the transport holds its public key and a key hook |
| `gzp_keys_lobby(..., sec, ...)`, `gzp_keys_host(sec, ...)`, `gzp_keys_scope_open`, `gzp_keys_scoped` | PR #53 `program/keys.h` | Moved inside `signer/` as private functions; the program sees only `gz_signer_t` |

### 4.2 What stays

`gz_key_port_t` keeps `pub(epoch, index, pub33)` and `host_pub(pub33)`. The node part still owns key allocation, because `key_index` must ride in the same batch as the guard (`journal.md` 8.3). It tells the signer about a slot with `slot_add` in the same step.

### 4.3 The signer port core sees

Core is pure and calls the program through ports. The signer is reached through one more port, of the same kind as the others:

```c
typedef struct {
    int (*slot_add)(void *ctx, const gz_sg_slot_t *s, uint8_t cpub[33], uint8_t fpub[33]);
    void (*slot_drop)(void *ctx, const uint8_t scope[32]);
    int (*gate_open)(void *ctx, const uint8_t scope[32], const uint8_t digest[32], uint8_t fpub[33]);
    void (*gate_close)(void *ctx, const uint8_t scope[32]);
    int (*sign_envelope)(void *ctx, gz_sg_key_t key, const uint8_t scope[32], uint16_t kind,
                         const uint8_t *records, size_t len, int fresh, uint8_t sig[64]);
    int (*sign_terms)(void *ctx, const uint8_t *outer, size_t olen, const uint8_t *cur, size_t clen,
                      uint8_t osig[64], uint8_t csig[64]);
    int (*sign_binding)(void *ctx, const uint8_t scope[32], gz_sg_key_t key, uint8_t sig[64]);
    int (*round_open)(void *ctx, const uint8_t scope[32], const gz_sign_def_t *def,
                      const uint8_t round_id[32], const uint8_t host_random[32], uint32_t *handle);
    int (*nonce)(void *ctx, uint32_t handle, uint16_t item, uint8_t pubnonce[66], uint8_t attest[64]);
    int (*partial)(void *ctx, uint32_t handle, uint16_t item, const uint8_t (*nonces)[66], uint8_t n,
                   uint8_t psig[32]);
    void (*round_close)(void *ctx, uint32_t handle);
    void *ctx;
} gz_signer_port_t;
```

The program implements it by calling `gz_sg_*` directly (Slice 1) or by sending a typed request to the signer process (1.0.0). The simulator implements it over a test signer in its world (`sim/`), so the existing multi-process and simulated tests keep their shape.

The engine keeps its own bookkeeping (`have_nonce`, `secnonce_serial`, `S2_ONE_NONCE`, `S2_ONE_PARTIAL`, the wipes on cancel and restart). The signer enforces the same rules independently. Two layers that must both fail before a nonce is reused.

## 5. The AT_JOIN gate and option (c)

### 5.1 Today (PR #52 and PR #53 disagree)

PR #52 opens the gate in core. On `GZ_CMD_LOBBY_READY` under AT_JOIN it calls `keys.secret(epoch, key_index + 1)` and copies the factory secret into `s->gate_secret`, bound to the digest in `s->gate_digest`. `sg_keys` then builds the factory keypair from that copy.

PR #53 keeps scoped secrets in the program (`gzp_keys_scope_open`, `gzp_keys_scoped`, bound to scope and digest, constant-time compare). Its `port_secret` returns 0 whenever `scoped_only` is set.

Merged as they stand, every AT_JOIN ready would fail with `no_key`, and `sg_keys` would also be refused the contribution key. That fails closed, so funds are safe, but the gate would not work, and there would be two copies of the one design.

### 5.2 After

- The gate's secret lives only in the signer (`gate_open`, `gate_close`). Core keeps a flag per slot.
- `ls_may_answer` (lobbyslot) is unchanged: the gate as a *policy* is still the node's. The scoped secret is the *key protection*, and that is the signer's.
- The contribution key is not scoped (`composite-node.md` 12.2: the transport needs it for every handshake). The signer derives it at `slot_add` and holds it while the slot lives, or re-derives it while unlocked. Which one is P8's open point. This design does not change it, but it keeps the answer inside the signer.

### 5.3 Option (c), PR #59

PR #59 moves the binding from `join` to the first `ready`. The factory key signs no binding (BD). Its rules map onto the signer like this:

| BD rule | Where it is enforced |
|---|---|
| BD1, one pair per seat for the lobby's life | The host's lobby engine, extended by #59 code item 6 to every seat ever held in the lobby; the signer refuses `slot_add` for a scope already held |
| BD2, factory key derived at the first ready, under the seat's saved epoch | `gate_open` derives it, refusing another epoch or frozen. Under AUTO and WHEN_UNLOCKED it is called with the any-terms digest at the first ready |
| BD3, `seat_key` saved before that ready is sent | `gate_open` returns `factory_pub`; the node calls `sign_binding`, saves `seat_key` with the factory key and the binding signature (field 10), and only then calls `sign_envelope(..., kind 22, ...)`. Later readies reuse the saved binding bytes (#59 H1) |
| BD4, own pair exactly once | `round_open` check 2 |
| BD5, re-derive before the first nonce and compare with `seat_key` | `round_open` check 3 |
| BD5a, compare at every later derivation; at a `ready` a mismatch sends no ready | `gate_open` when `seat_key` is known (after a restart, from `gz_sg_seat_key`): `GZ_SG_E_SEAT_KEY`, and the node sends no ready |
| BD6, a seat without a factory key is never chosen, standby seats and understudies included | The host's lobby engine (unchanged) |

With option (c) the factory key signs **only** MuSig2 partials. Row 2 of table 3.1 loses `gazpacho/bind`, and so does row 4. That removes the one single-key BIP 340 signature the host factory key made: the key that guards the timeout leaves then makes no BIP 340 signature of its own except, later, the typed timeout sweep (O2), which is the safest place to be short of splitting it (O2).

## 6. The funding wallet port (PR #56)

### 6.1 Today

`gz_wallet_port_t` (PR #56, `core/funding/include/gazpacho/funding.h`):

- `plan(amount, script, feerate, must_spend, tx, ..., prev, ...)`
- `sign(tx, tx_len, out, ...)`: "the signed bytes of the plan whose unsigned bytes are given"
- `hold(tx, tx_len)`
- `release(tx, tx_len)`
- `spend_back(tx, tx_len, index, fee, out, ...)`

Underneath, `gzt_funding_build`, `gzt_funding_release` and `gzt_funding_spend_back` take `const gzw_xprv *master`, so whoever implements the port must derive the master key, keep it alive and wipe it.

### 6.2 After

```c
typedef struct {
    int (*plan)(void *ctx, uint64_t amount, const uint8_t script[34], uint64_t feerate,
                const gz_outpoint_t *must_spend, uint8_t txid[32], uint8_t *tx, size_t cap,
                size_t *tx_len, gz_fund_prevout_t *prev, size_t max_prev, size_t *n_prev);
    int (*sign_plan)(void *ctx, const uint8_t txid[32], uint8_t *out, size_t cap, size_t *out_len);
    int (*adopt)(void *ctx, const uint8_t *tx, size_t tx_len, const uint8_t txid[32],
                 const uint8_t script[34], uint64_t amount);
    void (*release)(void *ctx, const uint8_t txid[32]);
    int (*spend_back)(void *ctx, const uint8_t txid[32], uint32_t index, uint64_t fee,
                      uint8_t *out, size_t cap, size_t *out_len);
    void *ctx;
} gz_wallet_port_t;
```

- `plan` returns the txid the signer holds the plan under. `sign_plan`, `spend_back` and `release` name that txid, never bytes. `hold` becomes `adopt`, with the checks of 2.3.
- The program implements the port over `gz_sg_fund_*`. The master key is derived and wiped inside each `gz_sg_fund_*` call and appears nowhere else.
- `gzt_funding_build`, `gzt_funding_release` and `gzt_funding_spend_back` keep their signatures, since `wallet/tx` is a pure library with its own tests, but only `signer/` may call them (section 7).
- The funding engine keeps its checks unchanged: H1 compares the plan with the proposal before `sign_plan`, and `signed_ok` checks the signed bytes after.

PR #56 is a draft and its port has no program implementation yet, so the rename costs least before it merges (section 9).

## 7. CI checks

### 7.1 No signing outside `signer/` (`tools/check-signer-boundary.sh`, new)

This is the same kind of check as `tools/check-core-isolation.sh` (which already limits `core/signing` to the exact names in `tools/signing-allowed-calls.txt`), applied the other way round.

**Banned symbols.** `tools/signer-only-symbols.txt` lists:

- `secp256k1_schnorrsig_sign32`, `secp256k1_schnorrsig_sign_custom`, `secp256k1_ecdsa_sign`, `secp256k1_ecdsa_sign_recoverable`;
- `secp256k1_musig_nonce_gen`, `secp256k1_musig_partial_sign`, `secp256k1_ecdh`, `secp256k1_keypair_create`;
- `secp256k1_ec_seckey_tweak_add`, `secp256k1_ec_privkey_tweak_add`, `secp256k1_keypair_xonly_tweak_add`;
- `gzt_sign_keypath`, `gzt_funding_build`, `gzt_funding_release`, `gzt_funding_spend_back`;
- `gzw_bip32_master`, `gzw_bip86_tweaked_keypair`, and every `gzw_*` function that returns a private key;
- SuperScalar's `musig_sign_taproot`, `musig_sign_all_local`, `musig_create_partial_sig`, `musig_nonce_pool_generate`, `musig_nonce_pool_next`, `adaptor_*` signing functions, and `factory_*` and `bolt11_*` functions that sign.

**Object check.** For every static library and executable the build makes, except `gazpacho_signer`, `gazpacho_wallet_keys`, `gazpacho_wallet_tx`, `gazpacho_superscalar` and the test and tool targets named in an allow file, `nm -u` must show none of the banned symbols. The check runs in the existing `ctest` job.

**Source check.** In headers under `core/`, `ports/` and `program/`, no function or function pointer may take parameters whose type and name together give one of these shapes:

- `uint8_t sec`/`secret`/`seckey`/`priv`/`sk` `[32]`;
- `secp256k1_keypair *`;
- a 32-byte `msg`/`hash`/`digest` together with a 64-byte `sig` in one parameter list (the generic shape).

This is a small Python script, like `wallet/tests/check_no_io.py`, run in CI. Exceptions are written in the script with the reason, one per line. There are none at the start.

**Allow list for core/signing.** `tools/signing-allowed-calls.txt` loses `secp256k1_keypair_create`, `secp256k1_musig_nonce_gen`, `secp256k1_musig_partial_sign` and `secp256k1_schnorrsig_sign32` when step S4 lands. The existing `signing_isolation` test then enforces the boundary for core/signing on its own.

**Test targets** (the simulator's test signer, the signing harness, vectors) are allowed by name in `tools/signer-boundary-allow.txt`. Each line names one target and the reason.

The check runs in report mode from S1 and fails the build from S4 (section 9).

### 7.2 No unregistered tag (`tools/check-tags.py`, new)

1. It collects every string literal that starts with `gazpacho/` and is not the operand of `#include`, in `core/`, `ports/`, `program/`, `wallet/`, `signer/` and `tools/`, excluding `core/superscalar/` and the literals listed with their reason in `tools/tags-allow.txt` (for example the deliberate mutation `gazpacho/v1/storagf` in a test).
2. Every one must appear in the tag table of `spec/PROTOCOL.md` 8.2, with a state that begins with "Specified" or "Reserved" (PR #60 leaves no "In code" state).
3. No tag may appear twice in that table.
4. Every tag the table marks "signed directly" must appear in table 3.1 of this note under some key.

It fails with the file, the line and the tag. It runs with `python -I`, like the other tools, and needs nothing but the standard library.

### 7.3 Also checked

- **Core dumps.** A program test asserts, after start, `RLIMIT_CORE == 0` and `PR_GET_DUMPABLE == 0` on Linux, as `wallet/tests/tool_faults.c` does for the wallet tool. The program calls the same `no_dumps()` as the KDF helper (`ports/storage/crypto/sc_kdf.c`) at its start.
- **Locked memory.** `gz_signer_t` is allocated in pages the program `mlock`s, or marks `MADV_DONTDUMP` where locking is refused. A test checks that the call is made. Whole-process `mlockall` is left for the signer process (section 10), because curl and OpenSSL allocation sizes make it fragile in the main process.

## 8. Mutation tests, one per check

These are in the style of `tests/*/mutants.txt` and `tools/mutate-*.py`. Each mutant removes or inverts one check of section 2.3, and a named test must fail. The file is `signer/tests/mutants.txt`.

| Mutant | The check it removes | Test that must catch it |
|---|---|---|
| `slot-epoch` | `slot_add` epoch current, not frozen | `signer_slot_refuses_other_epoch`, `signer_slot_refuses_frozen` |
| `slot-dup` | `slot_add` refuses a held scope | `signer_slot_refuses_twice` |
| `gate-epoch` | `gate_open` epoch check | `signer_gate_refuses_other_epoch` |
| `gate-seat-key` | `gate_open` compares with `seat_key` (BD5a) | `signer_gate_seat_key_mismatch` |
| `gate-digest` | `round_open` gate digest equals `terms_digest` | `signer_round_refuses_other_terms` |
| `gate-close-wipes` | `gate_close` wipes the secret and closes the rounds | `signer_gate_close_wipes` (valgrind: memory undefined after close) |
| `env-kind` | Kind in the key's row | `signer_env_refuses_member_kind_on_host`, `..._host_kind_on_member` |
| `env-factory` | The factory key signs no message | `signer_env_refuses_factory` |
| `env-240` | No record 240 in the input | `signer_env_refuses_sig_record` |
| `env-determ` | Deterministic only for the rebuilt kinds | `signer_env_deterministic_only_rebuilt` |
| `terms-hostkey` | `host_key` is ours | `signer_terms_refuses_other_host_key` |
| `terms-chain` | Chain is ours | `signer_terms_refuses_other_chain` |
| `bind-own-keys` | The binding uses the slot's own keys | `signer_bind_uses_own_keys` (vector) |
| `round-me` | This party present once with its own keys (BD4) | `signer_round_refuses_missing_me`, `..._me_twice`, `..._other_factory_key` |
| `round-script` | Spent script is the tweaked aggregate | `signer_round_refuses_wrong_script` |
| `round-funding` | Funding amount and script match | `signer_round_refuses_wrong_amount` |
| `round-root-all` | The root needs every participant | `signer_round_refuses_partial_root` |
| `round-c6` | Children in the same or an earlier tier | `signer_round_refuses_parent_first` |
| `round-id` | Recomputed round id equals the given one | `signer_round_refuses_id_mismatch` |
| `round-c10` | No second tree on the same funding | `signer_round_refuses_second_tree` |
| `round-sighash-own` | Partial uses the signer's own sighash | `signer_partial_ignores_caller_digest`: a test-only engine passes a doctored `def` after `round_open`; the partial must verify only against the original sighash |
| `nonce-once` | One secret nonce per item | `signer_nonce_refuses_second` |
| `nonce-inputs` | `sk`, `msg32` and `extra` passed to `nonce_gen` | `signer_nonce_vectors` (fixed randomness, BIP 327 vectors) |
| `partial-own-nonce` | Our own nonce at our position | `signer_partial_refuses_missing_own_nonce` |
| `partial-once` | Wipe and refuse a second partial | `signer_partial_refuses_second`, `signer_partial_wipes_on_failure` |
| `ecdh-factory` | ECDH never with the factory key | `signer_ecdh_refuses_factory` |
| `fund-txid` | `fund_sign` only for a held txid | `signer_fund_refuses_unknown_txid` |
| `fund-spend-back-dest` | The destination is chosen inside the signer | `signer_spend_back_pays_own_script` |
| `fund-spend-back-fee` | Fee within the spend-back's cap (2.3): level 2 admitted, one satoshi more refused | `signer_spend_back_refuses_high_fee`, `signer_spend_back_admits_level_2` |
| `fund-adopt-outputs` | `adopt` checks every output | `signer_adopt_refuses_foreign_output` |
| `fund-adopt-inputs` | `adopt` checks every input is ours | `signer_adopt_refuses_foreign_input` |
| `sighash-default` | Only `SIGHASH_DEFAULT` | `signer_never_other_sighash` (scans every signature the suite makes: 64 bytes, never 65) |
| `refusal-zeroes` | Outputs zeroed and state unchanged on refusal | `signer_refusal_zeroes_outputs` (run after every refusal test) |

Two more tests, which are not mutants:

- **Key-use census.** During a full multi-process round (`tests/program/signing.py`), and in the simulator, a test build of the signer logs `(key role, tag or sighash kind)` for every signature. The set must equal table 3.1.
- **The old shape is gone.** A test computes a TapSighash for a timeout-leaf spend of a built tree, then tries every signer operation with inputs it controls. No output may verify as a BIP 340 signature over that sighash under the host factory key.

## 9. Migration order against the open PRs

Each step is one PR, and each ends with the existing multi-process tests green (integrate continuously).

| Step | PR | What | Why in this order |
|---|---|---|---|
| S0 | This PR | Docs only: this note | Agree the shape before code moves |
| S1 | New, small | `PROTOCOL.md` 8.2 brought up to date (3.3); `tools/check-tags.py` failing the build; `tools/check-signer-boundary.sh` in **report** mode; `no_dumps()` at program start, with its test | Independent of every open PR; makes the starting point measurable |
| S2 | #53 merges first, unchanged in shape | Its `gzp_keys_*` is the derivation layer the signer will wrap. Before merge, one change: `gzp_net_sign_host` is not added (the host signs through the existing `port_sign` until S4), so no new generic hook lands | #53 is program-only and carries the scoped table that resolves the AT_JOIN conflict |
| S3 | #52 rebased on #53 | The AT_JOIN gate calls the key port's new `gate_open(scope, digest, epoch, index)`, which PR #53's `gzp_keys_scope_open` implements, in place of `secret()` into `gate_secret`. `gate_secret` is deleted. `host_secret` is not added: the key hook reads the host key through PR #53's `gzp_keys_host` inside the program's hook implementation. The `keys` hook stays for now | Merges the composite signing without the second copy of the scoped secret (5.1). The keypair hook is an interim shape removed in S4 |
| S4 | New: `signer/` | The library (section 2) built from PR #53's `keys.c`, the secret-key parts of `signing.c` (nonce, partial, `sign_digest`) and `program/net.c`'s ECDH key. The ports change as in section 4. `signing-allowed-calls.txt` shrinks. `check-signer-boundary.sh` switches to **fail**. The mutants of section 8 land | The big move, done once, after the code it moves has merged |
| S5 | #56, rebased on S4 | The wallet port as in 6.2, implemented over `gz_sg_fund_*` | #56 is a draft with no program implementation of its port yet. If #56 must merge before S4, it merges with the 6.2 port shape (txid, not bytes) implemented over `gzt_funding_*` directly in the program, and S4 moves that implementation into the signer. Either order works; the port shape is fixed now |
| S6 | #59's code step | Binding at the first ready (BD). `sign_binding` loses its factory-key form; `gate_open` gains the `seat_key` compare (BD5); the factory key's rows in 3.1 shrink to partials only; the mutant `env-factory` widens to cover bindings | #59's note already says its code follows #52. On top of S4 it is smaller: the BD checks land in one place |

What can slip without harm: S1 can land any time. S5 can go before or after S4 as described. S6 can go before S4 only if it keeps `bind_by_factory` out of the generic hook, which it does by deleting it.

## 10. 1.0.0: a separate signer process

The library of section 2 runs inside its own process, started by the program, in the same way the KDF helper runs today (`--gz-kdf-helper` in `sc_kdf.c`).

- **Transport.** A `socketpair`, one per client part. Requests and answers are typed TLV messages written with the project's own record writer: one message type per operation of section 2.3, a request id, and fixed-size fields. The decoder is fuzzed (`fuzz/corpus/signer/`).
- **Capability masks** (like `hsmd`'s `HSM_PERM_*`). Each client socket is given a mask when the signer starts, and the signer checks it before decoding the body:

  | Client | Mask |
  |---|---|
  | transport (`ports/net`) | `ECDH` |
  | node part (lobbies) | `SLOT`, `GATE`, `ENVELOPE_LOBBY`, `TERMS`, `BINDING` |
  | signing engine | `ROUND`, `ENVELOPE_ROUND` |
  | funding engine | `FUND` |
  | the local API | none: it reaches the gate only through the node's ready command |

  An operation outside the mask is refused and logged by name, never by contents.
- **Hardening.** At start the signer process:
  - sets `RLIMIT_CORE` to 0, `PR_SET_DUMPABLE` to 0 and `PR_SET_NO_NEW_PRIVS`;
  - calls `mlockall(MCL_CURRENT | MCL_FUTURE)`;
  - closes every file descriptor except its sockets;
  - installs a seccomp filter.

  The filter allows only `read`, `write`, `recvmsg`, `sendmsg`, `ppoll`, `getrandom`, `futex`, `mmap`/`munmap`/`mprotect` without `PROT_EXEC`, `clock_gettime` and `exit_group`. There is no `open`, `connect`, `socket` or `execve`. On platforms without seccomp it runs with the other measures and says so in the log at start.
- **Its own state.** The signer process keeps its own small encrypted journal, through the storage layer's sealed-file format: the C7 exposure records, C10's open rounds, `seat_key`s and the held funding plans. It does not trust the node's. This is VLS's approach: a compromised node cannot make the signer forget that it signed a tree on an outpoint.
- **Where the seed comes from.** The unlock happens in the signer process. The program forwards the passphrase from the local API over the `GATE` socket, and the signer runs the KDF helper itself. The main process then never sees the seed. To be confirmed when the program's unlock path (PR #51, PR #54) is final.
- **Checks that move in.**
  - The member's C1 rebuild and compare (core/tree's builder and import), so the signer refuses a tree the member did not build, whatever the node says.
  - Record decoding for the kinds that commit a party: `join`, `ready`, `round_nonces`, `round_partial_sigs`, `round_ack`, `terms_offer`, `start`, `round_propose`, `round_complete`.
  - A typed timeout-sweep operation and, with exits, the exit and penalty operations, each with a destination allowlist (the wallet's own scripts) and a fee range, as VLS's `policy-sweep-destination-allowlisted` and `policy-sweep-fee-range` do.

The operations do not change between Slice 1 and 1.0.0. The process step changes the transport and adds the checks above, nothing in the meaning.

## 11. Open point O2: split the host factory key?

The question is whether the host should use one key for its MuSig2 partials and a different key in the timeout leaves (`<h> CLTV DROP <K> CHECKSIG` and the CSV leaf), instead of the same factory key in both.

**For splitting:**

- The key in the timeout leaves can then **never** be reached by the round code, even through a bug in the signer's own round operations: no partial-signing path touches it.
- The timeout key is needed only at a tree's end of life. It can be derived only when a timeout sweep is due, and kept colder than the partial-signing key.
- It follows BIP 340's "one key pair for one purpose" exactly.
- A leak of the host's hot per-lobby key alone would not give the timeout path.

**Against splitting:**

- **Protocol change.** Each host participant entry needs a second public key, or a rule that derives it from the same path at another index. The leaf scripts, the round id preimage, the tree digest and the vectors change, and they are being regenerated anyway for PR #59 and the tag rename of `PROTOCOL.md` 11.
- **Compatibility with SuperScalar's tree shape.** SuperScalar's own factory uses the LSP's key in the timeout leaf (imported `factory.c`), so a split diverges from the reference implementation and from the shared work. That needs the SuperScalar team's agreement.
- **More keys.** More to derive, journal (`key_index` pairs become triples on the host) and restore. BD1's "one pair per seat" grows a third key on the host seat.
- **Less needed after this design.** After S4 and S6 the host factory key signs only MuSig2 partials over the signer's own sighashes. With option (c) no single-key BIP 340 signature is made with it. The residual risk is a bug inside `round_open` or `partial` that lets a caller choose the sighash, and the mutants `round-sighash-own` and `sighash-default` exist to catch exactly that.

**Not decided.** If it is done, it should be decided before the 1.0.0 vectors freeze, together with the tag rename, so that signed bytes change once. Until then the table of 3.1 forbids any script-path signature by the host factory key, and the future timeout-sweep operation is the only one that may make one.

## 12. Changes

- Draft 1 (2026-11-18): first draft, from the approved research recommendation.
- Draft 1, correction (2026-11-18): the spend-back's fee cap (2.3, `fund_spend_back` check 3) admits the whole fee ladder; "ceiling × vsize" refused level 2 (review B of #56, M-3).
- Draft 1, review fixes (2026-11-18, review of #59 to #63): kind table matches the specification's signed kinds (M1); the tag check skips `#include` paths and an allow list, and accepts states beginning "Specified" or "Reserved" (M2); BD1 is the host engine extended to every seat ever held (M3); the factory key's "Never" rests on K10 and CH-OP-1 and excepts O2's timeout sweep (M4); D9, the C1 rebuild at 1.0.0, pending the owner (M5); `sign_binding` once per seat, its bytes saved in `seat_key` field 10 (#59 H1); the parity check dropped (L1); key paths cited from `docs/notes/keys.md` (L2); `GZ_SG_E_SEAT_KEY` at a ready (L3); no local file cited (L4); `gazpacho/test-funding` from #52 (L5); the penalty operation's epoch exception (L6). The binding rules are named BD1 to BD6 (formerly K1-1 to K1-6), as in #59.
