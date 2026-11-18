# Keys: the derivation tree and the key port (P8)

Draft 1, 2026-11-17, contract v2 step P8 (`docs/notes/contract-v2.md` sections 13 and 17). **This note is not itself reviewed.** It proposes the whole derivation tree for the owner's open item (the key path, all hardened, and a check that on-chain coins follow BIP 86), says what the program holds in memory in each state, and how the key port replaces the stand-in keys. Code: `program/keys.h`, `program/keys.c`, the key port in `program/executor.c` and the transport keys in `program/net.c`; tests in `tests/program/`.

Everything here marked **proposed** waits for the owner. Draft 2 (2026-11-18): a host's own pairs move to `2'` (K2). Nothing in it changes a message, a record or the core.

## 1. The tree

One BIP 39 seed (64 bytes, empty BIP 39 passphrase) gives every key the wallet signs with. Storage keys are not in this tree: they are HKDF over the seed or over the storage key (`storage-encryption.md` 4.4), a different function and key.

```
m                                     BIP 32 master: HMAC-SHA512("Bitcoin seed", seed)
├── 254315617'                        Gazpacho's purpose P (section 2)
│   └── net'                          network level: 1 testnet4, 2 signet, 3 testnet3, 4 regtest;
│       │                             0 mainnet, reserved, never derived while mainnet is refused
│       ├── 0'                        a member's per-lobby keys
│       │   └── epoch'                restore epoch: 0 for the installation, else 31 random bits (R2)
│       │       ├── i'                contribution key = the member's BOLT 8 static key for that lobby
│       │       └── (i + 1)'          factory key (the MuSig2 key that signs the tree)
│       ├── 1'                        the host's long-term key
│       │   └── k'                    k the first valid of 0, 1, 2, ...
│       └── 2'                        a host's own per-lobby pairs: the same shape as 0' (K2)
│           └── epoch' / i', (i + 1)'
└── 86'                               BIP 86: the on-chain wallet
    └── coin'                         0 mainnet, 1 every test network (BIP 44 coin type)
        └── 0'                        account 0
            ├── 0 / j                 receive chain: ordinary addresses and payout scripts (section 5)
            └── 1 / j                 change chain
```

| Key | Path | Hardened | Who holds the secret, and when (section 7) |
|---|---|---|---|
| Contribution and BOLT 8 key of a member's lobby | `m/254315617'/net'/0'/epoch'/i'` | every step | the transport, for one `CONNECT`'s life |
| Factory key of that lobby (member) | `m/254315617'/net'/0'/epoch'/(i+1)'` | every step | nobody between uses; per round (AUTO, WHEN_UNLOCKED) or scoped to one check (AT_JOIN) |
| A host's own factory key in a lobby | `m/254315617'/net'/2'/epoch'/(i+1)'` | every step | nobody between uses; per round |
| Host's long-term key | `m/254315617'/net'/1'/k'` | every step | the host's transport, for the node's life |
| Receive address and payout script | `m/86'/coin'/0'/0/j` | three hardened, then BIP 86's two public steps | nobody; derived per spend |
| Change address | `m/86'/coin'/0'/1/j` | as above | as above |

**All hardened, except where BIP 86 says otherwise.** Every key below the Gazpacho purpose is hardened at every level: they are secret keys used one at a time, never an account whose public children anyone needs, so a leaked child secret reveals nothing about its siblings or its parent. The on-chain wallet is plain BIP 86 so that any BIP 86 wallet restored from the 24 words finds its coins: its last two levels (change, index) are public derivation, as BIP 86 requires. Making them hardened would break that recovery, so the owner's "all hardened" is read as "all of Gazpacho's own keys". No Gazpacho key is a child of `m/86'`, and nothing under `m/86'` reaches a Gazpacho key: the two subtrees share only the master.

**Following BIP 86** (the owner's check). The program's on-chain coins are only ever paid to scripts of section 1's `m/86'` branch: `OP_1 <Q>` with Q the BIP 341 output key of the BIP 86 internal key and no script tree (`wallet_keys.h`, `gzw_bip86_output_from_master`). That is shown three ways: BIP 86's own published vectors (the wallet's official vectors, `wallet/vectors/`), the same derivation for coin type 1 checked against embit (an independent BIP 32 and BIP 86 implementation) for the test words, and the program's `wallet first-address` line equal to that vector (test T13, section 10).

**The network level.** `net` separates the networks, because BIP 44's coin type is 1 on all of them: with a coin-type level, one seed would have the same host key and member keys on signet and testnet4, linkable across networks. Values: 0 mainnet (reserved), 1 testnet4, 2 signet, 3 testnet3, 4 regtest (**proposed**: contract v2 left regtest out; the program runs only signet and testnet4 today, and the level is defined so that a regtest build never shares keys with signet). `gzw_network`'s own numbering (testnet3 1, testnet4 2, signet 3, regtest 4) is a different enum and is mapped, never cast.

## 2. The purpose number

254315617 is the first four bytes of `SHA256("gazpacho keys")`, `8f 28 8c 61`, with the top bit cleared (rechecked here). It is not one of BIP 43's purposes in use (44, 45, 48, 49, 84, 86, 87), nor LND's 1017 or Eclair's 46 and 47.

**SLIP-0043 (review of PR 28, deferred to P8).** Checked on 2026-11-17: the SLIP repository (`satoshilabs/slips`, default branch at commit `7a2abdd1e8`) has no `slip-0043.md`, its index lists no SLIP-0043, and its history as served has no commit naming the file. So the number **could not be checked against a registry**: the file is gone from `satoshilabs/slips`. The number stays **proposed**. Registering a purpose is a public step; the owner decides whether and when (contract v2 section 18 item 1). Nothing in the program depends on it.

## 3. Factory and contribution keys per (epoch, index)

- **Pairs.** The node part allocates indexes in pairs (contract v2 section 13): the contribution key at i, the factory key at i + 1, and `key_index` records i + 1. Its first pair is (1, 2), not (0, 1): `np_save_pair` allocates above `highest_index`, which starts at 0, so index 0 is never used. Contract v2's test T13 says "(epoch 0, index 0)"; this note's T13 (section 10) uses the core as built: the first link at index 1, `key_index` 2, the second `CONNECT` at index 3.
- **The host's pair, on its own branch.** A host allocates a pair per lobby as a member does, and signs with its factory key at i + 1. Its i is never used (the host's BOLT 8 key is its long-term key), so it is burned, which costs nothing. The host's pairs are on `2'`, not `0'`. The key port chooses the branch by the data folder's role, which is fixed at the folder's first start (`gzp_keys_set_role`), so the core allocates indexes as before.
- **K2, resolved (2026-11-18).** Found by test T13: with host pairs on `0'`, one set of words used for a host folder and for a member folder gave the host's factory key (0, 2) to the member's first lobby too. The host then refused the member's join (seat state 7); across two hosts it would have put one key in two factories. With the host's pairs on `2'`, the same words can run a host and a member: T13 step 6 has a member made from the host's own words join that host's lobby with two others, and the lobby reaches Funding. Set-up checks all three branches, so a seed works in either role.
- **Only the current epoch.** The key port derives a per-lobby key only for the **current** epoch: the epoch of the newest `key_epoch` record the node has read or saved, 0 before there is one. For any other epoch `pub` and `secret` return 0, which the node already treats as "an epoch this wallet cannot derive" (`lobbyslot.c`: the slot is kept as a placeholder and left out). This is C12 and R3 enforced at the port as well as by the core: a restored node never derives a key of an earlier epoch, whatever a saved slot or a request names.
- **A restore start derives nothing until the new epoch is saved.** With the restore marker, the node loads the backup's slots (under the old epoch) before it saves the restore batch. Until the program carries out the SAVE that holds the new `key_epoch`, the port refuses every per-lobby key, so the old slots load as left out and their seats are lost, as R3 says ("a member restored while in an open lobby loses its seat there and must join again with a new key").
- **Audit M3.** The node derives a loaded slot's keys under the epoch saved in its `slot_opened` record. A port that derives any epoch (#52's stand-in) therefore lets a restored member reconnect with its old key and keep its seat and readiness. With this port that cannot happen: an old slot gets no key and loads as left out. T13 step 4 checks it as separate processes: no old key on the wire, and neither seat nor readiness in the backup's lobbies. The same test fails with the policy and the freeze removed. The node-side check (refuse a slot whose saved epoch is not the current one) is the core's, and would be a second line.
- **How the port learns the epoch.** The program sees every `key_epoch` record twice: when the node reads it back at a start (the executor wraps the storage reader it hands to `gz_node_start`) and when it carries out a SAVE holding one. The record's layout is `node.h`'s (`GZ_RECORD_KEY_EPOCH`, field 2, `u32`). No new action or port is needed.
- **Invalid children.** About 1 in 2^127 per step, so the rule only has to be total and safe:
  - at `i'` or `(i+1)'`: the port returns 0 for that key. Today the node part answers `503 no_key` and saves nothing, and the next try allocates the same pair again, so that one lobby can never be opened. Contract v2 asks the node part to skip the pair and allocate the next; **a core change (node part), which the P6a step makes**.
  - at `epoch'`: review R2-8 asks the epoch to be checked when it is drawn, before `key_epoch` is saved. The draw is in the node part (`np_restore_batch`), which cannot see the key port's derivation; **a core change, which the P6a step makes**: the key port gains `epoch_ok(epoch)` and the draw retries on 0 as it does for epoch 0. Until then an invalid epoch makes every per-lobby key of that installation return 0 (safe: no key is ever used twice; the wallet cannot open lobbies until a new restore).
  - at `net'` or `0'` (or `1'`, `86'`, `coin'`, `0'`): the seed cannot be used. The program refuses to start with it ("these words cannot be used with Gazpacho: make a new wallet"); set-up should refuse such words before they are shown (storage side).
  - the host key: k is the first valid of 0, 1, 2, ..., found at every start, so nothing is stored.

## 4. Per-lobby contribution and transport keys

- **The member's transport key is the contribution key.** A member never listens. Each `CONNECT` names (epoch, index); the program derives that contribution secret, hands it to the transport for the connection's handshakes (`gz_peers_connect`), keeps it in the target table for reconnects under the same `CONNECT` (`messages.md` 2: reconnects reuse the key), and wipes it at `DISCONNECT`, at a restart from storage and at shutdown. A fresh pair per `CONNECT` is the node part's (contract v2 section 3).
- **The member's process key.** The transport's configuration needs a static key even on a member, used only by a listener. The member's is a fresh random key per process, never shown, never saved and never used on the wire (it does not listen). It replaces `transport.key`, so no member key is ever linked across lobbies by a long-lived identity.
- **The host's transport key is the host key** (section 1), derived at start and held in the transport's configuration for the node's life, because every inbound handshake needs it. It does not change with the restore epoch: members pin it, and a restored host is the same host.
- **Where the contribution secret comes from while the wallet is locked** (composite 12.2's P8 matter). Nowhere: a locked program runs no node (`storage-encryption.md` 8.1), so nothing needs a handshake. While storage is unlocked the contribution key is derived from the seed on demand, under every signing setting, including AT_JOIN with its gate closed (12.2: "available whenever the node runs"). No separate key or key file is needed.

## 5. Payout receive indexes (`exit.md` 3.4)

- **The script.** For receive index j: the BIP 86 internal key at `m/86'/coin'/0'/0/j`, its output key Q, and `51 20 <Q>`, 34 bytes. It needs no secret: the port computes it from the account's public key (`m/86'/coin'/0'` neutered) and may cache that public key. It does not hold the account's private key.
- **One allocator.** Payout scripts and ordinary receive addresses share one counter, the receive chain's next unused j, so an index is never given twice. The allocation must be saved (journal) before the script is sent, as `key_index` is before a key is shown, and never reused even if the creation fails.
- **Port interface (proposed).** `payout_script(j, spk34)`: 1, or 0 if there is none (an invalid child at j: the allocator skips j as BIP 32 says). The allocation itself, the record that holds it and the `payout_script` record in `ready` are the core's and `messages.md`'s, not P8's; this note proposes the allocation rule below for them.
- **Open point 32 (proposed answer).** One receive index **per lobby** (per slot), allocated in the slot's first batch beside `key_index`, reused across that lobby's checks and attempts (they compete to make one factory; at most one is funded, R5), and burned when the lobby ends without a factory. The receive chain's highest allocated index goes into the guard, as key indexes do, so a restore that finds the guard scans at least that far. Without a guard, the restored wallet scans with the gap limit of 3.4 (20 plus 8 open slots). A run of burned indexes longer than that can still hide coins from a guardless restore; the wallet counts the run of consecutive unused receive indexes and, once a new allocation would make it longer than 28, warns the person before joining (owner to choose between warning and refusing).

## 6. The wallet's own BIP 86 chain

Account 0 of BIP 86 on the network's coin type. Receive at `0/j`, change at `1/j`, the standard gap limit of 20 plus section 5's allowance. Spending keys are derived per input when a transaction is signed (`gzw_bip86_tweaked_keypair`) and wiped right after the signature; no account private key is held across a session (`wallet-keys.md` 9 item 8 left this to the node layer: this is the decision, **proposed**). The host's funding signs this way too.

## 7. What is held in memory

The seed source is the storage layer while storage is unlocked (`storage-encryption.md` 8.1: its own copy of the seed in guarded memory) and, until storage lands, the stand-in `wallet-seed.standin` read at start (section 9). The key port itself keeps **no seed, no master key and no intermediate node**: each derivation asks the seed source for the seed, walks the path, keeps the one result and wipes everything else before it returns.

| State | Gate (`member_signing`) | The key port and the transport hold | Factory secrets |
|---|---|---|---|
| No wallet, Locked | any | nothing: no node runs (storage 8.1). The seed source answers 0, so every derivation returns 0 | none |
| Unlocked | AUTO | host: the host secret (transport). Member: one contribution secret per `CONNECT` (transport target table). Public keys may be cached | derived by the key hook per round (`secret(epoch, i + 1)`), wiped by the signing engine as soon as the operation is done |
| Unlocked | WHEN_UNLOCKED, gate open | as AUTO | as AUTO |
| Unlocked | WHEN_UNLOCKED, gate closed | as AUTO | none handed out: the gate is the core's (`may_answer`); a round already answered keeps its keys to its end (12.2) |
| Unlocked | AT_JOIN | as AUTO, and the scoped table: per open per-lobby gate, the lobby's factory and contribution secrets, bound to (scope, values digest) | `secret()` returns 0 for every index: factory keys come only from the scoped table, filled when the person readies with the passphrase and wiped at `forget(scope)`, at every start (the table starts empty) and at lock |

- **What AT_JOIN protects, exactly.** The key port holds no lobby's factory key before the person readies, and none after its check's last attempt ends (12.2, F2). It does not protect against a same-user attacker while storage is unlocked: the seed is in the storage layer's memory then (`local-api.md` 14.3 rule 4's words say so).
- **Open point K1: the join binding (owner to decide).** The member's `join` carries a binding signed with the factory key (`core/lobby/member.c`, `evaluate`), and under AT_JOIN a join without `ready: true` carries no passphrase. So at such a join the program derives the factory key, signs the binding and wipes the key at once. The key port never holds it, but "the factory key is derived only at ready" (`local-api.md` 14.3 rule 1) is not what happens. The two options:
  - (a) sign `join` with the per-lobby contribution key, and send the factory public key (with its proof) with `ready`. This needs a `messages.md` change.
  - (b) keep it as it is, and correct `local-api.md` 14.3 to say that the passphrase is needed at join under AT_JOIN.

  Until the owner decides, the lobby is unchanged and P8 implements today's behaviour: a transient derivation for the binding, wiped at once, never held.
- **Routing P4.3's key hook through the table (audit M2, planned for the merge after #52).** #52's node asks the key port for a secret by position only (`keys.secret(epoch, index)`, for the factory key at ready and for the contribution key at every nonce signature, abort and ack). So under AT_JOIN `port_secret` answers only from the scoped table, by position (`gzp_keys_scoped_at`): the contribution key at an open scope's index, the factory key at index + 1, current epoch, not frozen. A key the person has not readied for is never handed out, whatever the node asks, and the one-byte ready flag (audit M4) opens nothing by itself. What the merge after #52 adds:
  - the READY path that carries the passphrase calls `gzp_keys_scope_open(scope, digest, epoch, index)` once the passphrase is checked (unlock.h's CHECK), before it hands the node its ready command;
  - #52's `host_secret` port gets its P8 counterpart over `gzp_keys_host`, never the lobby path at (0, 0);
  - the checks that kill the four mutants `exec-forget-all`, `exec-forget`, `exec-secret-scoped` and `main-scoped-only`.
- **The scoped table.** At most `GZ_NODE_MAX_SLOTS` (8) entries; opening a gate for a scope that has one replaces it (the old secrets wiped first); the values digest is compared in constant time; a lookup for another digest gets nothing.
- **Protecting keys at rest for WHEN_UNLOCKED** (composite 12.2). The key port writes nothing to disk. At rest the seed is sealed in `keys.gzk` (storage 4.5); in memory while unlocked it is the storage layer's.

## 8. Wiping, constant time, memory locking

- **Wiping.** Every buffer that held a seed, an extended private key, a secret key, a `secp256k1_keypair` or an HMAC state is wiped before the function returns, on success and on every error path, with a wipe the compiler cannot remove (`gzw_wipe`). Every output holding key material is zeroed on failure. The scoped table and the transport's secrets are wiped at `forget`, at lock, at a restart from storage and at `gzp_keys_free`. Tests: a link-time wrap that records every wipe and checks each secret buffer was wiped (as `tests/net/test_wipes.c` does), plus ASan and valgrind runs.
- **Constant time.** Derivation goes through libsecp256k1's constant-time scalar and point code and libcrypto's HMAC-SHA512. No branch or index depends on a secret except the validity results of BIP 32 (secret key zero or above the order), which are public by nature (they change the path taken by every implementation). The scoped table compares values digests with `gzw_ct_equal`. Checked with valgrind's memcheck: the seed is marked undefined and every derivation run; any conditional jump or memory index on secret-dependent data is reported, and each report must be one of the listed points where a value is public by design (a public key, a validity result).
- **Memory locking.** The program's own key buffers are ordinary memory, as storage 8.3 says for keys derived outside the storage layer; core dumps are already off.

## 9. Where the seed comes from, and the unlock interface

`program/keys.h` defines a seed source: `int seed(void *ctx, uint8_t out[64])`, 1 with the BIP 39 seed (the caller wipes it) or 0 while there is none. Two implementations:

- **Today (main):** the stand-in `wallet-seed.standin` (32 bytes of entropy, mode 0600, `datadir.h`), read once at start into the seed source's memory and wiped at exit, as `main.c`'s wallet check already reads it. `transport.key` is no longer read or written (an existing one is left alone and unused).
- **With storage (S6, branch `s5-s6-program`):** the storage layer's unlocked seed. **`program/unlock.h` (commits `ee09595`, `4c72df2`, branch `p5-p6-api`) has no call that hands out the seed**: its jobs keep derived keys private (`job->keys`) and it exposes state, attempts, begin, finish, discard and lock. P8 needs one loop-thread call, valid only while the state is UNLOCKED, for example `int (*seed)(void *ctx, uint8_t out64[64])` (1, or 0 when locked; the caller wipes), or the equivalent for the key port to take the seed at `finish` of UNLOCK, CREATE and RESTORE and drop it at `lock`. **Reported; `unlock.h` is not changed here.**

## 10. Tests

| Test | What it shows |
|---|---|
| `tests/program/test_keys.c` | Vectors for every key of section 1 from the BIP 32 test seed and from the test words (24 × `abandon` ... `art`, entropy all zero): host key on signet and testnet4 (different), lobby keys at epochs 0, 1 and 2^31 - 1 and indexes 1, 2, 2^31 - 1, payout scripts j 0 and 1, receive and change addresses. Argument refusals (epoch or index at 2^31, mainnet, a network out of range). Only the current epoch; nothing in a restore start until the new epoch; the scoped table (open, digest match in constant time, replace, forget, forget all, a full table); every invalid-child level forced as in `wallet/tests/test_wallet_rare.c` |
| `tools/keys-vectors.py` | Recomputes every vector with embit (independent BIP 32, BIP 86 and BIP 341) and with a second, standard-library implementation; the C test's table is generated from it and both must agree |
| ct check | Section 8: valgrind with the seed marked secret |
| wipes | Section 8: the wrap test |
| sanitizers, valgrind | The unit tests and the fuzz run under ASan and UBSan, and under valgrind |
| fuzz | `keys.c` parses nothing it is sent (its inputs are numbers from the node and a seed from storage). The fuzz target drives the port with random seeds, epochs, indexes, networks and scoped-table operations, and checks the invariants: deterministic, public key equals the secret's, no key for another epoch, nothing after `forget` |
| mutation | `tools/mutate-keys.py` over `program/keys.c`, every survivor triaged in the pull request |
| T13 `program_derived_keys` | Host and member from the test words: the host key printed at start equals the vector, before and after a restart, and differs between a signet and a testnet4 folder; the member's first link is index 1's key and its `key_index` record says 2; a second `CONNECT` uses index 3; restarted, the same keys; after a restore the epoch changes and the host sees a new key |
| T2 step 3 | A member with two `CONNECT`s to one host: two links, a reply on one never arrives on the other |

## 11. What P8 does not do

- The core changes of section 3 (skip a pair with an invalid child; `epoch_ok` at the draw): the P6a step makes both. Section 5's receive allocator, its record and `payout_script` in `ready`: reported.
- The key hook and `scoped_secret` in `gz_key_port_t` (P4.3, `core/node` signing): P8 provides `gzp_keys_scope_open`, `gzp_keys_scoped` and `gzp_keys_forget` in `program/keys.h` for P4.3 to call, and wires the existing `forget` to them.
- `keys.gzk`, the storage layer's seed and the unlock flow: S6 and P5.
- Registering the purpose number: the owner.
