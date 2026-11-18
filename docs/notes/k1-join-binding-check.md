# BD (formerly K1): should `join` stop being signed by the factory key? (option c)

Independent check, 2026-11-17. Read-only. Specs read from `origin/main` after `git fetch`. External sources fetched as raw files. Nothing posted anywhere.

**Status: the owner approved option (c) with the five additions on 2026-11-17.** They are specified, as rules BD1 to BD6 (called K1-1 to K1-6 in earlier copies of this check; renamed so as not to clash with K1 of `docs/DECISIONS-WITHOUT-OWNER.md`), in `spec/messages.md` 6.3 and 6.4, `spec/signing-round.md` section 2, `spec/safety-rule.md` C7 and C12, and `spec/journal.md` 9.1. Section 6 lists the code changes. Mapping: addition 1 is `ready` records 12 and 14; addition 2 is BD1 (host) and BD4 (member); addition 3 is BD2; addition 4 is BD3 and BD5; addition 5 is BD6 and open point 8 of `messages.md`.

Verdict in one line: **(c) is safe with named additions.** The factory key's half of the binding protects nothing that the member's own C7 check, the contribution key's signature and the duplicate rule do not already protect. Keep the contribution key's half as it is (same tag, same hash, same 64-byte signature), move it from `join` to the seat's first `ready`, and add the five rules in section 5.

## 1. Where the two-way binding came from (quoted)

It took two review steps. Review 1 asked for the factory key to sign once. Review 2 made that two-way.

**Review 1, F10 item 9** (`docs/reviews/spec-review-1.md`). The motivation was to keep the factory key *away* from protocol messages:

> "So the same key would sign protocol messages, take part in MuSig2, and later sign an ordinary taproot spend. BIP 340 advises separating contexts ... I know of no attack ... but I know of no proof either. [R] Recommendation: sign contributions with a *separate* key ..., bound to the factory key once, in the lobby, by one statement signed with the factory key over a tagged hash."

The same review, on rogue keys (table near line 358):

> "MuSig2 key aggregation needs no proof of possession. I verified only that BIP 327 does not require one; the security claim is from the MuSig2 paper ..."

**Review 2, N17** (`docs/reviews/spec-review-2.md`):

> "Two seats could bind the same contribution key. The host should refuse duplicates, and the binding should be two-way (the contribution key also signs the factory key) so that no seat can claim another party's key."
>
> "**Change.** Derive a contribution key per lobby. Bind both ways. Refuse duplicates."

**signing-round.md section 2** (main):

> "**Binding, both ways.** In the lobby the factory key signs `TH("gazpacho/bind", lobby || factory key || contribution key)`, and the contribution key signs the same hash. Both signatures travel to every signer in `round_propose`, so anyone can check that each key vouches for the other. The host refuses two seats with one factory key or one contribution key."

Its change table: "N17 contribution key | Per lobby, two-way binding, duplicates refused, factory-key sentence corrected". F12 ("key before the lobby") only decided *when* the key index is chosen. It says nothing about who signs.

**messages.md 6.3** (main):

> "The binding is two-way: the factory key vouches for the contribution key and the contribution key for the factory key, so no seat can claim another party's key of either kind. Both signatures travel to every signer in `round_propose`, so anyone can check them."

**What these reasons actually say.**
- The factory key's signature was not added for MuSig2 security. Review 1 says outright that none is needed.
- Review 1 added it only to *link* the new contribution key to the factory key. It treated that as a cost, given its own key-separation worry.
- N17 added the *contribution* key's signature. Its stated threat was a seat claiming another party's contribution key. That direction is what makes evidence attributable. The factory key's half came along by symmetry ("of either kind"). No attack was given that needs it.
- No review weighed the need to derive the seed at Join. The AT_JOIN cost was not considered.

## 2. Primary sources

| Source | Finding | Bearing on (c) |
|---|---|---|
| BIP 327, "Simple Key Setup" ([raw](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327.mediawiki)) | "Key aggregation is non-interactive and fully compatible with BIP340 public keys." `KeyAgg` has no proof-of-possession step. Security is cited to the MuSig2 paper ([eprint 2020/1261](https://eprint.iacr.org/2020/1261)). The abstract says it is proven in the random oracle model under a weaker OMDL variant. That the model is the plain public-key one (no proofs of possession) is my memory of the paper, not quoted. | Signatures by the factory key add nothing to aggregation security, including against a host that picks its own key after seeing the members' keys. |
| BIP 327, duplicate keys | The algorithms handle duplicates, and "it is often impossible to tell at key aggregation which signer is to blame for the duplicate". An application "may reject duplicate individual public keys". | Duplicate refusal is the standard's own tool. Blame for a duplicate cannot come from key aggregation either way. |
| BIP 327, identifiable aborts | Blame works only if contributions are untampered ("e.g., because they were sent over authenticated connections"), nonces are aggregated honestly and partial signatures are verified. "A malicious aggregator ... can always make signing abort and wrongly hold honest signers accountable." Footnote: it is "an open question whether a BIP-340 signature valid under the corresponding aggregate public key is a proof of knowledge of all secret keys". | Blame rests on authenticated contributions, which here means the contribution key. Evidence never needed the factory key to sign anything. A valid group signature is not a proof of possession anyway. |
| BOLT 2 `open_channel` / `accept_channel` ([raw](https://raw.githubusercontent.com/lightning/bolts/master/02-peer-protocol.md)) | `funding_pubkey` is "the public key in the 2-of-2 multisig script". It is sent unsigned, authenticated only by the BOLT 8 session. Splicing: "SHOULD use a different `funding_pubkey` than the one used for the previous funding transaction." | Between peers, Lightning binds funding keys one way: the transport identity vouches for the key. That is exactly (c). |
| Simple taproot channels, lightning/bolts PR 995 ([file at c25dc059](https://raw.githubusercontent.com/lightning/bolts/c25dc0598985cfc154c3a79e2b0328da3b4b4749/bolt-simple-taproot.md)) | "MUST sort the exchanged `funding_pubkey`s using the `KeySort` algorithm" and aggregate with `KeyAgg`. No signature by the funding key in the peer protocol. | The MuSig2 version of Lightning keeps the one-way, transport-authenticated binding. |
| BOLT 7 `channel_announcement` ([raw](https://raw.githubusercontent.com/lightning/bolts/master/07-routing-gossip.md)) | Two-way binding exists here: `bitcoin_signature`s by the funding keys plus `node_signature`s, "proving that `node_1` owns `bitcoin_key_1`". | Lightning uses funding-key signatures only to convince *third parties* that a public channel exists and is owned (anti-spam for gossip). Gazpacho evidence never has to prove who owns a factory key (section 3, rows 2 and 3). |
| SuperScalar code at the pinned `50f7fa13` ([wire.h](https://raw.githubusercontent.com/8144225309/SuperScalar/50f7fa138b437af9b7a10acae8cd65986356810f/include/superscalar/wire.h), `src/client.c`) | "Client → LSP: HELLO {pubkey}", built by `wire_build_hello(ctx, &my_pubkey)` after `wire_noise_handshake_nk_initiator` (client.c:3369-3381). An NK handshake pins only the server's key. The client's factory key is sent with no signature and no proof of possession. | Upstream binds even less than (c). |
| Delving Bitcoin topics [1143](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143) and [1242](https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242), raw first pages | No discussion of binding factory keys to identities, proof of possession or rogue keys. | No design constraint from the posts. |

## 3. What (c) loses, with attacks, and whether each loss closes without new factory-key signatures

Notation: A is an honest member with keys (F_A, C_A). B is a malicious member. H is the host, which can also run sybil seats.

| # | Loss | Concrete attack under bare (c) | Harm | Closed without the factory key signing? |
|---|---|---|---|---|
| 1 | Squatting: a seat claims another's factory key | F_A is fresh per lobby and first leaves A's wallet in A's own `ready` to H. B cannot learn it earlier, so B cannot get in first. After an attempt fails, every member of that attempt has seen F_A. If A then leaves, B can `ready` with (F_A, C_B). If H leaks F_A early, H could seat a sybil with it first. | Denial of service only. Nobody but A can make partial signatures for F_A. A round containing (F_A, C_B) cannot complete, and the bad partial is blamed on C_B, the attacker. A host can deny service anyway. | **Yes.** (i) The host refuses a factory key already used *ever* in the lobby, including seats that left (today it checks only against current seats). (ii) A's C7 check refuses any list that does not hold the pair (F_A, C_A) exactly once (rule 2). (iii) Each seat's factory key is fixed at its first `ready`. |
| 2 | Attribution in `round_propose` and proof of fault | H builds a proposal with entry (F_A, C_H) to blame A for a missing or bad partial. | None. Every accusation in signing-round section 9 rests on the accused's contribution-key signatures (signed nonces, signed partial-signature message). With (c) the only binding naming F_A is the one C_H signed, so blame lands on C_H. H cannot pair C_A with a foreign F_X because that needs C_A's signature. That direction is the one that matters, and (c) keeps it. | **Yes**, provided the contribution key's binding signature is kept per participant in `round_propose` (rule 1). |
| 3 | A third party checks evidence without trusting the host | The third party gets the host-signed proposal and one 64-byte contribution-key binding per participant. It can check that C_i agreed to F_i in this lobby. It cannot check that F_i's holder agreed to C_i. Over two failed attempts, H can show bindings (F_A, C_A) and (F_A, C_H). | A third party sees two claimants of F_A. Since no fault in section 9 is proven through ownership of a factory key, nobody can be framed. Only the record looks confusing. | **Yes** for every fault in the section 9 table. The confusion is removed by rule 1(i) above (one factory key per lobby, ever), which members can also check against the proposals they saved for that lobby. |
| 4 | Key reuse across lobbies | B replays A's `ready` or binding from lobby L1 into L2. | None. The binding hash and the `ready` signature both commit to `scope`. C_A is a per-lobby BOLT 8 key whose possession the handshake proves to the host. An honest wallet never reuses F across lobbies (fresh index pair, C7). | **Yes**, already, as long as the binding keeps `scope` inside (rule 1). |
| 5 | Restore epochs | Restore *between* Join and Ready: the old seat has no factory key yet, so nothing old was ever derived. That is better than today. Restore *after* Ready: same as today; C7 and C12 refuse the old key. New hazard: a wallet that derives F at Ready under the *current* epoch, for a seat whose contribution key came from an *earlier* epoch, would bind a new-epoch F to an old-epoch C. | Possible wrong-epoch keys, or a stale seat revived after restore. | **Yes**: rule 3. F is derived at the seat's saved index plus 1, under the seat's saved epoch. If that epoch is not the current one, the seat is dead: no `ready`. C7's text "bound to this lobby at `join`" becomes "at the seat's first `ready`". |
| 6 | Host forges or swaps a member's factory key in the proposal | H replaces A's entry with (F_H, C_A). Or it drops A and inserts (F_A, C_H). Or it gives different members different lists. | Swap (F_H, C_A): fails C_A's binding, which every member verifies at step 2, and fails A's C7 check. Drop and insert: A's C7 check finds no (F_A, C_A) and refuses. Other members cannot tell a sybil from a real member under either design. Their money does not depend on who holds F_A, only their liveness does: the round fails, the attacker is blamed and H recovers its own coins after timeout. Split lists give different round identifiers, so the signatures never combine (C1, S6). | **Yes.** Under C1 every member rebuilds byte for byte from the one host-signed list. Each member checks: every binding verifies, every key is distinct, and its own pair (F, C) appears exactly once at an allowed position. The factory key's signature protected only F_A's owner, and that owner is A, who checks for itself. |
| 7 | Mistyped passphrase at Ready (new under (c)) | The wallet derives F' from a seed with the wrong passphrase and sends it. Later it signs with the right seed, and F does not match. | A's partials fail, and A is blamed for a round it could never sign. | **Yes**: rule 4. Save F's public key in the seat record before sending `ready`. At signing, derive again and compare. On a mismatch, abort locally before any nonce. |
| 8 | The host's own binding (open point 8) | — | Under two-way, the host's factory key signs a binding to its long-term key. | **Yes**: the host's long-term key signs `round_propose`, which lists the host's factory key first. Add the host's own binding signed by the long-term key so that every entry has one form. |

Nothing in the table needs the factory key to sign anything. The one real thing given up is the one Lightning needs only for gossip: proof to an outsider that F_A's holder chose C_A. Section 9 never relies on that.

## 4. Side benefits of (c)

- Review 1's original concern goes away. In protocol messages, the factory key signs no BIP 340 statement next to its MuSig2 work.
- The seed is no longer needed at Join, which restores the AT_JOIN promise.
- Each `round_propose` participant shrinks from 194 to 130 bytes.

**Caveat.** "No other factory-key signatures, ever" holds for protocol messages only. In the import, the distribution and penalty outputs pay to P2TR(F) [C: `factory.h:1258-1261`, `:536-541`], so spending them would be an ordinary single-signer signature by F. Design 2 (C2, payout scripts) moves payouts and the distribution transaction to a separate payout script. Check that the penalty output is covered too before stating "ever".

## 5. Verdict: (c) is safe with these named additions

1. **Keep `bind_by_contribution` unchanged and move it.** Same tag `gazpacho/bind`, same hash `TH("gazpacho/bind", scope || factory_key || contribution_key)`, same 64-byte signature by the contribution key. The M1 vector's `binding` and `bind_by_contribution` values do not change. Drop `bind_by_factory`. Carry `factory_key` and `bind_by_contribution` in the seat's first `ready`, not in `join`; later `ready`s repeat them or omit them, and must match. Use a standalone signature rather than relying on the `ready` envelope signature: it is 64 bytes in `round_propose`, and a third party can check it without the whole `ready` message.
2. **Duplicates and history.** The host refuses a factory key or contribution key already used *ever* in the lobby, including seats that left. A seat's factory key is fixed at its first `ready`; a different one is refused. A member refuses a proposal in which its own pair (F, C) is missing or appears more than once, or in which its F appears with another C or its C with another F (this tightens C7). It also refuses any key that is twice in the list, as today.
3. **Epoch and index.** At Ready, F is derived at the seat's saved `key_index` (i + 1) under the epoch saved with the seat. If that is not the current epoch, the wallet sends no `ready`. C7 and C12 wording becomes "bound at the seat's first `ready`".
4. **Save before sending.** F's public key is saved with the seat before `ready` is sent, under the R6 guard and journal ordering. At signing, the wallet derives F again and compares it with the saved key; on a mismatch it aborts before any nonce.
5. **Lobby rules.** A seat in Joined has no factory key and cannot be chosen for a ready check's attempt. Standby seats and understudies follow the same rule. Write down the host's own binding (open point 8) as a `bind_by_contribution` by the host's long-term key over its factory key.

Do not adopt a middle option where the factory key signs later (for example at Ready). It would bring back a BIP 340 statement by the factory key for no security gain. Section 3 shows that the contribution key's half carries all the evidence value.

Spec text to change if adopted: `messages.md` 6.3, 6.4, 7.2 participants (194 → 130 bytes), the signer table near line 176, tests 22, 30 and 43; `signing-round.md` section 2 "Binding, both ways"; `safety-rule.md` C7 and C12 ("bound at `join`").

## 6. What the code must change (after PR #52 merges)

Not done in this pull request, which changes documents only. Paths and lines are at `main` `3083d99`. PR #52 (P4.3) touches `core/signing`, so the lines there will move.

| # | Where | Change |
|---|---|---|
| 1 | `core/node/lobbyslot.c:176-177` | Stop deriving the factory public key (`key_index + 1`) when the slot starts. Derive it only when the seat's first `ready` is built, under the epoch saved in `slot_opened`. Refuse (no `ready`, seat lost) when that epoch is not the current `key_epoch` (BD2). `ls_sign` (`:93`) must refuse `GZ_LOBBY_KEY_FACTORY` for anything but the signing engine's partial signatures |
| 2 | `core/lobby/member.c:286-293` | `join` is built with no records 2, 4, 6 and no signatures. Drop `sf`, `sc` and the `GZ_LOBBY_KEY_FACTORY` call |
| 3 | `core/lobby/member.c:~122` (ready builder) | Add record 12 `factory_key` and record 14 `bind_by_contribution` (contribution key over `gz_lobby_binding`) to every `ready`. The first `ready` saves `seat_key` in the same batch as `ready_sent` and before the action that sends it (BD3). Later `ready`s copy the saved bytes |
| 4 | `core/lobby/member.c:712-722` | `stale_seat` is today detected by comparing the `join`'s factory key with the derived one. Detect it by the slot's saved epoch against `key_epoch`, and by `seat_key` |
| 5 | `core/lobby/wire.c:114-116` | Records 2, 4, 6 of `join` become unknown even records, so the message is refused. Decode records 12 and 14 of `ready`, both required |
| 6 | `core/lobby/host.c:571-613` | Move the binding check from `join` to `ready`. Verify only `bind_by_contribution`. Fix the factory key at the first `ready`. Apply BD1 against every seat record ever held in the lobby, not only `is_in` seats (`:599`) |
| 7 | `core/lobby/host.c:346`, `:793-797` | `self_bind` signs the host's binding with `GZ_LOBBY_KEY_HOST` only. Drop the `GZ_LOBBY_KEY_FACTORY` signature |
| 8 | `core/lobby/host.c:356-359` | Participant entries carry `bind_c` only |
| 9 | `core/lobby/include/gazpacho/lobby.h:199`, `lobby_handoff.h:25` | Remove `bind_by_factory` from the join view and the hand-off. Add `factory_key` and `bind_by_contribution` to the ready view. Register record `seat_key` (`0x0001001c`) and its largest size in the record table |
| 10 | `core/signing/round_msg.c:214-217`, `:265-268` | Participant entry of `round_propose` record 20: 130 bytes (factory key, contribution key, `bind_by_contribution`) |
| 11 | `core/tree/checks.c:162-177`, `core/tree/include/gazpacho/tree.h:264-265` | Verify the contribution key's signature only. Drop `bind_by_factory` |
| 12 | `core/signing/signing.c:252-264` | The own-entry check becomes BD4: the pair exactly once, and neither key paired with another. Add BD5: derive the factory key again before the first nonce and compare it with `seat_key` and with the entry. On a difference, `round_abort` reason 12 and no nonce |
| 13 | `core/journal` (`gz_journal_type_known`), `docs/notes/lobby.md` section 1 | Type `0x0001001c` `seat_key`: fields 2 scope, 4 factory key (33), 6 epoch (`u32`), 8 index (`u32`). The host's `seat` record drops field 8 (`bind_by_factory`), and its field 6 is absent while the seat has only joined. Update the layouts table |
| 14 | `tools/spec-vectors.py` | Done in this pull request (M1, M3) |
| 15 | Tests | `tests/lobby/test_lobby_vectors.c` (M1, M3 bytes), `tests/lobby/test_lobby.c`, `tests/lobby/world.h`, `tests/lobby/fuzz_lobby.c`, `tests/signing/test_round_msg.c`, `tests/tree/test_tree_checks.c`, `tests/tree/fuzz_tree_agree.c`. New tests: `messages.md` 12, tests 22, 30, 43 and 57 to 62 |
| 16 | End to end | A multi-process lobby run in which Join happens with the gate closed and no seed access, the passphrase is entered at Ready, and the round completes. A second run with a wrong passphrase at Ready must stop with reason 12 before any nonce |
