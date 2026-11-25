# Penalty check: SuperScalar's design and code against `exit.md` draft 3

**Status.** An independent check, not itself reviewed. Its recommendations are proposed, under audit (`docs/reviews/deviation-audit-2026-11-18.md`); nothing in it is decided. Section 8.6's option A (require an independent copy) is one of two options the owner has not chosen between.

Independent check, 2026-11-17. Sources read: Delving topics 1143 (36 posts), 1242 (3 posts) and 2705 (the implementation report, 3 posts) as raw text; the import on `origin/main` (`core/superscalar/`, pin `50f7fa13`); upstream `src/channel.c` and `src/client.c` at the same pin (not imported; fetched read-only); `spec/exit.md` and `spec/safety-rule.md` on `origin/main`. Our notes and the earlier check were not used as evidence.

Links: [1143] = https://delvingbitcoin.org/t/1143, [1242] = https://delvingbitcoin.org/t/1242, [2705] = https://delvingbitcoin.org/t/2705, post n = `/n` after the topic. Code at the pin: `https://github.com/8144225309/SuperScalar/blob/50f7fa138b437af9b7a10acae8cd65986356810f/<path>#L<n>`.

## 1. Short answer

- **The earlier claim is half wrong.** The L-stock poison and the import's *default* distribution outputs pay the member's factory key. The channel penalties (to_local, HTLC, PTLC) do **not**: they pay `P2TR(local_payment_basepoint)`, a per-channel point from a **random** secret (`client.c` 2818-2823), neither the factory key nor anything seed-derivable.
- **Channel penalties are single-signer and built by the wronged party**, with the revocation key that only it can compute once the cheater has revealed its per-commitment secret. Upstream builds them at cheat time from stored secrets, or ahead of time for its watchtower. Either way the destination is the builder's free choice. No agreement is needed, and the factory-key-like destination is just an implementation default.
- **The only pre-signed penalty is the L-stock poison** (N-of-N, outputs fixed at signing, paying `f->pubkeys[i]`). It exists only when a leaf state is superseded. **1.0.0 has no leaf advances (`exit.md` 1.1, O-3), so it has no poison and no stale L-stock to punish.**
- **So open point 34 is real but mis-aimed.** In 1.0.0 it concerns only the channel penalties. Their destination is the member's own choice when it signs the ladder at revocation (CH-5), so it needs a rule in `channel.md`, not a round message. For 1.1.0's poison, the `payout_script` in `ready` would cover it, provided upstream's poison builder takes a script per member.
- **Not trustless after a stale restore.** The destination is not the hard part of a restore. The penalty needs the host's per-commitment secrets, which cannot be re-derived, and the member's revocation secret from an earlier epoch (C12 tension). Since the host keeps the member's backup and chooses which copy to return (`safety-rule.md` section 9), a host can return an old backup and then publish a commitment revoked after it. Unless a tower or export outside the host's control holds the newer penalties, that is a loss of up to the whole channel. The spec does not state this case.

## 2. The penalties, one row each

| # | Penalty | Who cheats | Who builds it | When | Key / secret | Destination (upstream) | Pre-signed? | Restore-safe? |
|---|---|---|---|---|---|---|---|---|
| P1 | Channel penalty on a revoked commitment's `to_local` (LN-penalty, Poon-Dryja) | Either side publishing its own revoked commitment: the host with a revoked host commitment (exists in Gazpacho from H19), or a member with a revoked member commitment | The wronged party alone | Upstream: at detection (`channel_build_penalty_tx` reads the stored secret), or prebuilt for the watchtower at revocation [2705 post 1 item 5]. Gazpacho: pre-signed ladder at each revocation (CH-5) | Revocation privkey = f(own `revocation_basepoint_secret`, cheater's per-commitment secret) (`channel.c` 1153-1172) | `P2TR(local_payment_basepoint)`, key path only (`channel.c` 1233-1240) | No counterparty signature. Self-signed by the wronged party; destination its own choice | **Partly.** Revocations in the restored journal: yes, if the ladder is stored signed. Revocations after the backup: **no** (secrets lost). Destination: no if it pays an old-epoch or random key; yes with a receive-chain script |
| P2 | HTLC / PTLC penalty on a revoked commitment's payment outputs | As P1 | The wronged party alone | As P1. Upstream's watchtower holds "the per-HTLC sweeps" [2705 post 1 item 5] | Revocation key, script/key path of the HTLC taptree (`channel.c` 2870ff.) | `P2TR(local_payment_basepoint)` (`channel.c` 2981ff.) | As P1 | As P1 |
| P3 | "Second-stage" penalty (`exit.md` O-1 step 3, S10, `second_stage_unlock_by`) | Host moving a payment output of a revoked commitment to a second-stage tx | — | — | — | **Does not exist upstream.** HTLC outputs are spent directly. The broadcaster's own success/timeout path carries `to_self_delay` CSV (`channel.c` 2376, 2525; `channel.h` 573-585: "no pre-signed second-stage transaction") | — | — |
| P4 | L-stock poison (old-state poisoning) | Host publishing a superseded leaf state | Everyone in the leaf (N-of-N MuSig) | **Pre-signed at each state advance**. Completed at broadcast with the revealed secret (`factory.h` 576-592, `factory.c` 4392-4418) | Agg sig over Leaf P (hashlock `H_s` + N-of-N), preimage = per-(leaf,state) secret the host reveals on supersession (`factory.h` 218-225, 640-646) | Equal split to each non-host signer, `P2TR(f->pubkeys[signer])` = the **factory key** (`factory.c` 4609-4630, 4855-4867) | **Yes, destination fixed at signing** | **No** with factory-key outputs under R3. Not in 1.0.0 |
| P5 | Design 1 "burn" of L-stock (historical) | Host not bumping the latest state | All clients | Pre-signed | N-of-N | `OP_RETURN`, value to miners [1143 post 16] | Yes | Superseded by P4 [1242 post 1]; not built |
| — | Tree state outputs (Decker-Wattenhofer) | Host publishing an older DW state | — | — | — | No penalty of their own. Protection is the poison on the rightmost state [1242 post 1] plus the newer state's smaller `nSequence` | — | Not in 1.0.0 (advanceless) |
| — | Pseudo-Spilman leaf | Host or sockpuppet confirming an old chain tx | — | — | — | **No penalty: "Pseudo-Spilman leaves are non-revocable"**. Defence is each signer's refusal to co-sign a conflicting spend [2705 post 1] | — | 1.0.0: one leaf state ever (C7, X-I7) |
| — | Design-2 payouts / distribution tx (not penalties; listed because the earlier claim lumped them in) | Nobody: time-based default, host late | Everyone at creation | Pre-signed, lock time E | N-of-N key path | Default builder: `P2TR(f->pubkeys[i])` (`factory.c` 5398-5420). `factory_build_distribution_tx` takes caller outputs (5133). #508 per `exit.md` 3.4 rationale: factory key | **Yes** | Yes with 3.4's `payout_script` |

## 3. Evidence, by claim

**Leaf channels are Poon-Dryja, either side can cheat the other.**
- "a normal BOLT-2/3 Poon-Dryja channel with HTLCs" [2705 post 1].
- Designer: exit "using standard Poon-Dryja unilateral exit" [1143 post 1; 1242 post 1].
- Since H19 / #508 the host holds commitments of its own, so the host can cheat the member with a revoked one, and a modified member wallet can cheat the host (O-2).

**Channel penalty: wronged party, revocation key, payment-basepoint destination.**
- `channel.c` 1153: "Retrieve per_commitment_secret from received revocations". 1168: "Uses our revocation_basepoint_secret + their per_commitment_secret". 1233: "Build penalty tx output: P2TR(local_payment_basepoint) key-path-only".
- Penalty tx is version 3 with RBF sequence `0xFFFFFFFD` and an optional P2A (1256-1290).
- Basepoint secrets are random: `client.c` 505 says "local basepoint secrets (random, not SHA256-derived)", and 2818 says "Send client's basepoints to LSP (random secrets)".

**Upstream's watchtower holds finished penalties.** "The standalone watchtower's database holds only finished, pre-signed responses (the latest state, the poison, a penalty, the per-HTLC sweeps)" [2705 post 1].

**Flat revocation secrets.** ZmnSCPxj suggests "simply storing all the revocation keys" instead of shachain [1143 post 34]. So nothing about the peer's secrets is derivable after a restore.

**Old-state poisoning, as designed.**
- Fixed transactions that split the L-stock among the clients; the designer also poisons the channel outputs ("Channel with `A`: entirely goes to `A`") [1242 post 1, "Old State Poisoning"].
- "any client can trivially CPFP the 'poisoning' transaction" [1242 post 1].
- In the pseudo-Spilman section, the sub-factory and the new channel are poisoned too [1242 post 1].

**Poison, as built.**
- `factory.h` 586: "pre-signed at leaf-state-advance time, broadcast (by any client / watchtower)".
- Outputs: `factory.c` 4609 says "Each non-LSP signer gets a key-path-only P2TR of their own pubkey", built from `f->pubkeys[signer_idx]`.
- Hashlock gating (#53) so a live state's poison has no witness: `factory.h` 218-225.
- The host's poison seed is derived, and so restore-safe for the host: `factory.h` 625-634.
- Only the L-stock is poisoned, not the channel outputs: mismatch M5 below.

**L-stock history.** Design 1 was `<secret> | L`: the host shares the old secret and "the clients can then retaliate by burning the `L` output to miner fees" [1143 post 13]. Post 16 has a pre-signed `nLockTime`d burn to `OP_RETURN`. Topic 1242 replaced the burn with redistribution, and the code comment says so (`factory.c` 326).

**Design 2.** "sign an `nLockTime`d transaction that sends the funds to the clients ... with `L`-funds (i.e. the liquidity stock) split evenly among all clients" [1143 post 26]. "The `nLockTime`d transactions are signed at the same setup stage that creates the tree nodes" [1242 post 1]. "Standard Poon-Dryja mechanisms then ensure that the LSP publishes its ***latest*** commitment transaction" [1242 post 1, "Inversion of Timeout Default For Hosted Poon-Dryja Channels"].

**Reserves.** The client imposes a reserve on the LSP, not the reverse; the LSP is assumed "to have watchtowers with uptime uncorrelated with their actual LN node" [1242 post 2]. This matches CH-14 and 5.9 (reserve on the host's side).

## 4. Open point 34

1. **Premise.** "Penalty outputs still pay the factory key" is true only for the poison (P4), and it describes upstream, not a Gazpacho design: `channel.md` is not written. Upstream's channel penalties pay a random per-channel basepoint. That is not restore-safe either, but for a different reason: a random secret, not an old epoch.
2. **Channel penalties (P1, P2): built by the wronged party, so the destination is free.** Gazpacho pre-signs the ladder at revocation (CH-5), so the destination is fixed then, but by the member alone. No host agreement, no round record and no `payout_script` in `ready` is needed. The fix is a `channel.md` rule: every penalty rung (to_local and every payment output) pays a script from the member's BIP 86 receive chain. **Recommendation: pay the factory's own `payout_script`** (3.4 already says the member SHOULD use it for sweeps). A fresh index per revocation would put thousands of unused indexes ahead of the gap limit, and reusing the one index costs privacy only on a breach.
3. **Poison (P4): pre-signed, destination agreed at creation.** The `payout_script` in `ready` would cover it, but only if upstream's `factory_build_l_stock_poison_*` take a script per member (today they hard-code `f->pubkeys`). Not needed in 1.0.0. Add it to the upstream ask with open point 5 for 1.1.0.
4. **Restore.** With a receive-chain destination, the output of a penalty already signed is found by the gap-limit scan, so R3 holds. **But the destination is not the only restore problem.** See section 5, T3 and T4.

**Verdict on 34.** Keep it, re-scope it:
- (a) correct the premise;
- (b) owner `channel.md`, not this spec plus a message: every penalty rung pays the factory's `payout_script`, chosen by the member at revocation, with nothing sent to the host;
- (c) for 1.1.0's poison, an upstream ask beside open point 5;
- (d) add the key and secret problems of T3 and T4, which the destination fix does not solve.

## 5. Trustlessness end to end

**T1. Member against a cheating host, no restore: trustless, given watching.**
- The host cannot redirect a penalty: only the member can compute the revocation key.
- No penalty depends on the host's cooperation, apart from the host having revealed its secret before the member released anything (CH-12; upstream `channel_receive_revocation` is `SS_MUST_CHECK`).
- Online duty: the wallet, its locked watcher or a tower holding the penalty file must run once per watch interval W − B − A − M (121 blocks on signet at W = 144), before and after E, until a payout or a current commitment spends the channel output (4.4).
- A revoked host commitment competes with the channel payout from E too, so the duty does not end at E. The spec states this (4.4, O-1, `safety-rule.md` 11).

**T2. Host against a cheating member: trustless for the host only if the host watches within its own window.** That is the CSV on the member's commitment's `to_local`. H14 has no value for it yet ("the host's W is not yet a term"). The designer assumes a high-uptime LSP with independent towers [1242 post 2].

**T3. Member after a restore from an older backup: NOT trustless.**
- Secrets the host revealed after the backup are gone (flat secrets [1143 post 34]; not seed-derivable).
- The host keeps the member's backup and chooses which version to return (`safety-rule.md` section 9, 11). It can return an old one and publish a commitment revoked after it, knowing the member cannot answer. Loss: up to the whole channel.
- This exists **because of H19** (before #508 the host held no commitment of its own, `exit.md` 3.2).
- 6.7 says the payouts and path "cannot be stale" but is silent on the penalty file. `safety-rule.md` 11 covers a "penalty file cut while locked", not a stale restore.
- Only protection: a copy of the penalty file the host cannot choose, such as a tower, or a device file the restore does not overwrite. The R6 guard detects staleness but holds no secrets.
- Must be stated as an exclusion, and should drive the tower decision (open point 21).

**T4. C12 against penalties after a restore.**
- C12: "A restored node signs only with keys of its current restore epoch". A penalty for a channel opened before the restore needs that epoch's revocation basepoint secret.
- If every rung and every payment-output penalty is signed at revocation (CH-5), nothing is signed after the restore and C12 holds.
- Anything that needs signing later breaks C12 as written: a rung added later, a fee change, `exit.md`'s "second penalty". The upstream design has no second stage at all, which helps.
- Needs either an explicit C12 carve-out (unilateral penalty and sweep spends are recovery spends, with no double-signing risk) or a rule that nothing in the penalty path is ever signed late.
- Separately, upstream's basepoints are random, so a Gazpacho channel that copied them would be unrecoverable from the seed. `channel.md` must derive them (epoch-scoped) or journal them.

**T5. Host after a member restore: trustless.** The restored member never publishes its own commitment automatically (6.7). If the person chooses to and it is revoked, the host's penalty takes it. That is the member's loss, by choice.

**T6. Silence.**
- A silent host costs the member nothing beyond fees: payouts from E, penalty unaffected.
- A silent member costs the host fees or capacity at E (4.4, H20): the host's own risk, by design [1143 post 26].

**T7. Does choosing the address at spend time open an attack?** No.
- The penalty's inputs have no other spender before the CSV: the host's own `to_local` and HTLC paths wait `to_self_delay` (`channel.c` 2376, 2525). So nothing can race the member's signature; the only race is against c + W.
- One pinning surface, if copied from upstream: the penalty is TRUC and may carry a **keyless P2A** (`channel.c` 1256-1290). Anyone can then take its one child slot with up to 1,000 vB. The member's next RBF rung must out-pay that child too. This is bounded and payable from the swept value, but avoidable.
- **Recommend: no keyless P2A on penalties.** Pay the fee from the swept value, and bump by RBF rungs only (as CH-5 already says).

## 6. Mismatches with our spec

| # | Where | Ours | SuperScalar | Action |
|---|---|---|---|---|
| M1 | Open point 34 | "Penalty outputs still pay the factory key" | Channel penalties pay a random `local_payment_basepoint`; only the poison (and the default distribution builder) pay the factory key | Correct the premise; re-scope as section 4 |
| M2 | Open point 34 recommendation | "Extend the payout-script approach" (implies agreement in the round) | Channel penalties are unilateral; the member chooses at signing | `channel.md` rule, no message; reuse `payout_script` |
| M3 | O-1 step 3, S10, 6.6, `second_stage_unlock_by`, `safety-rule.md` 11 ("Penalties against the host's second-stage payment transactions cannot be pre-signed") | BOLT-3 second-stage HTLC transactions | Upstream HTLC outputs are single-stage; the broadcaster's paths are CSV-delayed; HTLC penalties spend the commitment's outputs directly and can be prebuilt at revocation (the watchtower holds "the per-HTLC sweeps") | Decide in `channel.md`. If we follow upstream, the locked watcher can answer payment outputs, and that exclusion and `second_stage_unlock_by` go away |
| M4 | O-1 step 2 / CH-5 | Ladder "pre-signed at revocation", fee from the swept value | Upstream builds at detection (or prebuilt for the tower), one fee rate, optional keyless P2A | Keep ours; state no keyless P2A on penalties (T7) |
| M5 | 1.1.0 poison (out of scope, 1.1) | — | Design poisons the channel outputs and the L-stock [1242 post 1]; code poisons the L-stock only, with hashlock gating | Note for 1.1.0 |
| M6 | 1.1.0 poison destination | — | Pre-signed to `f->pubkeys[i]` | Upstream ask beside open point 5 |
| M7 | 6.7, `safety-rule.md` 11 | Restore: "payouts and the tree path ... neither can be stale" | — (an LN-penalty limit, sharpened by H19 and host-held backups) | Add the stale-restore penalty exclusion (T3); tie it to the tower (open point 21) |
| M8 | C12 / R3 | Sign nothing with old-epoch keys after a restore | Penalty needs the channel's revocation basepoint secret | Carve-out or "everything pre-signed" rule (T4); `channel.md` must not use random unjournaled basepoints |
| M9 | H14 | Host's penalty window not a term | Designer assumes an LSP with towers | Make the host's window (member CSV) a term |
| M10 | 1.1 "Gazpacho never hands over a key" | Cooperative signing only | Design offers private key handover for assisted exit, and the client must then "select new keys at each timeout tree" [1242 post 1] | Consistent choice. With `payout_script`, a handed-over key would not move the payouts anyway; note it if handover is ever considered |
| M11 | 3.1 spare-liquidity payout to the leaf member | K = 1, all to the member | "split evenly among all clients" [1143 post 26] | Consistent at K = 1 |

## 7. Verdicts

- **Open point 34.** Valid concern, wrong premise and wrong remedy layer.
  - In 1.0.0 it concerns channel penalties only. Those are built and signed by the member alone, so the factory-key-like destination is an upstream default. The member should simply pay its `payout_script` (`channel.md`).
  - The `ready` record matters only for 1.1.0's pre-signed poison, and needs upstream support.
  - Point 34 should also carry the C12 and key issue (T4).
- **Trustlessness.** For both parties, without a restore and with watching inside the stated windows: trustless. No penalty needs the other side's cooperation, and choosing the address at spend time adds no attack. It is **not trustless across a restore from a backup older than the newest revocation** (T3): a host holding the member's backups can engineer that. The spec must state it and offer a host-independent copy of the penalty file. The host's own safety needs a stated penalty window (M9).

## 8. T3, restoring an older backup: options compared (second pass, 2026-11-17)

Asked by the owner through the coordinator: find the best answer to T3. The options considered were removing the attack class, keeping penalty data out of the host's reach, and restore behaviour, plus the honest window.

### 8.1 Why H19 exists

- **Design 2 needs it.** The designer writes: "reaching into the hosted channel also forces the LSP to publish its commitment transaction before the end-of-lifetime. Standard Poon-Dryja mechanisms then ensure that the LSP publishes its ***latest*** commitment transaction" [1242 post 1, "Inversion of Timeout Default For Hosted Poon-Dryja Channels"]. And: "If the blockheight approaches the `nLockTime` of the tree, the LSP ***must*** initiate the unilateral exit itself" [1143 post 26].
- **What forcing means.** To force a silent member out *with its real balance*, the host needs a unilateral transaction that pays the current split.
- **`exit.md` draft 3** brings it in as H19 (section 9) from #508 [PR], so that the host's forced exit (H-1, H6) pays the member its balance and not its capacity.
- **Without H19,** the only spends of a channel output are the member's own commitment (which the host cannot complete, CH-1) and the payout at E (the full capacity to the member).

### 8.2 Option 1: no revocable state on the host's side

- **What any host exit must do.** A host-held unilateral exit that pays the *current* balance must exist in a new version at every update. Older versions are valid spends unless something invalidates them.
- **What invalidates them.**
  - Revocation (Poon-Dryja): the member must hold the host's secrets.
  - A newer state with a shorter delay (Decker-Wattenhofer): the member must hold the newer state.
  - A later update (eltoo, which needs a soft fork): the member must hold the latest update.
  - Every one of these needs data the member gets after the backup. **So the T3 class is inherent in any design where the host can settle unilaterally at the current balance.** The attack does not depend on Poon-Dryja.
- **Spilman (one direction).** The one exception is a channel whose states only ever move value toward the party that holds them.
  - In a member-to-host Spilman channel the host holds the states. The newest pays the host most, so the host never gains from an old one, and the member needs no data at all. Prior art: Spilman 2013; duplex micropayment channels (Decker and Wattenhofer 2015); the designer's pseudo-Spilman for the host-to-members liquidity direction [1242 post 1].
  - The host-to-member direction has the opposite sign. There the member holds the newest state, and an *older* state favours the host. So a host that could publish anything in that direction can cheat again.
  - The member therefore holds that direction's states alone, and the host cannot force that direction out.
- **What a duplex Spilman pair gives instead.**
  - A silent member's host-to-member channel is settled only by the payout at E, so the member gets the full capacity: the host's unspent side becomes the member's.
  - That rewards silence: a member that received nothing and goes silent is paid the full capacity, the host's own liquidity. This is the very loss design 2's forcing exists to prevent (open point 7, 4.4's placement rationale).
  - Capacity in each direction is also used up for good within a factory's life: no leaf advances in 1.0.0, so no reset.
- **Ark-style designs** (no channel; the host is paid by expiry) drop channels altogether, which is outside this project.
- **Verdict: option 1 does not work in 1.0.0's shape.** Removing H19 removes T3 only by bringing back the free-capacity loss to silent members, which is worse and is a theft from the host rather than a risk to a careless member. Keep H19.

### 8.3 Option 2: penalty data outside the host's reach

- **Where the backup lives today.** `DESIGN.md` section 9: "The encrypted journal is also the backup: one copy with the host, one the user can export". Section 8: "A member's backup is held by the host using Lightning's peer-storage messages". The host chooses which version it returns. That is what turns T3 from bad luck into an attack.
- **Use shachain for the channel.** The host's per-commitment secrets come from BOLT 3's shachain. The receiver stores at most 49 (value, index) pairs, about 2 KB per channel, whatever the number of updates (BOLT 3, "Efficient Per-commitment Secret Storage").
  - Upstream uses flat secrets on ZmnSCPxj's advice [1143 post 34]. That advice is about a channel endpoint "composed of multiple signers". A Gazpacho channel has two single-signer endpoints, so shachain applies.
  - This is a `channel.md` choice, not an import change: Gazpacho writes its own channel engine (section 10.1 of `exit.md`).
- **The penalty record** per channel, about 2.3 KB:
  - the shachain store;
  - the member's revocation basepoint (or its derivation index), the host's delayed-payment and payment-output basepoints, `to_self_delay`, the channel output and the `payout_script`;
  - the highest commitment number revoked.
  - With it, a restored wallet can rebuild and sign the penalty for any revoked host commitment's `to_local`.
- **What the record cannot cover: payment outputs.** It cannot rebuild the penalty for the *payment* outputs of an old state, because their tapscripts need that state's payment hashes and expiries, which are O(n) data.
  - The loss there is bounded by what was in flight in that state.
  - Cap it with the member's `max_htlc_value_in_flight` (a `channel.md` term), and keep the full pre-signed ladders (O(n)) in the tower and on the device.
- **What each copy holds.**
  - **The member's independent copy** (an automatic encrypted write to a place the user chooses, never only the host's peer storage): the penalty record of every open channel, rewritten at every revocation it receives.
  - **The tower**, in the style of BOLT 13 and LND: one encrypted blob per revoked host commitment, keyed by that commitment's txid, holding the pre-signed penalty ladder. It learns nothing until a breach.
  - **The export:** the same as the independent copy, at the time of export. An export alone is stale by the next payment, so it does not count as the independent copy.
- **Ordering rule.** The member treats an update as done (it releases no payment secret and counts no received payment, CH-12) only after the host's revealed secret is in the independent copy or acknowledged by the tower. Cost: one small write per update.
- **Opening a channel.** The wallet refuses to let a channel's balance rise above zero (it accepts no incoming payment, CH-14) until an independent copy or tower is set up and has acknowledged a write. Joining with a zero balance is safe, since there is nothing to lose. So: refuse the balance, not the channel.

### 8.4 Option 3: restore behaviour

- **Lightning's data-loss handling.**
  - A node that finds it has fallen behind "MUST NOT broadcast its commitment transaction" and "SHOULD send an `error` to request the peer to fail the channel". The rationale says the error "should make the other node drop its current commitment transaction to the chain" (BOLT 2, `channel_reestablish`).
  - Static channel backups do the same: reconnect and ask the peer to close.
  - The known weakness: `channel_reestablish` tells the peer you are behind, and a dishonest peer then publishes a revoked state it knows you cannot punish.
  - In Gazpacho the host also *chose* the old backup, so it knows anyway when the backup came from it. Not revealing still matters when the backup came from the user's own copy.
- **"Assume stale."** After any restore, every channel is assumed stale. The wallet:
  1. publishes nothing of its own;
  2. stops payments;
  3. does not send `channel_reestablish` with its numbers. It sends one message that is the same from a restored wallet and an ordinary leaving one: "close this channel with your latest commitment, or co-sign a close". A wallet leaving for any reason uses the same message, so it reveals nothing;
  4. marks the channel's funds `at_risk` until a close is confirmed and buried, or until the independent penalty record is found and shown complete. With the record, the restored wallet can answer any revoked commitment's `to_local`, so it is protected as usual.

### 8.5 Option 4: the honest window when the data is missing

Without the penalty data a restored member has no answer to a revoked host commitment. The watch interval does not help: it governs how fast an answer goes out, and there is none. The only unilateral spends it has are its own commitment (possibly revoked, so a total loss) and the payouts from E. So:

| Situation at the restore (tip t) | Can the host confirm a revoked commitment before the member is safe? | Window in which the member is protected without the host |
|---|---|---|
| The channel output exists (the leaf transaction is confirmed) | Yes, in the next block | None |
| The path is not on chain, k tree steps missing | The host needs k + 1 blocks (one level per block under TRUC) and is done by block t + k + 1 | Only if t + k + 1 > E: the payout of the first missing output is valid in block E + 1, against the host's next step (a fee race at E + 1, not enforced). Whole path missing, k = d + 2: restored at tip E − (d + 2) or later, that is at most 3, 4 or 5 blocks before E at d = 1, 2, 3 |
| Any time, if the member publishes its own path to "leave at once" | It only creates the channel output sooner for the host | Makes it worse |

**So "close or leave at once" protects only through the host's cooperation.** On its own, the restored member's only real protection is the independent penalty record, plus the host not knowing whether one exists (deterrence: the host cannot tell whether a tower holds the ladder).

### 8.6 Recommendation

1. **Keep H19.** Option 1 is not viable in 1.0.0's shape (8.2).
2. **Make the penalty data independent of the host:** a shachain-based penalty record of about 2.3 KB per channel, written at every revocation to a copy the host does not control, before the update counts. Add a tower with the pre-signed ladders. No balance above zero until such a copy has acknowledged a write.
3. **Restore: assume stale** (8.4). Close everything at once through a message that does not reveal being behind. Funds stay `at_risk` until a close is buried or the record is found complete.
4. **C12: a narrow exception** for one key family. After a restore, the node may derive or read the revocation basepoint secret of an earlier epoch only to sign a penalty spending outputs of a host commitment already confirmed on chain, paying its own current `payout_script`. This replaces the earlier "pre-sign everything" recommendation (T4): the compact record cannot hold pre-signed ladders, and a penalty spends nothing a second tree or round could reuse, so it cannot cause the double signing R3 guards against.
5. **State the residual plainly.** Payment outputs of an old state, beyond what the record covers, are bounded by the in-flight cap. If no independent copy survives, a restore before E loses up to the member's balance to a dishonest host, unless it is restored at most d + 2 blocks before E with the path still off chain, and then only if the payouts win the race in block E + 1.
