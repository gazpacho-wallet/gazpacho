# Channel engine groundwork

Written 2026-11-11. Local note, not published. Purpose: establish from primary sources what Lightning's standard taproot channel format is, and work out what it takes to run such a channel on a funding output that is an off-chain leaf output which moves. This is input for `spec/channel.md`, which does not exist yet.

How to read this note:

- **[Read]** marks a statement taken from a primary source that was fetched and read today. The link and section follow.
- **[Import]** marks a statement read in the imported SuperScalar code under `core/superscalar/` at the pinned commit `e657395`.
- **Reasoning:** marks this note's own analysis. None of it has been reviewed.
- A wording trap: the project says "payment secret" for the value that proves payment. Lightning calls that the **payment preimage**. Lightning's own `payment_secret` is a different thing (a value in the invoice that the payer echoes to the payee). This note says "preimage" and writes `payment_secret` only for the Lightning field.

Source versions read:

| Source | Version read |
|---|---|
| Lightning specification (`lightning/bolts`) | `master` at commit `1914628`, dated 2026-10-19 |
| bLIP-56 draft | pull request 56 of `lightning/blips`, head commit `82c7595`, dated 2024-12-02 |
| Delving Bitcoin topics 1143, 1242, 1252 | raw text fetched 2026-11-11 (read only) |
| Bitcoin Core | `master` policy documents and release notes 28.0, 29.0, 30.0, 31.0, 32.1 |
| LND | release notes 0.17.0, 0.21.0, 0.22.0 |
| Eclair | release notes 0.13.0, 0.13.1, 0.14.0 |

---

## Part 1. Verified facts

### 1.1 Simple taproot channels

**Status.**

- [Read] The document is `bolt-simple-taproot.md` in the root of `lightning/bolts`, titled "Extension BOLT XX: Simple Taproot Channels". <https://github.com/lightning/bolts/blob/master/bolt-simple-taproot.md>
- [Read] It arrived through pull request 995, "extension-bolt: simple taproot channels (feature 80/81)", merged 2026-05-04 (merge commit `c7596e8`). <https://github.com/lightning/bolts/pull/995>
- [Read] A correction series was merged on 2026-10-19 (pull request 1352, "fix the output key derivations, signature rules and test vectors"). The commit messages say five output-key formulas had been written wrongly, the sighash type of HTLC signatures had not been stated where it was needed, and the secret nonce size was misdescribed. So the text changed materially five months after the merge. Anything built from the May text must be re-checked against the October text and the test vectors.
- [Read] It is an extension document. It is not folded into BOLT 2, 3 and 5, and its feature bits do not appear in the BOLT 9 table. Section "Feature Bits": bits 80/81 `option_simple_taproot` (depends on `option_channel_type` and `option_simple_close`), and bits 180/181 `option_simple_taproot_staging` for pre-final deployments. The link column of that table still reads "TODO".
- [Read] "Feature Bits": the channel type "cannot be announced on the public network (gossip protocol changes are required)" and "SHOULD only be used with explicit channel negotiation". "`open_channel` Extensions": the sender "MUST not set the `announce_channel` bit".
- [Read] The gossip extension that would allow announced taproot channels is pull request 1059, still open. <https://github.com/lightning/bolts/pull/1059>

So the secondary-source claim in the knowledge base is correct: the format was merged into the specification repository in 2026. Two qualifications: it is an extension document, and it covers unannounced channels only.

**Funding output.** [Read] Section "Funding Transactions" and "Key Aggregation".

- Script: `OP_1 funding_key`.
- `combined_funding_key = musig2.KeyAgg(musig2.KeySort(pubkey1, pubkey2))`, with MuSig2 as in BIP 327 version 1.0.0.
- `funding_key = combined_funding_key + tagged_hash("TapTweak", x_only(combined_funding_key))*G`. This is the BIP 86 form: the key commits to no script path.
- Ordering is by `KeySort`, so no ordering information is sent. "Throughout the lifetime of a channel any keys aggregated via musig2 also are assumed to use the `KeySort` routine."

**Commitment transaction outputs.** [Read] Section "Commitment Transactions". `simple_taproot_nums` is a fixed point with no known private key (section "Nothing Up My Sleeves Points").

| Output | Internal key | Script tree |
|---|---|---|
| `to_local` | `simple_taproot_nums` | Two leaves. Delay leaf: `<local_delayedpubkey> OP_CHECKSIGVERIFY <to_self_delay> OP_CHECKSEQUENCEVERIFY`. Revoke leaf: `<local_delayedpubkey> OP_DROP <revocation_pubkey> OP_CHECKSIG` |
| `to_remote` | `simple_taproot_nums` | One leaf: `<remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY` |
| Anchor (one per side) | `local_delayedpubkey` or `remotepubkey` | One leaf: `OP_16 OP_CHECKSEQUENCEVERIFY`. The key owner spends at once by key path; anyone may spend after 16 blocks |
| Offered HTLC | `revocation_pubkey` | Timeout leaf: `<local_htlcpubkey> OP_CHECKSIGVERIFY <remote_htlcpubkey> OP_CHECKSIG`. Success leaf: `OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY <remote_htlcpubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY` |
| Accepted HTLC | `revocation_pubkey` | Timeout leaf: `<remote_htlcpubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY OP_VERIFY <cltv_expiry> OP_CHECKLOCKTIMEVERIFY`. Success leaf: hash check as above, then `<local_htlcpubkey> OP_CHECKSIGVERIFY <remote_htlcpubkey> OP_CHECKSIG` |

- [Read] "Design Overview": the anchor semantics of the earlier anchor format are inherited. An anchor is omitted when its side has no main output, unless HTLCs are present.
- [Read] "To Local Outputs": the revocation on `to_local` is a script-path spend, chosen so that the keys third parties need to sweep anchors always appear on chain. For HTLC outputs the revocation is a key-path spend with the revocation key. "Taproot Key Path Spends": to use that path the tap tweak must be known, and "it's recommend that for a given revoked state, the tap tweak value is also stored".

**Second-stage HTLC transactions.** [Read] Section "HTLC Second Level Transactions".

- HTLC-success: version 2, locktime 0, one input with sequence 1, witness `<remotehtlcsig> <localhtlcsig> <preimage> <htlc_success_script> <control_block>`.
- HTLC-timeout: version 2, locktime `cltv_expiry`, one input with sequence 1.
- Each has one output: internal key `revocation_pubkey`, one leaf equal to the `to_local` delay script (`<local_delayedpubkey> OP_CHECKSIGVERIFY <to_self_delay> OP_CHECKSEQUENCEVERIFY`).
- "These transactions always have _zero_ fees attached, forcing them to be aggregated with each other and a change input." They are signed `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`, so each HTLC input must sit at the same index as its output when transactions are combined.

**Which signatures are MuSig2.** [Read] "`commitment_signed` Extensions" and "RBF Cooperative Close".

- MuSig2 partial signatures: the signature on the commitment transaction's funding input, and the signatures on cooperative closing transactions. Nothing else.
- Ordinary BIP 340 signatures: every HTLC signature (sighash `0x83`, sent as 64 bytes, the receiver appends the sighash byte), and every later spend of a commitment or second-stage output.
- In taproot messages the old 64-byte `signature` field is set to zero and the partial signature travels in a typed field.

**Nonces.** [Read] Sections "Nonce Generation", "Nonce Handling", "Nonce Terminology", "New TLV Types".

- Each side has two nonces per commitment state. The **verification nonce** is the one a party will use to sign its own commitment transaction; it is sent ahead of time so the peer can produce a partial signature. The **signing nonce** is generated just in time by whoever signs the peer's commitment and is sent with the partial signature.
- "In order to sign and broadcast a new commitment to force close a channel, a peer uses their _verification_ nonce to generate their final signature." The holder of a commitment therefore stores the peer's partial signature and signing nonce, and must be able to produce its own verification secret nonce later, possibly weeks later.
- "If nonces for commitment updates are not generated using the counter based scheme described above, then the nonces MUST be persisted to disk." The recommended scheme derives the verification nonce for commitment number N from a second shachain whose root is derived from the per-commitment seed, with a tag that includes the `funding_txid`, "which allows deriving distinct deterministic shachains when splicing".

Where nonces travel:

| Message | Field | Carries |
|---|---|---|
| `open_channel`, `accept_channel` | `next_local_nonce` (type 4) | Sender's verification nonce for its first commitment |
| `funding_created`, `funding_signed` | `partial_signature_with_nonce` (type 2, 98 bytes) | Partial signature for the peer's commitment, plus the signing nonce used |
| `channel_ready` | `next_local_nonce` (type 4) | Verification nonce for the next commitment |
| `commitment_signed` | `partial_signature_with_nonce` (type 2) | As for funding |
| `revoke_and_ack` | `next_local_nonces` (type 22) | A list of (`funding_txid`, nonce) entries: one verification nonce per active funding transaction |
| `channel_reestablish` | `next_local_nonces` (type 22) | Fresh verification nonces, one per active funding transaction |
| `shutdown` | `shutdown_nonce` (type 8) | The sender's "closee" nonce |
| `closing_complete` | types 5, 6, 7 (98 bytes) | Partial signature plus the closer's nonce |
| `closing_sig` | types 5, 6, 7 (32 bytes) and `next_closee_nonce` (type 22) | Partial signature; next closee nonce for a further fee bump |

- [Read] "`channel_reestablish` Extensions": the sender "MUST set `next_local_nonces` to fresh, unique `musig2` nonces" and include one entry per active commitment's `funding_txid`. A node that retransmits a `commitment_signed` after reconnecting "must regenerate the partial signature using the newly received `next_local_nonces`".
- [Read] "`revoke_and_ack` Extensions": the recipient must fail the channel if an active commitment's `funding_txid` is missing from the list.

**Cooperative close.** [Read] "RBF Cooperative Close". Only the newer closing protocol (`closing_complete`, `closing_sig`, from `option_simple_close`) is extended. The legacy `closing_signed` has no taproot extension.

**Revocation.** [Read] The document changes the scripts only. Per-commitment secrets, points and key derivation are those of BOLT 3 unchanged.

**Fees, dust, reserve, zero-conf.** [Read] The document adds no rules of its own. It says it inherits the anchor design, with second-stage transactions at zero fee. Its test vectors use a dust limit of 354 satoshis. It says nothing about zero-conf; reserve rules are those of BOLT 2.

**Splicing a taproot channel.** [Read] "Splice Coordination". Each pending funding transaction has its own entry in `next_local_nonces`, keyed by its transaction ID. Nonces are never reused across funding transactions. The section does not say how the two parties exchange the verification nonces needed for the very first commitment on a new funding output, nor how the MuSig2 signature that spends the old funding output is produced. BOLT 2's `tx_signatures` still describes that signature as ECDSA.

### 1.2 Base rules from BOLT 2, 3 and 5

All in <https://github.com/lightning/bolts/blob/master/02-peer-protocol.md>, `03-transactions.md`, `05-onchain.md`.

**The update sequence.** [Read] BOLT 2 "Normal Operation". One side sends `update_` messages and then `commitment_signed`; the other replies with `revoke_and_ack`. Updates apply first to the receiver's commitment. An update is "irrevocably committed" when both commitments contain it and both earlier commitments are revoked ("Forwarding HTLCs").

**Persistence.** [Read] BOLT 2 does not contain rules of the form "before sending X the node must have stored Y". What it says:

- "Message Retransmission", rationale: the design "encourages a single persistent write to disk for each `commitment_signed` sent or received", and the receiver "only needs to store updates upon receipt of `commitment_signed`".
- A node "MUST NOT assume that previously-transmitted messages were lost"; having sent a `commitment_signed` it "MUST handle the case where the corresponding commitment transaction is broadcast at any time by the other side".
- When both a `revoke_and_ack` and a `commitment_signed` are retransmitted, their original relative order must be kept.
- For a splice, the sender of `commitment_signed` "MUST remember the details of this splice transaction".

Reasoning: the storage rules the engine needs follow from these and are listed in Part 3, section 6.

**`channel_reestablish` and data-loss protection.** [Read] BOLT 2 "Message Retransmission".

- Fields: `next_commitment_number`, `next_revocation_number`, `your_last_per_commitment_secret`, `my_current_per_commitment_point`, plus typed fields `next_funding` and `my_current_funding_locked` for splices.
- If the peer's `next_revocation_number` is higher than expected and `your_last_per_commitment_secret` is correct for it, the node knows it has lost state. It "MUST NOT broadcast its commitment transaction" and "SHOULD send an `error` to request the peer to fail the channel".
- Rationale: the peer "should wait for that `error`" so the node that fell behind has a chance to repair its state first.

**HTLC deadlines.** [Read] BOLT 2 "`cltv_expiry_delta` Selection". With R the reorganisation depth allowed for, G the grace period before going to chain, and S the blocks needed to confirm a transaction:

- forwarding delta: `3R+2G+2S`, "at least 34 is reasonable (R=2, G=2, S=12)";
- deadline for a received HTLC the node has fulfilled: `2R+G+S` blocks before `cltv_expiry`, "18 blocks is reasonable";
- minimum expiry for a final payment: `2R+G+S`, default 18.
- Requirements: an offering node must fail the channel when an HTLC it offered is past its timeout deadline; a fulfilling node must fail the channel when an HTLC it has fulfilled is past its fulfilment deadline.

**`to_self_delay`.** [Read] BOLT 2 "`open_channel`": the sender should "set `to_self_delay` sufficient to ensure the sender can irreversibly spend a commitment transaction output, in case of misbehavior by the receiver". Each side sets the delay the *other* side's delayed outputs carry. The receiver must fail the channel if it is "unreasonably large". BOLT 3 "Commitment Transaction Outputs": HTLCs are resolved through a second-stage transaction so that they "can timeout or be fulfilled even though they are within the `to_self_delay` delay".

**Fee updates.** [Read] BOLT 2 "Updating Fees". Only the node that pays the fee (the opener) sends `update_fee`. The receiver must fail the channel if the rate is "too low for timely processing, OR is unreasonably large". BOLT 3 "Fee Payment": the commitment fee and both anchors are taken from the opener's balance.

**A second standard commitment format exists.** [Read] BOLT 9 bits 40/41 `zero_fee_commitments`, merged 2026-05-04 (pull request 1228). BOLT 3 "`shared_anchor` Output": the commitment is version 3, pays no fee, and has one pay-to-anchor output (`OP_1 <0x4e73>`) that anyone can spend. `update_fee` is forbidden. `max_accepted_htlcs` is at most 114. BOLT 2 "Defined Channel Types" lists three basic types (`option_static_remotekey`, `option_anchors`, `zero_fee_commitments`) with `option_scid_alias` and `option_zeroconf` as variations. No combination of taproot and zero-fee commitments is defined anywhere.

**Quiescence.** [Read] BOLT 2 "Channel Quiescence", feature 34/35.

- A node must not send `stfu` while any of its own additions, removals or fee updates are pending for either side.
- After sending `stfu` it sends no update message. When both have sent it, the channel is quiescent.
- "MUST disconnect after 60 seconds of quiescence if the HTLCs are pending." On disconnection the channel is no longer quiescent.
- A protocol that uses quiescence must define what ends it. There is no resume message.

What it guarantees: both commitment transactions contain the same set of updates and nothing is half-applied. It does not mean no HTLCs are in flight.

**On-chain enforcement.** [Read] BOLT 5.

- "General Nomenclature": a node with funds at stake must watch the chain until every output is irrevocably resolved (100 confirmations) and "MUST be prepared to resolve outputs multiple times, in case of blockchain reorganizations".
- "HTLC Output Handling": on its own commitment a node times out its offered HTLCs with HTLC-timeout and claims received ones with HTLC-success, then waits `to_self_delay`. On the peer's commitment it spends HTLC outputs directly.
- "Generation of HTLC Transactions": with zero-fee second-stage transactions a node "MUST combine it with inputs contributing sufficient fee".
- "Revoked Transaction Close Handling": all outputs of a revoked commitment can be taken with the revocation key.

### 1.3 Splicing

- [Read] Merged into BOLT 2 on 2026-03-23 through pull request 1160, feature bits 62/63 `option_splice`. Section "Channel Splicing".
- The channel must be quiescent first. `splice_init` and `splice_ack` carry each side's contribution and a new `funding_pubkey` ("SHOULD use a different `funding_pubkey` than the one used for the previous funding transaction").
- The splice transaction is built interactively and must spend the current funding output.
- Both sides then send `commitment_signed` for the new funding output, with the same commitment number and the same fee rate as the existing commitment, and with signatures for pending HTLCs. The receiver "MUST NOT respond with `revoke_and_ack`". Then they exchange `tx_signatures`, and the channel is no longer quiescent.
- "Splice Completion": while the splice is unconfirmed, "payments must be valid for all splice transactions". Every update is signed for every candidate funding output: `start_batch` announces the count, then one `commitment_signed` per funding transaction, each naming its `funding_txid`; a single `revoke_and_ack` answers the batch ("Batching channel messages", "Committing Updates So Far").
- The old funding output stops mattering when the splice transaction reaches acceptable depth and both sides have exchanged `splice_locked`. After that they "MUST stop sending `commitment_signed`" for the earlier funding transactions and "MAY discard" them.
- With `option_zeroconf`, `splice_locked` should be sent "immediately after exchanging `tx_signatures`", and replacing a splice transaction by fee is forbidden "because that creates a risk of losing funds".
- On reconnection, `next_funding` lets the two sides finish or abandon a half-signed splice, and `my_current_funding_locked` stands in for a lost `splice_locked`.

Reasoning: the per-commitment point belongs to the commitment number, not to the funding output. Because every candidate funding output carries the same commitment number, revoking that number revokes the commitment on every funding output at once. The splice rules rely on this without saying it.

### 1.4 Zero-conf and aliases

- [Read] BOLT 9: 46/47 `option_scid_alias`, 50/51 `option_zeroconf` (depends on the alias option). Both are channel-type variations.
- [Read] BOLT 2 "`accept_channel`": with `option_zeroconf` the sender "MUST set `minimum_depth` to zero".
- [Read] BOLT 2 "`open_channel`": the receiver must fail the channel if the type includes `option_zeroconf` "and it does not trust the sender to open an unconfirmed channel".
- [Read] BOLT 2 "`channel_ready`": the opener may send it at any time. With `option_scid_alias` the sender must supply an `alias`, must accept incoming HTLCs addressed to it, and if the channel type carries the alias option must refuse the real identifier. The receiver may use the alias in invoice route hints.
- [Read] Same section: a non-funding node "SHOULD forget the channel if it does not see the correct funding transaction after a timeout of 2016 blocks".
- [Read] The specification places no limit on what an unconfirmed channel may do once `channel_ready` is exchanged. The protection is the trust check above.

### 1.5 bLIP-56, pluggable channel factories

- [Read] Pull request 56 on `lightning/blips`, by ZmnSCPxj, opened 2024-12-02, still open, not merged. The draft file is dated by its last commit, 2024-12-02. Its header still says "bLIP: TBD". <https://github.com/lightning/blips/pull/56>
- Feature bit 271. One message type, 32800, with a 16-bit sub-message number.
- A typed field `channel_in_factory` (type 65600) in `open_channel` carries `factory_protocol_id`, `factory_instance_id` and a 16-bit `factory_early_warning_time`. The sender must select `option_zeroconf`.
- The funding outpoint is declared in the ordinary `funding_created`, with the value supplied by the factory code on each side and checked by the receiver against its own factory code.
- `channel_ready` waits for the factory code. The fundee must not forget the channel after 2016 blocks. The funder must not broadcast the funding transaction.
- HTLC deadlines: for `update_add_htlc` the sender must set `cltv_expiry` to at least the current height plus `factory_early_warning_time` plus 1, and the receiver must fail the channel otherwise. When an offered HTLC comes within the early warning time of its expiry, the node raises an event to the factory code, which is expected to start publishing the factory. Invoices should add the early warning time to `min_final_cltv_expiry_delta`. An outgoing first hop needs at least early warning time plus the next hop's delta.
- On channel failure the node tells the factory code, keeps its latest signed commitments, and "MUST NOT broadcast the latest commitment transaction until it has seen one of the possible funding transactions confirmed".
- A change of funding outpoint copies the splice procedure with other messages: `stfu`; `factory_change_init` and `factory_change_ack` (contribution and new `funding_pubkey`; a contribution of zero is allowed); `factory_change_funding` (new transaction ID and output index, cross-checked); `commitment_signed` for the new outpoint with the same commitment number, no `revoke_and_ack`; the factory code signs the new factory state; `factory_change_continue`; the channel resumes with batched signing for old and new outpoints; the factory invalidates its old state; `factory_change_locked`; old outpoint dropped.
- The draft predates the merged splice text (it speaks of a `batch` field in `commitment_signed`, where the merged text uses `start_batch`) and predates the taproot nonce rules. It does not mention nonces.

### 1.6 ZmnSCPxj's SuperScalar posts

Topic 1143 <https://delvingbitcoin.org/t/1143>, topic 1242 <https://delvingbitcoin.org/t/1242>, topic 1252 <https://delvingbitcoin.org/t/pluggable-channel-factories/1252>.

- [Read] 1143, "Timeout Trees" and "Tank, `A` Needs An Exit": channel outputs in the tree are plain `A & L` outputs. A unilateral exit publishes the path from the root, "then unilaterally exiting the Lightning channel (expected to be a Poon-Dryja) as well".
- [Read] 1143 post 21, "CLTV Locktime Extended By Decker-Wattenhofer Relative Delays": hosted HTLCs "have a minimum CLTV-delta that is equal to the current Decker-Wattenhofer `nSequence` state delay, plus any safety margin".
- [Read] 1242, "Pseudo-Spilman Factories At Leaves": for payments to clients the total of the relative delays "plus margin, would have to be specified as the `final_cltv_delta`"; for payments from clients, nothing changes if the route already needs more.
- [Read] 1143 post 21, "Asymmetric Onchain Fee Schemes": zero-fee commitments need outside coins, which "are not good for clients". Proposed instead: the host's commitment carries a pay-to-anchor output and is paid for from outside; the client's commitment is signed in several versions at different fee rates, paid from the client's own channel balance. This is a proposal in a forum post. It is not in any specification.
- [Read] 1143 post 13, "Tree Nodes Pay Fees": tree transactions should carry their own fee so that a client without coins can exit.
- [Read] 1242, "Inversion of Timeout Default For Hosted Poon-Dryja Channels": the channel funding output also gets a pre-signed transaction, locked until the factory's end date, that pays the client. This forces the host to publish its commitment before the end date, and "standard Poon-Dryja mechanisms then ensure that the LSP publishes its latest commitment transaction".
- [Read] 1143 post 27: under inverted timeouts, a client that never forwards does not need to enforce the timeout of its own outgoing HTLCs. If the host claims late with the preimage, the payment did happen. If the host never resolves it, the client recovers at the end date.
- [Read] 1242, "Pseudo-Spilman Channel Factories": in the original design a liquidity sale spends the *liquidity* output and creates "a novel channel with its own separate state" beside the existing one. Existing channels do not move. The stated cost is that host and client "have to implement local multipath". ZmnSCPxj also says the construction is "pointless" with a single client, since the liquidity can only ever go to that client.
- [Read] 1242, "Necessary BOLT Extensions": a change of funding outpoint should be "hand-over-hand", "exactly the same as in onchain splicing", and may be reverted if the new factory state cannot be made valid.
- [Read] 1252 post 3: if the factory layer is closed and the channels land on chain, "the channel can keep operating".
- [Read] 1143 post 34 (2026-02-13): ZmnSCPxj suggests removing the shachain "in favor of simply storing all the revocation keys", for the case where one endpoint is several signers.

No follow-up by ZmnSCPxj was found that describes, step by step, how a channel's commitments are updated when its leaf changes, beyond the "hand-over-hand" paragraph and bLIP-56.

### 1.7 LND and Eclair

- [Read] LND 0.17.0 release notes: taproot channels first shipped behind `--protocol.simple-taproot-chans`, on the staging bits.
- [Read] LND 0.21.0 release notes (released 2026-06-05): "production (final) simple taproot channels" with bits 80/81. The final scripts differ from the staging ones ("`OP_CHECKSIGVERIFY` instead of `OP_CHECKSIG` + `OP_DROP`"). Nonces in `channel_reestablish` and `revoke_and_ack` are a map keyed by funding transaction ID, "laying the groundwork for splice support". Zero-conf and alias variations are accepted. Channels must be requested explicitly and "must remain private". The cooperative-close implementation stores the partial signature in its state machine and invalidates nonces after each round. <https://github.com/lightningnetwork/lnd/blob/master/docs/release-notes/release-notes-0.21.0.md>
- [Read] Eclair 0.14.0 release notes (released 2026-05-21): "the final version of channel splicing, taproot channels and zero-fee commitments"; taproot is on by default, unannounced only, and "fully compatible with the `lnd` implementation". Zero-fee commitments are experimental and off by default "because we haven't tested yet that v3/TRUC transactions always propagate to miners". Eclair requires Bitcoin Core 30. <https://github.com/ACINQ/eclair/blob/master/docs/release-notes/eclair-v0.14.0.md>
- [Read] Eclair 0.13.0 and 0.13.1 commit lists: "Split commit nonces from funding nonce in `tx_complete`", "Allow omitting `previousTx` for taproot splices", "Create fresh shutdown nonce on reconnection", "Update taproot commit weight to match `lnd`".

Known or likely differences:

- Eclair supports splicing taproot channels and carries the nonces for it in `tx_complete`. That field is not in the specification text read today. LND's notes speak only of groundwork for splicing.
- The two had to align commitment weights, which shows the specification left that open.
- Neither set of release notes says how verification nonces are stored or derived. That would need a reading of their source code, which was not done.

### 1.8 Bitcoin Core relay rules

- [Read] 28.0 notes: one-parent-one-child package relay over the network ("not yet reliable under adversarial conditions"; a child with several unconfirmed parents is not supported over the network); version 3 transactions are standard under the rules of BIP 431; pay-to-anchor is a standard output; limited package replacement for clusters of size two.
- [Read] 29.0 notes: ephemeral dust. One dust output is allowed in a zero-fee transaction if a child in the same package spends it.
- [Read] 30.0 notes: default minimum relay and incremental fee rates are 0.1 satoshi per virtual byte, with the warning that lower-fee transactions "are not guaranteed to propagate or confirm" until this is widely deployed. One-parent-one-child relay works when the child has other parents already in the mempool. `submitpackage` no longer needs every unconfirmed parent in the package.
- [Read] 31.0 notes (2026-04-20): cluster mempool. Ancestor and descendant limits are gone; a cluster is at most 64 transactions and 101,000 virtual bytes. The carve-out that allowed one extra child is removed. In one-parent-one-child relay the parent may now pay below the minimum relay rate, "even 0 fee", for ordinary version 2 transactions as well.
- [Read] BIP 431: a version 3 transaction is at most 10,000 virtual bytes; its unconfirmed ancestors must all be version 3; it may have at most one unconfirmed ancestor and one unconfirmed descendant; a child is at most 1,000 virtual bytes. <https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki>
- [Read] `doc/policy/packages.md`: a package is at most 25 transactions and 404,000 weight units, and for submission must be one child with its parents. `src/rpc/mempool.cpp`: for `submitpackage`, "None of the parents may depend on each other". So one call cannot submit a chain of three.
- [Read] Version 32.0 was tagged but never released; 32.1 was released 2026-10-28. Its notes contain no relay-rule change relevant here.

### 1.9 Package submission through public servers

- [Read] Blockstream's Esplora interface documents `POST /txs/package`, taking a list of raw transactions, and says it needs Bitcoin Core 28.0 or later. <https://github.com/Blockstream/esplora/blob/master/API.md>
- [Read] The route exists in Blockstream's server source (`electrs`, branch `new-index`, `src/rest.rs`), in mempool.space's server source (`mempool/electrs`), and in mempool.space's backend as `POST /api/v1/txs/package`, which calls `submitpackage`.
- [Read] The Electrum protocol has `blockchain.transaction.broadcast_package` from protocol version 1.6. `docs/CHAIN-SERVERS.md` records that the public Electrum servers the project found report protocol 1.4, which does not have it.
- Not tested: whether the live public instances accept packages, on which networks, and with what limits. No request was sent.

### 1.10 The imported tree code

- [Import] `factory.c`, `build_musig_p2tr_spk` and `musig.c`, `musig_aggregate_keys`: keys are aggregated in the order given. There is no `KeySort`.
- [Import] `factory.c`, `add_node`: when a node has a timeout, its output key is the aggregate key tweaked with a script tree of one leaf, `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP <host key> OP_CHECKSIG`. This is the host-only timeout branch.
- [Import] `setup_ps_leaf_outputs`: for a pseudo-Spilman leaf, output 0 ("channel") is given the leaf node's own script, `node->spending_spk`. With one member per leaf that is the MuSig2 key of host and member in the tree's signer order, with the host-only timeout leaf. Output 1 is the host's spare liquidity. A pay-to-anchor output of 240 satoshis follows when tree anchors are on.
- [Import] `setup_single_leaf_outputs` (older leaf type): the channel output is MuSig2 of (member, host) in that order, with a host-only timeout leaf at the factory's end height.
- [Import] `channel.h`, `channel_discover_funding_keyagg`: the old channel code finds the key order by trying both orders and both timeout heights until the script matches. `channel_set_cltv_merkle_root` exists because the commitment signature has to account for the timeout leaf.
- [Import] Every participant has one key in the tree (`f->pubkeys[i]`). That key is used at every node and in the channel output. There is no separate channel funding key.
- [Import] `factory_advance_leaf`, pseudo-Spilman branch: a leaf change builds a transaction that spends output 0 of the previous leaf transaction and has **one** output, with the same script, worth the previous amount minus the tree fee. The comment says the spare liquidity "was committed once at chain[0] and already exists as a separate on-chain UTXO; we must not re-split it here". So, as imported, a leaf change on a one-member pseudo-Spilman leaf moves the channel output to a new outpoint and makes it slightly smaller. It does not add liquidity to it.
- [Import] Tree transactions are version 2 (`tx_builder.c`).
- [Import] `factory_early_warning_time` returns the sum of the worst-case relative delays, leaving out the leaf layer for pseudo-Spilman leaves. The hand-off note already records that it under-reports on deep trees.
- [Import] `channel.h` describes a channel format that is not the standard one: an optional revocation leaf, a single pay-to-anchor output, nonce pools addressed by index, and per-commitment secrets generated at random and stored one by one.

---

## Part 2. Analysis

### 2.1 Can the standard format be used unchanged on an unconfirmed, off-chain funding output?

**Facts.** The transaction formats depend on four things: the funding outpoint, its amount, the two funding keys, and the channel parameters. None refers to a block height or a confirmation. The specification's assumptions about confirmation are in the opening procedure and in behaviour, not in the formats.

**Reasoning.** The formats can be used byte for byte. Each assumption about a confirmed funding transaction needs a stated replacement:

| The specification assumes | Where | Replacement in a factory |
|---|---|---|
| The funding transaction confirms to `minimum_depth` before `channel_ready` | BOLT 2 `channel_ready` | Channel type includes `option_zeroconf`; `minimum_depth` is zero. `channel_ready` is sent when the factory's own funding output has reached the depth in the host's terms **and** the member holds every signed transaction on its path. This is bLIP-56's rule, made concrete |
| The acceptor trusts the opener not to double-spend an unconfirmed funding | BOLT 2 `open_channel` | No trust. The member has rebuilt the tree itself and holds its signed exit before funding is signed (safety rule C1, C6, H1) |
| The fundee forgets an unconfirmed channel after 2016 blocks | BOLT 2 `channel_ready` | Never forget while the factory is alive (bLIP-56) |
| A real short channel identifier exists after confirmation | BOLT 2, BOLT 7 | Alias only (`option_scid_alias` in the channel type). No real identifier ever exists |
| The channel may be announced | BOLT 7 | Never. The taproot format forbids it today in any case |
| The funding output is on chain, so spending it closes the channel | BOLT 5 | The watch engine watches the factory funding output and every output on the member's path, not only the leaf output. A spend of any of them by an unexpected transaction is a channel event |
| A reorganisation can unconfirm the funding | Implementations | The factory funding output is the only confirmed anchor. The watch engine applies the depth rule to it, and to every path transaction once an exit starts |
| A commitment can be broadcast at any time | BOLT 2, BOLT 5 | A commitment is broadcast only after the leaf transaction that creates its funding output has confirmed (bLIP-56). Until then the node cannot know which funding outpoint became real |
| Each side can add fees to its commitment through its anchor | Taproot document | True only once the leaf transaction is confirmed and only if the party has coins. See 2.5 |
| The opener watches fee rates and sends `update_fee` | BOLT 2 | The host is the opener and pays the commitment fee. The member enforces a floor and a ceiling |
| The channel ends in a cooperative closing transaction | BOLT 2 | A closing transaction spends the leaf output, so it can only be used after the whole path is on chain. Leaving cooperatively is a factory operation |
| One funding outpoint for the channel's life, or a confirmed splice | BOLT 2 | The outpoint moves with no confirmation. See 2.3 |

Two further points:

- The member starts with nothing. The taproot document drops the anchor of a side that has no main output, so at first the member's own commitment pays everything to the host. That is correct and needs no change.
- `funding_created` names the funding transaction ID before that transaction is signed. This works, because a taproot transaction's ID does not depend on its signatures, and the member computes the ID from its own rebuilt tree.

**Recommendation.** Use the formats unchanged. Write the twelve replacements above into `spec/channel.md` as rules.

### 2.2 The leaf output and the channel funding output

**Facts.** The standard requires `OP_1 <BIP 86 tweak of KeyAgg(KeySort(key1, key2))>`, with no script path. Section 1.10 shows what the imported tree builds.

**Reasoning.** As imported, the leaf's channel output is not the standard funding output. Four differences, each of which changes the output key:

1. **Key order.** The tree aggregates in signer order. The standard sorts. The two agree only by chance.
2. **Script path.** The tree commits to a host-only timeout leaf. The standard commits to none. This is the planned removal; until it lands, no leaf output can be a standard funding output.
3. **Which keys.** The tree uses each party's one tree key. The standard uses the `funding_pubkey` of `open_channel` and `accept_channel`. These could be made equal, but splicing and bLIP-56 both ask for a new funding key at each change of outpoint, and a separate key keeps the channel engine independent of the tree's key rules.
4. **Pseudo-Spilman leaves reuse the leaf node's key for the channel output**, because the next leaf transaction is signed with the node's key. With one member per leaf this is still a two-party MuSig2 key, so the structure fits. With more than one member per leaf it would not: the output would be an N-party key and could never be a standard two-party funding output.

What the leaf output must become: exactly the standard script, built from a member funding key and a host funding key that the channel engine supplies, sorted by `KeySort`, with no script path. The next leaf transaction then spends that output with a MuSig2 signature under the channel funding key, the same way a splice transaction spends a funding output.

The end-date payout fits this. ZmnSCPxj's version (section 1.6) is a pre-signed, time-locked transaction that *spends* the funding output. It adds a transaction, not a script branch, so the funding output stays standard. Each new funding outpoint needs its own payout (already rule 11a of the signing-round specification).

The funding key therefore signs four kinds of transaction: commitments, the next leaf transaction, the end-date payout, and a cooperative close if one is ever used. Each needs its own nonce handling. The first follows the taproot document. The other three go through the signing-round engine.

**Recommendation.** Ask the SuperScalar repository, as part of its second round of tree changes, for a leaf builder that takes the channel output script from the caller (or builds it by the standard rule from two supplied keys) and that has no timeout branch on that output. Until then, build the channel engine behind its format interface with a "funding script provider", so that the engine can be tested with the standard script in the simulator and with the import's present script on signet. Check the funding-output test vector in the taproot document against whatever the tree produces.

### 2.3 Moving the channel when the leaf changes

**A point to settle first.** There are two different meanings of "the host sells capacity on a pseudo-Spilman leaf", and they lead to different channel engines.

- **Move the channel.** The new leaf transaction spends the old channel output (and has to take in liquidity from somewhere) and creates a larger channel output. The funding outpoint changes. This is what the task describes and what the import's leaf-change function half does (section 1.10: it moves the output but adds nothing to it).
- **Add a channel.** ZmnSCPxj's original (section 1.6): the new transaction spends the *liquidity* output and creates a second channel beside the first. No channel ever moves. The member ends up with several channels to the host, and payments larger than one channel's capacity are split across them.

The rest of this section covers the first, because the owner's description assumes it. The second is set out as an alternative in Part 4, decision 2.

**Notation.** `O_N` is the channel output of leaf transaction N. `C(k, O)` is a commitment with number k that spends outpoint O. Each side holds its own. In the standard each side has its own counter; one letter is used here for both to keep the table readable. "The next update" below means a complete one, in which both sides revoke.

**The safe sequence.** It follows the splice procedure, with the factory signing round in place of interactive construction.

| Step | What happens | Each side holds afterwards |
|---|---|---|
| 0 | Normal operation on `O_N`. State number k | `C(k, O_N)` |
| 1 | Host proposes leaf N+1: inputs, outputs, new funding keys, the change in each side's balance. Member rebuilds it and computes its transaction ID and `O_N+1`. Safe-to-sign checks run | Unchanged |
| 2 | Both send `stfu`. No updates are half-applied | Unchanged |
| 3 | Both exchange verification nonces for `O_N+1`, then `commitment_signed` for `O_N+1`: same number k, same HTLCs, same fee rate, balances adjusted by the agreed change. No `revoke_and_ack`. Each verifies the other's partial signature against the commitment it built itself, and stores it | `C(k, O_N)` and `C(k, O_N+1)` |
| 4 | The end-date payout for `O_N+1` is signed (when payouts exist) | As above, plus the payout |
| 5 | Leaf transaction N+1 is signed by the signing round. A party sends its partial signature only after steps 3 and 4 are stored | As above. One side may hold leaf N+1 fully signed before the other |
| 6 | `round_complete`: both hold leaf N+1 fully signed and verified | As above, plus leaf N+1 |
| 7 | The channel resumes. Every update is signed for both outpoints as a batch, answered by one `revoke_and_ack` | `C(k+1, O_N)` and `C(k+1, O_N+1)`, and so on |
| 8 | "Locked": both confirm they hold leaf N+1 and everything under it. They stop signing for `O_N` | The last number signed for `O_N`, call it m, and the current state on `O_N+1` |
| 9 | The next update revokes number m. That revokes `C(m, O_N)` as well as `C(m, O_N+1)` | Only current commitments on `O_N+1` are unrevoked |

**Why the old outpoint becomes harmless.** In a splice the old funding output is spent on chain, which ends it. Here nothing confirms, and `O_N` can still appear on chain, because leaf N is an ancestor of leaf N+1. Once leaf N is confirmed, `O_N` can be spent either by leaf N+1 or by any commitment signed for `O_N`. What protects both sides is the revocation of commitment numbers:

- Between steps 3 and 9, the unrevoked commitments on `O_N` and on `O_N+1` carry the same number and the same member balance. Whichever reaches the chain, the member receives what it is owed. This satisfies check C4, first case.
- After step 9, every commitment ever signed for `O_N` has a revoked number. Publishing one is punishable in the ordinary way, with the ordinary per-commitment secret.

So no new cryptography is needed. Three things are needed that the standard does not ask for:

- **Watch old outpoints for the life of the factory.** `O_0` to `O_N` must all be watched, because the response to an old commitment on an old outpoint is the penalty.
- **Never let the two outpoints differ.** From the moment a party has sent its partial signature for leaf N+1 (step 5) until lock (step 8), it must refuse any update that is not signed for both outpoints.
- **Force step 9 to happen.** If the channel is idle after lock, number m stays unrevoked on both outpoints. That is harmless for balances, but it means "the old outpoint is dead" is not yet true. The rule in the specification should say what the node believes until the next update.

**Must the channel be quiet first?** Quiescence in the standard's sense, yes: step 3 signs a commitment with the same number for a second outpoint, which only makes sense if no update is half-applied. Payments in flight are a separate question. The splice procedure allows them and re-signs their HTLC transactions for the new outpoint. Two reasons to forbid them in the first release:

- the standard's rule to disconnect after 60 seconds of quiescence with HTLCs pending. The signing round's default timers add up to 60 seconds per attempt;
- check C9, and open point 5 of the safety rule, are not yet worked out for in-flight payments during a leaf change.

**Comparison.**

| | Splice (BOLT 2) | bLIP-56 | Proposed here |
|---|---|---|---|
| New outpoint agreed by | Interactive construction | Factory code on each side, cross-checked | Member rebuilds the leaf transaction itself |
| First commitment on new outpoint | After `tx_complete`, before `tx_signatures` | After `factory_change_funding`, before the factory signs | Before the leaf partial signatures (step 3 before step 5) |
| While both exist | Batch signing | Batch signing | Batch signing |
| Old outpoint ends | Splice confirms, `splice_locked` | Factory "invalidates" old state, `factory_change_locked` | Never on chain; ends by revocation of numbers (step 9), and old outpoints stay watched |
| Reverting | A pending splice may never confirm | Draft's rationale allows reverting | A round that fails before step 5 is dropped and `C(k, O_N+1)` is discarded. After any party has sent a leaf partial signature, both outpoints must be treated as possibly live |
| Taproot nonces for the new outpoint | Not specified for the first commitment | Not mentioned | Carried in the factory round messages, keyed by funding transaction ID |

bLIP-56 leaves "invalidate the old factory state" to the factory. For a chained leaf there is no such act: the old leaf transaction stays valid for ever. That is the main thing bLIP-56 does not cover for this design.

**Where a crash or a dishonest party could strand someone.**

1. *Member crashes between step 3 and step 5.* Its signing nonces for the round are gone and the round is over. The host holds a member-signed `C(k, O_N+1)` that is useless unless leaf N+1 is ever signed. The member must remember, across the crash, that it signed `C(k, O_N+1)`, so that a retry of the same leaf transaction is accepted and a different transaction with the same position and number is refused (check C7).
2. *Member has sent its leaf partial signature; host never sends `round_complete`.* The host can publish leaf N+1 and the member does not hold it. The member is safe only if it stored `C(k, O_N+1)` before sending the partial signature, and if its watch engine recognises leaf N+1 on chain by the transaction ID it computed. It can then use `C(k, O_N+1)`. If instead leaf N alone confirms, it uses `C(k, O_N)`. Both must be kept.
3. *The same, and the member continues to use the channel on `O_N` only.* This is the dangerous one. Suppose the member accepted an update signed only for `O_N` and the host then published leaf N+1. If the host had not yet revoked its own number k, it could close with its `C(k, O_N+1)` and the member would lose whatever it received since. If the host had revoked, neither side would hold an unrevoked commitment on `O_N+1`, and the member's funds there could move only with the host's agreement. Hence the rule above: after sending a leaf partial signature, no update without both outpoints. A member in the "Unfinished" state must stop the channel and, if the host does not complete on reconnect, exit.
4. *Host signs `C(k, O_N+1)` with the wrong balances.* The partial signature fails verification against the member's own transaction. Abort.
5. *Either side crashes after step 6 and restores an older journal.* It may believe only `O_N` exists and sign an update for `O_N` alone. The other side must refuse it. On reconnect, `channel_reestablish` must carry nonces for every funding transaction the sender considers active, and the receiver must fail if one it considers active is missing (the taproot document already requires this).
6. *Nonce reuse across outpoints.* The two commitments at number k are different transactions. If verification nonces are derived by commitment number alone, the same nonce would sign two messages, which can reveal the funding key. The derivation must include the funding transaction ID, as the taproot document recommends.
7. *The member's balance changes in the move.* If the move changed the member's balance, `C(k, O_N)` and `C(k, O_N+1)` would differ for the member, and the argument above fails. The move must leave the member's balance exactly as it was (the safety rule's table already says so). A fee for the liquidity is paid by an ordinary channel update before or after.
8. *A layer above the leaf is re-signed.* Every transaction under a re-signed layer gets a new ID, so every channel under it moves to a new outpoint with no change in capacity. The same nine steps apply, to many channels in one round. An old layer state that confirms brings old outpoints to life, for which only revoked commitments exist. The funds there cannot move without both signatures. The response is to publish the newer layer state inside the layer's own window, which is one timelock step and much shorter than two weeks. This belongs to the tree and watch specifications, but the channel specification must say that a channel whose current outpoint has been made unreachable is dead and is settled by the tree's rules.
9. *The end-date payout for an old outpoint.* If leaf N is confirmed and `O_N` is still unspent at the end date, its payout pays the member the old capacity. The host must make sure `O_N` is spent before then. This is part of the host's duty under H4.

**Recommendation.** Adopt the nine-step sequence. In the first release require the channel to be idle (no payments in flight) for a move. Keep and watch every old outpoint until the factory is closed. Carry the nonces for the new outpoint in the round messages. First, confirm with the SuperScalar session what transaction a liquidity sale on a one-member leaf actually signs, since the imported function does not add liquidity.

### 2.4 Deadlines

**Facts.** Section 1.2 gives the standard's reasoning; 1.5 gives bLIP-56's rule; 1.6 gives ZmnSCPxj's statement. All three agree that the tree's exit delay is added to the usual margin.

**Reasoning.** Define, for one member at one moment:

- `d_i`: the relative timelock, in blocks, on the i-th timed transaction on the member's path, at its current state. The knowledge base gives 432 as the figure per timed level at mainnet settings. The channel engine must take the real figures from the exit engine, not from `factory_early_warning_time`, which under-reports.
- `T`: the number of timed transactions on the path.
- `S`: blocks allowed for one broadcast to confirm. The standard treats 12 as a minimum where fees cannot be raised.
- `G`: grace before acting. `R`: reorganisation depth allowed for.
- `M`: a margin set by the host's terms.

Transactions with no timelock between them can be broadcast together, so the path confirms in waves. Each timed transaction starts a new wave.

```
E_commit = sum over i of (d_i + S)  +  S
```

`E_commit` is the time from the decision to exit until the member's commitment is confirmed: T waves that each wait out a timelock, then a last wave for the untimed transactions down to the leaf and the commitment itself.

**A payment to the member.** The host offers an HTLC with expiry `c`. After `c` the host can take it back on chain. The member claims on chain with HTLC-success, whose input needs one confirmation on the commitment.

```
E_claim = G + E_commit + 1 + S + R
```

- The member may send the preimage only while `c - now >= E_claim + M`.
- If the member has sent the preimage and the host has not irrevocably removed the HTLC, the member must start its exit no later than height `c - E_claim`. This is the standard's "fulfilment deadline".
- If the member has not sent the preimage and `c - now` falls below `E_claim + M`, it fails the HTLC back. It has lost nothing and takes no action on chain.
- The member refuses an incoming HTLC unless `c - now >= E_claim + M + H`, where H is the time it may take to answer. This is the value to put in the invoice as the final expiry delta, before the host's own addition below.
- `to_self_delay` does not appear. That is the purpose of the second-stage transaction: once HTLC-success confirms, only a revocation can take the output, and the member waits out `to_self_delay` in safety.

What the member must do if the host disappears, in order: publish its path wave by wave as each timelock expires; when the leaf transaction has confirmed, publish its commitment; one block later publish HTLC-success with the preimage and a fee-paying input (see 2.5); after `to_self_delay`, sweep.

**The host's side of the same payment.** The host holds the payer's HTLC on its ordinary node with expiry `c_up`, and offers the member an HTLC with expiry `c`. If the member neither fulfils nor fails, the host may cancel upstream only once the member can no longer claim, which means the host's HTLC-timeout has confirmed. For that the host's commitment must be confirmed by `c`.

- The host must start publishing the member's branch by height `c - E_commit - G`. This is the event bLIP-56 calls the early warning.
- `c_up - c >= S + R + G`, so that the upstream payment is still held when the timeout confirms.
- The invoice's final expiry delta is therefore about `E_claim + M + H + S + R + G`.

**A payment from the member.** The member offers the host an HTLC with expiry `c_out`. The host pays onward with expiry `c_down`.

- The host's duty: if the onward payment succeeds and the member does not cooperate, the host must claim the member's HTLC on chain before `c_out`. That takes `E_claim` computed for the host. So `c_out - c_down >= E_claim + M`. The factory's exit time is the host's forwarding delta.
- The member's requirement: `c_out >= now + (route's total delta, from the invoice) + E_claim + M`.
- The member has no urgent duty at `c_out`. If the host claims late with the preimage, the payee was paid. If the host never resolves the HTLC, the member's remedy is an ordinary exit followed by HTLC-timeout, or the end-date payout once payouts exist (ZmnSCPxj, section 1.6). This holds only because the member never forwards.

**Illustration.** With S = 6, G = 2, R = 2, these are examples and not decided values:

| Timed levels on the path | Sum of `d_i` | `E_commit` | `E_claim` |
|---|---|---|---|
| 1 (the 512-member shape with two fixed levels) | 432 | 444 | 455 |
| 3 (two 16-way timed levels) | 1,296 | 1,320 | 1,331 |
| 9 (two-way tree at 512) | 3,888 | 3,948 | 3,959 |

Ordinary nodes limit the total time lock they accept for a payment. The figure recalled for the common default is 2,016 blocks, which was not checked today. If it is right, the two-way shape cannot receive payments at all, the three-level shape leaves about 600 blocks for the whole route, and the one-level shape is comfortable. The design's shape rule ("upper levels are fixed where possible") is therefore a requirement for payments to work, not only a convenience.

**Recommendation.** Put the formulas above in the specification with `d_i` supplied by the exit engine. Have the schedule engine compute, for every HTLC, the height by which each side must act. Add a rule to the host's terms: a shape whose final expiry delta exceeds a stated ceiling is not offered. Choose S, G, R and M on signet, and check the ceiling against LND's and Eclair's real limits.

### 2.5 Fees

**Facts.** Sections 1.1 (anchors, zero-fee second-stage transactions), 1.2 (the opener pays the commitment fee), 1.8 and 1.9.

**Reasoning, transaction by transaction.**

- *Tree transactions.* Version 2, each with a built-in fee fixed at signing and, when enabled, a 240-satoshi pay-to-anchor output. A transaction that pays at least the minimum relay rate and the mempool's current minimum is accepted by itself. One that falls short needs a child that spends its anchor, relayed as a one-parent-one-child package. The child needs a confirmed coin, or the change of the previous child.
- *The whole path at once.* Not possible as a single package: `submitpackage` takes one child with parents that do not depend on each other, and network relay handles one parent and one child. A path is submitted transaction by transaction, or pair by pair. Timelocks split it into waves in any case. The unconfirmed part must stay inside cluster limits: 64 transactions and 101,000 virtual bytes on Core 31 and later, and 25 ancestors on earlier versions that are still widely run. A short path with one bump child each is well inside both.
- *Sub-1-satoshi fee rates.* The project's test rate of 0.1 satoshi per virtual byte is the default minimum only from Core 30. Older nodes refuse it.
- *The commitment.* Version 2. Its fee is set by the host through `update_fee` and comes out of the host's balance, on both sides' commitments. A member with no coins therefore has a commitment that already pays a fee. The member must refuse a fee rate below a floor. If fees rise later, the member's only tool is its own anchor.
- *The anchor.* 330 satoshis, spendable at once by its owner. Spent alone it adds at most 330 satoshis of fee.
- *HTLC-success and HTLC-timeout.* Zero fee by rule. They need an added input. Their own output is locked by `to_self_delay`, so a child cannot pay for them. **A member with no on-chain coins cannot, from its own commitment, claim a payment in flight or take back an expired one**, with one narrow exception: it can add its own 330-satoshi anchor as the extra input, which pays roughly 1 to 1.5 satoshis per virtual byte for one HTLC transaction.
- *On the host's commitment*, the member spends an HTLC output directly, with no second-stage transaction, and the fee comes out of the HTLC amount. But the member cannot make the host publish.
- *The member's main balance.* Swept after `to_self_delay` by a transaction that pays its fee from the balance. No coins needed.

So: the standard taproot format assumes each party has on-chain coins when it exits. The project's members start with none. The effect is confined to payments in flight at the moment of a forced exit. The exposure is one case: the member has released a preimage, the host has taken the upstream payment and refuses to complete the update, and the member cannot fund HTLC-success. The loss is that payment.

**Version 3 and ephemeral anchors.** They do not help the tree. A version 3 transaction may have only one unconfirmed ancestor, which must also be version 3, so a version 3 commitment cannot enter a mempool until its leaf transaction is confirmed, and a version 3 tree would be limited to parent and child at any time. The standard's zero-fee commitment format also cannot be combined with the taproot format today, and it moves the whole fee burden to outside coins, which is the opposite of what a member without coins needs.

**Public servers.** Package submission exists in both Esplora server code bases and is documented by Blockstream. Whether the public instances allow it was not tested. The Electrum servers the project found are too old for it. A member that depends on package submission should have at least two operators that accept it, and Gazpacho should fall back to single submission when each transaction pays its own way.

**Options for members without coins.**

| Option | Format stays standard? | Effect |
|---|---|---|
| A. Accept the gap, document it | Yes | A member without coins can lose a payment in flight to a host that cheats at that moment |
| B. Use the member's own anchor as the fee input | Yes | Works at low fee rates only, one HTLC at a time |
| C. Require a small on-chain reserve before a member may hold payments in flight above a threshold | Yes | Closes the gap for those members; contradicts "newcomers with no funds" unless the threshold is generous |
| D. A helper (another host, a watch service) supplies the fee input and the member signs the combined transaction. BOLT 5 requires the local signature to cover the whole transaction, so the member must sign after the helper's input is known | Yes | Depends on a third party being willing and reachable at that moment |
| E. ZmnSCPxj's asymmetric scheme: the member's commitment and HTLC transactions pre-signed at several fee rates, paid from channel funds | No | Closes the gap from the member's own funds; a different commitment format |

**Recommendation.** Keep the standard format. Build B into the exit engine, state A in the safety rule's list of limits, and limit the total value of payments in flight to a member that has no reserve (a term the host publishes), raising it when the member has a reserve (C). Treat E as the known alternative if the owner decides the gap is unacceptable. That would be a decision to leave the standard format.

### 2.6 Revocation and watching

**Facts.** Sections 1.1 and 1.2. BOLT 3 "Efficient Per-commitment Secret Storage": a receiver can keep all of a peer's revealed secrets in at most 49 values.

**Reasoning. What each side stores to punish an old commitment:**

- the peer's revealed per-commitment secrets (compact store);
- for each revoked commitment number that had HTLCs: each HTLC's payment hash, expiry, amount and direction, or the tap tweaks computed from them, since the key-path revocation of an HTLC output needs the tweak;
- the channel's static keys and both `to_self_delay` values;
- for each funding outpoint the channel has ever had: the outpoint, its amount, its script, and the range of commitment numbers signed for it;
- its own keys for the revocation path.

**Interaction with the moving leaf.**

- Storage per commitment number does not grow with the number of outpoints, because a number is revoked once for all of them.
- The watch list does grow: the factory funding output, every output on the path, every old channel outpoint, and the outputs of any commitment that appears.
- A commitment found on chain is identified by the number hidden in its lock time and sequence fields. Its outputs are matched by script, because the amounts on an old outpoint differ from those on the current one.
- A revoked commitment can only appear after the path above it has been published, which takes the tree's exit delay and is visible on chain. A member therefore gets warning from the tree before the channel's own window opens.

**"About two weeks to respond."** The member sets the `to_self_delay` that applies to the host's delayed outputs. Two weeks is 2,016 blocks.

- The member's window to punish a revoked host commitment is 2,016 blocks from that commitment's confirmation, and again 2,016 blocks from the confirmation of each second-stage transaction.
- The cost to the host: whenever the host closes a channel unilaterally, including when it forces out a member who has not cooperated before the end date, the host's whole balance in that channel is locked for 2,016 blocks after its commitment confirms, on top of the tree's exit delay. In a factory that lives about 30 days, capital in forced-out channels returns roughly two weeks after the factory ends. Only the host's commitment has to confirm before the end date, not the end of the delay, because the end-date payout spends the funding output and dies when the commitment confirms.
- Whether ordinary nodes accept 2,016 as a peer's `to_self_delay` was not checked. It matters only when the built-in node later opens channels to them.
- The host can set a much shorter delay on the member, because the host is always online. A short one helps the member, whose balance is otherwise locked for the delay after its own exit.
- "Two weeks" covers old channel states only. The window to answer an old state of a timed layer is one timelock step of that layer. The user-facing promise must not merge the two.

**Recommendation.** Member sets 2,016 on the host; host sets a short delay on the member, a term to choose (144 is the common minimum). Store HTLC details per revoked number, not only tweaks, so that the watch engine can be a separate process fed by records. State the two different response windows separately in the specification and in the interface.

### 2.7 Backup and restore

**Facts.** Section 1.2 (data-loss protection). The standard assumes static remote keys: the `to_remote` output on the peer's commitment pays to the node's fixed payment key. The taproot document, "To Remote Outputs": the fixed internal key "allows the remote party to scan for their output on chain".

**Reasoning.**

- *What the standard gives.* On reconnect a restored member learns, from the host's `channel_reestablish`, that it is behind, and gets proof. It must not publish. It asks the host to close. If the host closes, the member's balance sits in a `to_remote` output that the member can find and spend with a key derived from its recovery phrase, after one block. This matches the project's rule that a restored backup never publishes.
- *Does it work off chain?* The message exchange does. The outcome does not follow. "The host closes" now means the host publishes the member's whole branch and its commitment, at the host's cost, disturbing neighbouring members. An honest host will, though perhaps not at once. A dishonest host can decline, and the restored member has no safe commitment to publish.
- *What the member then has.* With the tree as imported, each node has a host-only timeout, so a member that cannot exit loses its balance at the end date. With end-date payouts at every level, the member receives the payout fixed when the output was created, which is not its balance. Recovery after loss of channel state depends on the host's honesty until the end date, and on the payout's size afterwards.
- *The path is easier to keep than the channel state.* Tree transactions change only at tree changes, which are rare. A user-exported backup refreshed at each tree change always contains a valid path. What it lacks is a current commitment.
- *Backup held by the host.* The design stores the encrypted journal with the host through the standard's peer-storage messages. If the host returns the latest copy, the member is fully restored. A host cannot be forced to. Whether the standard makes the host send the stored copy on every reconnect, so that it cannot tell a member that has lost its data from one that has not, was not re-read today.
- *Nonces.* If verification nonces are derived from the seed, commitment number and funding transaction ID, a restored member could in principle re-derive them. The rule that a restored copy never signs its own commitment stays essential, because the restored copy may hold a revoked state.

**Recommendation.** Keep the three layers: the host-held encrypted journal, a user export refreshed at every tree change, and data-loss protection as the last resort. State plainly in the specification that the last resort depends on the host. Ask the SuperScalar session to consider, in the payout design, what a member who lost its state receives at the end date.

### 2.8 The one-peer simplification

**Facts.** BOLT 4: every `update_add_htlc` carries a 1,366-byte onion, and the receiver "MUST decrypt" it. BOLT 11: field `s` is the `payment_secret`, `c` the final expiry delta (default 18), `r` private route hints. `docs/HOST-NODES.md`: the host's ordinary node creates an invoice for a hash whose preimage it does not know, and holds the payment.

**Reasoning.**

A member-side node with one channel can omit:

- BOLT 7 entirely: no gossip, no announcements, no route finding;
- BOLT 4 forwarding, blinded paths as an intermediate node, onion messages, multi-hop onion construction;
- BOLT 2 dual funding, interactive construction, splicing as specified, the legacy close negotiation, `announcement_signatures`;
- BOLT 12.

It cannot omit:

- BOLT 1 messages and BOLT 8 transport;
- BOLT 2 normal operation in full, including `channel_reestablish`, retransmission, fee updates and every limit check (reserve, `max_accepted_htlcs`, in-flight value, dust exposure);
- BOLT 3 in its taproot form, and the per-commitment secret generation;
- BOLT 5 in full, for its own commitment, the host's commitment and revoked commitments;
- final-hop handling from BOLT 4: decrypting one onion layer, checking amount and expiry against the HTLC, and producing failure messages;
- BOLT 11 decoding, to check what it is asked to pay.

**Who holds the preimage, and when.** For a payment to a member:

1. The member creates the preimage and gives the host only its hash.
2. The host's node issues an invoice for that hash and holds the payer's payment. It cannot settle without the preimage.
3. The host offers the member an HTLC for the hash.
4. The member waits until that HTLC is irrevocably committed in its channel, holds everything it needs to exit, and the deadline rule of 2.4 holds.
5. Only then does the member send the preimage. The host settles upstream.

The host cannot take the payment, because it never has the preimage before step 5. What the host can do is decline to complete after step 5. That is the case analysed in 2.4 and 2.5.

Consequences of the invoice belonging to the host's node:

- The invoice is signed by the host's node, not by the member. The payer's proof of payment names the host.
- The Lightning `payment_secret` in that invoice is known to the host's node, not to the member. It protects the host's node against probing. It plays no part in the member's safety.
- The member must check the invoice the host hands back before showing it: the hash is its own, the amount is right, and the final expiry delta is at least the figure from 2.4.

**Outgoing payments and redirection.** The member locks an HTLC to the hash in the invoice it wants paid. The host can claim that HTLC only with the preimage, and the preimage is released only by the true payee on receiving the invoice's amount. A host cannot redirect the money to anyone else. A host could overcharge, so the member fixes amount plus maximum fee, and it could learn the destination, which the design already accepts. A member-built multi-hop onion would restore privacy toward the host, but it needs the network graph, which a one-peer node does not have, and the adapter operation "pay an invoice" lets the host's node choose the route anyway.

The onion field must still be filled. The simplest standard-shaped choice: a one-hop onion in each direction, with the peer as the final node. From host to member it carries the ordinary final-hop fields. From member to host it carries the invoice to pay and the fee limit, in typed fields of the project's own.

**Recommendation.** First release: host-issued invoices and host-paid outgoing payments, as already decided, with one-hop onions on the factory channel. Write the member's checks on the invoice into the payment specification. Record member-signed invoices with a route hint as the later alternative, for when the built-in node holds ordinary channels itself.

### 2.9 Is "exactly the standard format" achievable?

**Reasoning.** The answer differs by layer.

| Layer | Exactly standard? | Note |
|---|---|---|
| Funding output script | Yes, after a change to the imported tree code (2.2) | Not true of the import today |
| Commitment, HTLC and second-stage transactions, keys, revocation | Yes | Checkable against the document's test vectors |
| Messages of normal operation and reconnection | Yes | Including the nonce fields |
| Opening | Standard messages, with three behavioural changes: outpoint from the tree, `channel_ready` timed by the factory, no forgetting | One extra typed field to mark the channel as in a factory |
| Moving the funding outpoint | No standard exists | Splice-shaped: standard `stfu`, batched `commitment_signed` with `funding_txid`, nonce lists by funding transaction ID; factory messages replace the splice messages |
| Deadlines | Stricter than standard, never looser | A behavioural rule |
| Fees | Standard format, with the gap in 2.5 | Or leave the standard (option E) |
| Closing | The standard close applies only once the leaf is on chain | Cooperative leaving is a factory operation |

**The smallest deviation** is therefore: no deviation in any transaction or in any message of normal operation; a marker field at opening; and a set of factory messages for moving the outpoint, modelled on splicing. All of it travels inside the project's one custom message type or in typed fields that an ordinary node would reject or ignore by the usual rule.

**What it costs in interoperability.** An ordinary LND or Eclair node cannot be the peer of a factory channel under any design, because it has no tree. What the exact format buys is different:

- one channel engine serves factory channels now and ordinary taproot channels to LND and Eclair later, when the built-in node holds its own channels;
- once a member's path is on chain, what is there is an ordinary taproot channel, which existing tools can recognise, watch and recover;
- the engine can be tested against the specification's vectors and, for normal operation, against LND and Eclair directly, by opening an ordinary taproot channel between them and Gazpacho's node.

Two limits on that later interoperability: taproot channels cannot be announced until the gossip extension is merged, so a host's public channels cannot be taproot yet; and splicing of taproot channels is not fully specified, with Eclair ahead of the text.

**Verdict.** The decision holds for the transaction format and for the messages of normal operation. It cannot hold for opening and moving, where no standard exists and the nearest ones are an unmerged draft and the splice procedure. It holds for fees only if the owner accepts the gap for members without coins.

---

## Part 3. Proposed outline for `spec/channel.md`

Every rule the specification must contain, grouped. "As standard" means: state the reference and add nothing.

**1. Scope and terms.** Host is the opener and fee payer. Member is the acceptor. One channel per member per factory (unless decision 2 goes the other way). Preimage and `payment_secret` defined and kept apart.

**2. Format.**
1. Channel type: `option_simple_taproot` with `option_scid_alias` and `option_zeroconf`. Never announced.
2. Funding output script, with the key sort and the tweak, and the test vector it must reproduce.
3. Funding keys: separate from tree keys; a new pair for each funding outpoint; how they are derived.
4. Commitment, HTLC and second-stage transactions: as standard, by section reference. Which text is authoritative (the October 2026 corrections).
5. Per-commitment secrets: generated by the BOLT 3 algorithm.
6. The format interface behind which the archived format could be reinstated.

**3. Parameters and limits.**
1. `to_self_delay` in each direction.
2. `dust_limit_satoshis`, `channel_reserve_satoshis` (and that a member starting at zero is below reserve until paid), `htlc_minimum_msat`, `max_accepted_htlcs`, `max_htlc_value_in_flight_msat`, the dust-exposure limit.
3. Fee rate: who sets it, the member's floor and ceiling, what happens when the host's `update_fee` is outside them.
4. The limit on value in flight for a member with no on-chain reserve.

**4. Opening inside a factory.**
1. Order: tree built unsigned; channel opened for the leaf outpoint; initial commitments exchanged; tree signed; funding signed (children before parents, sign before fund).
2. The messages used, the marker field, and what each side checks against its own tree.
3. `channel_ready`: the condition (factory funding depth, full path held), and that it is never sent on trust.
4. Aliases.
5. No forgetting; no broadcast of the leaf by the channel engine.
6. What happens to the 512 half-open channels if creation fails.

**5. Normal operation.**
1. The update sequence, as standard.
2. One update routine; updates arriving mid-update are queued.
3. H4: the host's own commitment is never behind the member's.
4. H3: the host does not act on a payment until it is irrevocably committed.
5. Refusal rules for every limit in section 3.

**6. What is saved before what is sent.**
1. Before `commitment_signed`: the updates it covers and the fact of having signed that number for that outpoint.
2. Before `revoke_and_ack`: the new commitment complete (peer's partial signature and signing nonce, HTLC signatures, HTLC details), for every active outpoint.
3. On receiving `revoke_and_ack`: the secret, before anything is done that depends on it.
4. Before `update_fulfill_htlc`: the preimage and the record that it was released.
5. Before a leaf partial signature: the commitment on the new outpoint and the payout for it.
6. What is never saved: round signing nonces. What is derived and not saved: verification nonces.

**7. Nonces.**
1. Verification nonce derivation, including the funding transaction ID.
2. Signing nonces are fresh and memory-only.
3. Which message carries which nonce, including the first nonces for a new outpoint.
4. Rules on reconnect: fresh list for every active outpoint; re-sign on retransmission.
5. Nonces for the leaf transaction and the payout belong to the signing round.

**8. Reconnection.**
1. `channel_reestablish`, as standard, with the nonce list.
2. Retransmission order.
3. How a half-finished move is recognised and resumed or abandoned.
4. Data-loss protection: what a node that is behind does and does not do.

**9. Moving the funding outpoint.**
1. When a move happens (liquidity change on the leaf; re-signing of a layer above).
2. Preconditions: quiescent; idle in the first release.
3. The nine steps, with the message for each.
4. The rule that the member's balance is unchanged by a move.
5. The rule that, from the first leaf partial signature until lock, no update is valid unless signed for both outpoints.
6. Lock: its condition and its message.
7. When the old outpoint is treated as dead (after the next revocation), and that it is still watched.
8. Aborting a move at each step, and what each side discards.
9. More than one pending move: forbidden in the first release.
10. Limits: the largest batch (the standard allows 20).

**10. Deadlines.**
1. The definitions and formulas of 2.4.
2. The minimum expiry for an incoming HTLC and the value put in invoices.
3. The member's fulfilment rule and its exit deadline.
4. The host's early-warning height and its upstream margin.
5. The outgoing rule for the member and the host's forwarding delta.
6. The ceiling above which a tree shape is not offered.
7. That every figure comes from the exit engine's real timelocks.

**11. Fees and on-chain resolution.**
1. A commitment is broadcast only after its leaf transaction has confirmed.
2. How each transaction gets its fee, and what a member without coins can and cannot do.
3. Use of the member's own anchor.
4. Submission order, package use, cluster limits.
5. Resolution of every output, as BOLT 5, for own commitment, host's commitment, revoked commitment.

**12. Revocation and watching.**
1. What is stored per revoked number and per outpoint.
2. The watch list.
3. The two response windows, stated separately.
4. The records handed to a separate watch process.

**13. Ending.**
1. Cooperative leaving is a factory operation; the channel must be idle and is then frozen.
2. The host's duty to close before the end date, and its deadline.
3. A channel whose outpoint became unreachable.
4. After a unilateral exit: the channel is closed, not continued (first release).

**14. Backup and restore.** The three layers; the never-publish rule; what depends on the host.

**15. Messages.** The table of every standard message used, with its fields; the factory messages added; test vectors.

**16. Tests.** For each rule: a scenario that breaks it and must be refused, and the same scenario with the rule removed that must show a loss. Cross-tests against LND and Eclair for normal operation.

**17. Open points.**

---

## Part 4. Decisions for the owner

1. **The leaf's channel output becomes the exact standard funding script.** This needs a change in the SuperScalar repository (sorted keys, no script path, keys supplied by the channel). Options: (a) request it in the second round of tree changes and build against a script-provider interface meanwhile; (b) keep the import's script and give up "exactly". *Recommended: (a).*

2. **What a liquidity sale does to the channel.** Options: (a) move the channel to a new, larger outpoint, splice-fashion; (b) ZmnSCPxj's original: add a second channel, never move one; (c) support both. (a) needs the moving procedure of 2.3, permanent watching of old outpoints, and a clear answer from the SuperScalar session on the leaf transaction's shape, since the imported function does not add liquidity. (b) needs no moving procedure for liquidity sales but needs several channels per member and splitting payments across them, and channels still move whenever a layer above is re-signed. *Recommended: (a), after the SuperScalar session confirms the transaction shape. The moving procedure is needed for layer updates in any case.*

3. **Payments in flight during a move.** Options: (a) forbid in the first release; (b) allow, as splicing does. *Recommended: (a).*

4. **Members without on-chain coins and payments in flight.** Options A to E in 2.5. *Recommended: keep the standard format; use the member's anchor where it suffices; cap value in flight for members without a reserve; state the remaining gap openly.* Choosing E means leaving the standard format.

5. **Verification nonces are derived, not stored.** The project rule says signing secrets are never stored. The taproot format requires a secret nonce that outlives a restart. Options: (a) derive it from the channel seed, commitment number and funding transaction ID, as the specification recommends; (b) store it encrypted. *Recommended: (a), recorded as a stated exception to the rule, with the never-publish-after-restore rule as its guard.*

6. **Per-commitment secrets by the standard algorithm.** ZmnSCPxj suggested storing all revocation keys instead, for multi-signer endpoints. Options: (a) the BOLT 3 algorithm; (b) random secrets. *Recommended: (a). It is part of "exactly", and each endpoint here is one signer.*

7. **Delays.** The member's requirement on the host (2,016 proposed) and the host's on the member (144 proposed). The first fixes how long the host's capital is locked after a forced exit.

8. **Deadline constants and the ceiling.** S, G, R, M, and the largest final expiry delta a host may offer. This also decides which tree shapes can receive payments.

9. **Opening messages.** Options: (a) the standard opening messages with a marker field; (b) fold opening into the factory's creation round. *Recommended: (a).* It keeps one opening path for factory and ordinary channels.

10. **Relation to bLIP-56.** The draft is open, unchanged since December 2024, uses an even message number (32800) where the design calls for an odd one, and predates taproot nonces and the merged splice text. Options: (a) follow its structure and ideas but use the project's own message type and fields; (b) implement it literally. *Recommended: (a), written so that it could be offered as an update to the draft.*

11. **Old outpoints.** Keep and watch every one until the factory is closed. *Recommended: yes.* The alternative needs a proof that an outpoint can never reach the chain, which a chained leaf cannot give.

12. **After a unilateral exit.** Options: (a) the channel is closed; (b) it continues as an ordinary on-chain channel, as ZmnSCPxj notes is possible. *Recommended: (a) for the first release.*

13. **Invoice model**, confirming the earlier decision in the light of 2.8: host-issued invoices and host-paid outgoing payments first, one-hop onions on the factory channel, member-signed invoices later.

14. **The user-facing promise.** "About two weeks to respond" is true for old channel states only. The window for an old state of a timed layer is one timelock step. Decide how the product words this.

---

## Part 5. What could not be verified

1. **Limits of ordinary nodes**: the largest total time lock LND, Core Lightning and Eclair accept for a payment (2,016 blocks is from memory), the largest `to_self_delay` they accept, and how long LND will hold a payment and when it cancels a held one. These decide whether the figures in 2.4 and 2.6 work in practice.
2. **How LND and Eclair derive or store verification nonces**, and how they behave on reconnect beyond what the release notes say. Their source code was not read.
3. **How a taproot channel's splice is signed** (first nonces for the new outpoint, the MuSig2 signature spending the old funding output). The specification text does not say; Eclair's implementation was not read.
4. **Whether public Esplora instances accept package submission** on signet, testnet4 and mainnet, and their limits. Only documentation and server source were read. No request was sent.
5. **How far the 0.1 satoshi per virtual byte minimum and Core 31's cluster rules are deployed** among relaying nodes and miners.
6. **The liquidity-sale transaction for a one-member pseudo-Spilman leaf.** Only the imported `factory.c` was read. The SuperScalar programs that drive it are not imported and were not read. The observation that a leaf change adds no liquidity is about `factory_advance_leaf` alone.
7. **The import's taproot tweak when there is no script tree** (whether it is the BIP 86 form), and whether the pinned `secp256k1-zkp` provides the standard key sort. Neither was located in the time available.
8. **The real timelock figures per shape.** 432 blocks per timed level is taken from the knowledge base. `dw_state.c` was not read, and the step size that sets the layer response window was not established.
9. **The taproot document's test vectors** were not reproduced. Nothing was built or run.
10. **Peer storage behaviour**: whether the standard requires the stored copy to be sent on every reconnect. Not re-read today.
11. **bLIP-56 since 2024.** The pull request shows activity in April 2026 but its only commit is from December 2024. The discussion comments were not read.
12. **Phoenix and other wallets without on-chain coins**: how they fund second-stage transactions on anchor channels. Relevant to decision 4; not researched.
13. **The implementation report at Delving topic 2705**, linked from topic 1242 in July 2026, was not read.
14. **All reasoning in Part 2** is this note's own and unreviewed. The argument most in need of an expert's eye is in 2.3: that revoking a commitment number makes every old outpoint safe, and the rule on signing for both outpoints.
