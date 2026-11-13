# Interface decisions

Decisions by the owner that shape the interface and the terms record. Newest last. Each also belongs in `docs/RECORD.md` when the layout work is merged.

## 2026-11-11

### 1. A host cannot change a lobby's outer rules; values may move only inside signed ranges

- A lobby's **outer rules** are fixed when it opens: the profile, every fixed term, and for each adjustable term the **range** it may take. Changing any of these is a new lobby.
- Inside a range, the host may move the **current value** until a freeze point. Proposed freeze point: the ready check. After it nothing moves.
- A member's limits are compared with the **whole range**, not only the current value, by default. A member whose limits cover the whole range can never be switched at the last moment. A looser choice ("ready while the current value fits; un-ready me if it moves outside") may be offered as an option.
- **Digests.** The outer rules have one digest, a tagged hash of their canonical encoding, signed by the host's long-term key. It is the lobby's identity. The current values have a version number and their own signed digest that includes the outer digest. A member's ready message names both. The signing round's identifier already includes the terms digest (`spec/signing-round.md`, section 3), so a signature can only be for the terms the member readied for, and the tree is still checked against the member's conditions at signing.
- This settles the question raised by the research ("a new version or a new lobby"): outer rules never change; inner values move within signed bounds and then freeze.
- To specify: the canonical encoding and the list of which terms may be ranges. This belongs in the host terms record specification. (Done: `spec/terms.md` draft 2 specifies both, 2026-11-12.)

### 2. Fees a host can charge

Owner's direction: a Lightning channel fee, and possibly a flat fee, a percentage, or a range tied to on-chain prices.

What is possible without trust, as understood today (not yet checked against the reference code):

| Fee | How it is collected | Can the member's app enforce its limit? |
|---|---|---|
| Per payment (a base amount plus a proportion) | Inside each payment, as any Lightning node charges | Yes, per payment |
| Flat joining fee | A member starts at zero, so it cannot be paid up front from the channel. Either taken from the first payment received, or paid beforehand over Lightning from elsewhere (a small trust in the host) | Yes at signing, if it is written into the terms |
| Percentage of the channel size | Same two routes as the flat fee | Yes |
| Tied to on-chain prices | The terms state a formula and a ceiling. The amount is fixed at the moment of signing from the fee rate the tree actually uses, which the member's app can see | Yes at signing. It cannot float afterwards |
| Recurring, at each move to a new factory | Agreed again at each move, like a joining fee | Yes, at each move |

Not possible without trust: any charge the member has not signed. Every change to a channel needs the member's signature, so a host cannot debit a balance by itself.

Proposed for 1.0.0: the per-payment fee, and an optional joining fee (flat, or a share of chain cost with a ceiling) taken from the first payment received. Proposed for 1.1.0: the fee for extra receiving room.

### 4. No role question: everyone can be member and host

Owner, 2026-11-11: "they should always be able to do both". The app never asks "member or host?", and hosting is not behind a mode switch. Hosting is an ordinary area, always visible, with a calm starting page until the person hosts something. Host items appear on the home only when the person has a lobby or factory of their own. This replaces "host mode" in the options map and in the first prototype's settings (`roles`).

### 5. Shared leaves and "coverage" arrive with sales in 1.1.0

Agreed with the SuperScalar session, 2026-11-11. One member per leaf (K = 1) is the default in 1.0.0. Shared leaves (K > 1) arrive together with sales of receiving room in 1.1.0, under the design's own answer (Delving topic 1242, "limited coverage"), not by re-signing the payouts higher up the tree:

- Each member's **coverage** is fixed when the factory is built: what the end-date payout would pay that member.
- Without sales a member's balance can never exceed its coverage, so 1.0.0 is fully covered.
- With sales it can. The wallet shows the covered amount beside the balance and warns as the balance nears it.
- A member holding more than its coverage keeps a small on-chain coin, so it can leave alone at its real balance.
- The host must fully back what it promises.
- Moving to the next factory resets coverage.
- Every sale spends only the spare liquidity and creates a **new channel** for the buyer; existing channels stay where they are (planned in SuperScalar for 1.1.0; today's code instead grows the existing channel and moves every channel). So in 1.1.0 a member can hold several channels in one factory: "my money" adds them up, the channel list shows each, and a payment may be split across them.

Interface consequences for 1.1.0: a "covered" figure under "my money"; a warning tier as the balance approaches it; a recommended on-chain reserve that becomes a requirement to receive past coverage (Gazpacho may be stricter than the reference: proposed, not decided).

### 6. Questions 3 answered (2026-11-11)

**"Fits only now"** (answer A): kept as a label, listed with the lobbies that do not fit, one tap showing the numbers.

**Where coins go** (answer A now; B and C planned). The owner read this as payout destinations and wants all three:
- 1.0.0: one wallet; coins from a factory come back to it, with an amount set aside for hosting.
- 1.1.0: choose derived addresses of the same wallet per factory (fresh address each time, so factories are not linked by address).
- 1.1.0 or later: pay out to an outside wallet, such as a hardware wallet, that Gazpacho does not control.
- Constraint found: transactions signed in advance (the end-date payout, the tree, the channel's own closing outputs) fix their destination when they are signed. An outside address must be given before the factory forms and stays for its life, and the tree builder must accept a destination per member (a request to SuperScalar, alongside the caller-supplied channel script). Cooperative closes and moves can pay anywhere chosen at that moment. An outside address must be proven before use (shown on the hardware wallet's screen, or a signed message), because a wrong address loses the coins.
- A hardware wallet cannot be the factory signer today (no group-signing support, and the factory needs an online signer); see `docs/AWAY.md`.

**Hosting on phones** (answer A, with C as an option): a Hosting tab always, which also advertises hosting; "header until you host" offered as a setting. Compare both later with screenshots. Any A/B comparison is done with testers, never with tracking inside the app.

**On-chain reserve** (answer A): no reserve required or recommended in 1.0.0. Members who receive nothing, or who move to the next factory, never need one; only a member who chooses to leave alone pays fees. Use pay-to-anchor outputs so the host or anyone can raise a fee, and build a "speed up a stuck transaction" action. Document and plan the alternatives (fee tiers signed in advance, paying the fee from the member's own output, a paid fee-bump helper) and show A/B samples later.

### 7. The dedication in the wallet (proposed 2026-11-11)

`DEDICATION.md` is part of the product, not only the repository:
- **About** (in Settings, Application or Help): three entries, "Dedication", "Credits" and "Licences". The dedication page shows the full text.
- **Credits:** the SuperScalar design (ZmnSCPxj) and code, the libraries Gazpacho is built on (libsecp256k1, libsecp256k1-zkp, OpenSSL's libcrypto, libcurl), the Lightning and Bitcoin specifications, and contributors. **Licences:** every bundled library's licence text, which the licences require anyway.
- **First run:** one quiet line on the last screen, "Gazpacho is dedicated to the developers who paid for our freedom to hold our own keys", linking to the dedication. Shown once, never in the way.
- **The program:** `gazpacho --version` prints a one-line dedication under the version.
- Never a pop-up, never on the home screen.

### 3. Buying receiving room is for 1.1.0

Buying liquidity, splicing and channels opened on demand are not in 1.0.0. They are designed for, documented, and built behind a switch that is off: the interface keeps a hidden place for them, the local API reserves the calls, and the terms record reserves the fee field. Everything about them is marked "1.1.0".

### 8. The shared protocol identifier (owner, 2026-11-12)

`factory_protocol_id` = SHA-256 of the UTF-8 bytes `SuperScalar/1` (hex `53757065725363616c61722f31`) = `c3a082d0fcb768d76999f4f8ad672f7110fbef6a13a1697686c7073961c842f1`. This follows bLIP-56's recommended form. It replaces the two other values found in use: the zero-padded ASCII "SuperScalar/v1" in the superscalar-cln plugin, and SHA256("SuperScalar" ‖ "0") in an April research note. To be recorded in superscalar-docs and adopted by superscalar-cln, the SuperScalar reference and Gazpacho. Gazpacho keeps sequential member placement (no timezone buckets), for privacy.

### 9. 1.0.0 trees are advanceless (owner, 2026-11-12, questions 4)

No timed (Decker-Wattenhofer) levels in 1.0.0: every interior level is fixed. Nothing in 1.0.0 would update a timed layer (one member per leaf, no sales, payments never advance the tree, members move by rotation), so timed levels would only lengthen exits and payment deadlines. Timed levels and layer updates arrive with 1.1.0, together with liquidity sales. Consequences: no tree race, so no on-chain reserve is needed (O2 resolved); refresh-in-place is never used, with or without timed layers, because under the end-date payout the old payout stays valid at the old date (SuperScalar's finding, 2026-11-12): extending a factory's life always means rotation to a new funding output; safe absence is set by the channel's own revocation delay (value to be set in the channel specification). Proposed to SuperScalar as their default too (`docs/handoff/2026-11-12-advanceless-default.md`). This replaces the earlier decision "full layered tree in the first release".

### 10. Seats (owner, 2026-11-12, questions 4)

1.0.0: seats are free, protected by invitation-only lobbies, host removal before the start, standby seats and the signing time budget. Next: a proof of control of a coin or channel for public lobbies, with a share of newcomer seats that need none. Later: the host chooses per lobby among several options in its terms (free, proof, deposit, and others).

### 11. Slice 1 ships with the interface (owner, 2026-11-12)

Owner: "try to ship this with some kind of ui in place and we want to do everything thru the ui". Slice 1 is not done from the command line. Every Slice 1 action is reachable through the local API and the interface: creating or restoring a wallet, the backup check of the words, conditions, finding and joining a lobby, hosting a lobby, the signing moment and refusals, and the live factory. The command line stays for start-up and diagnostics. This answers `OPEN-QUESTIONS.md` Q1 (the screens are in Slice 1, not a slice 1b). Applied in `spec/local-api.md` draft 2 (sections 2 and 2.1), `SLICES.md` and `SLICE1-WORK.md`.

### 12. The 24 words may appear in the browser, under fixed rules (owner, 2026-11-12)

Owner: the words may appear in the browser; "follow typical rules for key handling for wallets and elite crypto repos". This replaces the earlier rule in `DESIGN.md` section 13 that keys never enter the browser, for the words only; private keys, nonces, channel state and journal records still never do. The rules (`spec/local-api.md` section 12.7):
- shown only over loopback; at creation, and on reveal only after a fresh sign-in;
- never in URLs, logs, events or caches (`Cache-Control: no-store`), and never kept in page storage;
- no clipboard copy by default; cleared from the page after display;
- the backup check never reveals which positions are wrong, and has attempt limits;
- the program wipes its copies from memory after use.

Applied in `spec/local-api.md` draft 3 (section 12.7), after its second review: reveal now carries the passphrase in its own request rather than relying on a fresh sign-in, which is stricter; the words stay shown until the person presses Done, are hidden while the tab is hidden, and are cleared at a 10-minute ceiling.

### 13. Files are encrypted from the start (owner, 2026-11-12, questions 6, Q6 answer B)

Every file the program writes is encrypted from the first write, on test networks too, not only before mainnet. The design is `spec/storage-encryption.md` (being written). The local API handles a locked wallet: the program starts locked, does nothing until it is unlocked, and says so (`spec/local-api.md` sections 4.7 and 11.2). A backup export is the file as encrypted on disk.

Applied in `spec/storage-encryption.md` draft 1 and `spec/local-api.md` draft 3 (sections 4 and 4.7). One refinement for the owner to confirm: a locked program is not wholly idle. It keeps watching and leaves a factory in time from already-signed transactions (storage 8.7, its open point 15), so that a restart does not stop the protection; it signs, joins and pays nothing until unlocked.

### 14. Sign-in with the wallet passphrase, as in desktop wallets (owner, 2026-11-12)

The owner cited Sparrow. The person unlocks with the wallet passphrase, which is also what decrypts the files (decision 13):
- normal sign-in: the passphrase typed in the page; the program checks it by unlocking the storage key; attempts are rate-limited;
- first run, before any passphrase exists: the program opens the browser itself with a one-use start token in the address's fragment (never in the path or query, never logged), so a page opened elsewhere cannot create or restore a wallet; a code printed in the terminal is the fallback for headless use;
- fresh sign-in for sensitive actions: the passphrase again;
- lock: the key is dropped from memory, and the program then does nothing until unlocked.
The session token stays out of cookies (review of the local API, F1). Why a browser interface needs more than Sparrow does: other web pages in the same browser can send requests to loopback (`spec/local-api.md` section 4.1).

Applied in `spec/local-api.md` drafts 2 and 3. Draft 3, after the second review: the browser is opened through an owner-only redirect file, so the start token is on no command line; the passphrase is typed into the request itself for the words and for spending, and the 5-minute fresh sign-in stays only for reversible changes; "does nothing until unlocked" is refined as under decision 13.

Also decided the same day: interface ports 39735 (signet) and 39736 (testnet4), plus one optional extra port for a tunnel, off by default; and in Slice 1 one joined lobby and one hosted lobby at a time, with limits that stay editable (tightening leaves a lobby that no longer fits; loosening affects only future joins).

### 15. Questions 6 answered (owner, 2026-11-12)

The owner answered the nine questions that blocked the first factory (`questions-6-blocking.html`). Full answers, the owner's notes and what each leaves to do are in `OPEN-QUESTIONS.md` section 0. In short:

- **Q1, A:** no end-date payout and no friendly close in Slice 1. Both come later, built carefully from SuperScalar's work; a **Slice 1.5** tests every deferred feature end to end, and every path a factory can take is to be researched first, with what SuperScalar's tooling tracks.
- **Q2, A:** the proposed timing set for the Slice 1 test factory (T1's 144 blocks plus 36 of wind-down, burial 3 blocks, funding deadline 36 blocks, one signing budget for an unfinished round, 6 blocks per transaction plus 6 spare, timed-level fields fixed at 144 and 4).
- **Q3, A:** a member's starting limits are the small-lobby values (fewest members 3; smallest channel 50,000 sat; joining fee at most 2,000 sat; payment fee at most 1,000 msat plus 2,500 per million; factory life at most 8,640 blocks; leaving alone at most 1,008 blocks), as the Everyday preset, every number visible and editable.
- **Q4, A:** fees in 1.0.0 are a per-payment fee plus an optional flat joining fee. The owner wants every fee model researched, up to the host taking all the channel fees it sets or sharing them with the member whose coins were used, and what the rules can enforce (decision 2 stays the table of what is possible).
- **Q5:** not answered. The owner leans to a branch of its own in the standard key tree; it is not decided.
- **Q6, B:** encrypt from the start (decision 13).
- **Q7, A plus a tunnel port:** ports 39735 and 39736, one optional extra port; sign-in with the wallet passphrase, as in Sparrow (decision 14).
- **Q8, A:** one joined and one hosted lobby at a time in Slice 1; limits stay editable. Any skipped feature must be tested later.
- **Q9, A:** the transport's code review counts as its specification review; the specification is to be re-reviewed fully once the program is built.

This also confirms decision 11's answer to `OPEN-QUESTIONS.md` Q1: the screens are in Slice 1.

## 2026-11-13

### 16. Owner decisions of 13 November (owner, 2026-11-13)

**a. Host funding is automatic and on by default.** Once the host's H1 check passes, the host broadcasts the funding transaction without asking. Consent belongs at opening the lobby and at the start, not at funding. This holds on test networks now. Before real money it becomes a setting, and the setting still defaults to automatic.

**b. Several lobbies at once per wallet, from Slice 1.** This replaces the Slice 1 limit of one joined and one hosted lobby (Q8 of questions 6). Every lobby record carries a lobby field. The composite node design is PR 37.

**c. Host accountability in 1.0.0.**

- Signed seat receipts.
- The signer-choice rule written into the outer terms, so the member's app can check it.
- Removals always signed, with a reason.
- Signed lobby-wide counts, including seats removed by the host, with no identities.

Proofs may be published to Nostr later: only from fresh keys, only after the lobby ends, and never with member keys or addresses. The research behind this (lobby accountability and liveness) found that the host's choices are the main unchecked power in a lobby. Signed receipts and counts let a member prove what the host did without revealing who else was there.

**d. Member signing modes, selectable by members and hosts.**

- **A:** sign automatically.
- **B:** ask for the passphrase when the lobby fills.
- **C:** unlock that lobby's keys once at join. They sign only that factory, within the approved terms, and are wiped afterwards. **C is the default** (owner confirmed, 2026-11-13). Members and hosts can still choose A or B.
- **D:** watchtower services, the fourth way to take part in a lobby and join a factory. Scheduled after 1.2.0; research is pending. Four variants:
  - **D1:** passive, run by a third party, no keys.
  - **D2:** passive, run yourself.
  - **D3:** keyed, run yourself: a "home node" that can monitor, sign and join new factories for you.
  - **D4:** keyed, run by a third party. This is custody: never a default, at most an explicit, warned expert option.

In modes B and C, "not unlocked" counts as not answering the ready check. Slice 1 closes the ready check as soon as every seat has answered. Proposed defaults (owner to confirm): a 60 s ready window, 60 s per step, and a 10-minute signing budget. Measured signing on signet took 193 ms for 3 members.

**e. Understudies in 1.0.0** (moved from 1.1.0 by the owner the same day). Standby seats that answered the ready check are swapped in automatically: at the ready check for a no-show, and mid-signing for a member who drops. A mid-signing swap is a new attempt with fresh nonces from everyone. Every member's limits are re-checked against the new set. Standby order is covered by the signed receipts.

**f. A UI/UX review pass after 1.0.0,** to add all these modes and settings gracefully.

**g. Privacy roadmap.**

- Slice 1 (PR in progress): a generic user agent, an explicit chain proxy, and no addresses in logs.
- 1.0.0:
  - one Tor setting for hosts, chain and discovery; `socks5h` only; on by default when Tor is present; no silent clearnet fallback;
  - onion-service hosts, after the per-address connection limit is fixed for Tor;
  - the chain server over Tor, plus a "your own node" mode;
  - block-based chain lookups instead of per-txid and per-script queries.
- Later: built-in Tor (for example Arti) and a BIP 157/158 compact block filter light client, plus automatic onion creation and DNS-name hosts.
