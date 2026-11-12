# Interface decisions

Decisions by the owner that shape the interface and the terms record. Newest last. Each also belongs in `docs/RECORD.md` when the layout work is merged.

## 2026-11-11

### 1. A host cannot change a lobby's outer rules; values may move only inside signed ranges

- A lobby's **outer rules** are fixed when it opens: the profile, every fixed term, and for each adjustable term the **range** it may take. Changing any of these is a new lobby.
- Inside a range, the host may move the **current value** until a freeze point. Proposed freeze point: the ready check. After it nothing moves.
- A member's limits are compared with the **whole range**, not only the current value, by default. A member whose limits cover the whole range can never be switched at the last moment. A looser choice ("ready while the current value fits; un-ready me if it moves outside") may be offered as an option.
- **Digests.** The outer rules have one digest, a tagged hash of their canonical encoding, signed by the host's long-term key. It is the lobby's identity. The current values have a version number and their own signed digest that includes the outer digest. A member's ready message names both. The signing round's identifier already includes the terms digest (`spec/signing-round.md`, section 3), so a signature can only be for the terms the member readied for, and the tree is still checked against the member's conditions at signing.
- This settles the question raised by the research ("a new version or a new lobby"): outer rules never change; inner values move within signed bounds and then freeze.
- To specify: the canonical encoding and the list of which terms may be ranges. This belongs in the host terms record specification, which does not exist yet.

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
