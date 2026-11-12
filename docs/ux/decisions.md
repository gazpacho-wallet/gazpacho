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
- Every sale spends only the spare liquidity; existing channels stay where they are (planned in SuperScalar as the next leaf fix).

Interface consequences for 1.1.0: a "covered" figure under "my money"; a warning tier as the balance approaches it; a recommended on-chain reserve that becomes a requirement to receive past coverage (Gazpacho may be stricter than the reference: proposed, not decided).

### 3. Buying receiving room is for 1.1.0

Buying liquidity, splicing and channels opened on demand are not in 1.0.0. They are designed for, documented, and built behind a switch that is off: the interface keeps a hidden place for them, the local API reserves the calls, and the terms record reserves the fee field. Everything about them is marked "1.1.0".
