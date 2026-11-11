# Gazpacho proposals

How changes to rules and behaviour are requested, discussed and decided. Modelled on the processes Bitcoin (BIPs) and Lightning (bLIPs) use.

## Why

New joining rules, safety rules and protocol features usually change the code that decides what is safe to sign. Such changes are made in the open, one at a time, with a written record of who agreed and who objected. The record is kept even for proposals that are never shipped.

## What needs a proposal

- Anything that changes what a member or host will sign, or refuse to sign.
- Any change to messages, the host's published terms, or lobby rules.
- New rule profiles, joining requirements, deposits, reputation schemes.

Bug fixes and changes that cannot affect signing do not need one.

## Life of a proposal

| Status | Meaning |
|---|---|
| Draft | Written up using the template; not yet under discussion |
| Discussion | Open for comment. Reviewers reply with ACK (agree), NACK (object, with reasons) or a request for changes |
| Approved | The maintainers agree it is sound |
| Rejected | The maintainers do not agree it is sound. The reasons stay on record |
| Shipped | Included in a Gazpacho release, with the version noted |
| Approved, not shipped | Judged sound, but not included in Gazpacho releases, with the reason given (for example legal or product reasons). Other factory software is free to implement it |
| Withdrawn | The author gave it up |

Approval and shipping are separate decisions. A proposal can be approved and never shipped here, and the record says so plainly.

## Rules

- One proposal per file in this folder, named `NNNN-short-title.md`, numbered in order of submission.
- Every proposal states what it changes in the safe-to-sign rules, how it could be abused, and how it is tested.
- A proposal that touches signing is not shipped without an independent review and a test that fails when the rule is removed.
- The discussion record (who said ACK or NACK, and why) is linked from the proposal and is never deleted.

## Open

The name and numbering of these documents, and who the maintainers are beyond the owner, are still to be settled.
