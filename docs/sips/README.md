# SuperScalar Improvement Proposals (SIPs)

How changes to rules and behaviour are requested, discussed and decided. Modelled on the processes Bitcoin (BIPs) and Lightning (bLIPs) use.

SIPs are meant for anyone building SuperScalar factory software, not only Gazpacho. They live in this repository for now and can move to a home of their own.

## Why

New joining rules, safety rules and protocol features usually change the code that decides what is safe to sign. Such changes are made in the open, one at a time, with a written record of who agreed and who objected. The record is kept even for proposals that are never shipped.

## Categories

| Category | For | Template |
|---|---|---|
| **Rule** | A rule a host can set or a member can require: who may join, when a lobby starts, limits, deposits, profiles | `template-rule.md` (worked example: `example-rule-request.md`) |
| **Protocol** | Messages, the host's published terms, transaction construction, signing | `template-general.md` |
| **Process** | How SIPs or releases work | `template-general.md` |
| **Informational** | Guidance, analysis, recommended settings; changes no behaviour | `template-general.md` |

## What needs a SIP

- Anything that changes what a member or host will sign, or refuse to sign.
- Any change to messages, the host's published terms, or lobby rules.
- New rule profiles, joining requirements, deposits, reputation schemes.

Bug fixes and changes that cannot affect signing do not need one.

## Life of a SIP

| Status | Meaning |
|---|---|
| Draft | Written up using a template; not yet under discussion |
| Discussion | Open for comment. Reviewers reply with ACK (agree), NACK (object, with reasons) or a request for changes |
| Approved | The maintainers agree it is sound |
| Rejected | The maintainers do not agree it is sound. The reasons stay on record |
| Shipped | Included in a release, with the software and version noted |
| Approved, not shipped | Judged sound, but not included in Gazpacho releases, with the reason given (for example legal or product reasons). Other factory software is free to implement it |
| Withdrawn | The author gave it up |

Approval and shipping are separate decisions. A SIP can be approved and never shipped here, and the record says so plainly.

## Rules of the process

- One SIP per file in this folder, named `sip-NNNN-short-title.md`, numbered in order of submission.
- Every SIP states what it changes in the safe-to-sign rules, how it could be abused, and how it is tested.
- A SIP that touches signing is not shipped without an independent review and a test that fails when the rule is removed.
- The discussion record (who said ACK or NACK, and why) is linked from the SIP and is never deleted.

## Open

Who the maintainers are beyond the project owner.
