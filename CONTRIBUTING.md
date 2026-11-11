# Contributing

Gazpacho is at the design and early-code stage. The most useful contributions right now are review and criticism of the design.

## Where to start

Read `docs/KNOWLEDGE-BASE.md`. It maps the documents, defines the terms, lists the decisions in force, and says how sure we are of each claim.

## Ways to help

- **Review the design.** Open an issue saying what is wrong or missing in `docs/DESIGN.md`, `docs/LOBBY.md` or the specifications as they appear.
- **Propose a rule or feature.** Use the process in `docs/proposals/`.
- **Report a security problem** privately. See `SECURITY.md`.

## Code

- C11, no compiler warnings, and every change builds and passes under the memory-error checkers used in CI.
- Files under `core/superscalar/` are imported unchanged from SuperScalar. Do not edit them here; propose the change upstream.
- The core never touches the network, storage, the clock or randomness directly. Those are handed to it.
- Every safety rule comes with a test, and a run with the rule removed that must fail.
- Changes go through pull requests.

## Conduct

Be direct about problems and respectful of people.
