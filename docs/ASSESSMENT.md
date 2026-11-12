# What exists and what has to be built

Assessment of 2026-11-11. Sizes are lines of C in the SuperScalar repo's `src/` on `main` (116 files, about 76,700 lines). Effort figures are rough guesses made before any Gazpacho code exists; a one-day trial run is planned to firm them up.

**Superseded in part (2026-11-12).** The effort figures below were never measured and are withdrawn: they are not a schedule (`PLAN.md`: quality first, no deadline). Dates will follow from measured work. Two other points have changed since: the program has no member and host modes, since everyone can do both (owner decision 4, `ux/decisions.md`); and the screens are a local web interface served by the C program, not a WebAssembly build (`RECORD.md` section 14). The table is kept as written for the record.

## Starting point

The SuperScalar repo sorts into three piles for Gazpacho's purposes.

| Pile | Roughly | What is in it | What we do with it |
|---|---|---|---|
| **Reuse** | 11,000 lines | Factory tree, MuSig2 signing, timelock counter, ladder, transaction and script builders, adaptor signatures, HD keys, recovery phrases, keyfile, invoice encoding, sweeper, fee bumping | Import as the start of the core. Keep in step with fixes made upstream. |
| **Rebuild** | 35,000 lines | Host and member ceremony code, channel state, payments in the channel, rotation, reconnect, message format, database, watchtower, recovery | The logic is right in outline and proven on signet at 127 members, but it is tied to its own networking and database and has known safety gaps. Rewrite as state machines in the core, using this code as the reference. Expect it to come out smaller. |
| **Leave behind** | 30,000 lines | Gossip, route-finding, onion messages, BOLT 12, LNURL, trampoline, block-filter light client, Bitcoin P2P, JIT channels, splicing, PTLCs, metrics, demo and test scaffolding | Not needed for Gazpacho's first releases. Some of it (BOLT 8 transport, onion handling, channel open and close) is reference material for the self-contained host later. |

From the mothballed Soup wallet we take ideas, not code paths: the host policy record, the member-side check against it, and the host list.

## What has to be built new

| Piece | Why | Language | Size |
|---|---|---|---|
| Core state machines (both roles) | The rebuild pile above, as a library with no networking, storage or chain access of its own | C | Large: 5–8 weeks |
| One channel-update routine | Every channel change goes through one save, sign, revoke sequence | C | Inside the line above; the hardest part |
| Storage interface + SQLite backend | The core says what to save; the shell saves it | C | 1 week |
| Chain interface + three backends | Electrum protocol, HTTP block-explorer, Bitcoin node RPC | C | 2 weeks |
| Asking several servers and comparing | A hidden transaction can cost funds | C | A few days |
| Live watching | Subscribe to every factory and channel output; respond to old states | C | 1–2 weeks, partly reuse |
| Transport: TCP and WebSocket, encrypted | Browsers can only use WebSocket | C | 1–2 weeks |
| Host terms and member-side check | Refuse to sign outside the user's limits | C | 1 week |
| On-chain wallet | Receive, send, fee bumping for exits | C | 1–2 weeks, partly reuse |
| Swap-in | Bring on-chain bitcoin into a factory channel | C | 1–2 weeks |
| Command-line program | One binary, member and host modes | C | 1 week |
| Host service mode | Always on; many members; adapter to a regular Lightning node | C | 2 weeks, partly reuse |
| Browser build of the core | Compile the C core to WebAssembly | C + build scripts | 1 week |
| Web screens | The first graphical shell | HTML, CSS, JavaScript | 2–3 weeks |
| Encrypted off-device backup | Channel state cannot be rebuilt from a recovery phrase | C | 1 week |
| Shared format note | One message format for the repo and Gazpacho | Document | A few days, then discussion |
| Tests | Unit, regtest end-to-end, signet and testnet runs, fix-removed checks | C, shell, Python | Continuous; about a third of all effort |
| Self-contained host | Built-in node holds ordinary Lightning channels | C | Large and open; after the first releases |

## Keeping it in C

| Layer | C? | Notes |
|---|---|---|
| Core library | Yes | Portable C, no operating-system calls |
| Storage, chain, transport backends | Yes | |
| Command-line program and host service | Yes | |
| Browser build | Yes | The same C, compiled to WebAssembly |
| Web screens | No | A browser's interface has to be HTML and JavaScript. Kept thin: it calls the C core and draws what the core reports. |
| Tests | Mostly | C for unit tests; shell and Python to drive multi-process runs |
| Infrastructure | Mixed | We run existing servers; we do not write them |

Third-party code the core would rest on: libsecp256k1-zkp (signatures), SQLite (storage outside the browser), a small JSON library, and a TLS library for encrypted connections to chain servers. Each is C.

## Shape of the repository

```
core/      the library: tree, signing, ceremonies, channel, wallet, terms
ports/     storage, chain and transport backends
cli/       the gazpacho program (member and host modes)
web/       WebAssembly build and web screens
spec/      message format and terms record
tests/     unit, regtest, signet, testnet
infra/     how our public services are deployed
docs/      plan, assessment, user guides
```

## Infrastructure we run

| Service | Purpose | Build or run |
|---|---|---|
| Signet host | The default factory host in the first release | Run Gazpacho itself |
| Regular Lightning node behind it | The host's link to the rest of Lightning, until the host is self-contained | Run an existing node |
| Bitcoin node | For the host and for our chain server | Run |
| Electrum server and HTTP explorer | A dependable default chain view | Run existing software |
| Faucet | Signet coins and a first Lightning payment for new users | Small; build |
| Host list | Finding hosts, second release | Exists (Nostr-based); run |
| Download and web hosting | Releases and the web version | Run |
| Continuous integration | Every change is built and tested | Configure |

## Rough totals

| Milestone | What a user can do | Estimate |
|---|---|---|
| Command-line release on signet | Install, join our factory, receive, pay, swap in, force-exit | 8–12 weeks |
| Web release on signet | The same from a browser | + 3–4 weeks |
| Hosting release | Anyone can host with their own Lightning node; host list | + 3–4 weeks |
| Self-contained host | Host with Gazpacho alone | Open |
| Real funds | After design fixes, the audit and a capped beta | Open |

The first figure is longer than the earlier 4–7 week estimate because that one assumed reusing the repo's ceremony and channel code as it stands. Rebuilding those layers properly is the larger job, and it is the work that would otherwise be waiting before mainnet.

## Biggest unknowns

1. How cleanly the ceremony logic separates from the repo's networking and database. The trial run answers this.
2. Whether the browser can hold channel state safely enough for anything beyond signet.
3. How much of the repo's fix work lands in time for us to import it rather than redo it.
4. The shared message format: agreeing it early saves rework on both sides.
