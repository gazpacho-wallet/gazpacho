# Public chain servers

Gazpacho reads the chain through public servers unless the user points it at their own. This note records which servers were found to answer, and how they are used. Checked from the project's build server on 2026-11-11.

For now the project runs no Bitcoin node of its own (owner's decision, 2026-11-11). Development and the first vertical slice use the public servers below, on signet.

## Servers that answered

### Electrum protocol, over an encrypted connection

| Network | Server | Software reported | Tip height seen |
|---|---|---|---|
| Signet | `mempool.space:60602` | mempool-electrs, protocol 1.4 | 330437 |
| Testnet4 | `mempool.space:40002` | mempool-electrs, protocol 1.4 | 160702 |
| Testnet3 | `electrum.blockstream.info:60002` | electrs-esplora, protocol 1.4 | 5345037 |
| Mainnet | `electrum.blockstream.info:50002` | electrs-esplora, protocol 1.4 | 975473 |

### HTTP block-explorer interface (Esplora style)

| Network | Base address | Tip height seen |
|---|---|---|
| Signet | `https://mempool.space/signet/api` | 330437 |
| Signet | `https://blockstream.info/signet/api` | 330437 |
| Testnet4 | `https://mempool.space/testnet4/api` | 160702 |
| Testnet3 | `https://blockstream.info/testnet/api` | 5345034 |
| Mutinynet (a separate signet) | `https://mutinynet.com/api` | 3582251 |
| Mainnet | `https://mempool.space/api` | 975473 |
| Mainnet | `https://blockstream.info/api` | 975473 |

### Tried and did not answer

`mempool.space:50002`, `blockstream.info:993`, `signet-electrumx.wakiyamap.dev:50002`, `electrum.emzy.de:50002`. These were guesses at addresses and may simply be wrong; they are listed so they are not tried again without checking.

## What this gives us

- **Signet has two independent operators** on the HTTP interface (mempool.space and Blockstream) and one on the Electrum protocol. Both HTTP servers reported the same tip. That is enough to compare answers, which the design requires on signet.
- **Testnet4** has one operator found so far. A second is needed before answers can be compared there.
- **Mainnet** has two operators on HTTP and one found on Electrum. Mainnet stays switched off in releases regardless.

## How Gazpacho uses them

- The chain port has one interface and several backends. The **HTTP backend comes first**, because two independent signet operators answer on it and it needs only an HTTPS client. The **Electrum backend** follows; it can subscribe to a script and be told when it is spent, which suits watching.
- Every answer that matters is asked of at least two servers run by different operators. A disagreement is reported to the user and treated as "not confirmed".
- A server cannot be made to hand over anything secret: Gazpacho sends it only scripts to watch and transactions to broadcast. It does learn which scripts a user watches, and from which network address.
- These are other people's free services. Gazpacho keeps its request rate low, caches what it can, and backs off on errors. Their terms and limits have not been read yet.
- Anyone can replace the list with their own server or their own Bitcoin node. Hosts should.

## Limits of running without our own node

- **No private test chain.** Regtest scenarios (controlled blocks, deliberate reorganisations, old-state publication on demand) need a node we control. Until one is installed, those behaviours are tested in the simulator's pretend chain only, and on signet at signet's pace of about one block every ten minutes.
- **Signet coins** for the host's funding have to come from a faucet or from the owner.
- **Availability** is not ours to guarantee. One server of our own is planned around launch.

## To do

1. Find a second independent testnet4 operator, and a second signet operator on the Electrum protocol.
2. Read the operators' terms and rate limits.
3. Decide the default list for release, per network.
