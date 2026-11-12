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
| Testnet4 | `https://blockstream.info/testnet4/api` | 160708 (found later, see below) |
| Testnet3 | `https://blockstream.info/testnet/api` | 5345034 |
| Mutinynet (a separate signet) | `https://mutinynet.com/api` | 3582251 |
| Mainnet | `https://mempool.space/api` | 975473 |
| Mainnet | `https://blockstream.info/api` | 975473 |

### Tried and did not answer

`mempool.space:50002`, `blockstream.info:993`, `signet-electrumx.wakiyamap.dev:50002`. These were guesses at addresses and may simply be wrong; they are listed so they are not tried again without checking. `electrum.emzy.de:50002` is that host's mainnet port; on signet it answers on 53002 (below).

### Found later by the chain port's work

Checked from the build server on 2026-11-11 (`docs/notes/chain-port.md` section 11, on branch `chain-esplora`):

- **Testnet4, HTTP:** `https://blockstream.info/testnet4/api` answered with the same tip as mempool.space. That is a second independent operator.
- **Signet, Electrum protocol:** `electrum.emzy.de:53002` (ElectrumX) answered with the same tip as `mempool.space:60602`. That is a second independent operator.
- **Testnet4, Electrum protocol:** several community Fulcrum and ElectrumX servers answered, among them `blackie.c3-soft.com:57010`, `fulcrum.theuplink.net:60002`, `bitcoin.stagemole.eu:5010`, `testnet4.qtornado.com:51012` and `testnet.aranguren.org:52002`. Certificates were not checked.

## What this gives us

- **Signet has two independent operators** on the HTTP interface (mempool.space and Blockstream) and two on the Electrum protocol (mempool.space and emzy.de). Both HTTP servers reported the same tip. That is enough to compare answers, which the design requires on signet.
- **Testnet4** has two independent operators on HTTP (mempool.space and Blockstream) and several on the Electrum protocol, so answers can be compared there too.
- **Mainnet** has two operators on HTTP and one found on Electrum. Mainnet stays switched off in releases regardless.

## How Gazpacho uses them

- The chain port has one interface and several backends. The **HTTP backend comes first**, because two independent signet operators answer on it and it needs only an HTTPS client. The **Electrum backend** follows; it can subscribe to a script and be told when it is spent, which suits watching.
- Every answer that matters is asked of at least two servers run by different operators. A disagreement is reported to the user and treated as "not confirmed".
- A server cannot be made to hand over anything secret: Gazpacho sends it only scripts to watch and transactions to broadcast. It does learn which scripts a user watches, and from which network address.
- These are other people's free services. Gazpacho keeps its request rate low (at least 250 ms between requests to one server) and backs off on errors. It does not cache answers yet. What the operators publish about terms and limits is summarised in `notes/chain-port.md`, section 10; neither publishes a number.
- Anyone can replace the list with their own server or their own Bitcoin node. Hosts should.

## Limits of running without our own node

- **No private test chain.** Regtest scenarios (controlled blocks, deliberate reorganisations, old-state publication on demand) need a node we control. Until one is installed, those behaviours are tested in the simulator's pretend chain only, and on signet at signet's pace of about one block every ten minutes.
- **Signet coins** for the host's funding have to come from a faucet or from the owner.
- **Availability** is not ours to guarantee. One server of our own is planned around launch.

## To do

1. Done: a second independent testnet4 operator and a second signet Electrum operator were found (above).
2. Read the operators' terms and rate limits. Done as far as they are published: `notes/chain-port.md` section 10.
3. Decide the default list for release, per network.
