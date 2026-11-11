# Lightning nodes a host can link to

Working list, 2026-11-11. A host connects its factory to the rest of Lightning through a regular node. Gazpacho needs four operations from it:

1. Pay an invoice with a spending limit and a deadline, and return the payment secret.
2. Create an invoice for a payment hash whose secret the node does not know, and hold the incoming payment open.
3. Settle a held payment.
4. Cancel a held payment.

Every node can do the first. The other three are the deciding factor.

| Node | Share of public nodes | Hold, settle, cancel | How we would connect | Difficulty | Checked? |
|---|---|---|---|---|---|
| **LND** | About 90% | Built in (`AddHoldInvoice`, `SettleInvoice`, `CancelInvoice`) | Its network interface, from outside the node | Low | Yes, against LND's interface definition |
| **Core Lightning** | About 5% | Through the community `hold` plugin, not built in | The plugin's commands, or our own small plugin | Medium: a plugin must be installed in the node | Yes, from secondary sources |
| **Eclair** | Under 1% of public nodes, but heavily used behind mobile wallets | Not confirmed | Probably a plugin written for Eclair | Unknown, likely high | No |
| **LDK-based nodes** | Counted by volume, not node count; mostly private | The library has the calls; whether each packaged node exposes them is not confirmed | Per product | Unknown | No |
| **Anything that speaks Nostr Wallet Connect** | n/a | A Core Lightning plugin implements hold methods over it; whether these are in the general standard is not confirmed | One adapter for every wallet that supports the hold methods | Low if the methods are standard | Partly |
| **Gazpacho's own built-in node** (later) | n/a | Ours to build | No adapter: the built-in node holds ordinary channels itself | High; planned after the first releases | n/a |

The share figures come from a single vendor's comparison and should be checked against a network explorer before being quoted.

## Order

1. **LND** first: by far the most used, and it needs no code inside the node.
2. **Core Lightning** second: already running on our server.
3. **Nostr Wallet Connect** third, if its hold methods prove to be standard, because one adapter could cover many wallets and hosted nodes.
4. **Eclair** and specific **LDK** nodes as demand shows.
5. The **built-in node** removes the need for any of them.

## To verify before building each adapter

- LND: behaviour of a held payment across a node restart, and the longest it may be held.
- Core Lightning: which hold plugin to depend on, its maintenance status, and whether to ship our own.
- Nostr Wallet Connect: whether hold methods are part of the published standard and which wallets implement them.
- Eclair and LDK nodes: whether hold, settle and cancel are reachable at all without modifying the node.
- For all: that holding payments open does not harm the node's standing with its peers at the durations we need.

Sources:
- LND invoices interface: https://github.com/lightningnetwork/lnd/blob/master/lnrpc/invoicesrpc/invoices.proto
- Core Lightning Nostr Wallet Connect plugin (hold methods): https://github.com/daywalker90/cln-nip47
- Implementation shares (vendor comparison): https://www.spark.money/research/lightning-eclair-cln-lnd-implementation-comparison
