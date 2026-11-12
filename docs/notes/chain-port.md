# The chain port

How Gazpacho reads the chain through public chain servers. Written 2026-11-11 with the first version of the code in `ports/chain/`, revised 2026-11-12 after an independent review (pull request 7). "Verified" means checked from the project's build server against the live servers on those dates.

## 1. What it is

The chain view is a port: it sits outside the core. The core never calls it. The program around the core turns the core's "watch this script" and "broadcast this transaction" actions into calls on this port and feeds the results back as events.

There is one interface, `gz_chain` (`ports/chain/include/gazpacho/chain.h`), and two things that implement it:

- **The Esplora backend** (`esplora.c`) talks to one chain server over HTTPS.
- **The comparing backend** (`multi.c`) wraps two or more backends, checks that each is on the right network, asks all of them every question, and answers only when servers of at least two different operators say the same thing.

A program builds one Esplora backend per server and one comparing backend over them, and uses the comparing backend for everything. For a confirmation it calls `gz_chain_confirm_tx`, which checks the servers' claim against block headers and Merkle proofs.

All network traffic, the clock and sleeping go through a small transport interface, `gz_http` (`chain_http.h`). The real one uses libcurl (`http_curl.c`, POSIX only). The tests use a fake one, so the default test run never touches the network. The library keeps no global state of its own (libcurl keeps a process-wide reference count).

## 2. The interface in plain words

| Call | Question | Answer |
|---|---|---|
| `gz_chain_tip_get` | What is the best block? | Height and block hash |
| `gz_chain_block_hash` | Which block is at this height? | Block hash, or "not found" |
| `gz_chain_block_header` | Give me the header at this height | 80 bytes, already checked to hash to the block hash the server gave for that height |
| `gz_chain_block_summary` | How many transactions are in this block, and which is first? | Block hash, transaction count, coinbase txid (claims; `gz_chain_confirm_tx` checks them) |
| `gz_chain_tx_status` | Do you know this transaction? | Unknown, in the mempool, or confirmed at height H in block B. The confirmation count here is the server's **claim** (`claimed_confirmations`) |
| `gz_chain_script_outputs` | What unspent outputs pay this script? | A sorted list of (txid, output index, amount, confirmed height or mempool) |
| `gz_chain_outspend` | Is this output spent? | Not spent, or spent by input I of transaction T, confirmed in block B or still in the mempool |
| `gz_chain_raw_tx` | Give me this transaction | The bytes, already checked to hash to the txid asked for |
| `gz_chain_merkle_proof` | The branch for this transaction | Block height, position, and the hashes |
| `gz_chain_broadcast` | Send this transaction | The txid, or a refusal with the server's own reason text |
| `gz_chain_fee_estimates` | What fee rate for N blocks? | A table of opinions, never a fact |
| `gz_chain_check_network` | Is this server on the network I mean? | By its block 0 |
| `gz_chain_confirm_tx` | Is this transaction really confirmed, how deep? | A checked result: see section 6 |
| `gz_chain_choose_fee_rate` | Which fee rate should I use? | The policy in section 7 |

Helpers that need no server: `gz_header_hash`, `gz_header_links`, `gz_header_check_pow`, `gz_merkle_verify`, `gz_merkle_depth_for_count`, `gz_txid_from_raw`, `gz_tx_is_coinbase`, `gz_network_genesis`, `gz_operator_from_host`.

### Result codes

| Code | Meaning |
|---|---|
| `GZ_CHAIN_OK` | An answer |
| `GZ_CHAIN_NOT_FOUND` | The server (or every server) says it does not have this. A "no", not a failure |
| `GZ_CHAIN_REJECTED` | The server refused the request (a broadcast it will not accept; any other 4xx) |
| `GZ_CHAIN_UNREACHABLE` | Could not reach the server: no connection, timeout, or 429/5xx after the retries |
| `GZ_CHAIN_MALFORMED` | The server answered, but not in exactly the expected form, or contradicted itself |
| `GZ_CHAIN_TOO_LARGE` | The answer was bigger than the cap or the caller's buffer |
| `GZ_CHAIN_BAD_PROOF` | Well formed but failed a check against data it must match |
| `GZ_CHAIN_WRONG_NETWORK` | The server's block 0 is not the genesis block of the network asked for |
| `GZ_CHAIN_DISAGREE` | Comparing backend: servers contradict each other about confirmed data. Not confirmed |
| `GZ_CHAIN_LAG` | Comparing backend: the difference is what one server being a block behind looks like. Ask again shortly; if it persists, treat as disagreement |
| `GZ_CHAIN_NO_QUORUM` | Comparing backend: fewer than two operators gave a usable answer. Not confirmed |
| `GZ_CHAIN_INVALID_ARG`, `GZ_CHAIN_NO_MEMORY` | Caller error; out of memory |

The network type has no meaningful zero: `GZ_NET_INVALID` is 0, so a zeroed setting never means mainnet.

### Ownership and lifetimes

The caller owns every output. Nothing returned points into a backend, with one stated exception: the per-server output lists in the comparing backend's report, valid until its next call. A backend lives until `gz_chain_destroy`. The comparing backend borrows the backends it wraps and does not destroy them. One instance is for one thread at a time. Every call blocks, bounded by time limits and retry limits. Hashes are held in the byte order used inside transactions and headers; `gz_hash_to_hex` / `gz_hash_from_hex` convert to and from the reversed hex people read.

## 3. The Esplora endpoints used

Base address examples: `https://mempool.space/signet/api`, `https://blockstream.info/signet/api`. All twelve were verified against both servers; both returned byte-identical bodies for every request below except fee estimates and broadcast refusal text. The recorded bodies are in `ports/chain/tests/data/` (sources in its README).

| Used for | Request | Example answer (signet) |
|---|---|---|
| Tip height | `GET /blocks/tip/height` | `330438` (plain text) |
| Block hash at a height; tip hash; block 0 for the network check | `GET /block-height/329438` | `0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4` |
| Header | `GET /block/0000000e27…1cf4/header` | 160 hex characters |
| Block summary | `GET /block/0000000e27…1cf4` | `{"id":"0000000e27…","height":329438,"version":536870912,"timestamp":1793823982,"tx_count":243,…}` (13 fields) |
| First transaction of a block | `GET /block/0000000e27…1cf4/txid/0` | `f5b99c0f9b9150d7b980e249419425152f849b0d3e3bf0c1052c534688a18f54` |
| Transaction status | `GET /tx/8690387a…6c9a/status` | `{"confirmed":true,"block_height":329438,"block_hash":"0000000e27…1cf4","block_time":1793823982}` |
| Raw transaction; also tells "in mempool" from "unknown" | `GET /tx/8690387a…6c9a/hex` | 488 hex characters |
| Merkle proof | `GET /tx/8690387a…6c9a/merkle-proof` | `{"block_height":329438,"merkle":["f5b99c0f…8f54", … 8 hashes],"pos":1}` |
| Is an output spent | `GET /tx/8690387a…6c9a/outspend/0` | `{"spent":true,"txid":"ee18add1…944b","vin":0,"status":{…}}` |
| Unspent outputs of a script | `GET /scripthash/c7ecf668…7cd0/utxo` | `[{"txid":"8690387a…6c9a","vout":2,"status":{…},"value":43000}]` |
| Fee estimates | `GET /fee-estimates` | `{"1":1,"2":1,"3":0.5,…,"1008":0.1}` |
| Broadcast | `POST /tx`, body the transaction in hex | The txid as plain text; or HTTP 400 with a reason |

Found by checking rather than assuming:

- **Script lookup key.** SHA-256 of the scriptPubKey as the hash function produces it, **not reversed**. The reversed key (the Electrum protocol's convention) returns `[]` with no error, so the mistake looks like "no coins".
- **Unknown and mempool look the same in `/status`.** Both servers answer `{"confirmed":false}` for a txid they have never seen. The backend also asks `/tx/{txid}/hex`: 404 means unknown; bytes that hash to the txid mean mempool.
- **An output that does not exist looks unspent** (`{"spent":false}`). Ask only about outputs known to exist.
- **Fee estimates differ a lot.** mempool.space answers HTTP 203, blockstream.info 200. In the same minute on signet they gave 1 and 10 sat/vB for the next block.
- **Refusal text differs** between operators for the same refusal. Kept as sent (printable ASCII, at most 255 characters).
- **`/block/{hash}/txid/{n}`** answers `tx index out of range` (404) past the end.
- **Block 0** of each network, as served: signet `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`, testnet4 `00000000da84f2ba…f043`, testnet3 `000000000933ea01…4943`, mainnet `000000000019d668…e26f`. These are the constants in `gz_network_genesis`.
- **The tip is read as a pair**: height, then the hash at that height, so the pair is consistent even if a block arrives between the requests.

Not used: `/scripthash/{key}/txs` (history). `gz_chain_script_outputs` lists unspent outputs; to follow an output already seen, ask `gz_chain_outspend`.

## 4. What a server's answer must pass

Everything a server returns is treated as hostile.

- **Time.** Every request has a time limit (15 s by default); a backend cannot be created without one. The transport also sets libcurl's connection limit to the same value.
- **Size.** Each backend has one response buffer, allocated once (512 KiB by default). Each call has its own much smaller cap: 10 bytes for a height, 64 for a hash, 160 for a header, 256 for a status, 1 KiB for a block summary. The transport stops reading as soon as the cap is passed. Compressed responses are not requested, so a small body cannot expand. Nothing is allocated in proportion to what a server sends.
- **Form.** Text answers must be exactly the expected characters (lowercase hex of the exact length; digits with no sign, space or newline). A broadcast's txid answer may have white space around it, which is trimmed. JSON goes through a small strict tokenizer (`json.c`, under 300 lines, no allocation, no floating point): one value, no duplicate keys, printable ASCII only, bounded depth and size. Each object must have exactly the expected fields with exactly the expected types. Numbers are converted exactly and range-checked: heights below 2^31, amounts at most 21 million bitcoin, a block's transaction count 1 to 1,000,000, fee rates at most 5000 sat/vB. Counts come from what is present, never from a number the server states.
- **Consistency.** A header must hash to the block hash the server gave for that height. A block summary must name the block and height asked for. A raw transaction must parse completely and hash to the txid asked for. A broadcast answer must be the txid of what was sent. A confirmation cannot be above the server's own tip.
- **Transactions.** `gz_txid_from_raw` requires at least one input and one output, canonical length encodings, every length within the buffer, and no bytes left over. It refuses a transaction whose serialization without witness is exactly 64 bytes, because 64 bytes are also two Merkle nodes (see section 6).
- **Retries.** At most 3 tries, waiting 0.5 s then 1 s (never more than 30 s), only when the server could not be reached or answered 429 or 5xx. A definite answer is never retried. A broadcast is not repeated after a timeout or a 5xx, because the server may already have acted.
- **Request rate.** At least 250 ms between requests to one server.
- **Addresses.** `https://` only. Plain `http://` is accepted for exactly three hosts, this machine under its usual names: `localhost`, `127.0.0.1`, `[::1]`. The backend refuses anything else at creation and the transport refuses it again before sending. Certificates and host names are always verified; a different certificate authority file can be given for a user's own server. Redirects are not followed.

Why our own JSON tokenizer and not cJSON: the answers are small flat objects, and the strictness wanted (duplicate keys refused, no trailing bytes, exact integers, a bound on everything) is most of the work. cJSON would have added about 3000 lines, converts numbers through floating point, accepts duplicate keys, and allocates per node in proportion to the input.

## 5. Agreement rules of the comparing backend

### Who counts

- **Right network.** Before a server's answer counts, its block 0 must be the genesis block of the configured network. This is checked on first use and remembered. A server on another chain answers `GZ_CHAIN_WRONG_NETWORK` to every call and is never sent a broadcast. If the check could not be made (server down), it is tried again on the next call.
- **No duplicates.** Creation refuses two handles to one backend, two backends with the same normalised address (scheme and host lower-cased, default port dropped), and two backends on the same host, whatever operator name they are given.
- **Operators, not servers.** The quorum (default and minimum 2) counts distinct operators. A backend's operator is the name given in its configuration, or else the last two labels of its host name (`api.mempool.space` → `mempool.space`; an IP address counts as itself). Two hosts of one operator are one voice. This rule of thumb cannot know that two unrelated-looking names belong to one company: the server list must be chosen with that in mind.

### Verdicts

A server's reply is **usable** if it is an answer or a clear "not found". Anything else (unreachable, malformed, too large, wrong network) counts as no reply.

1. Usable replies from fewer than two operators: **no quorum**; or, if every server failed in the same way, that failure (all unreachable, all on the wrong network).
2. Usable replies that contradict each other about **confirmed** data: **servers disagree**, even when a majority agrees. There is no vote.
3. A contradiction of the kind one server being a block behind produces: **lag**. "That kind" means one server has a block, a confirmation or a confirmed spend that another does not, and their tips differ by at most `tip_slack` (default 1) and lie on one chain (the higher server has the lower server's tip at that height). Any other pattern is disagreement.
4. Differences only about **unconfirmed** data never block the answer: the confirmed, agreed part is returned and a flag (`unconfirmed_differs`) says the rest differs. Anyone can put a transaction in one server's mempool; it must not be able to blank a user's view.
5. Otherwise the common answer.

Every server's own reply to the last call can be read with `gz_multi_last_report`. Nothing is written to the caller's output unless the verdict is an answer.

### Per call

| Call | Rule |
|---|---|
| Tip | Heights may differ by at most `tip_slack`. The answer is the **lowest** tip, and every higher server must have the same block at that height. Same height with different hashes disagrees |
| Block hash, header, summary, Merkle proof | Every field identical. Present on one, absent on another: lag or disagreement as above |
| Transaction status | All confirmed: same height **and** same block hash; the claimed count returned is the lowest. None confirmed: an answer — "mempool" if all have it there, else "unknown", flagged if some have it. Some confirmed and some not: lag or disagreement |
| Outspend | A confirmed spend must be identical on every server (spender, input, height, block). No confirmed spend: an answer — the unconfirmed spend if all report the same one, else "not spent", flagged if any reports one. A confirmed spend on some servers only: lag or disagreement |
| Outputs of a script | The confirmed outputs identical everywhere, else lag or disagreement. The answer: those, plus the unconfirmed outputs every server lists identically; flagged if any were left out |
| Raw transaction | Every byte identical; each server's bytes are first rechecked to hash to the txid (the txid does not cover witness data) |
| Broadcast | Sent to every server on the right network. Success if any accepts and returns the right txid, or says it already has it and then shows it. Each server's result is kept. Accepted is not relayed: follow up with the status |
| Fee estimates | Never an agreed fact; see section 7 |

Consequences:

- Lag and unconfirmed differences are normal for a few seconds around a new block or transaction. Callers should treat lag as "not yet, ask again", and persistent lag as disagreement, because a dishonest server can pretend to be behind.
- A server that is permanently behind, broken or dishonest makes a two-operator setup permanently unable to confirm. That is the safe direction, and the reason three operators are better than two.

## 6. Confirmations: what is checked and what is trusted

`gz_chain_confirm_tx(chain, network, txid, want, out)` takes a server's (or the comparing backend's) "confirmed" claim and checks, in order:

1. the server's block 0 is the genesis block of `network`;
2. the transaction itself is fetched and its txid recomputed, so the id is that of a real transaction, and not of a 64-byte one;
3. the header at the stated height hashes to the stated block hash and meets its own proof-of-work target for `network`;
4. the Merkle branch is for that height, has exactly the depth implied by the block's transaction count, places the transaction below that count, and leads from the txid to the header's Merkle root; the fold refuses a step where our node sits on the right with an identical node on its left (the copy Bitcoin makes of an odd row's last node, which no transaction occupies);
5. the block's first transaction is fetched, must be a coinbase, and its own branch from position 0 must have the same depth and reach the same root — the server cannot choose a depth that does not fit a real tree;
6. up to `want - 1` later headers (at most 144) are fetched; each must link to the one before and meet its proof-of-work target.

The result carries `checked_confirmations`: 1 for the block plus one per linked header, never more than asked for, fewer if the chain is not that long yet. `status.claimed_confirmations`, the server's own count from the tip it claims, is passed along only as a claim: a server claiming a tip a million blocks up changes the claim and not the checked number. On any failure the output is cleared; nothing half-checked is returned as if confirmed.

What a passing result is worth, per network:

| Network | Established | Not established |
|---|---|---|
| Mainnet | The block and each header above it cost the work they claim, in a linked chain; the transaction is in the block at a position that fits its tree | That the claimed difficulty is the one the network required (no retargeting rules, no link back to a known block, no total-work comparison). An attacker with enough hash power at a lower, self-chosen difficulty, or a set of colluding servers presenting a private chain, is not ruled out by this check alone |
| Testnet3, testnet4 | The same | The same; and these networks allow minimum-difficulty blocks, which are cheap, so the work proves little |
| Signet | Only that the servers are consistent with themselves and with each other | Everything that makes a signet block real: the block signature is not checked (by decision). A set of colluding servers can fabricate every piece |

So on signet, and largely on the testnets, what stands between a user and an invented confirmation is that the servers are run by different operators and are compared.

What else is trusted rather than checked:

- **Absence.** No proof shows a transaction or a spend does not exist. A server can hide one; only another, honest server reveals it.
- **Unconfirmed data**, entirely.
- **Who runs a server.** The operator rule is a guess from host names (section 5).
- **Block 0.** A server can lie about it; that only gets it counted on a network whose later checks it must then pass.
- **Spenders.** `gz_chain_outspend` returns a spender's txid from the server. Before relying on a spend, fetch that transaction with `gz_chain_raw_tx` (which recomputes the txid) and check its input; the watch engine will do this.

## 7. Fees

Fee estimates are opinions. Nothing can check them, and the comparing backend never reports them as agreed facts.

- **Test networks.** `gz_chain_choose_fee_rate` returns a fixed 0.1 sat/vB (100 sat/kvB) on signet, testnet3 and testnet4 and asks no server. Estimates there are advisory only. (Owner's preference: 0.1 sat/vB on test networks.)
- **Mainnet.** The comparing backend's combined estimate, for each target every answering operator lists, is the **lowest** rate given, cut at the configured ceiling (default 200 sat/vB). If for any such target the highest rate is more than 3 times the lowest plus 1 sat/vB, the call returns `GZ_CHAIN_DISAGREE` instead. `gz_chain_choose_fee_rate` then picks the entry for the target, raises it to a floor of 0.1 sat/vB, and cuts it at a ceiling the **caller must supply**.
- **Single server.** Its parser refuses any rate above 5000 sat/vB as malformed.

Consequences: no single server can raise what the user pays. A single server can lower it, by at most the spread the disagreement rule allows (to about a third of the others' rate, less 1 sat/vB), and not below the floor. A transaction that pays too little is slow, not lost, and can be bumped; one that pays too much loses money for good. That is why the lowest is taken.

The live servers' signet answers (1 and 10 sat/vB for the next block) count as a disagreement under this rule. That is expected: on signet the estimates are not used.

## 8. What a dishonest server can and cannot do

Assume one of the configured servers is dishonest and at least one other, of another operator, is honest and reachable.

**Cannot:**

- Make the wallet accept an **invented confirmation**. The honest server contradicts it, so the comparing backend returns disagreement. Separately, `gz_chain_confirm_tx` requires the transaction, a header chain and a Merkle branch of the right shape; a transaction not in the block has no valid branch. Both are tested, including the case where every server tells the same lie and only the proof catches it.
- Inflate the **confirmation count**: it is counted along linked headers.
- **Hide a confirmed spend** of a watched output unnoticed: the result is disagreement (or, briefly, lag), with the honest answer in the report.
- **Hide or invent a confirmed deposit**: confirmed outputs must match exactly.
- **Blank the view by spamming the mempool**: unconfirmed differences are flagged, not fatal.
- Substitute a **different transaction** for a txid, or alter its witness unnoticed.
- Put the wallet on a **different chain** quietly: block 0, block hashes, headers and tips are checked or compared. A server on another network is excluded and never sent a broadcast.
- Pass itself off as **two servers**: duplicates are refused and the quorum counts operators.
- **Set the fee rate** upwards.
- Learn or take any **secret**.
- Exhaust memory or hang the program: sizes and times are capped.

**Can:**

- **Deny service.** One dishonest or broken operator out of two stops confirmations. With three, a server that is down or malformed is ignored, but one that sends well-formed contradictions still blocks. The user is told; nothing false is accepted. For a member with a deadline this matters: persistent disagreement must be shown early, and the user must be able to change servers.
- **Pretend to lag**, which delays answers the same way.
- **Lower the fee rate** a little (section 7).
- **Accept a broadcast and not relay it.** It also goes to the others.
- **Learn things** (section 9).

**If all configured servers collude, or are secretly one operator:** on signet they can invent anything, including whole blocks; on the proof-of-work networks they need work at a difficulty this code does not check against the network's rules; on any network they can hide transactions completely. This is why the list must hold servers of different operators, and why hosts should use their own node.

## 9. Privacy: what each server learns

Every configured server is asked every question. So each one learns:

- the user's **network address** (and so rough location), unless the user goes through Tor or a proxy, which is not built;
- **every script the user watches**, as its SHA-256 (which identifies the script as well as the script itself does: anyone can hash the scripts they see on chain and match);
- **every transaction the user looks up or broadcasts**, and when;
- the **User-Agent** `gazpacho-chain/0.0.1` on every request, which says the software is Gazpacho (and so, for a script it watches, that it is probably a factory output) and nothing about the user or machine. No other identifying header is sent.

**Comparing multiplies who knows.** With two servers, two operators learn the user's watched scripts and address, not one; with three, three. Asking different servers about different scripts would defeat the comparison. This is the price of not trusting one server; the alternatives are the user's own server or node, or Tor.

## 10. Operators' terms and limits

Read on 2026-11-11.

**mempool.space**

- The REST API documentation says they enforce rate limits, that exceeding them gets HTTP 429, that repeated excess may lead to a ban, and suggests an "enterprise sponsorship" for higher limits. <https://mempool.space/docs/api/rest>
- No numbers are published. A maintainer wrote that the limits are deliberately not disclosed, and advised running one's own node for payment monitoring. <https://github.com/mempool/mempool/discussions/752>
- The project's README recommends running one's own instance. <https://github.com/mempool/mempool>
- Paid offer: <https://mempool.space/enterprise>.
- Not found: any number, any Retry-After rule, any required client identification. The terms page <https://mempool.space/terms-of-service> could not be read by our tools (it is built by script in the browser): its clauses are **unread, not absent**.

**blockstream.info**

- The API description lists the public base addresses, including signet and testnet4, and says nothing about limits or terms. <https://github.com/Blockstream/esplora/blob/master/API.md>
- Blockstream's blog, 22 April 2026: rate limits are being introduced on free access to the REST API and Electrum RPC, free use is meant for individual use, prototyping and development, and production use is pointed to paid tiers. No numbers. <https://blog.blockstream.com/enhanced-analytics-and-infrastructure-improvements-for-the-blockstream-explorer-api/>
- Earlier posts describe the paid "Blockstream Explorer API" (11 February 2025 and 23 December 2025; they differ on whether 500,000 requests a month is free or the cheapest paid tier). <https://blog.blockstream.com/introducing-the-new-blockstream-explorer-api-faster-easier-and-more-transparent/>, <https://blog.blockstream.com/raising-the-bar-for-bitcoin-application-performance-with-the-blockstream-explorer-api/>
- The general terms <https://blockstream.com/terms/> have no clause on API use that we could find.
- Not found: an official number for the public endpoint without a key, or whether "free tier" means that endpoint.

**For Gazpacho.** Both allow light use without a key, and both say production software should not lean on the free service. Development, the slices, and individual users at a few requests a minute fit what is published. A released wallet whose every user polls these two by default does not obviously fit. The defaults here (at most 4 requests a second to a server, usually far fewer; backing off on 429) are a guess at "polite", not a figure from the operators. For the owner to decide before release.

## 11. Other servers found

Tested from the build server on 2026-11-11. "Answered" means it returned the right genesis block for the network and the same tip as mempool.space at that moment. Operators are judged from host names only. Nothing was signed up for and no key was used.

- **Testnet4, HTTP interface: a second operator found.** `https://blockstream.info/testnet4/api` answered (tip 160708, same block hash as `https://mempool.space/testnet4/api`). It is listed in Blockstream's API description. No third-party testnet4 HTTP server was found.
- **Testnet3, HTTP:** `https://mempool.space/testnet/api` also answered, same height as Blockstream's.
- **Testnet4, Electrum protocol** (TLS; certificates not checked in this probe), all with the testnet4 genesis block at height 160708: `blackie.c3-soft.com:57010` (Fulcrum 2.1.4), `fulcrum.theuplink.net:60002` (Fulcrum 2.1.4), `v22019051929289916.bestsrv.de:60002` (Fulcrum 2.1.4), `bitcoin.stagemole.eu:5010` (ElectrumX 1.19.0), `testnet4.qtornado.com:51012` (ElectrumX 2.0.0), `testnet.aranguren.org:52002` (Fulcrum 2.1.2), and two more servers known only by a numeric address (ElectrumX 1.19.0 and Fulcrum 1.11.1; not named here, as this repository names no machine by address). Sources: the Electrum wallet's list (<https://github.com/spesmilo/electrum>, `electrum/chains/testnet4/servers.json`) and <https://1209k.com/bitcoin-eye/ele.php?chain=tbtc4>.
- **Signet, Electrum protocol: a second operator found.** `electrum.emzy.de:53002` answered (ElectrumX 1.20.1, signet genesis block, height 330442, same as `mempool.space:60602`). `docs/CHAIN-SERVERS.md` had listed this host on port 50002, its mainnet port. `signet-electrumx.wakiyamap.dev:50002` timed out in the TLS handshake.
- **Signet, HTTP: no third operator found.** `https://explorer.bc-2.jp/api/…` answered 404; `https://exsignet.bublina.eu.org/api/…` answered a browser challenge page.
- **Did not answer:** `frigate.theuplink.net:60012` (refused the request), `electrum.blockstream.info:40002` and `:60602`, `blockstream.info:993`.

## 12. Decisions made where the documents were silent

The design documents settle that answers are compared across operators and that a disagreement means "not confirmed". These finer points were not settled anywhere and were decided here; each can be changed.

1. **No majority vote.** With three servers, one well-formed contradiction blocks an answer. Two colluding servers cannot outvote an honest one silently; the cost is that one bad server can block.
2. **Lag is its own result**, and is recognised only from the servers' tips (at most one block apart, same chain). A server can fake it.
3. **Unconfirmed differences never block**; they are flagged, and only unconfirmed data every server reports is returned.
4. **The lowest tip** is the agreed tip.
5. **Operators** are named in configuration or taken from the last two labels of the host name; one host can never be two servers.
6. **Network identity** is block 0, checked once per server and remembered.
7. **Fees**: fixed 0.1 sat/vB on test networks; on mainnet the lowest estimate, a factor-of-3-plus-1-sat/vB disagreement rule, a caller-supplied ceiling, a 0.1 sat/vB floor, and a 5000 sat/vB limit on any single answer.
8. **Confirmation depth**: at most 144 headers are followed per check.
9. **"Already known"** on broadcast is success only if the server then shows the transaction in its mempool or confirmed.
10. **64-byte transactions** are refused outright, as no wallet makes them.
11. **Plain http** only for this machine's loopback names, for a user's own server.
12. **Warnings as errors** is a build option (`GZ_WERROR`), on in CI, so a newer compiler's new warning does not stop someone building.
13. **Our own JSON tokenizer** instead of cJSON (section 4).

## 13. Testing

How to run: `ctest` runs everything except the live test; `ctest -LE slow` skips the local-server test; `cmake -DGZ_LIVE_TESTS=ON` and `ctest -R chain_live` runs the live test. `python3 -I ports/chain/tests/break_checks.py BUILD_DIR` runs the break-checks.

| Test | What it covers |
|---|---|
| `chain_json` | The tokenizer: valid and invalid JSON, duplicate keys, depth and size limits, exact numbers |
| `chain_headers` | Header parsing, hashing, links, proof of work on mainnet, testnet4 and signet headers, targets, txid computation, refused transaction shapes (no inputs, no outputs, 64 bytes, wrapping lengths), Merkle proofs on real signet data including tampered proofs, wrong blocks, the duplicated-node position, depth for a count, network identity, operator names |
| `chain_esplora` | Every call against the fake transport with recorded answers; every malformed-answer case listed in the file; time limits, retries, backoff cap, rate limit, size caps; addresses; network check; fee policy; broadcast trimming and "already known"; checked confirmations, including invented confirmations, lies about the tree's shape and the coinbase, and invented tips |
| `chain_multi` | The comparing backend over two and three servers: agreement, every kind of contradiction, lag, unconfirmed differences, duplicate servers, one operator under two names, a server on the wrong network, servers down, lying servers, broadcast, fees |
| `chain_model` | 20,000 random situations (one to four servers, one to three operators, up or down, right network or not, three tip heights, two chains, independent claims about a transaction, a spend, a block and a fee). Expected verdicts come from functions written from the rules in this document, which share no code with `multi.c`. `GZ_MODEL_SEED`, `GZ_MODEL_ROUNDS` replay or lengthen |
| `chain_fuzz` | Seeded mutation of 13 recorded answers fed to every parser, under the sanitizer build. A real fuzzer (libFuzzer or AFL++) should be attached to `gz_json_parse`, the eight `gz_es_parse_*` functions and `gz_txid_from_raw`, with `tests/data/` as corpus |
| `chain_local_servers` (label `slow`) | The real libcurl transport against servers on 127.0.0.1: a hostile HTTP server (oversized, endless, compressed, slow, dripping, redirecting, huge headers) and three HTTPS servers with a good certificate, one for another name, and a self-signed one; then `gz-chain` end to end against small Esplora look-alikes (agreement, hiding, one operator, duplicates, a mainnet server, broadcast refusals, fee). Needs python3 and openssl; skipped without them |
| `chain_tool_*` | The tool's mainnet refusal and usage text |
| `chain_live` (opt-in) | The two public signet servers: tip, a known transaction, a checked confirmation 6 deep, a spend, a script, raw bytes, fees, network |

Counts at the time of writing: see the final section.

### Not tested

- The Electrum protocol: no backend exists yet.
- Real proof-of-work attacks: no mainnet or testnet chain of our own; the proof-of-work checks are tested on recorded real headers and on altered copies.
- A long-running program using the port, reorganisations of more than one block, and the behaviour of the program around the core when disagreement persists: none exists yet.
- Concurrency: the port is single-threaded by design; nothing tests use from several threads.
- The transport on anything but Linux.
- That `curl_easy_setopt` failures are handled: they cannot be provoked in a test (they occur only on out-of-memory or an old libcurl).
- Some checks are kept as defence in depth although another check already catches every case the tests can build: the per-call raw-transaction size check in `esplora.c` (the transport cap catches it first), the "position below the transaction count" check and the coinbase-is-a-coinbase check in `verify.c` (the duplicated-node rule and the Merkle fold catch the cases), the address-equality check in `multi.c` (the same-host check catches it first), the comparing backend's own fee limit (the parser's limit catches it first), the cap on confirmation depth, and the proof-of-work check on later headers (all real signet headers pass it). Removing any of these makes no test fail; that is listed honestly in the break-check results.

## 14. Open questions

1. **Terms.** May a released wallet point every user at mempool.space and blockstream.info by default? Owner's decision; see section 10.
2. **Unanimity or majority** with three operators (section 12, item 1).
3. **Proving a spend.** When servers disagree about a spend, fetch the claimed spender and check that it really spends the output (and its signature). Then a hidden spend becomes a proven one. Belongs with the watch engine.
4. **Header chains on proof-of-work networks.** Only each header's own target is checked. Mainnet use needs difficulty rules or pinned known blocks.
5. **Unknown fields.** A server adding a field to an answer makes it malformed here. Deliberately strict; it could take a server out after an upgrade on their side.
6. **Persistent lag and disagreement**: how long the program waits before telling the user. Not decided.
7. **Privacy** (section 9): Tor, or the user's own server. Neither built.
8. **Blocking calls.** Servers are asked one after another; a slow one delays the others by up to its time limit times its retries. The program around the core needs the calls off its main loop.
9. **Default lists.** `gz-chain` uses `docs/CHAIN-SERVERS.md`. Testnet4 now has two HTTP operators (section 11); the list and the line in `docs/SLICES.md` about testnet4 can be updated by whoever owns those files.
10. **Signet block signatures.** Not verified, by decision. Verifying them would make signet confirmations checkable against the signet's known signing key, not just compared.
