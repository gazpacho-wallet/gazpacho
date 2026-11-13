# The chain port

How Gazpacho reads the chain through public chain servers. Written 2026-11-11 with the first version of the code in `ports/chain/`, revised 2026-11-12 after an independent review (pull request 7), and again the same day after the second round of that review (section 15). "Verified" means checked from the project's build server against the live servers on those dates.

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

Helpers that need no server: `gz_header_hash`, `gz_header_links`, `gz_header_check_pow`, `gz_merkle_verify`, `gz_merkle_depth_for_count`, `gz_txid_from_raw`, `gz_tx_is_coinbase`, `gz_network_genesis`, `gz_host_normalise`, `gz_host_is_loopback`, `gz_operator_from_host`, `gz_operator_name_valid`.

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
| `GZ_CHAIN_LAG` | Comparing backend: the difference has the shape of a server being behind: the disputed item lies above the tip of every server that lacks it, the tips are at most 3 blocks apart on one chain, and this has lasted at most 30 minutes (section 5). Ask again shortly. Past either limit the backend returns disagreement itself |
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
- **Addresses.** `https://` only. Plain `http://` is accepted for exactly three hosts, this machine under its usual names: `localhost`, `127.0.0.1`, `[::1]`. The backend refuses anything else at creation and the transport refuses it again before sending. Every host is put into one canonical form by one function, `gz_host_normalise`: lower case, one trailing dot (the DNS root) removed, labels of 1 to 63 letters, digits and inner dashes; a name in Unicode is refused, so only its punycode (`xn--`) spelling is accepted; a name whose last label starts with a digit must be a dotted IPv4 address in canonical form (so `127.1`, `0x7f.0.0.1`, `2130706433` and `127.000.0.1`, which resolvers read as addresses, are refused); the only bracketed host is `[::1]`. User information (`user@`), percent-encoding and anything else in the authority are refused. Requests are sent to the canonical address, not to the spelling given. The transport parses the authority itself (host, then an optional port of 1 to 5 digits, then `/`, `?`, `#` or the end; nothing else), requires libcurl's own parse of the URL to find the same host and no user or password, and makes the request with that parsed URL; it refuses user information over https too. Certificates and host names are always verified; a different certificate authority file can be given for a user's own server. Redirects are not followed.

Why our own JSON tokenizer and not cJSON: the answers are small flat objects, and the strictness wanted (duplicate keys refused, no trailing bytes, exact integers, a bound on everything) is most of the work. cJSON would have added about 3000 lines, converts numbers through floating point, accepts duplicate keys, and allocates per node in proportion to the input.

## 5. Agreement rules of the comparing backend

### Who counts

- **Right network.** Before a server's answer counts, its block 0 must be the genesis block of the configured network. This is checked on first use and remembered. A server on another chain answers `GZ_CHAIN_WRONG_NETWORK` to every call and is never sent a broadcast. If the check could not be made (server down), it is tried again on the next call.
- **No duplicates.** Creation refuses two handles to one backend, two backends with the same normalised address (canonical host, lower-case scheme, default port dropped), and two backends on the same host, whatever operator name they are given. Hosts are compared in the canonical form above, including hosts that a third-party backend reports through `gz_chain_describe` (a host that has no canonical form, or an operator name not in canonical form, makes creation fail). So `mempool.space` and `mempool.space.` are one host, refused as a pair.
- **Operators, not servers.** The quorum (default and minimum 2) counts distinct operators. A backend's operator is the name given in its configuration (canonical spelling only: lowercase letters, digits, inner dots and dashes, no empty label), or else derived from the canonical host: this machine's three names are one operator, `this-machine`; a dotted IPv4 address is its own operator; otherwise the last two labels (`api.mempool.space` -> `mempool.space`). Two hosts of one operator are one voice. This rule of thumb cannot know that two unrelated-looking names belong to one company, and it counts two numeric addresses as two operators, so configured lists name their operators: `gz-chain`'s default lists do (`mempool.space`, `blockstream.info`), and `--operator NAME` names the operator of a server given on the command line.

### Verdicts

A server's reply is **usable** if it is an answer or a clear "not found". Anything else (unreachable, malformed, too large, wrong network) counts as no reply.

1. Usable replies from fewer than two operators: **no quorum**; or, if every server failed in the same way, that failure (all unreachable, all on the wrong network).
2. Usable replies that contradict each other about **confirmed** data: **servers disagree**, even when a majority agrees. There is no vote.
3. A contradiction is **lag** only when it has the shape of servers behind one another, all of: (a) the disputed item (a block, a confirmation, a confirmed spend, a confirmed output) lies at a height **above the tip of every server that lacks it**, and not above the tip of any server that has it; for an output one server no longer lists, that server must show it spent by a confirmed transaction in a block above the tip of the server that still lists it; (b) the tips lie on one chain (each higher server has the lowest tip at that height) and differ by at most `tip_slack`, which is at most `GZ_MULTI_LAG_MAX_BLOCKS` = 3 (the default); (c) lag has not been seen continuously for more than `GZ_MULTI_LAG_MAX_MS` = 30 minutes, by the clock the caller supplies; the period ends when a call sees every server at one tip. Anything at or below the lower server's tip that servers disagree about is **disagreement**: a server cannot turn a contradiction into lag by naming the block before the honest server's tip. A transaction one server has and another lacks (raw bytes) has no height to judge by and is disagreement.
4. Differences only about **unconfirmed** data never block the answer: the confirmed, agreed part is returned and a flag (`unconfirmed_differs`) says the rest differs. Anyone can put a transaction in one server's mempool; it must not be able to blank a user's view.
5. Otherwise the common answer.

Every server's own reply to the last call can be read with `gz_multi_last_report`. Nothing is written to the caller's output unless the verdict is an answer.

### Per call

| Call | Rule |
|---|---|
| Tip | Heights may differ by at most `tip_slack` (default 3). The answer is the **lowest** tip, and every higher server must have the same block at that height. Same height with different hashes disagrees. Every server at one tip ends a period of lag |
| Block hash, header, summary, Merkle proof | Every field identical. Present on one, absent on another: lag if the block's height (for a proof, the proof's height) is above the tip of every server lacking it, else disagreement |
| Transaction status | All confirmed: same height **and** same block hash; the claimed count returned is the lowest. None confirmed: an answer — "mempool" if all have it there, else "unknown", flagged if some have it. Some confirmed and some not: lag or disagreement |
| Outspend | A confirmed spend must be identical on every server (spender, input, height, block). No confirmed spend: an answer — the unconfirmed spend if all report the same one, else "not spent", flagged if any reports one. A confirmed spend on some servers only: lag or disagreement |
| Outputs of a script | The confirmed outputs identical everywhere, else lag (each difference new above the lacking server's tip, or spent above the listing server's tip) or disagreement. The answer: those, plus the unconfirmed outputs every server lists; flagged if any server's list is not exactly the answer. A list naming one outpoint twice is a malformed reply |
| Raw transaction | Every byte identical; each server's bytes are first rechecked to hash to the txid (the txid does not cover witness data). Present on one, absent on another: disagreement |
| Broadcast | Sent to every server on the right network. Success if any accepts and returns the right txid, or says it already has it and then shows it. Each server's result is kept. Accepted is not relayed: follow up with the status |
| Fee estimates | Never an agreed fact; see section 7 |

Consequences:

- Lag and unconfirmed differences are normal for a few seconds around a new block or transaction. Lag is "not yet, ask again". A dishonest server can still pretend to be behind, but only about items above its claimed tip, and only within the limits: at most 3 blocks, at most 30 minutes; after that the comparing backend itself answers disagreement. Hiding anything at or below its own claimed tip is disagreement at once.
- A server that is permanently behind, broken or dishonest makes a two-operator setup permanently unable to confirm. That is the safe direction, and the reason three operators are better than two.

## 6. Confirmations: what is checked and what is trusted

`gz_chain_confirm_tx(chain, network, txid, want, out)` takes a server's (or the comparing backend's) "confirmed" claim and checks, in order:

1. the server's block 0 is the genesis block of `network`;
2. the transaction itself is fetched and its txid recomputed, so the id is that of a real transaction, and not of a 64-byte one;
3. the header at the stated height hashes to the stated block hash and meets its own proof-of-work target for `network`;
4. the Merkle branch is for that height, has exactly the depth implied by the block's transaction count, places the transaction below that count, and leads from the txid to the header's Merkle root; the fold refuses a step where our node sits on the right with an identical node on its left (the copy Bitcoin makes of an odd row's last node, which no transaction occupies);
5. the block's first transaction is fetched, must be a coinbase, and its own branch from position 0 must have the same depth and reach the same root — the server cannot choose a depth that does not fit a real tree;
6. the tip is read (on the comparing backend: the agreed, lowest tip) and up to `want - 1` later headers (at most 144), none above that tip, are fetched; each must link to the one before and meet its proof-of-work target. A server that has already seen a newer block therefore never stalls a confirmation: the count stops at the agreed tip. Servers disagreeing about a header at or below it is disagreement.

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
- **Mainnet.** A server **answers for** a target T with its estimate for the highest target it lists that is not above T (T itself or a faster target, so never a lower rate than T needs); a server that lists nothing at or below T does not answer for T. The comparing backend's combined table has an entry for each target any answering server lists; for each, only the servers answering for that target count. Fewer than a quorum of operators answer for it: the target is left out. Otherwise the entry is the **lowest** rate they give, cut at the configured ceiling (default 200 sat/vB); if the highest of those rates is more than 3 times the lowest plus 1 sat/vB, the call returns `GZ_CHAIN_DISAGREE` instead. `gz_chain_choose_fee_rate` then picks the entry for the highest target not above the one asked for (never a slower one: if every entry is slower, there is no rate, `GZ_CHAIN_NOT_FOUND`), raises it to a floor of 0.1 sat/vB, and cuts it at a ceiling the **caller must supply**.
- **Single server.** Its parser refuses any rate above 5000 sat/vB as malformed.

Consequences: no single server can raise what the user pays. A single server can lower a target's rate only to what the disagreement rule allows against the others' rates **for that same target** (about a third of theirs, less 1 sat/vB), and not below the floor. Leaving targets out does not get round it: a server that omits a target simply does not take part in it, and its estimates for slower targets never stand in for a faster one (the reviewer's case, one server answering only `{"1008":2}` against honest servers at 40 sat/vB for 6 blocks, now gives no 6-block rate with two servers, and the honest servers' rate with three; tested). A transaction that pays too little is slow, not lost, and can be bumped; one that pays too much loses money for good. That is why the lowest is taken.

The live servers' signet answers (1 and 10 sat/vB for the next block) count as a disagreement under this rule. That is expected: on signet the estimates are not used.

## 8. What a dishonest server can and cannot do

Assume one of the configured servers is dishonest and at least one other, of another operator, is honest and reachable.

**Cannot:**

- Make the wallet accept an **invented confirmation**. The honest server contradicts it, so the comparing backend returns disagreement. Separately, `gz_chain_confirm_tx` requires the transaction, a header chain and a Merkle branch of the right shape; a transaction not in the block has no valid branch. Both are tested, including the case where every server tells the same lie and only the proof catches it.
- Inflate the **confirmation count**: it is counted along linked headers.
- **Hide a confirmed spend** of a watched output unnoticed: the result is disagreement, with the honest answer in the report; lag only while the spend is in a block above the hiding server's claimed tip, for at most 3 blocks or 30 minutes.
- **Hide or invent a confirmed deposit**: confirmed outputs must match exactly.
- **Blank the view by spamming the mempool**: unconfirmed differences are flagged, not fatal.
- Substitute a **different transaction** for a txid, or alter its witness unnoticed.
- Put the wallet on a **different chain** quietly: block 0, block hashes, headers and tips are checked or compared. A server on another network is excluded and never sent a broadcast.
- Pass itself off as **two servers**: duplicates are refused, hosts are compared in one canonical spelling (case, trailing dot, numeric forms), and the quorum counts operators.
- **Set the fee rate** upwards.
- Learn or take any **secret**.
- Exhaust memory or hang the program: sizes and times are capped.

**Can:**

- **Deny service.** One dishonest or broken operator out of two stops confirmations. With three, a server that is down or malformed is ignored, but one that sends well-formed contradictions still blocks. The user is told; nothing false is accepted. For a member with a deadline this matters: persistent disagreement must be shown early, and the user must be able to change servers.
- **Pretend to lag**, which delays answers the same way, only about items above its claimed tip and for at most 3 blocks or 30 minutes.
- **Lower the fee rate** a little, within the disagreement rule for each target (section 7).
- **Accept a broadcast and not relay it.** It also goes to the others.
- **Learn things** (section 9).

**If all configured servers collude, or are secretly one operator:** on signet they can invent anything, including whole blocks; on the proof-of-work networks they need work at a difficulty this code does not check against the network's rules; on any network they can hide transactions completely. This is why the list must hold servers of different operators, and why hosts should use their own node.

## 9. Privacy: what each server learns

Every configured server is asked every question. So each one learns:

- the user's **network address** (and so rough location), unless the user goes through Tor: `gz_http_curl_config.proxy` (`gz-chain --proxy`) takes a `socks5h://HOST:PORT` proxy, and only that scheme, so names are resolved by the proxy too; requests to this machine bypass it. Without it no proxy is used: the transport sets `CURLOPT_PROXY` to `""` so `http_proxy`, `https_proxy`, `ALL_PROXY` and the like are never followed silently;
- **every script the user watches**, as its SHA-256 (which identifies the script as well as the script itself does: anyone can hash the scripts they see on chain and match);
- **every transaction the user looks up or broadcasts**, and when;
- the **User-Agent**, a common browser string (`GZ_HTTP_USER_AGENT`, Tor Browser's), which names neither Gazpacho nor the user or machine. No other identifying header is sent. (Until Privacy Slice 1 it was `gazpacho-chain/0.0.1`, which marked every request as Gazpacho.)

**Requirement for P7 (the chain worker and the watch loop): do not query the funding txid before it can have been broadcast.** A factory's funding txid is known to its members before the host broadcasts it. A server asked about a txid nobody else knows learns that the asker is a participant, and with several members asking, which addresses belong to one factory. So a member asks for the funding transaction's status only after the host's broadcast could have made it public (at the earliest when the host reports the broadcast, plus a delay), or watches by the funding output's script or by new blocks' transaction ids instead. No code yet; P7 must meet this and test it with a fake transport that records the first request naming the txid.

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
2. **Lag is its own result**, recognised only when the disputed item lies above the lower server's tip, within 3 blocks of tip difference and 30 minutes (`GZ_MULTI_LAG_MAX_BLOCKS`, `GZ_MULTI_LAG_MAX_MS` in `chain_multi.h`), whichever limit is reached first; beyond either it is disagreement. Decided by the owner's coordinator after the second review.
3. **Unconfirmed differences never block**; they are flagged, and only unconfirmed data every server reports is returned.
4. **The lowest tip** is the agreed tip.
5. **Operators** are named in configuration (and in `gz-chain`'s default lists), or taken from the canonical host: this machine's names are one operator, otherwise the last two labels; one host can never be two servers, in any spelling.
6. **Network identity** is block 0, checked once per server and remembered.
7. **Fees**: fixed 0.1 sat/vB on test networks; on mainnet, per target, the lowest estimate of the servers answering for that target (a server answers with its highest listed target not above it), a factor-of-3-plus-1-sat/vB disagreement rule, a caller-supplied ceiling, a 0.1 sat/vB floor, never a slower target's rate, and a 5000 sat/vB limit on any single answer.
8. **Confirmation depth**: at most 144 headers are followed per check, and none above the agreed tip.
9. **"Already known"** on broadcast is success only if the server then shows the transaction in its mempool or confirmed.
10. **64-byte transactions** are refused outright, as no wallet makes them.
11. **Plain http** only for this machine's loopback names, for a user's own server.
12. **Warnings as errors** is a build option (`GZ_WERROR`), on in CI, so a newer compiler's new warning does not stop someone building.
13. **Our own JSON tokenizer** instead of cJSON (section 4).

## 13. Testing

How to run: `ctest` runs everything except the live test (`-DGZ_CHAIN_TESTS=OFF` leaves this port's tests out of the build); `ctest -LE slow` skips the local-server test; `cmake -DGZ_LIVE_TESTS=ON` and `ctest -R chain_live` runs the live test. `python3 -I ports/chain/tests/break_checks.py BUILD_DIR` runs the break-checks.

| Test | What it covers |
|---|---|
| `chain_json` | The tokenizer: valid and invalid JSON, duplicate keys, depth and size limits, exact numbers |
| `chain_headers` | Header parsing, hashing, links, proof of work on mainnet, testnet4 and signet headers, targets, txid computation, refused transaction shapes (no inputs, no outputs, 64 bytes without witness, both ways for segwit, wrapping lengths), Merkle proofs on real signet data including tampered proofs, wrong blocks, the duplicated-node position, depth for a count, network identity, host normalisation (every accepted and refused spelling), operator names |
| `chain_esplora` | Every call against the fake transport with recorded answers; every malformed-answer case listed in the file; time limits, retries, backoff cap, rate limit, size caps; addresses; network check; fee policy; broadcast trimming and "already known"; checked confirmations, including invented confirmations, lies about the tree's shape and the coinbase, and invented tips |
| `chain_multi` | The comparing backend over two and three servers: agreement, every kind of contradiction, lag and its three conditions (item above the lower tip, 3 blocks, 30 minutes), lag for output lists, unconfirmed differences and their flag, duplicate servers and one host under several spellings, one operator under two names, a server on the wrong network, servers down, lying servers, broadcast, fees with targets left out, confirmations counted to the agreed tip |
| `chain_model` | 20,000 random situations (one to four servers, one to three operators, up or down, right network or not, five tip heights, two chains, independent claims about a transaction and a spend at a height drawn per situation, a block, and a fee for one of two targets). Expected verdicts come from functions written from the rules in this document, which share no code with `multi.c`. `GZ_MODEL_SEED`, `GZ_MODEL_ROUNDS` replay or lengthen |
| `chain_confirm` | `gz_chain_confirm_tx` against a backend serving fabricated blocks with valid signet proof of work (nonces in `tests/fab_nonces.h`, made again with `GZ_FAB_GRIND=1`): each coinbase step on its own against a block holding 64-byte transactions, the summary naming the block, the bytes rechecked against the id, the position below the count, the depth cap on a 147-header chain |
| `chain_fuzz` | Seeded mutation of 13 recorded answers fed to every parser, under the sanitizer build. A real fuzzer (libFuzzer or AFL++) should be attached to `gz_json_parse`, the eight `gz_es_parse_*` functions and `gz_txid_from_raw`, with `tests/data/` as corpus |
| `chain_local_servers` (label `slow`) | The real libcurl transport against servers on 127.0.0.1: a hostile HTTP server (oversized, endless, compressed, slow, dripping, redirecting, huge headers), addresses with user information and other malformed authorities, and three HTTPS servers with a good certificate, one for another name, and a self-signed one; then `gz-chain` end to end against small Esplora look-alikes (agreement, hiding, lag, fee disagreement, one machine under two names, duplicates and trailing dots, operator names, a mainnet server, broadcast refusals, fee) with each exit code. Needs python3 and openssl; skipped without them |
| `chain_tool_*` | The tool's mainnet refusal and usage text |
| `chain_live` (opt-in) | The two public signet servers: tip, a known transaction, a checked confirmation 6 deep, a spend, a script, raw bytes, fees, network |

Counts on 2026-11-12 after the second review, identical in the Release and the AddressSanitizer + UBSan builds (gcc 15.2, `-Wall -Wextra -Werror`):

| Test | Test functions | Checks |
|---|---|---|
| `chain_json` | 8 | 105 |
| `chain_headers` | 22 | 274 |
| `chain_esplora` | 35 | 724 |
| `chain_multi` | 29 | 482 |
| `chain_confirm` | 5 | 177 |
| `chain_model` | 1 (20,000 random situations, 4 calls each) | 9 |
| `chain_fuzz` | 2 (40,000 mutations of each of 13 answers, plus 20,000 random inputs and every prefix) | 10 |
| `chain_local_servers` | transport 49 checks, tool 24 cases | 73 |
| `chain_tool_refuses_mainnet_broadcast`, `chain_tool_usage` | 2 | 2 |
| `chain_live` (opt-in) | 2 | 35 |

`ctest -R '^chain_'` runs 10 tests, all passing; `ctest -R '^chain_' -LE slow` runs the 9 that need no local servers. The live test was not re-run after the second review (it reads only signet). Under valgrind (`tools/valgrind-tests.py --include '^chain_'`, RelWithDebInfo) the 8 test programs are clean; the two script tests are not run under it. The clang jobs (plain, ASan+UBSan, MemorySanitizer) could not be run on the build server, which has no clang; CI runs them.

Break-checks (`break_checks.py`, 163 behaviours after the second review, each removed in turn; 38 are new, for findings A to F and for the review's surviving mutations): on the sanitizer build, 163 caught, 0 survived. (The first version of the list had 125, all caught on 2026-11-12 before this round.) Three new entries first did not compile under `-Werror` and were corrected; one (lag for an item with no height) was dropped as equivalent: the height rule itself already refuses it, the early return only saves the tip requests. Two entries remove two checks together because each alone is covered by the other: the transport's strict authority parser and libcurl's own parse both refuse user information (h8), and, as before, the transport's body cap and libcurl's size limit (h4).

The second review's 18 surviving mutations and the 6 it could not compile were ported to the fixed code (made to compile) and rerun on the sanitizer build: 20 caught, 4 survived. Survivors: `e27` (the raw-transaction length check after the fetch, equivalent: the fetch is already capped at the caller's room), `t4` (the body cap in the write callback, equivalent with this libcurl: `CURLOPT_MAXFILESIZE_LARGE` stops the transfer first, also without a stated length), `t8` (both protocols allowed, equivalent: the URL is checked to be https, or http for loopback, before the request, and redirects are not followed), and `g8'` (the tool's proof command printing a result line after a failed check; its exit status was already 1, because a failed check clears the result; now killed by a tool test that no transaction line is printed, and caught as break-check g9).

### Not tested

- The Electrum protocol: no backend exists yet.
- Real proof-of-work attacks: no mainnet or testnet chain of our own; the proof-of-work checks are tested on recorded real headers and on altered copies.
- A long-running program using the port, reorganisations of more than one block, and the behaviour of the program around the core when disagreement persists: none exists yet.
- Concurrency: the port is single-threaded by design; nothing tests use from several threads.
- The transport on anything but Linux.
- That `curl_easy_setopt` failures are handled: they cannot be provoked in a test (they occur only on out-of-memory or an old libcurl).
- Some checks are kept as defence in depth although another check already catches every case the tests can build: the per-call raw-transaction size check in `esplora.c` (the fetch is capped at the caller's room; review e27), the address-equality check in `multi.c` (the same-host check catches it first), the comparing backend's own fee limit (the parser's limit catches it first), the transport's own body-size check and its protocol restriction (libcurl's size limit, and the URL check with no redirects; review t4, t8), each of the two refusals of user information in the transport on its own (the other refuses first), and the early return for an item with no height in the lag rule. Removing any one of these makes no test fail. The coinbase steps, the position check, the bytes-against-id check, the summary-names-the-block check, the proof of work of later headers and the depth cap were in this list before the second review; each is now tested on its own (`chain_confirm`, `chain_esplora`).

## 14. Open questions

1. **Terms.** May a released wallet point every user at mempool.space and blockstream.info by default? Owner's decision; see section 10.
2. **Unanimity or majority** with three operators (section 12, item 1).
3. **Proving a spend.** When servers disagree about a spend, fetch the claimed spender and check that it really spends the output (and its signature). Then a hidden spend becomes a proven one. Belongs with the watch engine.
4. **Header chains on proof-of-work networks.** Only each header's own target is checked. Mainnet use needs difficulty rules or pinned known blocks.
5. **Unknown fields.** A server adding a field to an answer makes it malformed here. Deliberately strict; it could take a server out after an upgrade on their side.
6. **Persistent disagreement**: how long the program waits before telling the user. Persistent lag is now bounded in the library (3 blocks or 30 minutes, then disagreement); what the program shows, and when, is not decided.
7. **Privacy** (section 9): Tor, or the user's own server. Neither built.
8. **Blocking calls.** Servers are asked one after another; a slow one delays the others by up to its time limit times its retries. The program around the core needs the calls off its main loop.
9. **Default lists.** `gz-chain` uses `docs/CHAIN-SERVERS.md`, with each server's operator named. Testnet4 now lists both HTTP operators (mempool.space and blockstream.info); testnet3 still has one in the list. The line in `docs/SLICES.md` about testnet4 can be updated by whoever owns that file.
10. **Signet block signatures.** Not verified, by decision. Verifying them would make signet confirmations checkable against the signet's known signing key, not just compared.

## 15. Changes after the second review

The second round of the independent review (2026-11-12) returned "merge after fixes" with findings A to G. What changed, and the test that shows each fix (each fails on the code before it; the break-checks and the mutation rerun below remove each fix again and require a test to fail):

- **A. One operator under two spellings.** All host normalisation is now one function, `gz_host_normalise` (section 4): case, one trailing dot, Unicode refused in favour of punycode, numeric forms other than canonical dotted IPv4 refused, user information and ports never part of a host. `url_parse`, `gz_operator_from_host` and the comparing backend's creation (for hosts any backend describes) all use it; requests go to the canonical address. This machine's three names are one operator. Operator names are accepted only in canonical spelling. `gz-chain`'s default lists name their operators, and `--operator` names one on the command line. Tests: `test_one_host_two_spellings` and `test_described_hosts_are_normalised` (`chain_multi`, including the reviewer's two pairs), `test_host_normalise`, `test_operator_names`, `test_operator_from_host` (`chain_headers`), the address cases in `test_describe_and_addresses` (`chain_esplora`), and the tool cases for both pairs and for `localhost.` in `local-servers.sh`.
- **B. Lag from the tips alone.** Lag now needs the disputed item above the tip of every server lacking it (section 5, rule 3), at most `GZ_MULTI_LAG_MAX_BLOCKS` = 3 blocks of tip difference and at most `GZ_MULTI_LAG_MAX_MS` = 30 minutes of continuous lag, whichever comes first (both named constants in `chain_multi.h`; the comparing backend now needs a clock in its configuration). Output lists use the same rule, with a confirmed spend above the listing server's tip as the explanation for an output gone. Tests: `test_lag_needs_the_item_above_the_lower_tip` (the reviewer's R2, R2c, R2b), `test_lag_for_output_lists`, `test_lag_has_limits` (the 30-minute and 3-block limits, and the end of a lag period), the updated `chain_model` (heights of the transaction and spend drawn per situation, tips over five heights).
- **C. Fees lowered by leaving targets out.** Per target, only the servers answering for it count, and a slower target never stands in for a faster one (section 7). Tests: `test_fee_targets_left_out` (`chain_multi`: the reviewer's 40 against 2 sat/vB case with two and three servers, the edge of the factor rule for one target, test networks at 0.1 sat/vB with no request), the single-server cases in `test_choose_fee_rate` (`chain_esplora`), and the fee part of `chain_model` (servers listing only the slow target).
- **D. A server a block ahead stalled confirmations.** `gz_chain_confirm_tx` reads the agreed tip and follows headers only up to it (section 6). Tests: `test_confirmation_counts_to_the_agreed_tip` (`chain_multi`, the reviewer's R5) and the single-server case at the end of `test_confirm_tx_header_chain`. A server claiming a tip far ahead of the others now makes a confirmation of more than one block disagree (there is no agreed tip); asked for one confirmation, the block is still checked (`test_invented_tip_does_not_raise_confirmations`).
- **E. Loopback check fooled by user information.** The transport parses the authority strictly, refuses user information, percent-encoding and anything else outside host and port, requires libcurl's parse to agree, and sends with that parsed URL (section 4). Tests: the reviewer's three URLs and the other refused forms in `not_local`, and user information over https, in `test_transport.c`.
- **F. Missing tests.** New test program `chain_confirm`: a backend serving fabricated blocks whose headers meet signet's proof-of-work limit (nonces ground once, `tests/fab_nonces.h`). It shows each coinbase step stopping an attack on its own, with every other check passing: a 64-byte transaction inside a block lets a server claim a transaction one level below it, and only the coinbase branch's depth (v6), that branch's fold (v8), that the first transaction is a coinbase (v7) with exactly one input (c14), or that no coinbase sits later (v9) stops it. So these steps are not merely defence in depth behind the 64-byte rule: the 64-byte rule stops a 64-byte transaction being confirmed, the coinbase steps stop one being used as a ladder. The same program tests the summary naming the block (v5), the bytes rechecked against the id (v2), the position below the count (v4) and the cap on depth with a 147-header chain (v14). `chain_headers` tests the 64-byte rule on segwit transactions both ways (c13); `chain_esplora` alters a later header's nonce (v11). The unconfirmed-differences flag for output lists is now one rule (a list differs exactly when it is not as long as the answer), tested with the extra output on each of three servers in turn; a backend naming an outpoint twice is a malformed reply. Tool exit codes for fee disagreement, lag and a failed proof are tested in `local-servers.sh` (g6, g7, g8).
- **G.** Testnet4's second operator is in `docs/CHAIN-SERVERS.md` and the default list. `chain.h` now says that the mainnet refusal lives in the program, not the library. The two Electrum servers known only by numeric address are no longer named in section 11.

Rebased onto `main` after the CI hardening (top-level `CMakeLists.txt`: both the wallet library and this port are added). Two adjustments for the CI jobs there: the tool's mainnet-refusal test now runs through `tests/expect-exit.sh` (it must exit 2, and `tools/valgrind-tests.py` requires exit 0 from the programs it runs, so it is listed there as a script test); and a new option `GZ_CHAIN_TESTS` (default ON) leaves this port's tests out, which `wallet/tests/break-checks.sh` now sets in the copy it builds for each wallet fault (none of this port's tests can notice a wallet fault, and the slow local-server test would run once per fault). No IP address other than 127.0.0.1 and the RFC 5737 ranges is left in the port; the three test lines that must hold `127.0.0.2` to show it refused carry `address-check: allow`.
