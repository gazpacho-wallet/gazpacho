# The chain port

How Gazpacho reads the chain through public chain servers. Written 2026-11-11 with the first version of the code in `ports/chain/`, revised 2026-11-12 after an independent review (pull request 7), and again the same day after the second round of that review (section 15). Sections 16 to 23 (the chain worker and the watch loop, plan items P7 and S8) were added on 2026-11-15. "Verified" means checked from the project's build server against the live servers on those dates.

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

- the user's **network address** (and so rough location), unless the user goes through Tor: `gz_http_curl_config.proxy` (`gz-chain --proxy`) takes a `socks5h://HOST:PORT` proxy, and only that scheme, so names are resolved by the proxy too; requests to this machine bypass it. A server elsewhere on the local network (a node at home, say) does **not** bypass it: over Tor it cannot be reached, which fails closed. Only "no authentication" is offered to the proxy, never GSSAPI, whose Kerberos exchange could reveal the user's principal. A proxy given by name is looked up by the system resolver, which tells DNS that a proxy is used; an IP address avoids that. Without it no proxy is used: the transport sets `CURLOPT_PROXY` to `""` so `http_proxy`, `https_proxy`, `ALL_PROXY` and the like are never followed silently;
- **every script the user watches**, as its SHA-256 (which identifies the script as well as the script itself does: anyone can hash the scripts they see on chain and match);
- **every transaction the user looks up or broadcasts**, and when;
- the **User-Agent**, the current Tor Browser string (`GZ_HTTP_USER_AGENT`, Firefox 140 ESR; bump it with each ESR), which keeps the product name out of requests and names neither the user nor the machine. No other identifying header is sent. **It does not hide the client:** libcurl's TLS fingerprint, the header order, the missing `Accept-Language`, and above all the access pattern (the same txids from many addresses) still let a server that wants to tell that this is Gazpacho. (Until Privacy Slice 1 it was `gazpacho-chain/0.0.1`, which marked every request as Gazpacho.)

**Requirement for P7 (the chain worker and the watch loop): do not query the funding txid before it can have been broadcast.** A factory's funding txid is known to its members before the host broadcasts it. A server asked about a txid nobody else knows learns that the asker is a participant, and with several members asking, which addresses belong to one factory. So a member asks for the funding transaction's status only after the host's broadcast could have made it public (at the earliest when the host reports the broadcast, plus a delay), or watches by the funding output's script or by new blocks' transaction ids instead. Built with the chain worker: the not-before flag of section 20, tested with a transport that records every request naming the txid, and over real HTTP.

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
- A long-running program using the port, and what it shows when disagreement persists: the chain worker exists (section 16), but the program is not wired to it yet (section 23). Reorganisations of several blocks are tested against a made-up chain only (section 22), not on a real network.
- Concurrency below the worker: a backend is still for one thread at a time. The chain worker is its only user, and the worker itself is tested with threads and under ThreadSanitizer (section 22).
- The transport on anything but Linux.
- That `curl_easy_setopt` failures are handled: they cannot be provoked in a test (they occur only on out-of-memory or an old libcurl).
- Some checks are kept as defence in depth although another check already catches every case the tests can build: the per-call raw-transaction size check in `esplora.c` (the fetch is capped at the caller's room; review e27), the address-equality check in `multi.c` (the same-host check catches it first), the comparing backend's own fee limit (the parser's limit catches it first), the transport's own body-size check and its protocol restriction (libcurl's size limit, and the URL check with no redirects; review t4, t8), each of the two refusals of user information in the transport on its own (the other refuses first), and the early return for an item with no height in the lag rule. Removing any one of these makes no test fail. The coinbase steps, the position check, the bytes-against-id check, the summary-names-the-block check, the proof of work of later headers and the depth cap were in this list before the second review; each is now tested on its own (`chain_confirm`, `chain_esplora`).

## 14. Open questions

1. **Terms.** May a released wallet point every user at mempool.space and blockstream.info by default? Owner's decision; see section 10.
2. **Unanimity or majority** with three operators (section 12, item 1).
3. **Proving a spend.** When servers disagree about a spend, fetch the claimed spender and check that it really spends the output (and its signature). Then a hidden spend becomes a proven one. The watch engine now fetches the spender a server names and checks that its input is the watched outpoint (section 18); the signature is still not checked.
4. **Header chains on proof-of-work networks.** Only each header's own target is checked. Mainnet use needs difficulty rules or pinned known blocks.
5. **Unknown fields.** A server adding a field to an answer makes it malformed here. Deliberately strict; it could take a server out after an upgrade on their side.
6. **Persistent disagreement**: how long the program waits before telling the user. Persistent lag is now bounded in the library (3 blocks or 30 minutes, then disagreement); what the program shows, and when, is not decided.
7. **Privacy** (section 9): Tor, or the user's own server. Neither built.
8. **Blocking calls.** Answered by the chain worker (section 16): one thread owns the chain view and the loop never waits. The program is wired to it in the follow-up of section 23.
9. **Default lists.** `gz-chain` uses `docs/CHAIN-SERVERS.md`, with each server's operator named. Testnet4 now lists both HTTP operators (mempool.space and blockstream.info); testnet3 still has one in the list. The line in `docs/SLICES.md` about testnet4 can be updated by whoever owns that file.
10. **Signet block signatures.** Not verified, by decision. Verifying them would make signet confirmations checkable against the signet's known signing key, not just compared.
11. **A node of our own for package relay.** Exits of low-fee trees need one-parent-one-child package relay, and one public operator offers a package endpoint on signet and testnet4 (section 19). Whether the project runs a Bitcoin Core 29.1 node with a package endpoint, and tells hosts to, is for the owner.
12. **A false block 0 is remembered for good.** A server that once answers with the block 0 of another network is left out until the program starts again (section 5). Right for a server on the wrong chain; harsh for a single bad answer. A long-running worker could ask again after a long wait.
13. **Expected difficulty.** Proof of work is checked against the network limit only (section 18). Before mainnet: a retargeting rule, or checkpoints shipped with the program. Review of PR 43, M2.
14. **The cost of linking old confirmations.** A watch set again at start on a confirmation a year old makes the engine fetch every header down to it, from each server, 144 per pass: tens of thousands of requests once per start. A checked height and hash saved by the program (a checkpoint of its own) would make that unnecessary. For the P7 wiring or later.

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

## 16. The chain worker and the watch loop (P7, S8)

Added 2026-11-15. Everything above describes a chain view whose every call blocks. The program has one loop and must never wait on the network (contract v2, section 5). So `ports/chain` now has two more layers, both in the library `gazpacho_chain`:

- **The watch engine** (`watch.c`, internal header `watch.h`). No thread, no lock. It holds the watch set, a chain of checked block headers and the broadcasts in flight. One call, `gz_watch_step`, makes one pass over the chain view and hands each change to a callback as an event.
- **The chain worker** (`chainw.c`, public header `gazpacho/chain_watch.h`). One thread that owns the `gz_chain` and the engine and does all chain I/O. The loop talks to it only through two bounded queues and one descriptor.

```
loop thread                                   worker thread
-----------                                   -------------
gz_chainw_watch_tx / _outpoint   --requests-->  engine: watch set
gz_chainw_unwatch_*, _release                   header chain
gz_chainw_broadcast, _package                   broadcasts in flight
                                                   |
poll(gz_chainw_fd) readable      <---events---  gz_watch_step -> gz_chain (blocking)
gz_chainw_take
```

### 16.1 What the loop may call, and what each call costs

Every loop-side call takes one mutex for a few instructions and returns. None waits on a condition variable, on the worker, or on the network. A call that cannot be queued is **refused with a reason, never an error and never a wait**:

| Return | Meaning |
|---|---|
| `GZ_CHAINW_OK` | Queued |
| `GZ_CHAINW_FULL` | The watch set already holds `max_watches` (default 256, at most 1,024), or 16 broadcasts have no final outcome yet. Nothing was queued |
| `GZ_CHAINW_BUSY` | `max_requests` (default 1,024) requests wait for the worker. Nothing was queued; ask again later |
| `GZ_CHAINW_INVALID` | A NULL argument, a depth above 144, an unknown flag, or bytes that are not a transaction |

This differs from the sketch in contract v2 section 5 in one point: there a full request queue was fatal for the incarnation. Here it is a refusal the caller can see, because the task for this work asked for "bounded in number with a refusal, never an error". The program may still treat `GZ_CHAINW_BUSY` as fatal if it wants the old rule.

`gz_chainw_fd` is the read end of a pipe. It is readable exactly while events wait: the worker writes one byte when the queue goes from empty to not empty, and `gz_chainw_take` reads it back when it takes the last event. The loop gives the descriptor to `poll()` and never reads or writes it.

### 16.2 Never dropping an event

Watches report only on a change, so a lost report is never repeated. When the event queue (`max_results`, default 4,096) is full, the worker **waits** for `gz_chainw_take` to make room. It asks the servers nothing meanwhile, which only delays reports. Two kinds of event are replaced in place when the newest thing in the queue is of the same kind: a tip and a sources event. That keeps the order and needs no room.

### 16.3 Generations

`gz_chainw_reset` (for a restart from storage inside one process) purges both queues and the wake byte, forgets every watch and broadcast, and returns a new generation number. Every event carries its generation, and events made by a pass that was still running when the reset came are discarded, under the same mutex. The first event about the chain in every generation is the tip. The checked headers are kept across a reset: they are facts about the chain, not about the node.

### 16.4 Shutdown and reset with a request in flight

`gz_chainw_free` and `gz_chainw_reset` call the configured `interrupt` hook. With the libcurl transport that is `gz_http_curl_interrupt` (new in `chain_http.h`): the transfer in progress ends at once, a retry wait in progress ends at once, and every later request fails immediately until the interrupt is taken back. To make that possible `http_curl.c` now runs each request on the multi interface (one transfer, `curl_multi_poll`, woken by `curl_multi_wakeup`) and sleeps on a condition variable.

Measured on the build server against a stub that answers after 30 s: `gz_chainw_free` returns in well under 2 s (the test allows 2 s; contract v2 test T5 allows the program 2 s). The bound holds for name lookups only when libcurl resolves names without blocking; `gz_http_curl_async_dns()` says whether it does (true for the libcurl on the build server and on GitHub runners). Without a hook the worker is still joined, after the request in flight runs into its own time limit.

libcurl global state is as contract v2 says: the loop thread creates the `gz_http` and the `gz_chain` before `gz_chainw_new` and destroys them after `gz_chainw_free`.

### 16.5 Limits and defaults

| Setting | Default | Meaning |
|---|---|---|
| `tip_poll_ms` | 60,000 | Time between two looks at the tip and at every unconfirmed watch |
| `retry_ms`, `retry_max_ms` | 5 s, 5 min | Wait after a failed pass, doubled per failure in a row. Lag does not grow the wait |
| `burial_depth` | 3 | Depth of a watch set with depth 0 (`spec/exit.md` B, `safety-rule.md` value 3) |
| `max_watches` | 256 | Refused beyond |
| `max_requests`, `max_results` | 1,024, 4,096 | The two queues |
| `broadcast_attempts`, backoff | 6 tries, 2 s doubling to 60 s | Only while no server can be reached |
| `header_window`, `max_catchup`, `max_link` | 288, 144, 52,560 | Hashes kept in the normal course; most headers fetched in one pass, forward toward the tip or down toward an older confirmation; most hashes ever kept, which bounds how far below the tip a confirmation can be linked (a year of blocks, 1.7 MB at most) |

Mainnet is refused: `gz_chainw_new` returns NULL for any network that is not signet, testnet3 or testnet4.

## 17. The event contract

Events come out in the order they were made, each at most once per change of state. All txids are in hashing order. `generation` is on every event.

| Event | When | Fields |
|---|---|---|
| `GZ_CHAINW_TIP` | The checked best block changed. The first event about the chain in a generation; a broadcast outcome or `SOURCES` can come before it | `height`, `block_hash` |
| `GZ_CHAINW_REORG` | Blocks left the checked chain. Sent **before** the new tip and before what the reorganisation did to each watch | `height` (lowest height whose block changed), `disconnected` |
| `GZ_CHAINW_TX_MEMPOOL` | A watched transaction first seen unconfirmed, by every server | `txid` |
| `GZ_CHAINW_TX_EVICTED` | A transaction reported in the mempool is known to no server and is not confirmed | `txid` |
| `GZ_CHAINW_TX_CONFIRMED` | First seen confirmed (with its real count, which may exceed the depth), then at each block that changes its count cut at the watch depth | `txid`, `height`, `block_hash`, `confirmations`, `buried` (count has reached the depth), `reorg` (count lower than the one told before) |
| `GZ_CHAINW_TX_UNCONFIRMED` | A confirmation told earlier was undone | `txid`, `in_mempool` |
| `GZ_CHAINW_OUTPOINT_SPENT` | A spender first seen (0 confirmations while unconfirmed), then as for TX_CONFIRMED | `outpoint_txid`, `outpoint_vout`, `txid` (the spender), `vin`, `confirmations`, `height`, `block_hash`, `buried`, `replaced` (a different spender from the one told before), `reorg` (the spender told before was confirmed and is no longer, or its count went down) |
| `GZ_CHAINW_OUTPOINT_UNSPENT` | A spend told earlier is gone and nothing else spends the outpoint | outpoint, `txid` (the spender that left), `reorg` (it had been confirmed) |
| `GZ_CHAINW_BROADCAST` | The outcome of a broadcast (section 19) | `txid`, `broadcast` |
| `GZ_CHAINW_SOURCES` | What the servers are worth changed. Sent at the end of the pass that found it | `sources`: `GZ_CHAIN_OK`, or lag, disagreement, no quorum, unreachable, wrong network, bad proof, malformed |

Rules that follow from the code and are each tested:

- **Within one pass**: `REORG`, then `TIP`, then the watches in the order they were set (starting after the watch that ended the previous pass, if one did), then `SOURCES`. Broadcast outcomes come whenever a broadcast is due: at the start of a pass and after every chain call, so they can fall between watch events, and before the first tip.
- **A confirmation that stands is not asked about again.** It is counted along the checked headers. It is asked about again only when a reorganisation replaced blocks at or above its height, or when the watch is set again. So a server cannot make a confirmation flap by hiding it later.
- **Setting a watch again** replaces its depth and tells the state found again, as `action.h` WATCHES says.
- **Burial.** After the count reaches the depth, nothing more is told for that confirmation unless a reorganisation changes it. Every count is a distance along the checked chain (section 18). A confirmation below the hashes held is first linked to them header by header, and keeps its count when its block is later dropped from them, because the chain has only grown since by linked headers. A reorganisation is told however deep it reaches.
- **A tip several blocks ahead** is followed `max_catchup` headers per pass; each pass tells the tip it reached and the counts that changed. Counts in between are not told.
- **Unconfirmed data** follows section 5: seen only when every server shows it, gone only when none does. While servers differ, nothing is told.
- **While `sources` is not OK**, nothing is told that depends on the failing answer. Watches that can still be answered are.

### Reorganisations

The engine compares the servers tip with its own chain, walks down to the highest block both have, fetches and checks every header from there to the tip, and only then replaces its headers. Then every recorded confirmation above the common block is asked about again:

| What the servers now say | Events |
|---|---|
| Not confirmed | `TX_UNCONFIRMED` (with `in_mempool`); for an outpoint `OUTPOINT_SPENT` with 0 confirmations and `reorg`, or `OUTPOINT_UNSPENT` with `reorg` |
| Confirmed in another block | `TX_UNCONFIRMED`, then `TX_CONFIRMED` with the new count |
| The same block, the chain shorter | `TX_CONFIRMED` with the lower count and `reorg` |
| Another transaction spends the outpoint | `OUTPOINT_SPENT` naming it, with `replaced` and `reorg` |

A reorganisation that reaches below the hashes held, or servers whose chain shares no block with them, starts the header chain again at their tip. Every hash held is then told as replaced (`REORG` from the oldest one: nothing shows which were not), and every confirmation is placed on the new chain again, header by header, before it counts. A tip further ahead is never a reason to start again: it is followed.

## 18. Server rules in the worker

The worker uses the comparing backend over two operators, so sections 4 to 6 apply to every answer. On top of them:

- **Header chain linking.** The engine keeps a chain of block hashes with no gap from the first header it checked to the tip. A hash enters it only from a header that (a) the servers agree on, (b) hashes to the block hash the servers gave for that height, (c) meets its own proof-of-work target, which must be no easier than the network limit, and (d) names the header before it (going up), or is named by the header above it (going down, to link an older confirmation). Depth is counted along this chain and nowhere else: a claimed tip adds nothing until linked headers reach it, and a confirmation below the hashes held counts only once the headers down to it are linked.
- **What that is worth on the test networks: little.** The target of each header is checked only against the easiest one the network allows. There is no retargeting rule, no expected difficulty and no comparison of total work. testnet4 allows difficulty-1 blocks (about 4 billion hashes each: seconds on a GPU, nothing for an ASIC) and keeps the 20-minute minimum-difficulty rule, so real headers at that difficulty exist; on signet the work is nominal and the block signature is not checked. So on signet and testnet4, servers that agree, or the one server a user runs, can make linked fake headers almost for free: **depth on the test networks rests on the operators agreeing**, not on work. What linking does buy there: a single lying server cannot add depth (the other operator contradicts it), and nobody can add depth with one header at a claimed tip. Before mainnet, an expected-difficulty rule (retargeting, or checkpoints shipped with the program) is needed. Checking signet block signatures is a follow-up (open question 10): it needs the signet challenge script evaluated, which is not small.
- **A confirmation must be in a block of that chain.** A status naming a height and a block hash that the checked chain does not have at that height is disagreement. Then `gz_chain_confirm_tx` proves the transaction is in the block (bytes, header, Merkle branch, coinbase).
- **A spender must spend the outpoint.** The spender a server names is fetched (so its bytes hash to its txid) and its input read; if that input is not the watched outpoint the answer is a bad proof. This closes open question 3 of section 14 as far as the input goes; the spender signature is not checked.
- **A server far behind is refused.** The comparing backend refuses tips more than 3 blocks apart. The engine also refuses a tip more than 3 blocks below what it has already checked, whichever branch it is on.
- **A server on another chain is refused** by its block 0 (section 5). One consequence is kept and now tested: a server that once answers with another network block 0 stays left out until the program starts again.
- **Timeouts** are the backend ones (15 s per request by default), and every wait of the worker is interruptible.
- **Retries** after a failed pass back off from 5 s to 5 min. The servers are never asked faster than `tip_poll_ms` when nothing fails.

## 19. Broadcast, and packages

`gz_chainw_broadcast(w, id, raw, len)` copies the transaction and queues it. **Exactly one final event** follows each accepted call (unless a reset or shutdown comes first), carrying the caller `id`:

| Outcome | Meaning | Final? |
|---|---|---|
| `GZ_CHAINW_ACCEPTED` | A server took it | Yes |
| `GZ_CHAINW_ALREADY_KNOWN` | A server refused it as one it has, and was then seen to have it | Yes |
| `GZ_CHAINW_REJECTED` | A server answered and refused; `reason` holds its words (at most 127 characters) and `server_status` the HTTP status | Yes. The worker does not argue with a server |
| `GZ_CHAINW_UNREACHABLE` | No server gave a usable answer | Not at first: it is tried again with growing waits (2 s doubling to 60 s, 6 tries), said once, and final after the last try |
| `GZ_CHAINW_NO_PACKAGE_RELAY` | A package only: no configured server has a package endpoint | Yes |

A broadcast is never dropped silently: it is refused at the call (`GZ_CHAINW_FULL` with 16 in flight) or it gets its final event. The event also carries the comparing backend per-server results, for the log. As contract v2 section 9 says, the outcome is advice: what a transaction did is learnt from the watches.

### 19.1 Packages are required for exits

SuperScalar main builds TRUC (version 3) tree transactions with a pay-to-anchor output at a tree fee rate that may be 0.1 sat/vB or zero. A parent below the relay fee is refused alone. It enters a mempool only together with the child that pays for it, as a one-parent-one-child package (`submitpackage`, Bitcoin Core 28 and later; 29.1 for the low-fee cases). So an exit cannot be published through a server that has no package endpoint.

New in the chain view: `gz_chain_broadcast_package(c, parent, child, out)` and the result code `GZ_CHAIN_UNSUPPORTED`. The Esplora backend posts `["<parent hex>","<child hex>"]` as JSON to `/txs/package` and, if that answers 404 or 405, to `/v1/txs/package`. The answer is the `submitpackage` result of Bitcoin Core; the pair counts as accepted only when `package_msg` is `success` and both txids are listed without an error. The outcome of each transaction and the server words for it are reported (`gz_package_result.parent`, `.child`; in the worker event `parent_outcome`, `child_outcome`, `parent_txid`). The comparing backend sends the package to every server on the right network; accepted by one is success; a refusal is reported before unreachability; `GZ_CHAIN_UNSUPPORTED` only when every server that could be asked has no endpoint.

**The pair is never sent one after the other instead.** A parent that needs its child would be refused alone and the failure would read as a fee problem. No endpoint is its own, explicit, final outcome with the reason text "no chain server accepts transaction packages".

A transaction already in the mempool of a server is reported, per transaction, as `ALREADY_KNOWN` when the server says so (`other-wtxid` in its answer). If the first package path keeps answering 429, the second is still tried, and the outcome is `UNREACHABLE` only when neither answered. Package outcomes are advice, as for single transactions.

### 19.2 Which public servers take packages

Checked from the build server on 2026-11-14 with requests that send no transaction (GET and OPTIONS only; nothing was broadcast to any network):

| Server | `/txs/package` | `/v1/txs/package` |
|---|---|---|
| mempool.space, signet | 404 | **exists**: OPTIONS answers 200 with `Allow: POST`; GET answers 404 "Cannot GET", as for any POST-only route |
| mempool.space, testnet4 | 404 | **exists**, the same answers |
| blockstream.info, signet | 404 "endpoint does not exist" | 404 |
| blockstream.info, testnet4 | 404 | 404 |
| mutinynet.com (a separate signet) | 404 on GET, 204 on OPTIONS (not conclusive) | 404 on GET, 204 on OPTIONS (not conclusive) |

The Esplora API description documents `POST /txs/package` ("requires Bitcoin Core 28.0 or later"), but the public blockstream.info signet and testnet4 servers do not serve it.

What is **not** established: that the mempool.space endpoint accepts a real package, which node version is behind it, and whether it relays a zero-fee TRUC parent. That can only be shown by sending one, which this work did not do.

### 19.3 What this means for exits

- On signet and testnet4 today, **one** public operator takes packages. A package therefore reaches the network through a single operator: there is no second, independent relay, and that operator can refuse or silently drop an exit. Confirmation is still checked through both operators, so a dropped package is seen as "not confirmed", not as success.
- If that operator removes the endpoint, changes its policy or is unreachable, **no exit of a low-fee tree can be published at all** through public servers. The worker then reports `GZ_CHAINW_NO_PACKAGE_RELAY` (no endpoint) or `GZ_CHAINW_UNREACHABLE` (endpoint down); it cannot do more.
- **A node of our own is needed for exits to be dependable.** That is the plain answer to the question the exit-path audit raised: Bitcoin Core 29.1 or later with `submitpackage`, behind the same package endpoint (an Esplora or mempool backend in front of it, or the small broadcast-only endpoint `spec/exit.md` already asks the chain port for). For Slice 1 on signet the single public endpoint may be enough to demonstrate an exit, once it has been shown to accept one. For anything a person relies on before a deadline (`leave_by`), it is not: the project should run a package-relaying node, and hosts should be told to run theirs. This is for the owner to decide; it is open question 11.
- The wallet rule on fees is unchanged (section 21): the child pays the lowest rate at which the pair relays.

## 20. Privacy in the worker

- **Proxy.** The worker makes no connection of its own. Every request goes through the one `gz_http` the program built, so the `socks5h://` setting of section 9 covers every request, including broadcasts and packages. Requests to this machine still bypass it.
- **User agent.** Unchanged: the generic string of section 9.
- **Not before.** A watch set with `GZ_CHAINW_NOT_BEFORE` is kept and nothing naming its txid is sent to any server, however the chain moves, until `gz_chainw_release(w, txid, delay_ms)` and the delay have passed. Release covers the transaction watch and the watches on its outputs. A later release cannot push an earlier one back; setting the watch again with the flag does not hold it back again. This meets the P7 requirement of section 9: the member sets the funding watches held back and releases them when the host reports the broadcast, plus a delay. Tested with a transport that records every request URL, and over real HTTP against the log of the stub.
- **What a server still learns.** After release, each operator sees the funding txid and the watched outpoints from this address, as section 9 says. Per-txid polling stays the default until measured.

### 20.1 Block-based watching: designed, not built

The 1.0.0 plan (`THREAT-MODEL.md` 2.8) is to match locally so that a server learns only that a wallet follows blocks. It did not fit this change. The design:

- A setting `watch_mode = blocks`, off by default. In this mode the engine never calls `tx_status` or `outspend` for a watch.
- Per new checked block: `GET /block/{hash}/txids` (every txid, about 67 bytes each, so the response cap rises to a few megabytes for this one call) and match watched txids locally. Inclusion is proved by recomputing the Merkle root from the full list against the checked header, with no request that names the txid.
- Spends of watched outpoints cannot be found from txids alone. The engine fetches the raw block (`GET /block/{hash}/raw`, up to 4 MB) and reads every input. That is one large request per block per server instead of a few small ones per watch.
- The mempool is not visible in this mode: `TX_MEMPOOL`, `TX_EVICTED` and unconfirmed spends are not told. An engine that must see an unconfirmed spend early keeps per-outpoint polling for those outpoints, or accepts one block of delay.
- To measure before choosing: about 144 blocks a day on signet, each fetched from two operators, against what the operators publish (section 10).

## 21. Fees

The worker has no fee estimator and asks no server for one. The wallet rule is to pay the lowest rate that relays (0.1 sat/vB); section 7 already fixes that rate on test networks. Nothing in `chain_watch.h` takes or returns a fee rate.

## 22. Testing the worker

Written first: nothing a chain server can send, do or fail to do may crash the worker or become a fatal error. Everything below runs in CI except where it says so.

| Test | What it covers |
|---|---|
| `chain_watch` (`tests/test_watch.c`) | The engine against a made-up chain told by two simulated servers (`tests/sim.c`: 12 heights, three branches, headers that meet the signet proof-of-work limit, a funding-like transaction, two competing spenders of one outpoint, a child), through the real Esplora and comparing backends, on a clock the test moves. Each scenario asserts the exact event sequence: confirm, reorganise out, confirm in another block; a five-block reorganisation that moves a confirmation and replaces a spender; depth going down; a double spend in the mempool, in a block, and across a reorganisation; a server that lags, and lag that turns into disagreement after 30 minutes; servers six blocks apart; servers on another chain; two servers that disagree; servers that lie about depth (an earlier height, a claimed tip, blocks that do not link, a header without proof of work, another branch below the oldest header kept); a mempool eviction and servers that differ about the mempool; a broadcast rejected then accepted, already known, unreachable with backoff, 16 at once; packages (no endpoint, the second path, refused, endpoint down) and the package parser; not-before; the watch set and its limits; the header window; retry backoff; a false spender |
| the same file, `test_hostile_servers` | 2,040 cases: each of 68 kinds of bad answer (down, timeout, 500, larger than the cap, 12 garbage bodies including valid JSON that lies, the right body cut at 12 lengths, the right body with one byte changed 40 ways) on each of 10 groups of requests, on one server, the other, and both. In every case: nothing false is told while the fault lasts, and when the servers behave again the truth arrives exactly once. The one remembered answer is counted apart: a false block 0 leaves that server out for good (section 18) |
| `chain_chainw` (`tests/test_chainw.c`) | The worker thread on the real clock: events through the descriptor and its readable state; **the loop-side calls return at once while every request stalls for 30 s** (each call under 250 ms, a thousand more calls under 2 s, a reset, then shutdown, all before the first request would have ended); shutdown while idle, between passes, in a request, with a full event queue, and without an interrupt hook; a full queue of 2 loses nothing; reset and generations, 20 resets in a row; every refusal; broadcasts and release through the worker; and 40 rounds of everything racing (random loop calls against servers that change, fail and stall every few milliseconds, then shutdown in the middle) |
| `tools/chain-tsan.sh` | The same `chain_chainw` built with ThreadSanitizer; a step of the `build (OFF)` CI job |
| `chain_watch_stub` (`tests/test_stub.c`, `tests/watch_stub.py`, `tests/watch-stub.sh`) | The worker over real HTTP: libcurl, two Esplora backends and the comparing backend against a scripted Esplora stub on 127.0.0.1 that plays two servers from scenes the test publishes. The scenarios again with exact sequences (confirm, reorganise, confirm elsewhere; double spend; lag; disagreement; lies about depth; eviction; broadcast rejected then accepted, known, unreachable; the three package outcomes; not-before checked against the request log of the stub), a 30 s stall with shutdown inside 2 s, and broken connections (dropped mid-body, dripped, two megabytes, hung up, 502) on one and both servers |
| `chain_local_servers` (label `slow`, not in CI) | Now also: a POST as JSON, and `gz_http_curl_interrupt` ending a request and a sleep from another thread |
| `chain_fuzz_parse` / `fuzz_chain_parse` | Every parser of a server answer (16 entry points) |
| `chain_fuzz_watch` / `fuzz_chain_watch` | The engine driven by a script from the fuzz input, with servers that answer any request with bytes of the input. Asserted on every event: a block named is a block of the made-up chain, a transaction called confirmed is in it, a spender spends the outpoint |
| `chain_live_watch` (opt-in, `GZ_LIVE_TESTS`, never in CI) | The worker against the two public signet servers: the tip and a known confirmed transaction. Reads only |

Counts on 2026-11-15 on the build server (gcc 15.2, `-Wall -Wextra -Werror`), the same in the Release and the AddressSanitizer + UBSan builds:

| Test | Test functions | Checks |
|---|---|---|
| `chain_watch` | 22 | 2,455 (2,040 of them the hostile-server cases) |
| `chain_chainw` | 9 | 260 |
| `chain_watch_stub` | 9 scenarios | exact sequences, see above |
| `chain_live_watch` (opt-in) | 1 | 10 |

`ctest -R '^chain_'` now runs 15 tests, all passing (the two opt-in live tests apart).

**Sanitizers.** gcc `-Werror` Release; gcc ASan+UBSan (all chain tests, including the local-server and stub tests); clang 18 ASan+UBSan (`chain_watch`, `chain_chainw`); ThreadSanitizer (`tools/chain-tsan.sh`); valgrind memcheck (`chain_watch`, `chain_chainw` at 8 rounds, both fuzz drivers): all clean on the build server. MemorySanitizer was not run on the build server (it needs an instrumented OpenSSL); the CI job runs it.

**Fuzzing.** libFuzzer with ASan and UBSan, 600 s per target on the build server: `fuzz_chain_parse` 51,363,874 runs, `fuzz_chain_watch` 352,112 runs, no finding. CI runs each for 60 s.

**Mutation probes** (`python3 -I tools/mutate-chain-watch.py`, list in `ports/chain/tests/watch_mutants.txt`): 85 deliberate faults in `watch.c`, `chainw.c` and the package code of `esplora.c` and `multi.c`, each applied to a scratch copy and run against `chain_watch` and `chain_chainw`. **83 caught, 2 survived.** The first full run caught 77; tests were added for six of the eight survivors. The two that remain:

- `w-deep-short`: the check that a confirmation older than the header window was followed for as many headers as asked. A block that old always has that many headers above it, so the check cannot fail; it is kept in case the window is ever configured smaller than the depth.
- `c-stop-on-reset`: after a reset the engine stops its pass between two requests. Without it the pass runs on and its events are discarded all the same, so only time is lost, and with the interrupt hook the requests fail at once. Nothing a test can see changes.

The libcurl changes (`http_curl.c`) are not in the mutation list: their test, `chain_local_servers`, takes 35 s per run.

**Signet check** (`chain_live_watch`, 2026-11-15, read-only, nothing broadcast): against mempool.space and blockstream.info the worker told the tip (height 330999) after 2.4 s, the known transaction of block 329438 confirmed with 6 checked confirmations after 11.4 s, and its output 0 spent by the known spender in block 329439 with 6 checked confirmations after 20.1 s; shutdown took 1 ms.

### Not tested

- The program around the worker: nothing in `program/` uses it yet (section 23).
- A real reorganisation, a real double spend, or a real package: all against the made-up chain or the stub.
- That mempool.space accepts a package (section 19.2).
- Shutdown while libcurl is inside a blocking name lookup (only possible with a libcurl built without asynchronous lookups).
- The worker on anything but Linux.


## 23. The wiring step the program owes: "P7 wiring"

**Status: done** in the P7 wiring pull request, except item 6 (the core has no "not before" field yet), item 8 (no package action yet) and the non-blocking start of item 3 (see the end of this section). Named follow-up, for after PR 41 (composite node P4.1) and its stack have merged. It was left out here on purpose: PR 41 is changing `program/` and `core/node`, and this change touches neither. It is small because the worker already has the shape contract v2 section 5 asked for.

**What to change, in `program/` only:**

1. **Build the chain view the worker owns** (`pchain.c`, `gzp_chain_open`). Keep the mainnet refusal. Build one `gz_http` (with the proxy setting), one Esplora backend per configured server and the comparing backend over them, on the loop thread, before any thread starts. Today `pchain.c` builds a single Esplora backend; the worker also runs over one, but then nothing is compared.
2. **Start the worker** with `gz_chainw_new`: `interrupt = gz_http_curl_interrupt_hook`, `interrupt_ctx = &http`, `tip_poll_ms` from `--chain-poll-ms`. Log `gz_http_curl_async_dns()` once.
3. **Replace the blocking calls.** `gzp_chain_poll` and `gzp_chain_timeout` go: the loop adds `gz_chainw_fd` to its `poll()` set and, when it is readable, calls `gz_chainw_take` until it returns 0 (at most a few per turn, as for the transport). The start-up network check and first tip stop blocking the start: they arrive as `GZ_CHAINW_SOURCES` and `GZ_CHAINW_TIP`. `--check-chain` keeps its own blocking check, since it runs no loop.
4. **Actions out.** `WATCH_TX` -> `gz_chainw_watch_tx(w, txid, depth, flags)`; `WATCH_OUTPOINT` -> `gz_chainw_watch_outpoint`; `BROADCAST` -> `gz_chainw_broadcast` with an id the program keeps. Every return must be looked at: the header marks these calls `warn_unused_result`, so ignoring one does not compile under `-Werror`. `GZ_CHAINW_BUSY` on a watch, an unwatch or a release must be retried from a backlog the program keeps, or treated as fatal for the incarnation (contract v2): some requests are made once only, and a release refused and forgotten keeps the funding watches held back for ever. `GZ_CHAINW_FULL` on a watch is fatal (the watch set is sized for the node); on a broadcast it is retried after the next final broadcast event. Size `max_requests` at least `max_watches + GZ_CHAINW_MAX_BROADCASTS` plus the releases that can come at once; `gz_chainw_new` refuses less than the first two.
5. **Events in**, one core event per worker event (one change per event, as the composite node expects):

| Worker event | Core event |
|---|---|
| `GZ_CHAINW_TIP` | `GZ_CHAIN_NEW_TIP` (height) |
| `GZ_CHAINW_TX_CONFIRMED` | `GZ_CHAIN_TX_CONFIRMED` (txid, confirmations) |
| `GZ_CHAINW_TX_UNCONFIRMED` | `GZ_CHAIN_TX_UNCONFIRMED` (txid) |
| `GZ_CHAINW_OUTPOINT_SPENT` | `GZ_CHAIN_OUTPOINT_SPENT` (outpoint, spender txid, confirmations; 0 while unconfirmed or after a confirmed spender left) |
| `GZ_CHAINW_BROADCAST`, final | `GZ_CHAIN_BROADCAST_RESULT`: accepted and already-known -> `GZ_BROADCAST_ACCEPTED`; rejected and no-package-relay -> `GZ_BROADCAST_REFUSED` with `reason`; unreachable -> `GZ_BROADCAST_UNREACHABLE`. Events that are not final go to the log only |
| `GZ_CHAINW_SOURCES` | Not to the node: the chain state of the local API (`local-api.md` 11.2) and the log |
| `GZ_CHAINW_REORG`, `TX_MEMPOOL`, `TX_EVICTED`, `OUTPOINT_UNSPENT` | No core event exists yet. Log them. `spec/exit.md` 3.2 asks for a block-disconnected event and `action.h` says a spender that vanishes "is not reported: no event for it is defined yet"; when the core gains them, these are their sources |

6. **The funding txid.** A member sets the funding `WATCH_TX` (and the watches on the funding outputs) with `GZ_CHAINW_NOT_BEFORE`, and calls `gz_chainw_release(w, txid, delay_ms)` when the host reports the broadcast. The core has no field for this yet: either `WATCH_TX` gains a "not before" flag and a release action, or the program holds the rule (a member never passes a funding watch to the worker before the host message that reports the broadcast). The first is cleaner and belongs with P4.5 (the funding engine). The host, which broadcasts itself, sets its watches without the flag.
7. **Restart from storage**: `gz_chainw_reset`, then the new node sets its watches again; no event of the old generation is delivered. **Shutdown**: `gz_chainw_free` after the node stops and before the `gz_chain` and `gz_http` are destroyed (contract v2 section 4).
8. **Packages.** When the exit engine exists, a tree transaction and its fee child go out through `gz_chainw_broadcast_package`; `action.h` needs the "broadcast package" action `spec/exit.md` lists.

**As built.**

- The start-up check stays blocking: block 0 of every server is compared with the network before the loop starts, so a server on another network still stops the program at start (exit 5), and the node is told the tip at every start. The worker starts right after it, on the same view.
- With one `--chain-url` the worker runs over that Esplora backend; with two to four, over the comparing backend.
- `program/pchain.c` keeps a backlog of up to 1,024 requests answered BUSY (and broadcasts answered FULL), asks them again in order every turn (and every 50 ms while it is not empty), and keeps the order: a new request waits behind held ones. A full backlog, FULL on a watch or INVALID is a node error for the incarnation (`chain-backlog-full`, `chain-watch-refused`, `chain-request-refused`).
- A restart from storage resets the worker (a new generation) and clears the backlog; the test engine saves its watches (record `0x0008`) and sets them again at every start (rule 4), so a crash or a restart restores them.
- The tip goes to the node once per new tip; a broadcast of bytes that are not a transaction is answered REFUSED without asking a server.
- `--test-chain-small` builds a worker with 16 watches and 32 requests, so tests can make it answer BUSY.

**Tests that come with it** (contract v2): T5 `program_chain_stall`, T9 `program_broadcast_result`, T10 `program_watches`. The scripted stub (`tests/watch_stub.py`) and the scenes (`sim_dump`) built here play all three; the worker-level versions of them are already in `chain_watch_stub`.

## 24. Changes after the review of PR 43

An independent review of head `da3d354` (2026-11-16) returned "merge after the listed fixes". What changed, each with a test that fails on the code before the fix (shown by the mutation probes of the same names, `ports/chain/tests/watch_mutants.txt`, which put the old behaviour back):

- **H1. Depth from one header.** The header chain is never started again because the tip is far ahead: it is followed `max_catchup` headers per pass. A confirmation below the hashes held is linked to them header by header (down to `max_link` blocks) before it counts, for a new watch and after a restart alike; the "deep" shortcut that took a count from `gz_chain_confirm_tx` above an unlinked block is gone. Tests: `test_no_depth_from_one_header` (the reviewer's scenario, and a new watch whose lower headers belong to another branch), the updated `test_headers`; mutants `h1-*`.
- **H2. One stalling server.** A pass ends at the first answer that says the servers cannot be asked (`UNREACHABLE`, `NO_QUORUM`), and the next pass starts with the next watch. Due broadcasts run after every chain call, and the worker hands over requests queued meanwhile between chain calls, so a broadcast does not wait for the end of a pass. Retry waits are counted from the end of the pass. Tests: `test_pass_ends_at_first_failure` (one time limit instead of eight, the wait from the end, the next watch first, a broadcast queued mid-pass sent within it) and `test_broadcast_not_held_by_a_stall` in `chain_chainw` (one server stalls on every transaction question with eight watches: the broadcast is told within 3.5 s, where it took a whole pass before); mutants `h2-*`.
- **M1. No REORG after a jump.** Follows from H1: a jump is followed, so the common block is found and the replaced blocks are told; a restart tells every hash held as replaced. Test: `test_reorg_told_after_a_jump`.
- **M2. Proof of work on the test networks.** Section 18 and `THREAT-MODEL.md` now say plainly that depth on signet and testnet4 rests on the operators agreeing. Signet block signatures and an expected-difficulty rule are open questions 10 and 13.
- **M3. Survivors.** Tests were added for the reviewer's survivors that guard a promise: the tip never takes the place of a waiting report (`k-coalesce-any`), a pass running at a reset tells nothing to the new generation (`k-emit-during-reset`), a claim in a replaced block is placed again (`r-still-placed`, `r-same-conf-*`), a confirmation that moved between the two questions is not taken (`r-conf-block`; `r-conf-height` is equivalent: a block hash fixes its height), a tip whose header is not the block named is not taken (`r-start-tip-hash`, `r-tip-moved`), the engine checks the network itself (`r-network-check`), the spender input is in the event (`r-vin-*`: S2 now spends with its second input), and twelve more (`r-release-fresh`, `r-recheck-clear`, `r-later`, `r-clear-*`, `r-reason-cut`, `r-tx-len`, `k-reset-room`, `k-free-work`, `k-enqueue-signal`, `k-child-len`, `k-count-nonfinal`, `k-reset-interrupt`). All are in `watch_mutants.txt`.
- **M4. BUSY.** The calls that can refuse are marked `warn_unused_result`; `chain_watch.h` and section 23 say that BUSY on a watch or a release must be retried or treated as fatal, and why; `gz_chainw_new` refuses `max_requests` below `max_watches + GZ_CHAINW_MAX_BROADCASTS`.
- **L2.** The header now says the first event about the chain is the tip, and that a broadcast or `SOURCES` can come first.
- **L3.** Per-transaction `ALREADY_KNOWN` from `other-wtxid`; a busy first package path no longer keeps the second untried.
- **L4.** The worker counts requests the engine refuses after the loop side accepted them (`gz_chainw_stats.diverged`); the racing test requires 0.
- **L1, follow-up.** The transport break checks that survived are equivalent with this libcurl (it enforces its size limit during the transfer, also without a stated length) or timing hidden by the 200 ms poll slice; they are listed in the pull request as follow-ups.

Counts after these changes, on the build server (gcc 15.2, `-Werror`): `chain_watch` 35 test functions, 2,547 checks; `chain_chainw` 17 test functions, 386 checks; all 15 `chain_` tests pass in the Release and the ASan+UBSan builds; `tools/chain-tsan.sh` is clean. Mutation probes: 119, 118 caught. The survivor is `c-stop-on-reset` (section 22: only time is lost). Two of the reviewer survivors were not added because they are equivalent here: `r-release-fresh` (a held watch was never asked, so it is still marked new when released) and an unlinked confirmation counted without being asked (one is always asked: whatever unlinks it also marks it to be asked again).

Follow-ups, not done here: the transport break checks of L1 (a chunked oversized body without a stated length, and the interrupt with a long poll slice) in `chain_local_servers`; signet block signatures (open question 10); an expected-difficulty rule (13); a checkpoint saved by the program to avoid linking a year of headers at start (14).

## UNWATCH (step P4.5)

The contract gained `GZ_ACTION_UNWATCH` (`action.h`): an engine drops a transaction watch (`is_tx` 1) or an outpoint watch it no longer needs. Before it, a watch could not be dropped, and a node-wide engine's watches (the funding engine's, one set per factory) added up over a run until the worker's set was full, which is fatal (exit 7). Now:

- **The composite** (`core/node/watches.c`, `gz_watch_unnote`) clears the engine's bit in the registry and lets the UNWATCH out only when no engine asks for the watch any more; otherwise it is dropped. A report for a released watch reaches nobody.
- **The program** (`program/executor.c`, `pchain.c`) passes it to the worker's `gz_chainw_unwatch_tx` or `gz_chainw_unwatch_outpoint`, which frees the place in the watch set. BUSY is held in the backlog and asked again, like a watch.
- **At a restart** the worker forgets everything (`gz_chainw_reset`) and every engine sets again only the watches it still needs (node.h rule 4), so a released watch does not come back.
- `GZ_NODE_MAX_WATCHES` is 112: the test engines 32, the slots 32, the funding engine 48 (`GZ_NODE_FUNDING_WATCHES`, task T-P45-1), held by the registry's static assertion; the worker holds `GZP_MAX_WATCHES` (256).
- Not yet: a slot that closes (`gz_watch_forget`) frees its registry entries without an UNWATCH; the worker keeps them until the next start. Slots watch nothing in Slice 1.

## WATCH_SYNCED (step P4.5; review B of PR 56, H-1)

A watch reports what it finds, but nothing when it finds nothing: a watched transaction not in the chain, or an outpoint not spent, never reports. After a start the funding engine must not take "no report yet" for "not confirmed" (a funding buried while the program was down would be given up), and no count of tips can stand in for the answer, because a block can arrive before the worker has asked about the watches set at start. So the contract has one more event:

- **GZ_CHAIN_WATCH_SYNCED** (`event.h`; `action.h`, WATCHES, SYNCED): once the chain view has asked its servers about a watch it was given (set, or set again) for the tip it last reported, it reports SYNCED for that watch, after any TX_CONFIRMED or OUTPOINT_SPENT the answer gave. `is_tx` says which watch: `txid`, or `outpoint`.
- **The worker** (`ports/chain/watch.c`): with `report_synced` (`gz_chainw_config`, off by default, so the worker's own scenario tests are unchanged), a watch's first successful answer since it was set is followed by `GZ_CHAINW_SYNCED`. A pass the servers cut short leaves the watch to be asked again, and its SYNCED comes then. A watch held back (`GZ_CHAINW_NOT_BEFORE`) gets its SYNCED after its release.
- **The program** (`program/pchain.c`) sets `report_synced`, logs `chain-synced tx=...` or `chain-synced outpoint=...:n`, and hands the node `GZ_CHAIN_WATCH_SYNCED`.
- **The composite** routes it by its watch, like a report (`gz_watch_mask`). A WATCH dropped as already set gets no SYNCED of its own; the first one's reaches every engine in the entry.
- **GZ_CHAIN_TIP_SYNCED** (integration B12): the same at every tip, not only after a start. A new tip comes before the reports it brings, so once the chain view has answered every watch it holds for a tip it reported, it reports TIP_SYNCED with that `height`, once per tip, after those reports. The worker sends it at the end of the first pass that looked at the tip and answered every watch (no pass cut short, no answer put off); the program logs `chain-tip-synced`; the composite gives it to whoever takes tips. TIP_SYNCED and NEW_TIP carry the tip block's hash (review B of PR 56, second confirmation, G-2): a TIP_SYNCED for a block replaced at the same height is not this tip's.
- **GZ_CHAIN_WATCH_FAILED** (review B of PR 56, second confirmation, G-1): a watch no pass can answer must not hold back every tip, since a host can name a funding input spent long ago. A confirmation more than `max_link` below the tip gives `GZ_CHAIN_TOO_LARGE` on every pass; with `report_synced` the worker tells it once for that watch (`GZ_CHAINW_WATCH_FAILED`, the result in `sources`), asks no more about it until it is set again, and leaves it out of TIP_SYNCED and of the sources. The program logs `chain-watch-failed` and the composite routes it by its watch. Other failures (servers that cannot be asked, disagree or prove nothing) are about the servers, not one watch, and still hold back the tip: waiting is the safe side there.
- **Only a depth fails a watch; an answer put off is pending** (review B of PR 56, third confirmation). `GZ_CHAIN_TOO_LARGE` also means an answer too large to fetch (Esplora caps the raw bytes of a transaction or a spender at half of `max_response_bytes`), which a host can cause with an inflated witness: that is a size, not a depth, and may be answered later, so it no longer fails the watch. Neither does a confirmation still being linked (`max_catchup` headers a pass, which a host can make take minutes to hours by naming an input spent long ago), nor a spender gone between two questions. Each is retried at the next pass; after `GZ_CHAINW_DEFER_PASSES` passes in a row the worker tells the watch pending once (`GZ_CHAINW_WATCH_PENDING`; the program's `GZ_CHAIN_WATCH_PENDING`, logged `chain-watch-pending`, routed by its watch), and TIP_SYNCED no longer waits for it. When its answer comes, its reports and its SYNCED follow. The funding engine makes that factory alone wait meanwhile, and fails it closed `GZ_FUND_PENDING_GRACE` blocks past its deadline if the answer never comes.
- **A proof has room for any transaction a block can hold** (review of PR 72, P-2): the transaction and its block's coinbase are fetched with room for `GZ_TX_CONSENSUS_MAX_BYTES` (4,000,000), and so is a watched input's spender. Esplora fetches a transaction larger than its response buffer into a buffer of its own when the caller gives more room than `GZ_TX_MAX_BYTES`; every other call keeps its cap. So neither a funding with an inflated witness nor a block with a large coinbase is beyond proof. Only a transaction in the mempool is still checked within the usual cap: it is told pending, and answered from its status once confirmed.
- **One proof per transaction and block** (integration B15): a proof that a transaction is in a block is kept (the last 16), and the block is checked against the headers at each use, so a funding watched both itself and as a watched input's spender is proved once. The other half of B15, telling a new tip before a long pass of proofs ends, is not done: TIP_SYNCED needs a pass that answers every watch at one tip, and cutting passes for the tip would need a new rule for that; on signet the delay is seconds.
- **The funding engine** takes no deadline decision for a factory restored at start until every watch of it has its SYNCED, and none at any tip until that tip's TIP_SYNCED. While the servers cannot be asked, none comes and the engine waits: the safe side.
- Tests: `chain_test_watch` `test_synced` (the worker), `node_watch_release` (the routing), `program_chain_watch` case 2b (the program logs it after a restart), and the funding engine's lag tests.

- **A transaction's bytes are compared without the witness** (C-2, the confirmation of the review of PR 72). The comparing backend checks that each server's bytes hash to the txid asked for, then compares the servers by txid, which covers every byte but the witness. A host can make two valid witnesses for its funding (one txid, two wtxids) and give each of a member's servers its own; compared byte for byte, a member's watch on a funding input answered `GZ_CHAIN_DISAGREE` on every pass and held back every watch's TIP_SYNCED until the funding was mined. Nothing in the chain port reads a witness (the proof needs the txid and the coinbase's input, the spend check the spender's input), so either server's bytes will do.
