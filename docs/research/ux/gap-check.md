# Gap check: options map against SuperScalar sources

Date: 2026-11-11. Read-only analysis. Nothing was posted, pushed or changed anywhere else.

Checked document: `docs/ux/options-map.html` (read in full), with `docs/DESIGN.md` and `docs/KNOWLEDGE-BASE.md` for decisions already made.

## How to read the marks

- **V** = VERIFIED. I read it myself this session. Pointer given.
- **D** = VERIFIED BY A DELEGATED READER this session. A helper session read the source in full and reported the pointer. I spot-checked a sample of these pointers (the "account limit" and "deposit insurance" lines in t1242.md, the client flags in `superscalar_client.c`, the creation form labels in `FactoryCreate.tsx`) and they matched. I did not re-read every line. Treat D as "read today, not double-checked".
- **R** = RECALLED. Not read today.

Scopes: S1 My conditions, S2 Lobby terms, S3 Wallet, S4 Watching, S5 Connections, S6 Hosting. "Status" and "Never" are the map's two other lists.

Source locations (scratch area, outside the project):
`C:\Users\user\AppData\Local\Temp\claude\7b754e3b26b2652b\15dad3e8-7e85-4563-99c8-ac4587dda7c0\scratchpad\gap\` holds clones of `superscalar-wallet` (the Soup wallet), `soup-rendezvous`, `SuperScalar`, `superscalar-docs` (the website's source) and `superscalar-cln`. The posts are `...\scratchpad\t1143.md` and `t1242.md`.

Short path names used below: **FE** = `superscalar-wallet/apps/frontend/src`; **SR** = `soup-rendezvous`; **SS** = `SuperScalar`; **site** = `superscalar-docs` (same text as https://superscalar.win); **cln** = `superscalar-cln`; **PR56** = `lightning/blips` pull request 56, file `blip-0056.md`.

---

## A. What each source has, and whether the map covers it

### A1. Soup wallet (`8144225309/superscalar-wallet`) and its listing server (`soup-rendezvous`)

The Soup wallet is a web screen in front of a Core Lightning node. It does not hold keys. (V: `superscalar-wallet/docs/SEED_BACKUP.md:3-6`.)

| Capability, option, screen or status | Pointer | Mark | In options map? |
|---|---|---|---|
| Four top tabs: Dashboard, Bookkeeper, Factories, Connect | FE/components/ui/Menu/Menu.tsx:11-16 | D | No. The map lists options, not screens |
| List of many factories at once, with role filter (All, LSP, Client) and search | FE/components/factories/FactoryList/FactoryList.tsx:57,228,393-431 | D | No. Map statuses speak of one lobby and one factory |
| Factory buckets: live, failed or abandoned, history, hidden; hide; discard a failed record | FactoryList.tsx:58,89-106,176-198 | D | No |
| Counters across all factories (active, signed, dying or expired) | FE/components/factories/FactoriesOverview/FactoriesOverview.tsx:61-116 | D | No |
| Factory detail: lifecycle, role, members, updates used of maximum, channels, creation block, end block, old-state incidents, payout transaction status, funding id | FE/components/factories/FactoryDetail/FactoryDetail.tsx:373-460 | D | Partly. Status list has Live, Winding down and so on, and the dates. Not updates left, payout status or old-state incidents |
| Signing progress steps: proposed, nonces, partial signatures, complete, failed | FE/components/factories/CeremonyProgress/CeremonyProgress.tsx:33-60 | D | Partly. Lobby status "Signing" only |
| End-date warnings by blocks left (danger at 144, warning at 432) | FE/components/factories/ExpiryWarnings/ExpiryWarnings.tsx:42-46 | D | Yes. S4 "Warn me this early", Status "Date near" |
| Old-state ("breach") status card | FE/components/factories/BreachStatus/BreachStatus.tsx:32-52 | D | No. No status for "an old state was published and answered" |
| Ladder timeline: one bar per factory from creation to end, with a now marker | FE/components/factories/LadderingTimeline/LadderingTimeline.tsx:37-92 | D | Partly. S6 Schedule mentions the ladder. No view of it |
| "Close safety" indicator: safe, caution, unsafe | FactoryDetail.tsx:63-112,608-617 | D | No |
| Host creation form: total funding, most members, size per member, host's spare liquidity per leaf | FE/components/factories/FactoryCreate/FactoryCreate.tsx:464-507 | D | Yes. S2 channel size, spare liquidity; S6 templates |
| Leaf type (pseudo-Spilman or older type), wide-leaf factor, members per leaf | FactoryCreate.tsx:533-573 | D | Partly. S2 "Tree shape". Gazpacho fixed one member per pseudo-Spilman leaf, so most of this is decided, not an option |
| Lifetime preset: 30+3 days, 7+2 days demo, custom; active blocks; winding-down blocks | FactoryCreate.tsx:591-616 | D | Partly. S2 "Lifetime" is days only. The winding-down length is not a term |
| Most updates of the upper layers ("epochs") | FactoryCreate.tsx:618-628 | D | No |
| Blocks before the end at which the app starts leaving alone | FactoryCreate.tsx:631-638 | D | Yes. S4 "Leave before the end", margin above a floor |
| Ladder cadence in hours; open the next factory automatically | FactoryCreate.tsx:641-670 | D | Yes. S6 Schedule |
| Finish automatically at wind-down (last update and signed payout) | FactoryCreate.tsx:671-684 | D | No. Should be fixed behaviour, see B |
| Accept joiners automatically; banned keys for this factory | FactoryCreate.tsx:707-720,765-776 | D | No. S6 has "Remove a member" only |
| Minimum to start; deadline; "starts at capacity, or at the deadline with the minimum" | FactoryCreate.tsx:724-763 | D | Yes. S2 Start rule |
| Allow BOLT 12 offers; allow multi-part (AMP); smallest and largest payment | FactoryCreate.tsx:783-818 | D | No |
| Advertise on Nostr (on or off); which chain | FactoryCreate.tsx:832-869 | D | Yes. S2 "Who can find it"; S3 Network |
| Different size per member ("allocations override") | FactoryCreate.tsx:886-913 | D | No. Map has one channel size per lobby |
| Host preview: ladder at steady state, wait for a new member, on-chain cost per month, capital per factory and per ladder | FactoryCreate.tsx:918-955 | D | Yes. S6 Terms templates "live preview" |
| Planner warnings: wind-down under 24 hours, ladder over 30 factories, payment-deadline budget under 2016 blocks | FE/utilities/factory-planner.ts:207-308 | D | Partly. S6 preview "problems" |
| Policy shown to the member, 16 rows: fees, payment size limits, most payments in flight, deadline deltas, size range per join, proof required, rotation interval | FE/components/factories/FactoryPolicyView/FactoryPolicyView.tsx:127-142 | D | Partly. S2 has fees, size, lifetime. No payment limits or deadline terms |
| Full policy list, 59 fields in 13 groups, with defaults | superscalar-wallet/docs/FACTORY_POLICY_V1.md:1661-1719 | V | Partly. See B for the fields with no home |
| Member's signing preferences: 12 limits compared with the policy | FE/components/factories/SigningPrefs/SigningPrefs.tsx:71-153; FE/utilities/policy-validator.ts:37-50 | D | Partly. S1 has the same idea with different rows. No payment-limit rows |
| "Sign automatically when policy passes" on or off; held proposals; approve or refuse | SigningPrefs.tsx:299-322; FE/components/factories/ReviewProposal/ReviewProposalModal.tsx:132-151 | D | Covered as a decision. Map "Never": readying is the consent, no prompt mid-round. This is a deliberate difference |
| Review screen: "your stake", all allocations, policy against my preferences, verdict | ReviewProposalModal.tsx:209-331 | D | Yes. The S1 and S2 comparison |
| Missed, refused and expired signing rounds, as an audit list | FE/components/factories/ReviewProposal/MissedCeremoniesBanner.tsx:51-53 | D | Yes. S4 Activity record |
| Host preferences for join requests: auto-accept threshold, smallest and largest requested size, required reputation; per-factory overrides | FE/components/factories/OperatorPrefs/OperatorPrefs.tsx:52-73; OperatorPrefsCard.tsx:36-59 | D | No |
| Host inbox of join requests: approve, refuse with a reason, bulk actions; banner "N pending" | FE/components/factories/LspOperatorConsole/LspOperatorConsole.tsx:60-99,197-238; JoinQueueBanner.tsx:78-90 | D | No |
| Known peers: label, note, reputation score, ban | FE/components/factories/KnownPeers/KnownPeers.tsx:133-277 | D | Partly. S1 has favourite, avoid and block lists for the member. Nothing for the host |
| Member asks for a size when joining (default 100,000 sats) | FE/components/connect/JoinFactoryModal/JoinFactoryModal.tsx:249-260 | D | No |
| My join attempts: sent, queued, accepted, signed, rejected, cancelled, timed out, already in | FE/components/connect/MyJoinAttemptsCard/MyJoinAttemptsCard.tsx:67-78 | D | Partly. Status "For me" has five values. No list of attempts |
| Invitation link and QR, with size range, label, expiry (never, 1 day, 1 week, 30 days, 90 days), prefer onion address | FE/utilities/inviteUrl.ts:3-31; FE/components/factories/InviteModal/InviteModal.tsx:162-204 | D | Partly. S2 "Invitation (link or QR)". No expiry or address choice |
| Warning that an invitation shows the host's network address; trust tick-box before connecting to a public address | InviteModal.tsx:214-217; FE/components/factories/AcceptInviteModal/AcceptInviteModal.tsx:213-220 | D | Partly. S5 Privacy note covers the member side only |
| Connect to a host by typing its key and address | FE/components/connect/ManualConnectModal/ManualConnectModal.tsx:99-164 | D | No |
| Host actions on a factory: start signing now, open channels, recover stuck, rotate, cooperative close, force close | FactoryDetail.tsx:140-277,538-681 | D | Partly. S6 has start, cancel, remove, wind down. No host force close, no "recover stuck" |
| Member action: force close, with a cost and delay warning | FactoryDetail.tsx:263,663-681 | D | No. Map has automatic leaving only |
| Listing settings: which listing verifiers ("coordinators") to accept, per network; relays; caps; refresh; show weak-proof listings or not | FE/components/connect/RendezvousSettings/RendezvousSettings.tsx:220-416 | D | Partly. S5 "Listings: Nostr relays". No choice of whose listings to accept |
| Three kinds of host proof: has a public channel, holds coins, is reachable | SR/README.md:95-99; SR/PROOF_OF_CHANNEL.md; SR/PROOF_OF_UTXO.md; SR/PROOF_OF_PEER.md | D | Partly. S1 "proof required or not", S2 "Host's record and proof". No kinds of proof |
| Listing lifetime: 30 days on test networks, 14 on mainnet; host must renew | SR/README.md:57-68 | D | No. A host duty |
| Listing badges: source of proof, "self", "old state seen", "open now" | FE/components/connect/ConnectList/ConnectList.tsx:147-152,555-581 | D | No |
| Sample-data switch on the listing page | ConnectList.tsx:459-470 | D | No. Not needed |
| Several nodes in one wallet, node picker with health dots | FE/components/ui/NodePicker/NodePicker.tsx:351-386 | D | No. Does not apply: Gazpacho carries its own node |
| Banner "Not real bitcoin" on test networks | FE/components/ui/Header/Header.tsx:43-53 | D | Partly. S3 Network. No always-visible marker in the rules |
| Settings: fiat currency, sats or BTC, fiat beside sats, theme | FE/components/ui/Settings/Settings.tsx:175-177 | D | Partly. S3 has units and theme. No fiat |
| Glossary (15 terms), What's new, version, show my node id as QR | FE/components/modals/Glossary/Glossary.tsx:45-125; Settings.tsx:103-131 | D | No |
| Password login, reset password, single sign-on, login rate limits | FE/components/modals/Login/Login.tsx:122-151; superscalar-wallet/README.md:108 | D | Partly. S3 "Access to the app" |
| Export and import of display settings only | superscalar-wallet/docs/SEED_BACKUP.md:8-38 | V | No |
| Backup: the UI backs up nothing that matters; seed and channel database are the node's job | SEED_BACKUP.md:40-113 | V | Yes. S3 covers this better than Soup did |
| Audit log of every changing action, kept on the server | superscalar-wallet/docs/AUDIT_LOG.md (headings only) | V | Partly. S4 Activity record |
| SQL terminal | FE/components/modals/SQLTerminal/SQLTerminal.tsx:310-352 | D | No. Not needed |
| Lightning send (invoice, offer, keysend) and receive (invoice, offer) | FE/components/cln/CLNSend/CLNSend.tsx:237-361; CLNReceive.tsx:187-246 | D | No. The map has no payments scope |
| Overview numbers: balance, most I can send, most I can receive | FE/components/cln/Overview/Overview.tsx:83-169 | D | No |
| On-chain deposit, withdraw (send all, custom fee rate), transaction list | FE/components/cln/BTCDeposit, BTCWithdraw/BTCWithdraw.tsx:159-288 | D | Yes. S3 On-chain funds, fee rate |
| Accounting graphs: account events, flow of sats, volume, by period | FE/components/bookkeeper/ | D | Partly. S6 Earnings for hosts. Nothing for members |
| Per-factory activity: forwarded, received, sent, 12-month chart, last 10 events | FE/components/factories/FactoryActivityCard/FactoryActivityCard.tsx:282-407 | D | Partly. S6 Earnings |

### A2. Website `superscalar.win` (source: `superscalar-docs`; the helper found the live site byte-identical to the clone)

| Capability or claim | Pointer | Mark | In options map? |
|---|---|---|---|
| Join with no on-chain coins; the provider funds everything | site/index.md:32; how-it-works/building-a-factory.md:130 | D | Yes. S3 "Members need none to join" |
| Everyone must be online together when the factory is built | building-a-factory.md:21 | D | Yes. S2 Signing time budget |
| Who pays: provider pays funding and tree fees; member pays for receiving room; whoever publishes pays to leave alone | building-a-factory.md:121-128 | D | Partly. No term says who pays to leave alone. Gazpacho decided the fee is built in from the host's side |
| If a member drops during building, the provider restarts without them | building-a-factory.md:132-139 | D | Yes. Status "ready but not counted", Failed |
| Buying receiving room: member asks, member and provider co-sign, nothing on chain | how-it-works/updating-state.md:35-62 | D | Partly. S1 has the fee limit, S6 has "Sell receiving room". No member-side action or state |
| Each purchase uses up a little channel value as a fee | updating-state.md:88-90 | D | No |
| Provider nudges an offline member with a push message | updating-state.md:74-78; how-it-works/client-migration.md:17 | D | Partly. S4 Reminders are the member's own. No host-sent wake-up |
| Re-signing the whole factory in place with a new end date; needs everyone; membership cannot change | updating-state.md:102-121 | D | No |
| Ladder: about 30 days active, 3 days winding down, one new factory a day, about 33 at once | core-concepts/laddering.md:40-46 | D | Yes. S6 Schedule; S2 Lifetime |
| Member duty: come online once in each 3-day wind-down, about monthly | client-migration.md:106 | D | Yes. Status Dates |
| Three ways to move: pay across over Lightning, swap to on-chain, assisted exit with key hand-over | client-migration.md:33-85 | D | Partly. S1 "Automatic move". No choice or term for the way of moving |
| Provider may refuse an assisted exit | deep-dives/security-model.md:99-107 | D | No |
| Missing the wind-down: one page says paid on chain at the end, two say "must force-close" | client-migration.md:99-104; laddering.md:96,158-165 | D | Partly. Map says each date tells what happens at zero. The answer itself is not settled in the sources |
| Cooperative close: one transaction, each member checks its own balance first | how-it-works/cooperative-close.md:23-45 | D | Partly. S6 "Wind down". No member view |
| Partial cooperation: only the absent members' branches go on chain | cooperative-close.md:74 | D | No |
| Leaving alone: steps, up to about a week, about three times the cost of a normal close | how-it-works/force-close.md:18-56,130-142; deep-dives/network-economics.md:56-71 | D | Partly. Status "Leaving alone (step by step)", S4 longest absence. No cost or time estimate shown |
| One member leaving alone pushes neighbours in the same branch on chain | force-close.md:82-106 | D | No. No status "a neighbour left; your branch is on chain" |
| Payout at the end date pays every member; anyone with a copy can broadcast | force-close.md:144-148; how-it-works/client-recovery.md:59 | D | Partly. Status "Factory ends on". Gazpacho's end-date payout is still a draft |
| What to back up: the changing database and the key | client-recovery.md:29-34 | D | Yes. S3 |
| Recovery runs in rounds as parents confirm | client-recovery.md:46-51 | D | Yes. Status "Leaving alone (step by step)" |
| Watcher holds no keys; several can run; it reports whether it is up | deep-dives/watchtower.md:26-51 | D | Yes. S4 |
| Member's response to a provider caught forging: continue, halt (default), close; a lasting "do not reconnect" marker | deep-dives/lsp-misbehavior.md:17-37 | D | No |
| Provider's spare liquidity is split among the leaf's members if the provider publishes an old state | core-concepts/l-stock-redistribution.md:28-39 | D | No. Not a setting; a fact the app may need to show |
| Fake-member weakness; advice to keep an outside reserve | l-stock-redistribution.md:91-93 | D | Partly. S3 Fee reserve |
| Fallback: provider opens an ordinary on-chain channel beside the factory one; payments split across both | extensions/jit-channel-fallbacks.md:20-68 | D | No. Gazpacho decided this is off for the first release |
| Adding or withdrawing funds by splice: future | extensions/splicing-integration.md:26-56 | D | No. Not planned |
| Provider income: sells receiving room and charges a recurring fee | foundations/what-is-an-lsp.md:45-51 | D | Partly. S2 Fees has no recurring fee |
| Flat monthly fee hedged with fee futures: no market yet | extensions/feerate-futures.md:48-84 | D | No. Not planned |
| Balance below the cost of leaving cannot be recovered; provider should set a minimum | security-model.md:132-133 | D | No |
| Limited number of upper-layer updates (16 by default) | security-model.md:135-136 | D | No |
| Members can change provider at a factory change | what-is-an-lsp.md:84-88 | D | Partly. S1 "Off (leave instead)". No "move to another host" |
| Pooled-capital factories with shared fees | extensions/cooperative-factories.md:11-18 | D | No. Conflicts with "host funds everything" |
| The site has no wallet screenshots or downloads | helper's report, whole site | D | — |

### A3. SuperScalar repository (`README.md`, `docs/`, the two programs' flags) and the Core Lightning plugin

| Option, flag, command, status or duty | Pointer | Mark | In options map? |
|---|---|---|---|
| Network choice; mainnet needs an "I accept the risk" flag and other gates | SS/tools/superscalar_lsp.c:1653,2489-2511 | D | Yes. S3 Network; Never "Refusing mainnet" |
| Members to gather; funding amount | superscalar_lsp.c:1625-1627 | D | Yes. S2 |
| Tree shape per level; fixed top levels; states per layer; blocks per step; start refused if the worst exit is over 2016 blocks | superscalar_lsp.c:1832,1865,1825,2596-2613; SS/docs/factory-arity.md:125-172 | D | Partly. S2 Tree shape. The 2016-block ceiling is a "problem" the host preview must show |
| Active blocks, winding-down blocks, absolute end | superscalar_lsp.c:1811-1813,1673 | D | Partly. S2 Lifetime |
| Confirmations: funding 3, close 6, penalty 6, sweep 6; one flag sets all | superscalar_lsp.c:2160-2168 | D | Partly. S2 "Confirmations before live" only |
| Fee rate, fee source (node, recent blocks, web service, fixed), most to spend on a fee bump, share of value to spend | superscalar_lsp.c:1643,2156,2228-2233 | D | Partly. S3 "Automatic or Fixed". No ceiling on fee spending |
| Routing fee in parts per million | superscalar_lsp.c:2095 | D | Yes. S2 per-payment fee |
| Host's share of each channel at the start (default 100%) | superscalar_lsp.c:2097-2100 | D | Yes, as a decision: members start at zero |
| Where members are placed in the tree: in order, inward, outward, grouped by time zone | superscalar_lsp.c:2122-2128 | D | No |
| Who keeps routing fees: host takes all, or shared with members; share per member; settlement interval | superscalar_lsp.c:2130-2143 | D | No |
| Member refuses a factory whose profit share is too low | SS/tools/superscalar_client.c:2471 | V | No |
| Automatic rebalancing of channels and its threshold | superscalar_lsp.c:2145-2150 | D | No |
| Fallback on-chain channel: size, off switch; member "accept automatically" | superscalar_lsp.c:1815-1817; superscalar_client.c:2470 | V/D | No. Off in Gazpacho's first release |
| Rotation that waits for members to reconnect; rotation with only the members who are online | superscalar_lsp.c:1819; SS/docs/pre-mainnet-design-decisions.md:218-224 | D | Partly. S1 auto-move; Status "Moving to the next". No state for "moved without you" |
| Host sends events to a web address or a script: rotation needed, factory ending, payment received, queue item | superscalar_lsp.c:1821-1823; SS/src/notify.c:156-159 | D | No |
| Link to an ordinary Lightning node through a bridge; start order; limits (no keysend, no multi-part, one use per payment hash) | SS/docs/lsp-operator-guide.md:390-627 | D | Partly. S5 "Host's Lightning node link" with a four-step test. No limits shown |
| Host keys: key file, passphrase, 24 words, restore from words | superscalar_lsp.c:1657-1659,2176-2180 | D | Partly. S3 Recovery phrase. Nothing says the host's key cannot be changed while factories are open |
| Host backup: database plus key, encrypted; verify; restore; snapshot before each rotation; restore drill | superscalar_lsp.c:2182-2186,1645; SS/docs/mainnet-runbook.md:151-215 | D | Partly. S3 Factory backup is written for a member |
| Never run a second copy of a host while a factory is open | mainnet-runbook.md:104-109 | D | No |
| Tor: proxy, hidden service, Tor only; listen port; most connections; rate limits; wait time per member | superscalar_lsp.c:2108-2118,1623,2073-2088 | D | Partly. S5 Tor later, local port. No host address or reachability |
| Publish the host's key; member must pin it | mainnet-runbook.md:281-309; superscalar_client.c:2843 | D | Yes, by design: host key pinned, invitations carry it |
| Find a host by domain name | superscalar_client.c:2845 | D | No |
| Chain view: full node, or compact filters with fallbacks | superscalar_lsp.c:2190-2192 | D | Yes. S5 |
| Logs, diagnostic report, heartbeat line, metrics, admin interface | superscalar_lsp.c:1635,2158,2210,2104,2222-2226 | D | No |
| What to alert on: reorganisation, old state seen, slow signer, signing stuck over 10 minutes, node link down, disk low, low funds | mainnet-runbook.md:317-327 | D | Partly. Status "Needs attention" has nine items, none of these host ones |
| Host commands: pay, rebalance, status, rotate, close, make an invoice for a member, sell receiving room, pay an outside invoice | SS/src/lsp_channels.c:6651-6858 | D | Partly. S6 Running a factory |
| Offers (BOLT 12); buying liquidity by the LSPS standard messages | superscalar_lsp.c:2204-2206; SS/src/lsps.c:84-169 | D | No |
| Plugin commands: funding pre-check, abort a stuck signing, close a departed member's channel, confirm closed, scan for an outside close, check after a reorganisation | cln/SUPERSCALAR_RPC_SPEC.md:16-46 | D | No |
| Member: leave alone on demand, run again as each level matures; sweep; destination | superscalar_client.c:2862-2866 | D | Partly. Status "Leaving alone (step by step)". No manual start, no destination |
| Member: response to a forged revocation (continue, halt, close); separate setting for the leaf; "poisoned" marker file | superscalar_client.c:2482-2487,2619-2620 | V | No |
| Member must run with chain access or old states are not noticed | SS/docs/client-user-guide.md:124,270 | D | Yes. S4, S5 |
| Member seed is stored unencrypted in the reference code | SS/docs/release-notes/release-notes-0.2.0.md | D | Yes, better: Gazpacho encrypts at rest |
| Statuses: factory active, dying (no new liquidity sales), expired; closed by whom; frozen while funding re-confirms; updates remaining | SS/include/superscalar/factory.h:116-118; mainnet-runbook.md:458-463; cln/README.md:67-113 | D | Partly. No "re-confirming", no "updates remaining", no "how it ended" |
| Statuses of penalty, sweep and fee-bump transactions | cln/factory_state.h:178-308 | D | Partly. "Leaving alone (step by step)" |
| End-date payout is unsigned on one creation path in the reference code, so it is not yet a safe backstop | SS/docs/trustless-offline-tolerant-rollover-plan.md:32-38,198-206 | D | Known. The map says the end-date payout is not finished |
| Out-of-band contact for every member; latency target | mainnet-runbook.md:59-60,122 | D | No |
| Read-only dashboard with 12 tabs | SS/docs/demo-walkthrough.md:476-491 | D | No. Developer view |

### A4. ZmnSCPxj's posts (`t1143.md`, `t1242.md`)

All rows are from ZmnSCPxj's own text unless marked.

| User-visible concept or duty | Pointer | Mark | In options map? |
|---|---|---|---|
| Present it as a "Bitcoin-denominated checking account"; copy banking apps | t1242.md:1107-1125 | D | Not applicable. Gazpacho chose host, member, lobby |
| "Account limit": the most you can hold or receive; inverse of a credit card | t1242.md:1163-1171 | V | Partly. S2 "Channel size". No status that shows it |
| Under the hood: the limit is capacity minus a reserve | t1242.md:1172-1175 | V | No |
| Show balance and limit close together, with the room left | t1242.md:1184-1191 | V | No |
| "Upgrade account limit" = buy receiving room, for a price the provider quotes; any time; takes minutes to an hour; payments continue | t1242.md:1192-1205,1783-1792 | D | Partly. S1 fee limit; S6 sell. No flow |
| The limit cannot be hidden; say before the first deposit that raising it costs money | t1242.md:1206-1248 | D | No |
| Option: let the app raise the limit automatically as the balance nears it | t1242.md:1779-1781 | D | No |
| Sold receiving room is never taken back or refunded | t1242.md:449-451 | D | No |
| Each purchase makes leaving alone bigger and dearer | t1242.md:502-504,794-795 | D | No |
| Who must be online for a purchase: buyer, leaf neighbour, provider | t1242.md:624-628 | D | Does not apply with one member per leaf |
| "Deposit insurance", limited (default, free) or unlimited (needs the member's own on-chain reserve) | t1242.md:268,1292-1348 | V | Partly. S3 Fee reserve, Status "Reserve low". No statement of how much I can get back alone |
| Coverage is fixed at the start of the month; balance can exceed it after a mid-month purchase | t1242.md:1312-1331,1361-1368 | D | No |
| Remind at 90% of coverage | t1242.md:1681-1684 | D | No |
| Reserve can be moved back; then coverage is limited again | t1242.md:1332-1340,1686-1694 | D | Partly. S3 On-chain funds |
| Below a minimum balance, leaving alone recovers nothing; it goes to miners | t1242.md:1705-1710,2133-2139 | D | No |
| First screen: "open an account"; may offer a choice of providers | t1242.md:1425-1428 | D | Yes. Listings and lobbies |
| Three ways to start: Standard (a scheduled time, within 48 hours), Express (pay an invoice, usable at once), Onchain (deposit to an address) | t1242.md:1432-1440,1500-1634 | V/D | Partly. Only Standard, as the lobby. The other two are decided as later |
| Terms shown at opening: monthly fee, waiver rule, starting limit, upgrade price, date and time of the next fee | t1242.md:1445-1457 | D | Partly. S2. No recurring fee, no waiver |
| Standard start: cannot send or receive until the scheduled time is attended; one alternative time | t1242.md:1500-1524 | D | Partly. Lobby status. No "joined, cannot pay yet" |
| Anti-spam: minimum first deposit or a starting fee | t1242.md:1526-1543 | D | Yes. S1 and S2 seat cost, marked open |
| "Monthly maintenance fee" is really the move to the newest factory | t1242.md:1126-1135,1471-1490 | D | Partly. S1 auto-move; Dates |
| Duty: be online with notifications allowed at the fee time; further dated windows; miss all and the account is closed to on-chain | t1242.md:1458-1469 | D | Partly. Dates. No list of retry windows |
| App should pay the fee automatically by default | t1242.md:1839-1845 | D | Yes. S1 auto-move default On |
| Provider wakes the app; LSPS5 webhooks through the app vendor's server | t1242.md:1051-1100,1847-1859 | D | No. Gazpacho is a local program, not a phone app |
| During the move: sending and receiving work; no limit upgrade | t1242.md:1867-1920 | D | No |
| The app must enforce its own limit during the move (double capacity for a moment) | t1242.md:1960-1983 | D | No. Belongs in "Never a setting" |
| Paid but missed: provider retries on later days, then force-closes and refunds the fee | t1242.md:1887-1899 | D | No |
| Closing: assisted (needs nothing pending) or forced (any time, either side); once started, no send, receive or upgrade | t1242.md:1988-2002 | D | Partly. Status "Leaving alone". No member-started cooperative leave |
| App steers to cooperative closing first; contact the provider first | t1242.md:1301-1304,1711-1713 | D | No |
| Assisted closing: cost estimate with a warning that fees move; member proposes a fee rate and pre-pays; member picks confirmation depth | t1242.md:2035-2078 | D | No |
| Forced closing by timeout (slow, cheap) or by publication (fast, dear); durations of weeks to two months | t1242.md:2105-2171 | D | Partly. S4 "Leave before the end" |
| After closing: sweep to an address, or reopen | t1242.md:2012-2017,2176-2178 | D | Partly. S3 On-chain funds |
| Outgoing payments show "pending" with funds locked | t1242.md:1768-1774 | D | No |
| Incoming payments need a longer final deadline; some senders may fail | t1242.md:786-790; t1143.md:1063 | D | No |
| Provider tracks uptime, groups members by active hours, gives high-uptime members cheaper exits | t1242.md:947-978 | D | No |
| Reward for the neighbour who helped a purchase | t1242.md:939-943 | D | No. Does not apply |
| Two pricing models: sell receiving room and charge no routing fee, or charge routing fees | t1242.md:935 | D | Partly. S2 Fees has both, with no "model" choice |
| At the end date funds default to members; provider must act first | t1242.md:328-335; t1143.md:1187-1200 | D | Known. KNOWLEDGE-BASE section 3 |
| Provider's capital is locked like a term deposit; a member who exits instead of moving can lock it a month | t1242.md:864-866,1213-1235 | D | Partly. S6 Earnings "idle capital" |
| A member with zero balance who vanishes costs the provider an on-chain path | t1242.md:392-395 | D | No |
| Restoring an old backup can leak a key through a reused nonce | t1242.md:407-409 | D | Yes. Never: one-time secrets; restored backup never publishes |
| New keys for each factory | t1242.md:412-414 | D | Not a setting |
| Move to another provider at the end | t1242.md:318; t1143.md:491 | D | No |

### A5. bLIP-56 (lightning/blips pull request 56, "Pluggable Channel Factories", open draft)

| Parameter or rule | Pointer | Mark | In options map? |
|---|---|---|---|
| Early-warning time per factory, in blocks. Payments whose deadline is nearer than this are refused | PR56 Glossary; `channel_in_factory` section | D | Partly as a design rule (DESIGN section 7). Not shown to the user |
| Invoices should carry a longer final deadline (add the early-warning time) | PR56 same section | D | No |
| Outgoing payments lock funds longer on failure | PR56 same section | D | No |
| Channels in a factory never wait for confirmations of their own | PR56 same section | D | Covered by S2 "Confirmations before live" for the factory |
| Channel is "pending" until the factory signing completes | PR56 same section; Overview | D | Yes. Lobby status Signing, Funding |
| Closing a channel is handed to the factory layer; the channel's own close waits until the tree is on chain | PR56 same section | D | Yes. Status "Leaving alone (step by step)" |
| Factory layer may order "forget this channel" | PR56 same section and Rationale | D | No. A status for "ended with nothing to do" |
| Channel is paused while the factory state changes, then resumes | PR56 `factory_change_*` sections | D | Partly. Status "Payments paused" |
| Capacity change without an on-chain transaction (the mechanism behind buying receiving room) | PR56 `factory_change_init` | D | Partly. See buying receiving room in B |
| List of factory protocols each side supports | PR56 `supported_factory_protocols` | D | No. Would show as "this host speaks a protocol I do not" |
| Not in the draft: funding depth, lifetime, winding down, fees, announcement rules | PR56 whole file | D | — |
| Gazpacho has its own message format, not this draft's | docs/DESIGN.md:87-97 | V | — |

---

## B. Gaps, most important first

Each gap says: what it is; source; where it belongs; any conflict with a Gazpacho decision; first release or later. "First release" here means I think the first release cannot honestly ship without at least showing it. Those are my judgements, not owner decisions.

1. **Paying and receiving have no place in the map.** No scope holds invoice or offer choice, amount, description, pending payments, a payment list, "most I can send / receive", or payment size limits. Sources: FE/components/cln/CLNSend, CLNReceive, Overview (D); t1242.md:1768-1774 (D). Belongs in a NEW scope or category, "Payments". No conflict. First release (it is Slice 2).

2. **Balance, ceiling and room left are not a status.** The posts make this the centre of the product: show the balance and the most you can hold close together. Source: t1242.md:1163-1191 (V). Belongs in "Status, not options" and on the home screen. No conflict. Do not use the phrase "account limit" (see D). First release.

3. **Buying receiving room has no member-side flow or options.** The map has the fee I accept (S1) and the host's "sell" action (S6). Missing: the request, the quote, the wait, the result, a failure state, "buy automatically as I near the ceiling" with a cap, the fact that it is never refunded, and that each purchase makes leaving alone dearer. Sources: t1242.md:1192-1205, 1779-1792, 449-451, 502-504 (D); site updating-state.md:35-90 (D); SS lsp_channels.c:6838 (D). Belongs in Payments (action) plus one S1 option (automatic buying, with a ceiling). No conflict; DESIGN section 7 says liquidity changes alter the tree, so this needs a signing step. First release or the one after: owner's call, but the map must say which.

4. **How much I could get back alone, what it would cost, and how long.** The map has "Fee reserve" and "Reserve low". Missing as status: the estimated cost and time of leaving alone now; "your balance is below the cost of leaving"; "your balance is above what you can recover without a reserve"; a warning level (the posts suggest 90%). Sources: t1242.md:268, 1292-1368, 1681-1710 (V/D); site security-model.md:132-133, force-close.md:130-142 (D). Belongs in S4 (status) and S3 (the reserve). Partial conflict: Gazpacho decided exit fees are built in from the host's side, so the "limited or unlimited" split may not carry over. The minimum-balance problem remains either way. First release, as status.

5. **Leaving on purpose.** The map only has the automatic exit before the end. Missing: a member's own "leave now", cooperative or alone; the cost and time estimate before confirming; where the coins go; that paying and receiving stop once it starts; "contact the host first". Also the host side: force close, and what to do with a member who has gone silent. Sources: t1242.md:1988-2100 (D); FactoryDetail.tsx:263,663-681 (D); superscalar_client.c:2862-2866 (D). Belongs in a NEW category of actions on a factory (member), plus S6 actions (host). Conflict: the cooperative single-member exit in the sources works by swap-out or key hand-over. Swap-out is "after the first release" (DESIGN section 7), and key hand-over is not decided. Leaving alone by hand: first release. Cooperative leave for one member: later.

6. **More than one factory at a time.** The map's statuses are written for one lobby and one factory. During a move a member is in two. A host with a ladder is in many. One person may host and be a member at once. S1 says conditions are "locked while I am in a lobby", which needs a rule for someone always in some factory. Sources: FactoryList.tsx (D); laddering.md:40-46 (D); t1143.md:612-614 (D). Belongs in "Status" (make it a list) and "Rules for any layout". No conflict. First release needs at least two at once.

7. **The move to the next factory is thinner than the sources.** Missing: the list of retry windows and the last one; "the host moved on without you" as a state; what works during the move; the way of moving as a term (pay across over Lightning, co-signed close into the next factory, or leave to on-chain) and as a condition; moving to a different host. Sources: t1242.md:1458-1495, 1867-1931 (D); client-migration.md:33-85 (D); FACTORY_POLICY_V1.md:1708 (V); pre-mainnet-design-decisions.md:218-224 (D). Belongs in S2 (term), S1 (condition), Status (states). No conflict; DESIGN section 7 names two ways already. First release if rotation is (M4).

8. **Fee kinds.** The map has joining, per payment, and extra receiving room, and says these were invented by the prototype. Sources add: a recurring fee charged at each move, with a waiver for a high balance (t1242.md:1126-1147, D); a base fee as well as a percentage (FACTORY_POLICY_V1.md:1711-1713, V); sharing routing income with members (superscalar_lsp.c:2130-2143, D; superscalar_client.c:2471, V); a statement of who pays to leave alone (building-a-factory.md:121-128, D). Belongs in S2 with matching rows in S1. No conflict. Decide the list before the first release; profit sharing can be later.

9. **Payment limits and deadlines as terms.** Smallest and largest payment, most payments in flight, deadline deltas, whether offers and multi-part payments are allowed. The Soup wallet let a member refuse a lobby on these. A user-visible effect exists even with no option: incoming payments need a long final deadline, and some senders will fail. Sources: FactoryPolicyView.tsx:127-142, policy-validator.ts:37-50 (D); FACTORY_POLICY_V1.md:1682-1691 (V); PR56 (D); t1242.md:786-790 (D). Belongs in S2 and S1 (a short list), and a status line in Payments ("refused: too little time left"). No conflict. First release needs smallest and largest payment and the deadline fact.

10. **Host caught cheating, and how a factory ended.** No status for "the host published an old state; the app answered", none for "host failed a check; this host is now avoided", and "Ended" does not say how (everyone signed, I left alone, end date, penalty). The reference member has a choice of continue, halt or close. Sources: superscalar_client.c:2482-2487 (V); lsp-misbehavior.md:17-37 (D); BreachStatus.tsx (D); FE/types/factories.type.ts:1-23 (D). Belongs in Status and "Needs attention". Conflict: the map says answering an old state is never a setting. Keep that. Add the states, and say plainly that the reference "continue" choice is deliberately not offered. First release.

11. **Host's admission controls and inbox.** Accept joiners automatically or review each; a ban list and allow list per lobby; a list of requests with approve, refuse and a reason; notes on known members. Sources: OperatorPrefs.tsx, LspOperatorConsole.tsx, KnownPeers.tsx (D); FACTORY_POLICY_V1.md:1692-1697 (V). Belongs in S6. Conflict: "required reputation" and lasting notes on members sit badly with "identity is new per lobby by default"; they can only work for members who attach a key. First release for auto or manual accept and a host ban list.

12. **Whose listings I trust, and kinds of host proof.** S5 has relays only. The Soup wallet let the user choose which listing verifiers to accept, hide weak-proof listings, and see a badge per listing. Listings also expire and the host must renew them. Also missing: joining a host by typing its key and address. Sources: RendezvousSettings.tsx:220-416 (D); SR/README.md:57-99 (D); ManualConnectModal.tsx (D). Belongs in S5 (verifiers), S1 (proof kind I require), S6 (renew listing: a host duty and date). Possible conflict: Gazpacho decided "listings and host proofs on Nostr; everything else direct" but has not said whether a third-party verifier exists at all. First release if listings ship.

13. **What happens while the app is closed.** The sources assume a phone that the provider wakes by push message. Gazpacho is a program on the user's machine. The map never says "you cannot receive while Gazpacho is not running", and has no host-side setting to notify members (the reference host sends "rotation needed", "factory ending", "payment received"). Sources: t1242.md:1051-1100, 1847-1859 (D); superscalar_lsp.c:1821-1823 (D). Belongs in S4 (status: "app closed means no receiving") and S6 (notify members, later). Consistent with the decision "in-app countdowns first". First release for the plain statement.

14. **Host running duties.** Missing from S6: the host's public address and reachability (port, onion address); host backup of database and key, with a snapshot before each move; "never run two copies"; the host key cannot be changed while factories are open; logs and a diagnostic report; alerts for a slow signer, signing stuck, node link down, low funds; a contact address for members. Sources: superscalar_lsp.c flags (D); mainnet-runbook.md:59-60, 104-109, 151-215, 250-262, 317-327 (D). Belongs in S6, with host items added to "Needs attention". No conflict. First release for address, backup and alerts.

15. **Size chosen by the member.** In the Soup wallet a member asks for a size, and a host can give different sizes. The map has one channel size per lobby and "smallest channel" as a condition. Sources: JoinFactoryModal.tsx:249-260, FactoryCreate.tsx:886-913 (D). Belongs in S2 (fixed size, or a range) and S1 (size I want). No recorded decision either way. Later is fine, but mark it open.

16. **Updates left, and re-signing in place.** Upper layers can change only a limited number of times. Nothing in the map shows a host how many remain, or a member that "a factory update is in progress". Sources: FactoryDetail.tsx:395 (D); security-model.md:135-136 (D); updating-state.md:102-121 (D). Belongs in Status (host) and S2 (a term, since it bounds how much receiving room can be moved). No conflict. First release for the host status.

17. **Ceiling on what the app may spend on fees.** The reference has a cap in sats and a share of the value at stake for fee bumps, and a choice of fee source. The map has "Automatic or Fixed" only. Sources: superscalar_lsp.c:2156, 2228-2233 (D); tools/superscalar_watchtower.c:114-116 (D). Belongs in S3 or S4. No conflict. First release once the exit engine exists.

18. **Confirmation floor as my own option.** The map mentions "the member's app has its own floor" in a note but lists no option in S1. The reference has four depths. Source: superscalar_lsp.c:2160-2168 (D). Belongs in S1. First release.

19. **Chain trouble.** No "Needs attention" item for a reorganisation that un-confirms the funding (the reference freezes signing until it re-confirms). Source: mainnet-runbook.md:434-463 (D). Belongs in Status. First release.

20. **A neighbour left alone.** One member leaving can put part of the tree on chain for others. No status covers "part of your branch is now on chain; this is what changed for you". Source: force-close.md:82-106 (D); t1242.md:666-698 (D). Belongs in Status. First release if the layered tree ships.

21. **Starting without waiting, or with on-chain coins.** The posts describe an "Express" start (pay an invoice, usable at once) and an "Onchain" start. Source: t1242.md:1551-1662 (D). Conflict: Gazpacho decided the fallback channel is off and that swap-in and members adding coins come after the first release. Later. For now the first-run screen must say "you cannot pay or receive until the factory starts at this time".

22. **Help and plumbing.** Glossary, version and what's new, logs, export of settings, fiat display, a visible "not real bitcoin" marker on test networks. Sources: Glossary.tsx, Settings.tsx, Header.tsx:43-53 (D). Belongs in a small NEW category "About and help", and S3 for fiat. No conflict. The test-network marker is first release; the rest can follow.

23. **Placement and grouping of members by the host.** Order in the tree, grouping by active hours, better terms for members who are online more. Sources: superscalar_lsp.c:2122-2128 (D); t1242.md:947-978 (D). Belongs in S6. Conflict: DESIGN section 7 says members are placed "in an agreed order, host first". Later, if ever.

### Items in the wrong scope, or split across scopes

- **Fee reserve** sits in S3 Wallet, but it exists only to make leaving alone possible. It reads better beside "Longest safe absence" in S4, or S4 should show it as status. (V: options-map.html lines 111, 123.)
- **Activity record** sits in S4 Watching. It is the history of everything the app did, including joins and refusals in lobbies. It is closer to a general history than to watching. (V: line 129.)
- **Pause** sits in S1 but the map itself says it is a stop button, not a preference. (V: line 80.)
- **Host's Lightning node link** sits in S5; the map already notes it belongs with S6. (V: line 140.)
- **Confirmations before live** is an S2 term whose matching condition lives only in a note. (V: line 101.)
- **Invitations** appear twice: as an S2 term and as an S6 action. The invitation's own options (expiry, address shown) have no home. (V: lines 96, 152.)

### Source features the map rightly leaves out

Voting or manual approval in the middle of signing (Soup's "auto-sign off"); several nodes in one wallet; a SQL terminal; pooled-capital factories; several members per leaf with a helper reward; the fallback on-chain channel; splicing; test and cheat flags.

---

## C. Screens the sources imply and the ten moments lack

The ten planned moments: first run; ordinary home; finding and joining a lobby; automatic joining unattended; the signing moment with a refusal; a live factory with its dates; paying and receiving; something needs attention; hosting; each option scope.

1. **Buying receiving room.** Request, quote, wait, done or failed; and the automatic version. (t1242.md:1192-1205, 1779-1834, D; updating-state.md:35-62, D.)
2. **Leaving, step by step.** Both "leave now" by choice and the automatic exit: estimate first, then each transaction, each wait, and the final sweep. It may run for days. "Something needs attention" does not cover a multi-day process. (force-close.md:18-56, D; t1242.md:2035-2171, D; client-recovery.md:46-51, D.)
3. **The move to the next factory.** A view of old and new side by side, the retry windows, and what happens after the last one. (t1242.md:1458-1495, 1867-1931, D.)
4. **Several factories.** A list with role, state and next date, and a history of ended ones saying how each ended. (FactoryList.tsx, D.)
5. **Waiting to start.** After joining and before the factory is live: "you cannot pay or receive yet; starts at this time". (t1242.md:1500-1524, D.)
6. **After the end.** Funds are on chain; send them somewhere or join again. (t1242.md:2012-2017, 2176-2178, D.)
7. **Backup and restore as flows.** Showing and checking the 24 words; exporting the factory backup; restoring, including the wait for the host to prove the latest state. The map itself says the restored-wallet view is not designed. (client-recovery.md:29-51, D; options-map.html line 116, V.)
8. **On-chain wallet.** Receive address, send, list. In S3 as options, in no moment. (BTCDeposit, BTCWithdraw, D.)
9. **Payment and activity history.** A list of payments, separate from the record of what the app did alone. (CLNTransactionsList, bookkeeper, D.)
10. **Host: the ladder.** Many factories on a time line, with capital committed and the next opening. (LadderingTimeline.tsx:37-92, D; FactoryCreate.tsx:918-955, D.)
11. **Host: requests to join.** The inbox with approve and refuse. (LspOperatorConsole.tsx, D.)
12. **Host: one factory in detail, with its actions.** Sell receiving room, wind down, force close, members who have not moved yet and what that will cost the host. (FactoryDetail.tsx, D; t1242.md:392-395, 1491-1495, D.)
13. **Host: earnings.** In S6 as a report; not clearly in the hosting moment. (FactoryActivityCard.tsx:282-407, D; t1242.md:858-870, D.)
14. **Host cheated, or an old state was answered.** What happened, what the app did, what the user got. (lsp-misbehavior.md, D; BreachStatus.tsx, D.)
15. **The app was closed.** On opening: what was missed while away, including that nothing could be received. (t1242.md:1051-1090, D, for the phone case; for Gazpacho this is my inference from DESIGN section 13.)
16. **Help.** A glossary reachable from any term. (Glossary.tsx, D.)

Not supported by any source read today, so not listed as missing: contacts or an address book; on-chain swap in and out as a screen (the posts describe the mechanism, DESIGN defers it); a third-party watcher marketplace.

---

## D. Terms

| Source's word | Where | Gazpacho's word | Note |
|---|---|---|---|
| LSP | posts, site, repo, Soup | Host | Decided (KNOWLEDGE-BASE section 2, V) |
| Client; also "joiner", "participant" | posts, site, Soup | Member | Decided |
| Host (as a verb: "Host Factory"); "host" in the listing server | FactoriesNav.tsx:42-49; SR docs (D) | Host | Same word already in use there |
| Account, account balance | t1242.md:1116,1184 (V) | No word yet. "Balance" is safe | "Account" suggests a bank holds the money |
| Account limit; "upgrade account limit" | t1242.md:1163-1205 (V) | "Channel size" (S2) and "receiving room" | "Limit" is a ceiling on holding, not on spending. "Upgrade" hides that it is a purchase with no refund |
| Inbound liquidity | everywhere | "Receiving room" | Keep one phrase; the map uses both "receiving room" and "liquidity fee" |
| Liquidity stock, L-stock, "sales stock", "LSP reserve per leaf" | t1242.md:931; Glossary.tsx:90-93 (D) | Host's spare liquidity | Decided |
| Deposit insurance, limited and unlimited; coverage | t1242.md:268,1292 (V) | None. Avoid | There is no insurer. The post says so itself (t1242.md:1379-1382, D). "Unlimited" is still minus fees |
| Monthly maintenance fee; service month | t1242.md:1126,1312 (D) | "Move to the next factory" | It is a required move. Missing it ends the factory for you |
| Locked reserve fund | t1242.md:1687 (D) | Fee reserve | The same post calls it "not locked" (t1242.md:267, D) |
| Assisted exit, assisted account closure, cooperative exit, mutual exit | t1242.md:318,903,2022 (D) | "Leaving with the host's help" is not yet a Gazpacho term | Four names for one thing. Gazpacho's "cooperative exit" means everyone signs one transaction, which is a different thing (KNOWLEDGE-BASE, V) |
| Unilateral exit, force close, forced account closure | posts, site, Soup | Leaving alone | Decided |
| Dying period; "dying"; "expired" | t1242.md:874; laddering.md (D) | Winding down; ended | Decided |
| Ceremony; trigger | CeremonyProgress.tsx (D) | Signing; start | — |
| Epoch | FactoryDetail.tsx:395 (D) | No word yet. "Updates left" | — |
| Rotation; refresh; migration; rollover | site, repo | Move to the next factory | "Refresh" means two different things on the site (D) |
| Policy; signing preferences | Soup | Terms; my conditions | Decided |
| Vouch; coordinator; rendezvous; tier | SR docs (D) | Listing; no word for the verifier | "Tier" means two things in Soup (D) |
| Breach; poison; burn; penalty; justice; redistribution | site, repo | "Answering an old state" | Used loosely for different mechanisms (D) |
| Evict; rug; sockpuppet | t1242.md:1161; t1143.md:491 (D) | Remove; none | Developer slang |
| "Your stake" | ReviewProposalModal.tsx:209 (D) | Never. Banned word family | The map bans "staking". This Soup label is the same trap |
| JIT channel | site, repo | Not offered | Here it is an ordinary on-chain channel beside the factory, not a factory feature |
| Watchtower | site, repo | Watcher | — |

Source wording that would mislead users if copied:

- "No on-chain bitcoin required." True for joining. The same site advises larger holders to keep an outside reserve, and small balances may not be recoverable. (index.md:32; l-stock-redistribution.md:93; security-model.md:132-133. D.)
- "Funds are always recoverable." The same pages give a week-long delay, a real cost, and the small-balance problem. (D.)
- "Trustless, no counterparty risk" and "LSP cannot steal". The posts cap the protection at an amount fixed at setup. (t1242.md:246-263, D.)
- "Liveness needed only for convenience." Elsewhere the member must be online to join, to buy receiving room and once per wind-down. (security-model.md:38, D.)
- "No per-leaf watchtower needed." The watcher page lists old leaf states among the things to watch. (D.)
- "The LSP must accept" an assisted closing. Nothing forces it. (t1242.md:2023, D.)
- Durations and who pays differ from place to place in the posts and on the site. Do not quote any single figure as a promise. (t1242.md:1153, 1321, 1348, 1715, 1702-1704, D.)
- "127 clients on signet." One operator ran all 127 on one machine. (signet-exhibition.md:60-68, D.)

---

## E. What I could not read or verify

- **I did not read most sources line by line myself.** Four helper sessions did, and reported with pointers. I read directly: the options map, DESIGN.md, KNOWLEDGE-BASE.md, `FACTORY_POLICY_V1.md` lines 1657-1719, `SEED_BACKUP.md`, the headings of the other Soup `docs/` files, and the spot-checks named at the top. Everything marked D rests on a helper's reading.
- **No repository named "soup".** `gh repo list 8144225309` shows `superscalar-wallet` (a fork of `cln-application`, whose own runbook calls it "Soupwallet") and `soup-rendezvous`. I took these two as the Soup wallet. (V.)
- **Soup wallet, not read:** `docs/PROTOCOL_V1.md`, `PROTOCOL_NOTES.md`, `OPERATOR_RUNBOOK.md`, `MAINNET_AUTH.md`, `CONFORMANCE.md` and the body of `AUDIT_LOG.md` (headings only); `FACTORY_POLICY_V1.md` outside the defaults table (121 KB; the field meanings in section 4 were not read); backend controllers and services; most large screen files were read for labels and comments, not every code line; the payment and accounting screens were skimmed.
- **SuperScalar repository, not read:** `testing-guide.md`, `release-process.md`, the `trustless-*` plans other than the rollover plan, `cl4-rollover-remediation-plan.md`, `p6-bounded-nonce-retry.md`, `gap-scan-findings-2026-07.md`, `cln-bridge-security-review.md`, `test-harness-rigor-audit.md`; files under `docs/design`, `docs/ptlc` and top-level `doc/` were headings only, apart from one section. Flags `--scb-path` and `--bind` were seen but their meaning was not read. Parameters of the admin commands were read for one command only.
- **Docs and code disagree in the repository** on several defaults (host's starting share, placement mode, confirmation wait, most members). The helper took the code as correct. The numbers in A3 follow the code.
- **Website:** `http://www.superscalar.win` redirects to `superscalar.win`. The page is a script shell; content was read from the raw text files and from the clone, which matched. Thirteen background pages (primers, history, transaction internals) were not inventoried. Signet transaction ids on the site were not checked on chain. External links were not followed.
- **bLIP-56:** the pull request body and full file were read. The review comments were not.
- **Posts:** both files were read in full. `t1143.md` lacks post 10. Linked material (fee futures post, LSPS2, LSPS5, swap-in-potentiam, the implementation report) was not read.
- **Gazpacho's own documents not read today:** `LOBBY.md`, `AWAY.md`, `HOST-NODES.md`, `CHAIN-SERVERS.md`, `OPEN-QUESTIONS.md`, the two specifications. Some gaps above may already be noted there as open questions. The "first release or later" calls are my judgement against DESIGN.md and KNOWLEDGE-BASE.md only.
- **Nothing was run.** No program was built or started; no statement here is a test result.
