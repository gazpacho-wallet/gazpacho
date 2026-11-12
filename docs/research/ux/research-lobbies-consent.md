# Research: lobbies, unattended signing, consent and deadlines

Date: 2026-11-11. Purpose: inform the Gazpacho interface. Sources were read on the web only. Nothing was installed, run, signed up for or posted.

## How to read the tags

Every factual statement carries one tag.

| Tag | Meaning |
|---|---|
| **[V]** | VERIFIED. Read this session on the page given. |
| **[V*]** | VERIFIED, weak. Seen this session only as a search-result summary of the page given. The page itself was not opened, or would not open. Treat as probably right. |
| **[R]** | RECALLED. From my own knowledge. Not checked this session. |

Part 6 (the synthesis) is recommendation, not fact. Each recommendation points back to the statement IDs it rests on.

Counts are at the very end.

## Sources

| Key | Page |
|---|---|
| S1 | Wasabi docs, Coinjoin: https://docs.wasabiwallet.io/using-wasabi/CoinJoin.html |
| S2 | Wasabi docs, FAQ: https://docs.wasabiwallet.io/FAQ/FAQ-UseWasabi.html |
| S3 | Wasabi incident disclosure, July 2024: https://github.com/orgs/WalletWasabi/discussions/13249 |
| S4 | No Bullshit Bitcoin on Wasabi 2.2.0: https://nobsbitcoin.com/wasabi-wallet-v2-2-0 |
| S5 | Bitcoin Magazine on Wasabi 2.0: https://bitcoinmagazine.com/business/wasabi-wallet-2-contains-new-features-for-optimizing-bitcoin-coinjoins |
| S6 | Jam docs home: https://jamdocs.org/ |
| S7 | Jam docs, Earn: https://jamdocs.org/interface/03-earn/ |
| S8 | Jam docs, Send: https://jamdocs.org/interface/02-send/ |
| S9 | Jam docs, Sweep: https://jamdocs.org/interface/04-sweep/ |
| S10 | Jam docs, Fees: https://jamdocs.org/market/fees/ |
| S11 | Jam docs, Cheatsheet: https://jamdocs.org/interface/00-cheatsheet/ |
| S12 | Econoalchemist guide, Whirlpool with Sparrow (third party, not official): https://whirlpool.econoalchemist.com/04_Whirlpool-with-Sparrow.html |
| S13 | Team Fortress wiki, Server Browser (community wiki of a Valve game): https://wiki.teamfortress.com/wiki/Server_Browser |
| S14 | Steamworks, Matchmaking and Lobbies: https://partner.steamgames.com/doc/features/multiplayer/matchmaking |
| S15 | Steamworks, ISteamMatchmakingServers: https://partner.steamgames.com/doc/api/ISteamMatchmakingServers |
| S16 | Amazon GameLift FlexMatch, player acceptance: https://docs.aws.amazon.com/gamelift/latest/flexmatchguide/match-client-accept.html |
| S17 | Riot support, Queue dodging: https://support.riotgames.com/en-us/league-of-legends/gameplay/queue-dodging |
| S18 | Signal blog, safety number updates: https://signal.org/blog/verified-safety-number-updates/ |
| S19 | Trezor, Trusted Display: https://trezor.io/guides/trezor-devices/trezor-fundamentals/trezor-s-trusted-display-verify-every-address-on-your-device |
| S20 | Ledger Academy, clear signing: https://www.ledger.com/academy/glossary/clear-signing |
| S21 | MetaMask support, simulations: https://support.metamask.io/manage-crypto/transactions/simulations/ |
| S22 | NN/g, ten heuristics: https://www.nngroup.com/articles/ten-usability-heuristics/ |
| S23 | NN/g, progressive disclosure: https://www.nngroup.com/articles/progressive-disclosure/ |
| S24 | NN/g, the power of defaults: https://www.nngroup.com/articles/the-power-of-defaults/ |
| S25 | NN/g, confirmation dialogs: https://www.nngroup.com/articles/confirmation-dialog/ |
| S26 | Wikipedia, alarm fatigue: https://en.wikipedia.org/wiki/Alarm_fatigue |
| S27 | Bitcoin Design Guide, daily spending wallet: https://bitcoin.design/guide/daily-spending-wallet/ |
| S28 | Bitcoin Design Guide, settings: https://bitcoin.design/guide/daily-spending-wallet/settings/ |
| S29 | Bitcoin Design Guide, first use: https://bitcoin.design/guide/daily-spending-wallet/first-use/ |
| S30 | Bitcoin Design Guide, Lightning services: https://bitcoin.design/guide/how-it-works/lightning-services/ |
| S31 | Bitcoin Design Guide, liquidity: https://bitcoin.design/guide/how-it-works/liquidity/ |
| S32 | Bitcoin Design Guide, backups: https://bitcoin.design/guide/how-it-works/backups/ |
| S33 | Bitcoin Design Guide, personal finance: https://bitcoin.design/guide/designing-products/personal-finance/ |

### What I could not check

- **Sparrow's official Whirlpool page** returned 404 on both addresses tried (sparrowwallet.com/docs/mixing-whirlpool.html, with and without www). Sparrow detail comes from a third-party guide (S12) and recall.
- **Samourai's own documentation** was not found or read. All Samourai statements are recalled.
- **Valve's developer wiki** page on the Steam server browser returned 403. The Team Fortress wiki (S13) and the Steamworks API pages (S14, S15) stand in for it. I did not see the Steam client's own server browser window, only descriptions of the in-game Source one, which is the same design family.
- **Signal's support page** on safety numbers returned 403. Signal's own blog post (S18) was read instead. Signal's settings layout was not checked.
- **Proton's settings page** returned 404. Everything on Proton is recalled.
- **MetaMask's security-alerts support page** came back empty. Its content is known only from a search summary.
- **Rabby**: no official page turned up. Search results were low-quality blogs. Everything on Rabby is recalled.
- **Wasabi's blog** (blog.wasabiwallet.io) did not resolve. The older profile names come from a search summary and from Bitcoin Magazine.
- **Jam's running state**: the docs do not describe what is on screen while a collaborative send or the scheduler is in progress, how an abort looks, or the fee-limit prompt. Those are recalled or left open.
- **No screenshots were examined.** All interface descriptions come from text.
- **Dota 2, Counter-Strike and World of Warcraft ready checks**: no official page found. Recalled.
- No primary research paper on warning habituation was read. Alert-fatigue material is from Wikipedia (S26) and NN/g (S25).

---

## Part 1. Coinjoin clients

These are the closest precedent. The user sets limits, walks away, and the app signs multi-party transactions alone.

### 1.1 Wasabi Wallet (WabiSabi)

| ID | Statement | Tag | Source |
|---|---|---|---|
| W1 | Auto-start is a wallet setting labelled "Automatically start coinjoin". The current docs say it is off by default. | [V] | S1 |
| W2 | At the 2.0 launch, coinjoin was on by default and began at login. Users could turn it off. Users could not pick which coins took part. | [V] | S5 |
| W3 | With auto-start on, a countdown labelled "Waiting to auto-start coinjoin" runs for about 1 to 3 minutes before the wallet joins a round. | [V] | S1 |
| W4 | Manual control is a Play button and a pause button on a "music box". The FAQ says the music box is used to "start, pause and stop coinjoining" and shows information about the current round. | [V] | S1, S2 |
| W5 | Auto-start only applies when the balance is at or above the "Stop coinjoin threshold" (default 0.005 BTC). Below it, the user must press Play. | [V] | S1, S2 |
| W6 | Settings are bundled into three named strategies. Each one sets exactly two things: "Non-private coin isolation" and "Anonymity score target". Enhance privacy: on, random 30 to 50. Default strategy: on, 10. Reduce costs: off, 5. A custom strategy is also possible. | [V] | S2 |
| W7 | The docs say the Default Strategy "is sufficient for most users". New wallets get it. | [V] | S1, S2 |
| W8 | The strategies had different names at the 2.0 launch: Minimize costs, Maximize speed, Maximize privacy. The first two targeted score 5. The privacy one used a random 50 to 100, later narrowed to 27 to 76. | [V*] | search summary of blog.wasabiwallet.io posts |
| W9 | Bitcoin Magazine, at launch: the speed and cost choices set the score to 5, the privacy choice defaulted to 50, and the custom range was 2 to 300. | [V] | S5 |
| W10 | So the profile names and numbers changed at least twice between 2022 and now (from W6, W8, W9). | [V] | S2, S5 |
| W11 | When a coin reaches the target, its amount is shown as "PRIVATE" in the main view. The goal is shown as a state, not a number to interpret. | [V] | S1 |
| W12 | A green glow means the wallet is coinjoining. An orange glow means the round is in a critical phase. Wasabi blocks closing the app during that phase. | [V] | S1 |
| W13 | The user can set a maximum mining fee rate they will accept (default 50 sat/vB) and a minimum input count for a round (default 21). The coordinator sets the round's actual fee rate. | [V] | S1 |
| W14 | Since 2.2.0.0 the coordination fee is gone. The client only joins rounds where it pays mining fees, and skips rounds where the coordinator charges. The stated reasons were to avoid unknown incentives and limit user risk. | [V] | S1, S2, S4 |
| W15 | The music box gives named reasons when nothing is happening: "Insufficient funds eligible for coinjoin" and "Some funds are rejected from coinjoining". Ban times can be looked up in the Wallet Coins dialog. | [V] | S2 |
| W16 | "Awaiting the blame round" is shown when another participant failed to sign and a new round is formed from those who responded. | [V] | S2 |
| W17 | Failed rounds are abandoned and restarted. Inputs that failed to sign are temporarily banned. The docs tell users that some attempts fail and to leave Wasabi running. | [V] | S1 |
| W18 | A successful round appears in the history list. | [V] | S1 |
| W19 | July 2024: a third-party coordinator exploited a flaw that let a coordinator charge more than the user's stated maximum. It also required only 2 inputs, made rounds as fast as possible, charged the top allowed fee and raised it after failures. Outsiders monitoring spotted it. Users were told to pause. Version 2.1.0 followed. The disclosure calls the impact "relatively limited" and gives no figure. | [V] | S3 |
| W20 | Version 2.0.8.1 added a user-set maximum coordination fee rate and a check that mining fees match the requested rate. Version 2.1.0 lowered the absolute cap on coordination fee from 0.01 to 0.005 and raised the absolute minimum input count from 2 to 5. | [V*] | search summary of nobsbitcoin.com release notes |
| W21 | 2.2.0 added a message shown when no coordinator is configured, pointing the user to how to find one. | [V] | S4 |
| W22 | The coordinator is changed in a Coordinator tab in Settings, followed by a restart. The docs list directories of coordinators and tell users to verify them themselves. | [V] | S2 |
| W23 | The 2.0 fee was 0.3%, charged on fresh coins only, not on remixes and not on amounts of 0.01 BTC or less. | [V] | S5 |
| W24 | The exemptions in W23 were branded "friends don't pay" and "plebs don't pay". The related setting was first called something like "plebs stop threshold". It is now "Stop coinjoin threshold". Jargon was replaced by a plain label. | [R] | blog page did not load |
| W25 | The original company (zkSNACKs) shut its coordinator in mid-2024. After that, users had to choose a coordinator themselves. A choice the app once made silently became a user decision with money at stake. | [R] | not checked |
| W26 | Hardware wallets cannot coinjoin in Wasabi. Unattended signing needs a hot key. | [V] | S1 |

**What Wasabi teaches**

- One always-visible control (the music box) carries state, reason and the play/pause action. (W4, W12, W15)
- A profile is only safe if it shows the numbers it sets. Wasabi's profiles are two numbers in a table. (W6)
- Profile names drift and confuse. Names moved from goals ("Maximize privacy") to plainer verbs ("Enhance privacy"). (W8, W10)
- A user limit is worthless if the other side's claim is trusted. The 2024 incident was a limit that the client did not enforce properly. (W19)
- When a limit is hard to enforce, removing the variable is cleaner than warning about it. Wasabi deleted the fee. (W14)
- The seconds when quitting would hurt others get a distinct colour and the app refuses to close. (W12)
- A small balance needs a deliberate press. Automation has a floor. (W5)

### 1.2 JoinMarket and Jam

| ID | Statement | Tag | Source |
|---|---|---|---|
| J1 | Jam is a web interface for JoinMarket. It labels itself beta. | [V] | S6 |
| J2 | The main screens are Send, Earn, Sweep and Receive. | [V] | S6 |
| J3 | Earn is the maker role. The user picks an offer type (absolute, for example 250 sats, or relative, for example 0.03%), picks the fee, and presses "Start Earning!". | [V] | S7, S10 |
| J4 | Makers pay no mining fees. The taker pays all of them. | [V] | S7 |
| J5 | The docs say plainly that an uncompetitive offer will likely not be taken and will earn nothing. | [V] | S10 |
| J6 | Fidelity bonds carry a blunt warning: "It is impossible to move or spend funds that are locked in a fidelity bond before the bond expires." Bonded funds are also excluded from offers. | [V] | S7 |
| J7 | Send is the taker role. Collaborative sending is the default and can be turned off under "Sending options". | [V] | S8 |
| J8 | The number of collaborators defaults to a random 8 to 10. The docs state the trade: more collaborators, more privacy, more fees. | [V] | S8 |
| J9 | Sweeping a jar can "significantly exceed" the user's fee limit, because there is no change output to absorb the difference. The docs warn about this. A default maximum fee difference of 80% applies to sweeps. | [V] | S8 |
| J10 | The Sweep tab runs a scheduler (the "tumbler"). It makes a series of collaborative sweeps through the jars, with random waits and fees, ending at three destination addresses the user enters. | [V] | S9 |
| J11 | While the scheduler runs, a green light shows the service is running. It "automatically takes any matching offer". The user can stop it at any time. | [V] | S9 |
| J12 | The cheatsheet warns that some processes take a long time and that fees and earnings "depend on market conditions". | [V] | S11 |
| J13 | Fee limits live under Settings, "Adjust fee limits". | [V*] | search summary of a 2022 forum post |
| J14 | JoinMarket takers have two limits, one absolute (sats) and one relative (fraction of amount). An offer is acceptable if it passes either. Jam will not start a collaborative send until the user has set them. | [R] | not found in docs read |
| J15 | While the maker or the scheduler is running, the rest of the Jam wallet is locked. The user cannot send by hand. The screen shows this. | [R] | not found in docs read |
| J16 | Jam shows an earn report (a table of past maker transactions and what each earned). | [R] | not found in docs read |

**What Jam teaches**

- The two roles are two screens with two verbs: Earn and Send. Maker settings and taker limits never share a form. (J2, J3, J7)
- A lock with a date gets an absolute, plain sentence. No softening. (J6)
- The honest warning is the one about the case where the limit does not hold. (J9)
- A long unattended job needs a running light, a stop button, and a statement of what it will accept without asking. (J11)
- The Jam docs do not say what happens on failure. That gap is itself a finding: this is where such tools are weakest.

### 1.3 Whirlpool in Sparrow and Samourai

| ID | Statement | Tag | Source |
|---|---|---|---|
| H1 | Before committing, Sparrow shows a preview: which pool fits the amount, the anonymity set, the pool fee, and how many outputs will be created for mixing. | [V] | S12 (third party) |
| H2 | The commitment transaction (Tx0) is shown as a diagram with four parts: Whirlpool fee, Badbank change, Premix outputs, miner fee. The button reads "Broadcast Premix Transaction". | [V] | S12 |
| H3 | After Tx0 the wallet shows four tabs: Deposit, Premix, Postmix, Badbank. Funds are physically sorted by stage. | [V] | S12 |
| H4 | The official Sparrow page describes premix, postmix and badbank wallets and requires a balance above 0.001 BTC to start. | [V*] | search summary of sparrowwallet.com docs; page 404 |
| H5 | Remixing continues only while the desktop app stays connected. Remixes cost nothing more. | [V] | S12 |
| H6 | "Mix to" sets a stop condition. The user picks a destination wallet and a minimum number of mixes. After the minimum, each coin still has a 25% chance of mixing again. The button then shows the destination wallet's name. | [V] | S12 |
| H7 | "Mix to" also has an "Index range" option, default "Full". | [V] | S12 |
| H8 | Pools were fixed offers: a few set denominations, each with one flat entry fee paid once at Tx0. The user chose a pool. Nothing in a pool was negotiable. | [R] | not checked |
| H9 | Sparrow has a Start Mixing / Stop Mixing button on the Premix and Postmix tabs, and a per-coin mix count with a progress or error indicator. | [R] | S12 does not describe it |
| H10 | The Whirlpool coordinator stopped in April 2024 when Samourai's operators were arrested. Sparrow later removed its Whirlpool client. A design that depends on one coordinator ends when that coordinator ends. | [R] | not checked |
| H11 | In Samourai's phone app, mixing ran in the background and remixes happened whenever the phone was online. | [R] | not checked |

**What Whirlpool teaches**

- A pool is a fixed-term offer. The user does not tune it. The only question is "this pool or not". This is the closest match to a Gazpacho lobby with signed terms. (H1, H8)
- The one moment of consent (Tx0) shows where every satoshi goes, as a picture. After that, mixing needs no prompts. (H2, H5)
- Stage is shown by place. Coins in Premix have not mixed. Coins in Postmix have. (H3)
- The stop condition is a destination plus a count, and it stays visible on the button. (H6)
- "Only while the app is open" was the single most important operating fact and was easy to miss. (H5)

### 1.4 Coinjoin clients compared

| Question | Wasabi | Jam | Sparrow Whirlpool |
|---|---|---|---|
| Set once | Strategy (two numbers), max mining fee rate, min input count, stop threshold, auto-start, coordinator. [V] W5 W6 W13 W22 | Fee limits [R] J14; maker offer type and fee [V] J3 | "Mix to" destination and minimum mixes [V] H6 |
| Chosen per session | Play or pause [V] W4 | Amount, destination, number of collaborators [V] J8; three sweep addresses [V] J10 | Which coins, which pool [V] H1 |
| Shown at commitment | Nothing per round. Consent is the setting plus Play. [V] W1 W4 | "Start Earning!" for makers [V] J3. Send review screen not documented. | Full Tx0 preview and diagram [V] H1 H2 |
| How automation is bounded | Fee rate cap, input-count floor, balance floor, score target as the finish line [V] W5 W6 W13 | Fee limits [R]; "takes any matching offer" [V] J11 | Pool is fixed; minimum mixes [V] H6 |
| Shown while running | Music box text, green or orange glow [V] W12 | Green light [V] J11 | Per-coin mix count [R] H9 |
| Pause and stop | Pause any time except the critical phase, when closing is blocked [V] W12 | Stop any time [V] J11 | Stop Mixing [R] H9 |
| Refusal or failure | Named reasons in the music box; blame rounds; bans visible [V] W15 W16 W17 | Not documented | Not documented in what I read |
| Deadlines for the user | None | Fidelity bond expiry [V] J6 | None |
| Known failure | Fee limit not enforced, 2024 [V] W19; renamed profiles [V] W10 | Sweep can exceed fee limit [V] J9 | Needs the app open [V] H5; single coordinator [R] H10 |

---

## Part 2. Game lobbies and server browsers

### 2.1 Steam server browser

| ID | Statement | Tag | Source |
|---|---|---|---|
| G1 | The browser has seven tabs: Internet, Favorites, History, Spectate, LAN, Friends, Blacklisted Servers. All but the last share the same filters. | [V] | S13 |
| G2 | Columns are: server name, game, players (current and maximum), bots, map, latency, tags. Small icons at the left show password, anti-cheat and replay support. | [V] | S13 |
| G3 | Filters include tags (include or exclude), map, maximum player count, latency, location, anti-cheat, "Server Not Full", "Has Users Playing", "Is Not Password Protected". | [V] | S13 |
| G4 | Servers that fail a filter are left out of the list. They are not shown greyed. | [V] | S13 |
| G5 | The page does not say outright that filters persist. A 2010 patch fixed filters not being saved, which implies they are meant to be saved between sessions. | [V] | S13 |
| G6 | In my experience filters are saved per tab and stay until changed. | [R] | |
| G7 | Favorites are added by right-click. History lists recently visited servers with their current status, and entries can be removed. | [V] | S13 |
| G8 | Blacklisted servers are hidden from results but can still be joined directly. A blacklist can be imported from a file. | [V] | S13 |
| G9 | The Internet list is built only when the user presses refresh. Latency is the value at the last refresh. The list is a snapshot, not live. | [V] | S13 |
| G10 | "View server info" shows the players, their scores and their time on the server. It also opens when the user tries to join a full server. | [V] | S13 |
| G11 | For a full server there is an Auto-Retry button with two choices: "Alert me when a player slot is available" and "Join the server as soon as a player slot is available". | [V] | S13 |
| G12 | The Steamworks API exposes the same list types: internet, LAN, friends, favorites, history, spectator. | [V] | S15 |
| G13 | Server filters are key and value pairs, such as map, dedicated, secure, notfull, hasplayers, noplayers, tag matches, and boolean and/or/nand/nor groups. | [V] | S15 |
| G14 | A game can ask a server directly for its "rules" (key and value pairs the server sets) and its player list. | [V] | S15 |

### 2.2 Steam lobbies

| ID | Statement | Tag | Source |
|---|---|---|---|
| G15 | A Steam lobby has exactly one owner. Only the owner can set or delete the lobby's data. Members are told when it changes. | [V] | S14 |
| G16 | Each member can set their own member data, separate from lobby data. The platform itself keeps "what the owner says" and "what I say" in two different stores. | [V] | S14 |
| G17 | Lobby search filters are: string compare, number compare, "near value" sorting, slots available, distance, and a result cap. Full lobbies are left out by default. | [V] | S14 |
| G18 | A lobby holds up to 250 users. It is destroyed when everyone leaves. When the game is ready, members connect to the game and leave the lobby. | [V] | S14 |

### 2.3 Ready checks, countdowns and minimum players

| ID | Statement | Tag | Source |
|---|---|---|---|
| G19 | In Amazon's matchmaker, a proposed match can require acceptance. Every player must accept within a time limit. | [V] | S16 |
| G20 | If anyone rejects or times out, the match fails. Players who accepted go back into the pool automatically. Players who did not accept are dropped and must start again. | [V] | S16 |
| G21 | In League of Legends, repeatedly missing the Ready Check brings "escalating penalties": timed queue bans, then temporary bans, in extreme cases a permanent ban. Penalties apply to the whole account. | [V] | S17 |
| G22 | Leaving during champion select has a published ladder: 6 minutes, then 30 minutes, then 12 hours. The tier falls back after 24 hours of good behaviour. | [V] | S17 |
| G23 | When one player leaves, everyone else is returned to the queue. | [V] | S17 |
| G24 | The usual ready-check screen is a modal with one large Accept button, a shrinking timer bar, a sound, and a row of markers that fill in as each player accepts. Names of those who have not accepted are usually not shown. | [R] | Counter-Strike, Dota 2, League |
| G25 | On failure the usual message is short and blameless for those who accepted, such as "a player failed to accept", and they are requeued without doing anything. | [R] | |
| G26 | Many lobby games show "Waiting for players 6/10", start a countdown once a minimum is reached, and shorten the countdown when the lobby fills. | [R] | common in minigame servers and party games |
| G27 | World of Warcraft's raid ready check is leader-started, shows a tick or cross per member, and has no penalty. It gathers information. It does not gate anything. | [R] | |

**What game lobbies teach**

- The browser is a table. One row per server. The most-compared facts are columns. Everything else is one click away in "server info". (G2, G10)
- Filters are a saved view. They hide rows. They never decide anything for the user. (G3, G4, G5)
- Favourites, history and a block list are standard and sit beside the main list as tabs. (G1, G7, G8)
- "Alert me" and "join as soon as" are offered side by side. That is exactly Gazpacho's manual versus automatic joining. (G11)
- Owner data and member data are different things at the platform level. (G15, G16)
- When a start fails, people who did their part go back in line with no effort and no blame. People who caused it get a clear, published, escalating cost. (G20, G21, G22, G23)
- Gazpacho replaces the ready check with pre-agreed conditions. The game pattern still shows what to display: a count filling up, a timer, and a plain outcome.

---

## Part 3. Consent and safety communication

| ID | Statement | Tag | Source |
|---|---|---|---|
| C1 | Signal used to hold messages for manual approval after a contact's safety number changed. It stopped. Incoming messages now show at once, with a warning line in the conversation. | [V] | S18 |
| C2 | The stated reason: users want to know about a change but do not want to be blocked by it, and it happens every time a contact gets a new phone or reinstalls. | [V] | S18 |
| C3 | For sending, Signal warns ahead of time. It asks for approval only if the user has not yet had a real chance to see the warning. | [V] | S18 |
| C4 | A user can mark a safety number as verified. If a verified number changes, sending always needs approval. The user's own earlier choice decides how strict the app is. | [V] | S18 |
| C5 | Signal's goal as stated: cut friction, but never let a message go silently to a changed key. | [V] | S18 |
| C6 | Signal's settings are few and grouped by plain topic (Account, Privacy, Notifications, Chats, and so on). Security detail sits per contact, not in global settings. | [R] | support page blocked |
| C7 | Proton splits settings into account-wide ones (password, recovery, security, sessions) and per-app ones (Mail, Calendar, Drive, VPN). Recovery has its own section and a visible "your account is / is not recoverable" status. | [R] | page 404 |
| C8 | Trezor calls its screen the "Trusted Display". It shows the real transaction the device is about to sign. The computer screen can be faked, and clipboard malware can swap addresses. | [V] | S19 |
| C9 | The user is told to compare address and amount on the device with what they intended, and to refuse if anything differs. | [V] | S19 |
| C10 | Trezor states the limit: the display "can't tell you whether an address someone gave you is the right one". It proves what is signed, not that it is wise. | [V] | S19 |
| C11 | Trezor Suite's send guide tells the user to check recipient, amount and fee on the device. The mobile flow uses hold-to-confirm for the total including fee. | [V*] | search summary of trezor.io guides |
| C12 | Ledger defines clear signing as verifying the full details in human-readable form on a secure screen before approving. The opposite is approving raw data that cannot be read, which lets a scammer hide instructions. | [V] | S20 |
| C13 | MetaMask shows "estimated changes" on the confirmation screen before signing: what will leave and enter the account. | [V] | S21 |
| C14 | MetaMask says these are a test run and are not guaranteed to match what happens on chain. A malicious contract can behave differently in the test. An optional "Added protection" enforces the outcome on chain or reverts. | [V] | S21 |
| C15 | MetaMask's security alerts are on by default. A flagged request shows a warning on the confirmation screen. The user can still proceed. | [V*] | search summary of support.metamask.io |
| C16 | Rabby shows a pre-sign balance-change preview and a list of risk checks, each passed or flagged. Some flags must be ticked off one by one before the sign button works. Users can keep a whitelist of trusted addresses. | [R] | no official source found |
| C17 | Alarm fatigue: people become desensitised by frequent alerts and ignore or respond poorly to real ones. | [V] | S26 |
| C18 | Example: in a 2009 Washington train collision, about 8,000 track alerts a week had "thoroughly desensitized" dispatchers. | [V] | S26 |
| C19 | Listed remedies: tailor alarm thresholds, decide which alarms matter most, use tiers so the loudest channel is kept for the most serious events, and remove alarms that do nothing. | [V] | S26 |
| C20 | NN/g: use confirmation dialogs only before serious, hard-to-undo actions. Routine confirmations train people to click through and weaken later warnings. | [V] | S25 |
| C21 | NN/g: a confirmation must be specific. Restate the action and its effect, show identifying details, and label buttons with the outcome, not Yes and No. | [V] | S25 |
| C22 | NN/g: thresholds reduce interruptions (confirm only what is unusual for this user). Undo is better than confirm where undo is possible. | [V] | S25 |

**What these teach**

- Warn in place and keep going when the event is common and usually harmless. Block only when the user has earlier said "this matters to me" or has not yet seen the warning. (C1 to C5)
- The consent screen shows the effect ("what leaves, what arrives, what it costs") and not the mechanism. (C8, C12, C13)
- Say what the screen does not prove. (C10, C14)
- A warning the user can click through is advice. A limit the app enforces is protection. Gazpacho's conditions are the second kind and should look like it. (C15, compare W13)
- Every extra prompt spends attention that the urgent prompt will need later. (C17 to C22)

---

## Part 4. Usability heuristics and the Bitcoin Design Guide

| ID | Statement | Tag | Source |
|---|---|---|---|
| D1 | Nielsen's ten heuristics are: visibility of system status; match between system and the real world; user control and freedom; consistency and standards; error prevention; recognition rather than recall; flexibility and efficiency of use; aesthetic and minimalist design; help users recognize, diagnose and recover from errors; help and documentation. | [V] | S22 |
| D2 | Heuristic 9 asks that errors be in plain language, name the problem and suggest a fix. | [V] | S22 |
| D3 | Progressive disclosure: show a few core options first and reveal specialised ones on request. | [V] | S23 |
| D4 | Keep it to two levels. With three or more, users get lost. The way to the second level must be easy to spot and labelled so users know what is behind it. | [V] | S23 |
| D5 | Staged disclosure (a wizard) works when steps are independent. It fails when the user must flip between steps to compare. | [V] | S23 |
| D6 | Users rarely change defaults, so the default is what most people get. Defaults also teach: they show a typical value. | [V] | S24 |
| D7 | Defaults should be chosen from real use, and never to push the option that pays the designer most. That damages trust. | [V] | S24 |
| D8 | "Choice architecture" and "nudge" (Thaler and Sunstein) hold that there is no neutral presentation. The designer who orders the options shapes the outcome and should do so in the chooser's interest. | [R] | |
| D9 | The Bitcoin Design Guide's daily spending wallet hides channel management entirely. The wallet works with a service provider so users never think about channels. It ships with "sensible defaults". | [V] | S27 |
| D10 | Its settings have seven groups: General, Fees, Privacy, Security, Wallet backup, Network, Help and support. | [V] | S28 |
| D11 | Settings are not a frequent destination. Options are surfaced where they matter (for example, change the unit on the send screen). Settings hold the full set. | [V] | S28 |
| D12 | Fees get their own settings page that summarises every fee the wallet may charge. Fee information also appears in context, at payment review. | [V] | S28 |
| D13 | The Network group holds node connections, Tor and watchtower options. Most users are not expected to change it. | [V] | S28 |
| D14 | Wallet limits that block high-value payments are an optional security control found in settings. | [V] | S28 |
| D15 | First use should be skippable and jargon-free. Costs such as a channel-opening fee should be explained before the deposit. | [V] | S29 |
| D16 | Backup reminders should come after funds arrive, and their prominence can scale with the amount at risk: loud for large balances, quiet for small. | [V] | S29 |
| D17 | Where a service adds trust or privacy trade-offs, users "should be made aware of these and be able to opt out". Users should be able to switch or use several providers. | [V] | S30 |
| D18 | Watchtowers watch channels while the user is offline. The guide recommends one not run by the user's own service provider, and several rather than one. | [V] | S30 |
| D19 | The guide suggests "send limit" and "receive limit" in place of "outbound" and "inbound". It suggests telling users at funding time that a small reserve is held back but still theirs. | [V] | S31 |
| D20 | It lists regular wallet opens, together with watchtowers, as what protects against cheating without other user action. | [V] | S31 |
| D21 | A recovery phrase alone is not enough for Lightning. Channel state must be backed up too. | [V] | S32 |
| D22 | The guide sorts wallets by financial role. Day-to-day spending puts convenience first on a phone. Savings puts safety first with multiple keys. The design should follow the role. | [V] | S33 |
| D23 | The guide has no "shared output" or "factory" wallet type. Gazpacho has no ready-made reference design there. | [V] | S33, S27 |

**Where Gazpacho differs from the daily spending reference.** The guide hides channels because the user has no dates to keep. A Gazpacho member has three. So Gazpacho can hide mechanics (signing rounds, trees, transactions) but cannot hide the dates or the terms. (D9, D20)

---

## Part 5. The five questions, across everything

| Question | Best precedent | Statement IDs |
|---|---|---|
| What is set once | A named profile that shows its numbers, plus a few hard limits | W6, W13, J14, H6 |
| What is chosen per session | Which pool or server, how much, play or pause | H1, G11, W4 |
| What is shown at commitment | Where every unit goes, in effect terms, with an outcome-labelled button | H2, C13, C21 |
| How automation is bounded | Enforced caps, a floor below which it will not act alone, a finish line | W5, W13, H6, D14 |
| How it is shown while running | One persistent control with state and reason; colour for the critical seconds | W4, W12, J11 |
| How it is paused and stopped | Always, except during the critical seconds, and say so | W12, J11 |
| How refusals and failures are explained | Named reason, who caused it, what happens next, no action needed from the innocent | W15, W16, G20, G23, D2 |
| How deadlines are surfaced | Poorly, almost everywhere. Best is Jam's absolute sentence about a locked bond | J6, D16 |
| Known failures | Unenforced limit; renamed profiles; "must stay open" missed; limit that does not hold in one mode; alert overload | W19, W10, H5, J9, C18 |

Deadlines are the gap. None of the coinjoin clients gives the user a date to keep, apart from Jam's bond. Gazpacho is on its own there and should lean on the alert-fatigue and backup-reminder guidance (C17 to C22, D16).

---

## Part 6. Synthesis for Gazpacho

Recommendations. Each cites the statements behind it.

### (a) Conditions versus lobby terms

**Two objects, two looks, two voices.**

| | My conditions | Lobby terms |
|---|---|---|
| Who sets it | Me | The host |
| Voice | "I will accept at most…" | "This lobby offers…" |
| Look | Editable controls | A sealed card. No input controls at all. Shows host name and "signed by host". |
| Where | Its own top-level place, same on every screen | Only inside a lobby's detail, and as a frozen copy in my record |
| Changes | Whenever I like, for future lobbies | Never. A change is a new lobby with a new identity. |

Basis: G15, G16 (owner data versus member data), H8 (a pool is a fixed offer), J2 (two roles, two screens).

**They meet in exactly one place: the fit check.** A three-column table in the lobby detail.

| Term | This lobby | My limit | Fits |
|---|---|---|---|
| Host fee | 0.20% | at most 0.30% | Yes |
| Lifetime | 90 days | at most 60 days | **No** |
| Exit time | 2 days | at most 3 days | Yes |

- The lobby column is plain text. The limit column is plain text with one "Edit my conditions" link under the table, not per row. Editing happens in the conditions screen, not here. That keeps a lobby screen from ever containing an input that looks like it changes the lobby.
- A row that fails is a full sentence: "Lifetime is 90 days. Your limit is 60 days." (D2, W15)
- The browser's "Fits" column is this table reduced to one mark. (G2)

**Profiles and individual limits.**

- Offer at most three profiles plus Custom. Each profile is a row in a table that shows every number it sets. (W6)
- A profile is a starting point. Changing any number switches the label to "Custom". No hidden coupling. (W6, D6)
- Name profiles by plain outcome and keep the names stable. Wasabi renamed its profiles and re-tuned the numbers under the same names. Avoid both. If numbers must change in an update, tell the user and show old and new. (W8, W10)
- The default profile must be the one that is right for most members, not the one that suits hosts. (D7, W7)
- Every condition is a hard limit that the app enforces against the host's signed terms. Do not mix in "preferences" that only sort the list. Sorting belongs to browser filters. (W13, W19, C15)
- The block list is a condition. It lives with the conditions, not in the browser. (G8)

**What locks when.**

| Moment | Lobby terms | My conditions |
|---|---|---|
| Lobby is listed | Locked from the start. Signed. | Free to edit |
| I join (or the app joins for me) | Locked | A snapshot is stored with the lobby: "Joined under these conditions." Edits still allowed. |
| I tighten a condition so a joined lobby no longer fits | Locked | The app leaves that lobby before it starts and says so. It never signs outside the current conditions. |
| I loosen a condition | Locked | Applies to future joins. Does not silently widen what an already-joined lobby may do. |
| Start: signing, a few seconds | Locked | Locked. The pause control is disabled and says why. The app resists closing. (W12) |
| After start | Shown as a frozen copy for the factory's life | No longer relevant to this factory. The dates take over. |

The check at signing time compares the host's signed terms to the stored snapshot and to the live conditions, and uses the stricter. If the terms presented differ in any way from what was joined, refuse. (W19, C4, C5)

### (b) Automatic joining and unattended signing

**Two different consents. Keep them apart.**

1. **Signing without a prompt at start.** This is what joining a lobby means. Consent is given at Join. The Join screen is the commitment screen.
2. **Joining without a prompt.** A standing permission. Off by default. (W1, G11)

**The Join screen (commitment).** Show effects, not mechanics. (H2, C13, C21)

- What I put in, what it costs me at most, what I can spend afterwards.
- The three dates as actual dates.
- The start rule in one sentence: "Starts at once with 20 members. Otherwise starts on 14 Nov 18:00 if at least 12 have joined. Otherwise cancelled."
- One plain line: "When it starts, this app signs for you without asking. It will refuse if anything differs from what is shown here."
- Button labelled with the outcome: "Join this lobby". Second button: "Not now". (C21)
- Say what the screen does not promise, for example that the lobby may be cancelled. (C10, C14)

**Turning on automatic joining.** Treat it like Rabby or MetaMask treat a standing approval: show the worst case it permits.

- "The app may join lobbies that fit your conditions, up to [amount] in total and [n] factories at a time."
- Budget controls that exist only here: total amount, number at once, and a floor below which the app will not join alone. (W5, D14, C22)
- Offer Steam's two choices side by side: "Tell me when a lobby fits" and "Join when a lobby fits". (G11)

**Status while running: one control, always visible.** Modelled on the music box. (W4, W12, W15, J11)

| State | Text | Control |
|---|---|---|
| Off | "Automatic joining is off." | Play |
| Looking | "Looking for a lobby that fits. 14 open, 0 fit. Most common reason: fee above your limit." | Pause |
| In a lobby | "In Blue Heron's lobby. 9 of 12 needed. Starts by 14 Nov 18:00." | Leave |
| Signing | "Signing. Keep the app open. About 10 seconds." | Disabled, with reason |
| Started | "You are in. Open the app by 21 Nov." | none |
| Refused | "Did not sign. The host's fee was 0.40%. Your limit is 0.30%. Nothing moved." | Dismiss |
| Cancelled | "Lobby cancelled. 9 joined, 12 were needed. Nothing was signed. Nothing moved." | Dismiss |

- "Looking" must give the reason when nothing fits. Wasabi's "Insufficient funds eligible" is the model. A silent spinner is the failure. (W15)
- Pause takes effect at once and leaves every lobby that has not started. The one exception is the signing seconds. (W12)
- If signing needs the app open, say so before joining and again during the countdown. This was Whirlpool's most-missed fact. (H5)

**Refusals.** Always the same four parts: what happened, the two numbers, what did not happen to the money, what to do next. No codes. (D2, W15, W16)

**Blame and requeue.** If a start fails because someone else did not sign, say "another member did not respond" and put this member back in line without any action. Never name temporary members. If this member's own app caused it, say so plainly and show any waiting period with its end time. (G20, G23, G21, G22, W17)

**Activity record.** One list, newest first. Every automatic act is an entry: joined, left, signed, refused, cancelled. Each entry keeps the lobby terms and the conditions as they were at that moment, and the reason. This is the user's proof of what the app did while they were away. (W18, J16, D1 "visibility of system status")

### (c) The three dates, and alerts without fatigue

**One timeline, three dates, one next action.**

- Show the dates as a single horizontal line per factory: now, "open the app by", "move by", "ends on". (D1, recognition rather than recall)
- Above it, one sentence: the single next thing to do and its date. "Nothing to do until 21 Nov." is a valid and common sentence.
- Give every date both ways: "21 Nov (in 9 days)". Relative alone goes stale in a screenshot. Absolute alone needs arithmetic.
- State the consequence of missing each date in one line, Jam-style, with no softening. (J6)
- The dates come from the host's signed terms. Show them on the Join screen before commitment and never change them afterwards. (D15)

**Alert tiers.** Keep the loudest channel for the rarest event. (C19, C20)

| Tier | When | Channel | Count |
|---|---|---|---|
| Record | Anything the app did by itself and that needs nothing from me (joined, signed, cancelled, refused) | Activity list, and a quiet badge | Unlimited, silent |
| Heads-up | A date is approaching and there is plenty of time | One notification, plus the home line | Once |
| Act now | A date is close and the action is still undone | Notification repeated on a fixed, stated schedule; a banner inside the app that cannot be dismissed until done | A few, escalating |
| At risk | The date has passed or protection has lapsed | Persistent, top of every screen | Until resolved |

Rules that keep it quiet:

- If the app can do the thing itself, it does it and files a Record. No alert. (C22)
- Opening the app satisfies "open the app by". The alert clears itself. The user should never have to find a button to acknowledge it.
- Scale prominence with the amount at risk. (D16)
- Never use the "Act now" style for news, tips or host messages. (C17, C18)
- If watching is set up and covers the absence, say so in the alert: "You are covered until 2 Dec." An alert that ignores existing protection is a false alarm. (D18, D20)
- Let the user see the schedule of future alerts for a factory before joining. No surprises. (D1, D15)
- Changed terms are impossible by design, so there is no "terms changed" alert. If the app ever sees different terms, that is a refusal, not a notice. (C5)

### (d) A "Lobby browser" layout

**Navigation skeleton.** Four destinations and one persistent strip. Two levels deep at most. (D4)

| Place | Holds |
|---|---|
| **Home** | Balance and send/receive. The next-action sentence. The date timeline for each factory. Watching status in one line. |
| **Lobbies** | The browser. Tabs: Open, Joined, Hosts I trust, History, Blocked. |
| **Activity** | Payments and the record of automatic acts, filterable. |
| **Settings** | Wallet, Watching, Connections, Hosting. |
| **Status strip** (every screen) | The play/pause control and state text from part (b). Tapping it opens Conditions. |

**Home screen.** Top to bottom: next-action sentence; balance with send and receive; one card per factory with its timeline; "Protected while away: yes, until 2 Dec" linking to Watching. Lobbies do not appear on Home unless one is joined and waiting. Then it is one card with the count and the start time. (D9, D11, W11)

**The browser table.** One row per lobby. (G2, G9, G10)

| Column | Notes |
|---|---|
| Fits | Yes, or No with the first failing reason on hover or tap |
| Host | Name, and a mark if in "Hosts I trust" |
| Size | What each member puts in |
| Fee | Total cost to me, one figure |
| Members | "9 / 20, needs 12" |
| Starts by | Deadline, absolute and relative |
| Lifetime | Or the end date |
| Exit time | |

- Default view: lobbies that fit, soonest start first.
- A toggle "Show lobbies that do not fit" reveals the rest, greyed, each with its reason. Steam hides non-matching rows outright. Gazpacho should not, because the reason a lobby does not fit is useful. (G4, W15)
- **Filters hide. Conditions refuse.** Filters are a saved view and sit above the table. Conditions are a link to a separate screen. A filter must never look like a limit, and a filter must never stop the app from signing. The words differ too: "Show" for filters, "Accept at most" for conditions. (G3, G5, W13)
- The list is a snapshot with a visible "updated 20 s ago" and a refresh control. (G9)
- Tapping a row opens lobby detail: the sealed terms card, the fit check, the member count, the start rule, the three dates, and Join. (G10, H1)
- Member names are per lobby and temporary, so lobby detail shows a count and, at most, the temporary names. No profiles, no history per member, no voting controls anywhere.

**Where the six option areas live.**

| Area | Home of it | Also surfaced | Why |
|---|---|---|---|
| Personal conditions | Its own screen, reached from the status strip and from the Lobbies header. Not inside Settings. | Fit check column; Join screen | It is the main control of the product. Burying it in Settings repeats Jam's hidden fee limits. (J13, D11) |
| Lobby terms | Lobby detail only, read-only | Frozen copy in Activity and on each factory card | Host-owned. Must never share a screen with inputs. (G15, H8) |
| Wallet options | Settings, Wallet | Unit switch in place on Home | Units, backup, app lock, spending limit. Standard. (D10, D14, D21) |
| Watching options | Settings, Watching | One status line on Home; mentioned in date alerts | Answers "what protects me while away". Status matters more than the settings. (D18, D20, C7) |
| Connections | Settings, Connections | Only when broken | Node, Tor, relays. Most users never open it. (D13) |
| Hosting | Settings, Hosting, behind a switch. When on, Lobbies gains a "My lobbies" tab and a "Open a lobby" button. | Nothing for members | A different role with different money. Keep it off the member's path, as Jam separates Earn from Send. (J2, J3) |

Host forms and member conditions must never share a screen, a component, or a vocabulary.

### (e) Checklist: 22 testable rules

Each can be checked against a mock-up or a build.

1. No screen contains both an editable condition and a lobby term outside the fit-check table.
2. Lobby terms are never rendered with input controls, on any screen.
3. Every lobby term shown carries the host's name and a "signed by host" mark.
4. Every profile shows all the values it sets, on the same screen as its name.
5. Changing one value in a profile changes its label to "Custom".
6. For every lobby that does not fit, the user can see the failing term, the lobby's value and their own limit, within one tap.
7. Filters use the word "Show". Conditions use "Accept at most" or "at least". The two never share a panel.
8. Changing a filter never changes what the app will sign. A test can prove this by signing with all filters set to exclude the lobby.
9. The Join screen shows, without scrolling on a common phone: amount in, maximum cost, the three dates as calendar dates, and the start rule.
10. The Join button's label names the outcome. No "OK", "Yes" or "Confirm".
11. The Join screen states in words that signing at start happens without a prompt.
12. Automatic joining is off on a fresh install.
13. Turning on automatic joining shows the total amount and the number of factories it may commit, before it takes effect.
14. A status line and a pause control are visible from every screen while automatic joining is on or a lobby is joined.
15. Pause takes effect within one second and leaves all lobbies that have not started. The only exception is the signing phase, where the control is visibly disabled with a reason.
16. "Looking" with no result for more than a set time shows the most common reason nothing fits.
17. Every refusal message contains: the term, the offered value, the user's limit, and the words that nothing moved.
18. A cancelled or failed start that was not this member's doing needs no action from them and says so.
19. Every automatic act creates an Activity entry that keeps the terms and the conditions as they were at that time.
20. Each factory shows one next action with a date in both absolute and relative form, or says "Nothing to do until [date]".
21. Opening the app clears the "open the app by" alert with no further tap. The "Act now" alert style is used for nothing except a required action with a date.
22. Every date's consequence is written in one sentence on the factory card, and all alerts for a factory can be previewed before joining.

Extra rules worth holding to:

23. Nothing in the interface offers voting, kicking or rating of members.
24. No screen is more than two levels below its top-level destination.
25. Whether the app must stay open or online for signing is stated before joining and during the countdown.

---

## Statement counts

Counted from the tags in the tables of Parts 1 to 4.

| Tag | Count |
|---|---|
| [V] verified on the page | 101 |
| [V*] verified from a search summary only | 6 |
| [R] recalled | 18 |
| Total | 125 |
