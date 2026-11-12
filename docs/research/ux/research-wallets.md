# Wallet interface research for Gazpacho

Date: 2026-11-11. Scope: Phoenix, Zeus, BlueWallet, Muun, Sparrow, Electrum, Trezor Suite.

## How to read this file

Every factual statement carries one tag.

| Tag | Meaning |
|---|---|
| `[V Sn]` | VERIFIED. Read this session in source Sn (list at the end). |
| `[VS Sn]` | VERIFIED, weaker. Seen only in a search-result summary of source Sn, not in the page itself. |
| `[R]` | RECALLED. From my own knowledge. Not checked this session. |

Limits you should know about:

- Pages were read through a fetch tool that returns a summary of the page, not the raw page. Exact wording of quoted labels is as that summary gave it. Label names from source code files are the most reliable.
- I did not run any of the apps. I saw no screenshots. Layout order comes from source code and docs.
- Source code was read from the default branch on the day. A shipped release can differ.
- Large files were only partly read. Zeus `en.json`: characters 0 to 200,000 of 218,000. Electrum `main_window.py`: first 100,000 of 126,000.
- Could not open: Phoenix FAQ (HTTP 403), two guessed Zeus docs pages (404), two guessed Trezor URLs (404).
- iOS versions of Phoenix, Zeus, BlueWallet and Muun were not checked. Android or shared code only.
- Section 9 (praise and criticism) leans on review sites of mixed quality. Treat it as opinion.
- The synthesis (section B onward) is design judgement. It is not tagged. It rests on the tagged facts.

---

## A. Product records

### A1. Phoenix (ACINQ)

**1. Home screen**

- Order from top: top bar, balance, separator, notices, latest payments list, bottom bar. `[V S5]`
- Top bar holds: connection status (opens a connection dialog), a Tor control, a count of in-flight payments, a notice when push delivery is unavailable, a power-saver indicator, and a "Request liquidity" button shown only when it applies. `[V S5]`
- The balance block shows the Lightning balance, plus the swap-in wallet balance with its next timeout, plus the "final wallet" balance. `[V S5]`
- The header (top bar, balance) fades as the user scrolls the payments list. `[V S5]`
- Bottom bar has three buttons in this order: settings, receive, send. `[V S5]`
- Empty state text: "Use the Receive and Send buttons at the bottom of this screen to get started!" `[V S2]`
- The list ends with "Show all payments…". `[V S2]`

**2. Navigation**

- Single home screen. No tabs. Settings is a button on the home bottom bar that opens a menu list. `[V S5]` `[V S4]`
- No desktop wallet app with this interface. `[R]`

**3. Settings groups** (from the settings menu source, in order)

| Group | Entries |
|---|---|
| (top, no heading) | Wallet switcher |
| General | About, Display, Payment settings, Payment history, Contacts, Notifications (with a count), Converter |
| Fees | Channel management (the fee policy), Add liquidity (only when possible) |
| Security | Access control, Recovery phrase, Electrum server, Tor |
| Advanced | Wallet info, Payment channels list, Experimental, Logs |
| Danger zone | Close channels (mutual), Reset wallet, Force close (in the error colour) |

All rows `[V S4]`. Entry labels cross-checked against the strings file `[V S2]`.

**4. Channel and liquidity state**

- Each user has one channel. Splicing resizes it. `[V S1]`
- The channel list sits under Advanced, titled "Payment channels", with an "Overview" header, "Balance" and "Inbound liquidity". `[V S4]` `[V S2]`
- Inbound liquidity is explained in one line: what the channels can receive "without having to go on-chain and pay fees". `[V S2]`
- Buying inbound capacity ahead is its own screen: "Plan ahead your liquidity", "Estimate liquidity cost", then "Accept". `[V S3]`
- It warns when the fee is more than 25% of the amount asked for, and when fees exceed the balance. `[V S3]`
- It states an end date in plain words: "After one year, the remaining unused liquidity will be reclaimed by the service." `[V S3]`

**5. Automatic actions with a user-set limit**

- Screen title "Channel management". Section header "My fee setting". `[V S2]`
- One switch: "Automated channel management". When off: "Incoming payments that require on-chain operations will be rejected." `[V S3]`
- One number: "Max fee amount". Help: "Payments whose fees exceed that value will be rejected." `[V S3]`
- The limit is checked live against the current estimate: "Below the expected fee. Some payments may be rejected." and "This value is too low." `[V S3]`
- A second, advanced screen ("Advanced channels management") adds "Percentage check" and "Skip absolute fee check for Lightning". `[V S2]` `[V S3]`
- When the limit blocks something, the message names both numbers: "The fee was X, but your max fee was set to Y. Tap for details." `[V S3]`
- The home screen says what will happen to waiting on-chain funds under the current limit: "Will deploy to Lightning when mining fees are below X." or "Will remain on-chain because automated channels management is disabled." `[V S3]`
- If the fee is over the limit, a swap-in waits and retries later; a Lightning payment is rejected. `[V S1]`
- Before a receive that will cost a fee, the app shows a note in advance ("Friendly fee warning"). `[V S1]`

**6. Backup, server choice, connection status**

- Backup is a 12-word recovery phrase screen with two tick boxes the user must accept ("I have saved my recovery phrase somewhere safe." and a loss disclaimer). `[V S3]` (12 words: `[R]`)
- Until done, an in-app notice says "Backup your wallet to prevent losing your bitcoins." with the action "Backup my wallet". `[V S3]`
- Electrum server: "By default, random servers are used. You can also configure Phoenix to connect only to your own server." Shows "Connected to …". `[V S2]`
- It rejects a server with an unknown certificate, and warns to use an onion address when Tor is on. `[V S2]`
- Connection status is in the home top bar and opens a dialog. `[V S5]`

**7. Simple versus advanced**

- No mode switch. "Advanced" is a settings group at the bottom, just above "Danger zone". `[V S4]`
- Advanced fee options are a second screen behind the simple fee screen. `[V S2]`

**8. Warnings and attention items**

- Notices sit on the home screen between balance and payments. `[V S5]`
- The settings entry "Notifications" shows a count. `[V S4]`
- Notice types found: seed not backed up; background processing restricted; power saving mode; payment rejected (with reason); deposit about to expire ("This swap will expire in a day!"); watchtower late; watchtower alert. `[V S3]`
- The watchtower reports good news too: "N channel was successfully checked on [date]. No issues were found." `[V S3]`
- When it could not watch: "Phoenix regularly monitors the blockchain when in the background, but was unable to do so the last few days." `[V S3]`
- System notification channels are described in plain words, for example "Tells you when Phoenix needs to be started to settle a pending payment." `[V S2]`
- Destructive actions carry consequence text: force close "will cost you money … and will cause your funds to be locked for days", and "Do not uninstall the app until your channels are fully closed". `[V S3]`

**9. Praise and criticism**

- Praised: "Best Lightning UX on any platform"; feels "as simple as a custodial app"; user sees one number and one send button. `[V S6]`
- Criticised: dependence on one liquidity provider; 0.4% send fee plus mining fees; must be online to receive. `[V S6]`
- Criticised: users still meet liquidity and mining-fee trade-offs and need to understand fee previews. `[VS S39]`

### A2. Zeus

**1. Home screen**

- The main screen is a set of bottom tabs with icons only, no labels. `[V S9]`
- Tabs in order: Balance, Keypad, Channels, Camera (QR scanner). Channels shows only when the backend supports channel management. `[V S9]`
- The default tab is a user setting; if unset it is Keypad. `[V S9]`
- The Balance tab shows layered balances (`LayerBalances`). `[V S9]` It shows separate rows for Lightning and on-chain. `[R]`
- History is not on the home. It is a pull-up "Activity" bar at the bottom of Balance that opens a separate screen. `[V S9]`
- While the node starts, a connecting screen replaces the tabs and shows a status line (starting node, syncing, connecting, and so on). `[V S9]`
- On error the tab bar turns the error colour and Balance offers "go to wallet config" and Retry. `[V S9]`

**2. Navigation**

- Bottom tabs plus a settings menu reached from the header. `[V S9]` (header contents not in the file read; menu icon top-left `[R]`)
- Phone app only; no desktop build. `[R]`
- One app, many backends: embedded node, own LND or Core Lightning node, LNDHub, and others. `[V S7]`

**3. Settings groups** (blocks in order; many are conditional)

| Block | Entries | Shown when |
|---|---|---|
| 1 | Embedded node | Using the built-in node |
| 2 | LSP | Backend supports it |
| 3 | Ecash | Backend supports it |
| 4 | Payments, Invoices | A wallet is selected |
| 5 | Channels | Backend supports channel management |
| 6 | Networking, Privacy, Security | Always |
| 7 | Currency, Language | Always |
| 8 | Display | Always |
| 9 | Point of Sale | A wallet is selected |

All rows `[V S8]`.

- Embedded node screen holds: Pathfinding, Neutrino Peers, Zero conf Peers, Express Graph Sync, Disaster recovery, Advanced disaster recovery, Troubleshooting, Channel tools, logs, Rescan wallet, and "Persistent" mode (keep the node running when the app is closed). `[V S10]`
- Privacy holds: default block explorer, Lurker mode, clipboard reading, mempool fee suggestions. `[V S10]`
- Security holds: PIN, Duress PIN, scramble PIN, require login on return. `[V S10]`

**4. Channel and liquidity state**

- Channels are a first-level tab, not hidden. `[V S9]`
- Labels use plain words with the technical word in brackets: "Sending capacity (outbound)", "Receiving capacity (inbound)". `[V S10]`
- The list switches between Open, Pending and Closed, with a count for each. `[V S11]`
- The single channel view stresses the channel reserve. `[V S11]`
- A totals header includes "Total offline". `[V S10]`
- Each channel row draws a two-colour bar of local versus remote balance. `[R]`

**5. Automatic actions with a limit**

- The LSP is a switch: "Enable Lightning Service Provider (LSP)" with the line "The LSP will get you connected to the Lightning network by opening up payment channels for you." `[V S10]`
- Fees are explained on a "What are these fees?" screen rather than capped by a user number. `[V S10]`
- I found no user-set fee cap for automatic channel opening in the strings I read. `[V S10]` (absence in the part read; not proof)
- "Enable automatic backups": "Automatically create disaster recovery data and send it to the Olympus backup service." `[V S10]`

**6. Backup, server choice, connection status**

- Seed screen: "The following 24 words are your wallet backup." `[V S10]`
- A second reminder covers what the seed does not: "Don't forget your channels!" You "also need to export your channel backup file." Dismiss is "I'll do it later." `[V S10]`
- Home nudge: "Back up your funds", "Create a backup to never lose access to your bitcoin.", "Start backup ->". `[V S10]`
- Restore carries its cost: "Restoring a wallet will trigger a force close of all your channels." `[V S10]`
- Server choice is the choice of whole backend (own node or embedded). Chain peers for the embedded node are under Embedded node > Neutrino Peers. `[V S7]` `[V S10]`
- Networking has "Disable offline detection" for when the app wrongly shows offline. `[V S10]`

**7. Simple versus advanced**

- No global mode. Advanced is per screen: "Advanced settings", "Advanced set-up", "Advanced disaster recovery". `[V S10]`
- Whole settings blocks appear or vanish by backend type. `[V S8]`

**8. Warnings**

- Full-screen status while starting; error colour on the tab bar. `[V S9]`
- Dialogs for "Battery Saver Mode Detected", "Startup is taking longer than expected", "Restart required". `[V S10]`
- Danger wording in capitals: "DANGER: Only proceed if you have NOT imported your channel backup on another device." `[V S10]`

**9. Praise and criticism**

- Praised: full control of node and channels for power users; easy switching between a remote node and the embedded node. `[VS S40]`
- Criticised: steeper onboarding than Phoenix; start-up delay of 10 to 60 seconds while the embedded node catches up. `[VS S40]`
- Called "one of the most complex and complete" apps by a user. `[VS S40]`

### A3. BlueWallet

**1. Home screen**

- Order: a horizontal carousel of wallet cards, then a list of the latest transactions across wallets (up to 10). `[V S15]`
- The carousel ends with an add-wallet card. Tap a card to open that wallet. Long-press to manage wallets. `[V S15]`
- With several wallets, an optional total balance bar replaces the "wallets" label. `[V S15]`
- One floating scan button, shown only when wallets exist. Long-press offers image, scan, or paste. `[V S15]`
- No send button on the home. Send and receive live inside each wallet. `[V S15]` (inside-wallet placement `[R]`)
- On wide screens the carousel is hidden and only the transaction list stays. `[V S15]` Wallets move to a side drawer. `[R]`

**2. Navigation**

- Single home plus drill-down into a wallet. Settings from the header. `[V S15]` `[R]` (header not in file read)
- A desktop (Mac) build exists using the same screens. `[R]`

**3. Settings groups** (flat list, in order)

| Entry | Holds |
|---|---|
| Donate | External link |
| General | On Launch, Widgets, Continuity, analytics switch |
| Currency | Fiat currency and rate source |
| Language | Language |
| Security | Storage encryption, Plausible Deniability, Biometrics |
| Network | Electrum Server, Lightning Settings, Block Explorer, notifications |
| Tools | Self-test, performance test |
| About | About |

Top-level list `[V S13]`. Contents `[V S14]`.

**4. Channel and liquidity state**

- Lightning in BlueWallet is an account on an LNDHub server, so there are no channels to show. `[V S14]` `[R]`
- The Lightning wallet card has "Manage Funds" and "Refill". `[V S14]`
- The hosted LNDHub service shut down on 30 April 2023. Lightning now needs the user's own LNDHub. `[VS S16]` `[V S17]`

**5. Automatic actions with a limit**

- None found. `[V S14]` (absence in strings read)

**6. Backup, server choice, connection status**

- After creating a wallet: "Please save this wallet backup." and "Without the backup phrase, your funds will be permanently lost." `[V S14]`
- It asks outright: "Have you saved your wallet's backup phrase?" with "Yes, I have." and "No, I have not." `[V S14]`
- Electrum server screen shows "Connected" or "Not Connected", has "Offline Mode", "Set as preferred" and "Reset to default". `[V S14]`
- Reset explains itself: "This will let BlueWallet randomly choose a server from the server list." `[V S14]`
- Connection status is on that settings screen, not on the home. `[R]`

**7. Simple versus advanced**

- Help text for multisig refers to "Advanced Mode in the Settings", but the strings read contain no such switch now. It looks removed. `[V S14]`
- "Advanced" survives as a section inside wallet details. `[V S14]`

**8. Warnings**

- Mostly dialogs at the moment of action. No notice area on the home was found. `[V S15]`

**9. Praise and criticism**

- Praised: "clean, polished"; one of the best-looking mobile wallets; UI rated 9/10. `[V S17]`
- Praised: advanced on-chain tools (coin control, multisig, watch-only) inside a simple app. `[V S17]`
- Criticised: Lightning is not plug-and-play since the hosted service ended; harder than Phoenix for Lightning beginners. `[V S17]`

### A4. Muun

**1. Home screen**

- Balance at the top ("Tap to reveal balance" when hidden), Send and Receive buttons, payment history below. `[V S19]` `[V S21]`
- One balance covers on-chain and Lightning. `[V S18]` `[V S20]`
- Cards on the home prompt single tasks: "Back up your wallet.", a Taproot upgrade card, and a congestion card: "The Bitcoin Network is congested. Fees are high, and confirmation times are slow." `[V S19]`
- History is reached by pulling up a sheet from the bottom of the home. `[R]`

**2. Navigation**

- Three bottom tabs: Wallet, Security, Settings. `[V S19]`
- No desktop app. `[R]`

**3. Settings groups**

| Group | Entries |
|---|---|
| Wallet details | Email, Phone number, Main currency, Bitcoin unit |
| Recovery and security | Change password, Fingerprint unlock, Recovery Code, Recovery Tool |
| Advanced settings | Lightning Network, Bitcoin Network (address type) |
| General | Log out, Delete wallet |

All `[V S19]`.

**4. Channel and liquidity state**

- Hidden completely. Lightning payments are done by submarine swap from the one balance. "Zero channel configuration." `[V S20]`
- The only channel word in the app is a switch, "Turbo channels". Turning it off warns: "Receiving some lightning payments will take much longer." `[V S19]`
- The cost of hiding shows up as fees: payment details list a "Lightning fee" and a "Swap fee". `[V S20]`

**5. Automatic actions with a limit**

- No user-set caps. Fees are chosen per payment: "Select a confirmation time" or "Enter fee manually". `[V S19]`

**6. Backup, server choice, connection status**

- Backup is a whole tab, "Security Center", with three steps: email backup, Recovery Code, Emergency Kit. `[V S19]`
- The tab header is a status sentence that changes: "Your wallet is not backed up", "Your wallet has a basic backup", "You're one step away from a complete setup", "You completed your setup". `[V S19]`
- Each step has a pending and a done wording. `[V S19]`
- No seed words. The Emergency Kit is an exported document with keys and output descriptors. `[V S18]`
- No server choice. No own-node support. `[V S21]`

**7. Simple versus advanced**

- One "Advanced settings" group with two entries. `[V S19]`

**8. Warnings**

- Home cards for backup and for network congestion. `[V S19]`
- Errors are short titles plus a plain explanation: "There is no available route", "This payment is too small". `[V S19]`
- Delete wallet opens "Please read carefully". `[V S19]`

**9. Praise and criticism**

- Praised: minimal; "no tabs, no hamburger menus hiding features, no settings buried three levels deep". (The reviewer's words. The app does have three bottom tabs.) `[V S21]`
- Praised: one balance, no channel management, no inbound limit. `[V S21]`
- Criticised: Lightning fees "10-50x higher than native Lightning wallets due to submarine swaps"; swap margin not itemised. `[V S21]`
- Criticised: it is in effect an on-chain wallet that swaps, and Muun's servers see user activity. `[VS S22]` `[V S21]`

### A5. Sparrow

**1. Home screen**

- There is no dashboard. The window shows the open wallet. Each wallet has a column of tabs on the left. `[V S23]` `[V S25]`
- The left tabs are: Transactions, Send, Receive, Addresses, UTXOs, Settings. `[R]` (Transactions, Receive, Addresses, UTXOs and Settings confirmed `[V S23]`)
- The tabs are grey until the wallet is valid, then turn blue. `[V S23]`
- Transactions shows the balance and a history table. `[R]`

**2. Navigation**

- Desktop only. `[V S28]` Top tabs for open wallets and transactions, left tabs inside a wallet, a menu bar, and a status bar. `[R]`
- "Sparrow is a tab based desktop wallet". `[V S25]`

**3. Settings groups**

- Two different things, clearly split: app Settings (a dialog) and wallet Settings (a tab inside the wallet). `[V S23]` `[V S24]`
- App Settings dialog has a General tab and a Server tab. `[VS S41]` `[V S24]`
- Wallet Settings tab holds policy type, script type, keystores, and an Advanced button (gap limit lives there). `[V S26]` `[R]`

**4. Channel and liquidity state**

- Not applicable. No Lightning. `[V S28]`

**5. Automatic actions with a limit**

- None of note. Fees are set by hand per transaction on a diagram. `[V S25]`

**6. Backup, server choice, connection status**

- Seed creation forces a re-entry test: "Confirm Backup…" then "Re-enter Words…" before the keystore is created. `[V S23]`
- Three server types, each with its own icon: public server, Bitcoin Core node, private Electrum server. `[V S23]`
- The public option carries the privacy cost in words: it shares "your public key information (and thus your privacy)". Also "Your funds are never at risk, but your privacy is shared." `[V S23]`
- "Test Connection" button shows the result inside the dialog. `[V S24]`
- A toggle in the status bar switches online and offline. Its colour shows the kind of connection. `[V S23]`
- Colours in the stylesheet: green (#50a14f) for Bitcoin Core, gold for a public server. `[V S27]` Blue for a private Electrum server. `[VS S42]`
- A red Tor icon in the status bar means the proxy cannot be reached; the tooltip gives the error. `[V S26]`
- A red icon on a wallet's tab means its history failed to load. `[V S26]`
- Scan progress and time remaining appear in the status bar. `[V S24]`

**7. Simple versus advanced**

- No modes. Everything is visible. A few items sit behind "Advanced" buttons. `[V S26]`
- Rare options are config-file only. `[V S26]`

**8. Warnings**

- Status bar text, coloured icons on tabs, and tooltips. `[V S26]`

**9. Praise and criticism**

- Praised: the editable transaction diagram that shows inputs and outputs before signing. `[V S25]` `[V S28]`
- Praised: own-node and Tor support built in; nothing hidden. `[V S28]`
- Criticised: steep learning curve; ease of use 6/10; detail overwhelms people who only want to send and receive. `[V S28]`

### A6. Electrum

**1. Home screen**

- Desktop: the window opens on the History tab. Tabs always shown, in order: History, Send, Receive. `[V S30]`
- Balance is not at the top. It is text in the status bar at the bottom ("Balance" plus amount, plus fiat if enabled). `[V S30]`
- Phone (Android): balance at the top with Send and Receive buttons and a history list. `[R]`

**2. Navigation**

- Desktop: top tabs, a menu bar (File, Wallet, View, Tools, Help), and a status bar with icon buttons. `[V S30]`
- Optional tabs, off until switched on from the View menu: Addresses, Channels, Coins, Contacts, Console, Notes. `[V S30]`
- The Channels tab turns itself on when the wallet has Lightning. `[V S30]`

**3. Settings groups**

| Where | What |
|---|---|
| Tools > Preferences: Appearance | Language, colour theme, block explorer |
| Preferences: Units | Base unit, decimals, separators |
| Preferences: Fiat | Currency, rate source, history rates |
| Preferences: Lightning | Trampoline on or off (one tick box) |
| Preferences: Misc | Update checks, logs, screenshot protection, alias, camera |
| Tools > Network (own dialog) | Server, Nostr, Proxy tabs |
| Wallet menu | Information, Password, Seed, Private keys, Labels |

Preferences tabs `[V S32]`. Network dialog `[V S31]`. Menus `[V S30]`.

- Settings are spread over three places: Preferences, Network, and the Wallet menu. `[V S30]`

**4. Channel and liquidity state**

- Channels tab columns: Short Channel ID, Node alias, Capacity, Can send, Can receive, Status. `[V S33]`
- A status line sums it: "Can send X; can receive Y". `[V S33]`
- Tools on the tab: "New Channel", "Rebalance channels", "Submarine swap", "Import channel backup". `[V S33]`
- Per-channel right-click: Details, Freeze for sending or receiving, Cooperative close, Force-close, Export backup. `[V S33]`
- A channel that the seed cannot recover carries an icon with the tooltip "This channel cannot be recovered from your seed. You must back it up manually." `[V S33]`

**5. Automatic actions with a limit**

- Server choice has three named modes: autoconnect, manual, one-server. `[V S31]`
- No automatic channel actions with a user cap were found. `[V S32]` `[V S33]`
- The watchtower is a tick box, "use a remote watchtower", plus a URL. The tower itself is a separate daemon set up on the command line. `[V S34]`

**6. Backup, server choice, connection status**

- Seed phrase; the docs advise paper. Restore through "I already have a seed." `[V S29]`
- File > Save backup. With channels, the dialog warns the backup holds channel backups that cannot make payments. `[V S30]`
- Force-close dialog offers a "Create a backup now" tick box. `[V S33]`
- Electrum keeps about 10 server connections and picks one as the main server. `[V S29]`
- Network dialog Server tab shows: connection mode, server field (red when invalid), Status, Blockchain height, and a tree of "Connected nodes" and "Other known servers". `[V S31]`
- Fork state is put in words: "Fork detected at block N", "You are following branch …". `[V S31]`
- Proxy tab: "Use proxy", type, host, port, and a "Detect Tor proxy" button. `[V S31]`
- Status bar network button changes icon by state. States: offline, "Not connected", "Synchronizing...", "Server is lagging (N blocks)", "Connected", with proxy and fork variants. `[V S30]`
- Clicking that button opens the Network dialog. `[R]`
- The status bar also has buttons for password, preferences, seed, a Lightning button showing sync percent, and a Tor button when proxied. `[V S30]`

**7. Simple versus advanced**

- Advanced is revealed tab by tab from the View menu. The choice is remembered. `[V S30]`
- The last resort is a Console tab. `[V S30]`

**8. Warnings**

- One-time dialogs with "Don't show this again" (testnet mode). `[V S30]`
- A fixed "This wallet is watching-only." message. `[V S30]`
- Colour in tables: addresses beyond the gap limit have a red background. `[V S29]`
- A "Password required" warning button in the status bar. `[V S30]`

**9. Praise and criticism**

- Praised: fee control, multisig, cold storage; "Bitcoin-centric features are hard to beat". `[VS S35]`
- Criticised: interface "looks dated"; "not apt for beginners". `[VS S35]`
- Criticised: a server could push text into the app, which was used for fake "update" phishing; no auto-update. `[VS S35]`

### A7. Trezor Suite

**1. Home screen**

- The Dashboard is the first screen. `[VS S43]`
- Before funds: a "Your wallet is ready." message with Receive and Buy buttons. `[V S37]`
- After funds: a Portfolio chart first, with a time-range filter, then an Assets section by coin. `[V S37]`
- Security checks card and a recent activity area on the dashboard. `[R]`

**2. Navigation**

- Desktop: left sidebar with the account list, a wallet and device switcher top-left, Settings in the sidebar. `[V S37]` `[VS S43]`
- Each account has action tabs: Receive, Send, Buy and sell, Swap. `[V S37]`
- Bottom-left corner: discreet mode (eye icon) and version or update notice. Bottom-right: a help guide (lightbulb). `[V S37]`
- Phone: a bottom menu (Trade, My assets, Settings), wallet menu at the top, Receive and Send on the dashboard. `[V S37]`

**3. Settings groups**

| Tab (desktop) | Holds |
|---|---|
| Application | Language, fiat, units; Labeling; Privacy (auto eject wallets, Tor, biometric); colour scheme; data collection; log; updates; Experimental (Early Access, Experimental features) |
| Device | Wallet backup (status, check backup); Passphrase; Firmware; Security (PIN, safety checks); Customization (name, homescreen, auto-lock); Connection; **Danger area** (wipe, wipe code, custom firmware, turn off checks) |
| Networks | Enable or disable networks; custom backend per network |
| Connected apps | Wallet Connect, Trezor Connect |

All `[V S36]`.

- The settings are split by what they act on: the app, the device, the networks. `[V S36]`
- The Device tab needs a connected device. `[V S36]`
- Phone splits it another way: app Settings in the bottom menu, device settings under a gear in the wallet menu. `[V S37]`
- Phone has an "Advanced" group and a "Danger Zone". `[V S36]`

**4. Channel and liquidity state**

- Not applicable. No Lightning. `[R]`

**5. Automatic actions with a limit**

- "Auto eject wallets" and "Auto-lock time" are the automatic behaviours, each a single setting. `[V S36]`
- Fee levels with a custom option on send. `[R]`

**6. Backup, server choice, connection status**

- "Backup status" and "Check wallet backup" sit in Device settings. `[V S36]`
- The backup is written from the device screen during setup. Suite says it "never asks for your recovery seed". `[V S37]`
- Server choice: "Custom backends", a sliders icon beside each network, for a Blockbook or Electrum server. `[V S36]`
- Tor is a switch under Application > Privacy. `[V S36]`
- A Tor and backend status indicator in the sidebar. `[R]`
- View-only: wallets stay visible after unplugging; sending needs the device. `[V S37]`

**7. Simple versus advanced**

- Advanced is gated in steps: "Experimental features" and "Early Access Program" switches at the bottom of Application. `[V S36]`
- A hidden debug settings tab exists, opened by clicking the Settings title several times. `[R]`
- Passphrase wallets are an opt-in ("Use passphrase wallets"). `[V S36]`

**8. Warnings**

- Update notice in the bottom-left corner. `[V S37]`
- Top-of-window banners for firmware, backup not done, and device problems. `[R]`
- Setup is a guided flow with a device authenticity check. `[V S37]`

**9. Praise and criticism**

- Praised: "clean and beginner-friendly"; makes send and receive understandable without overwhelming. `[V S38]`
- Praised: one official app lowers phishing risk. `[V S38]`
- Criticised: built-in buy, sell and swap go through third parties with spreads; some assets need other wallets. `[V S38]`

---

## B. Synthesis

### (a) Patterns at least three products share

| # | Pattern | Seen in |
|---|---|---|
| 1 | Home is balance, then Send and Receive, then history. | Phoenix, Muun, Trezor Suite (phone), Electrum (phone, recalled) |
| 2 | A named danger area holds destructive actions, apart from the rest. | Phoenix ("Danger zone"), Trezor ("Danger area", "Danger Zone"), Muun (General: delete), Zeus (DANGER wording) |
| 3 | "Advanced" is a place, not a mode. A group or a button at the bottom. | Phoenix, Muun, Zeus, Sparrow, BlueWallet |
| 4 | Backup is a task with a state, nagged from the home until done. | Phoenix, Muun, Zeus, BlueWallet (asks at creation) |
| 5 | Backup demands proof or an explicit promise. | Sparrow (re-enter words), Phoenix (tick boxes), BlueWallet (yes or no question) |
| 6 | The chain server defaults to random public servers, with an own-server override. | Phoenix, BlueWallet, Sparrow, Electrum, Trezor (custom backend) |
| 7 | Connection state is always visible in a small fixed spot, and tapping it opens the detail. | Phoenix (top bar), Sparrow (status bar toggle), Electrum (status bar button) |
| 8 | Destructive actions state the consequence in a sentence. | Phoenix, Zeus, Electrum, Muun |
| 9 | Capacity is shown as two plain numbers: what you can send and what you can receive. | Phoenix, Zeus, Electrum |
| 10 | Tor is one switch, with a status icon. | Phoenix, Sparrow, Electrum, Trezor |

### (b) Distinctive patterns worth borrowing

| Pattern | From | Gazpacho problem it solves |
|---|---|---|
| One switch plus one number for automation ("Automated channel management" and "Max fee amount"), with the advanced checks on a second screen. | Phoenix | Personal joining conditions. Keeps the first screen to a few limits. Extra limits go one level down. |
| The limit is checked live against today's reality ("Below the expected fee. Some payments may be rejected."). | Phoenix | A member sets conditions so strict that no lobby matches. Show "0 of 14 open lobbies fit these conditions" beside the field. |
| When the limit blocks something, the message shows both numbers ("The fee was X, but your max was Y"). | Phoenix | Explains why the app did not join or did not sign. Builds trust in automatic signing. |
| A sentence on the home saying what the automation will do next ("Will deploy when fees are below X"). | Phoenix | "Will join a lobby when one fits your conditions" or "Signing is paused: you turned off auto-join". |
| The watcher reports good news with a date ("N channel checked on [date]. No issues."), and admits when it could not watch. | Phoenix | Watching options. The member needs to know the app looked while they were away. |
| Deadlines in words with time left ("This swap will expire in a day!", "After one year … reclaimed"). | Phoenix | Factory lifetime and end date. Reminders and deadlines. |
| Backup as a staged status sentence ("not backed up", "basic backup", "one step away", "completed"). | Muun | Wallet options. Gazpacho backup may have more than one part (keys plus factory state). |
| A second reminder for what the seed does not cover ("Don't forget your channels!"). | Zeus, Electrum (icon and tooltip) | If factory state needs a backup beyond the phrase, say so separately. |
| Settings blocks appear or vanish by role. | Zeus | Hosting options. Show the hosting area only when hosting is on. Members never see it. |
| Plain word first, technical word in brackets ("Receiving capacity (inbound)"). | Zeus | All Gazpacho labels. Fits the plain-language rule. |
| Settings split by what they act on (Application, Device, Networks). | Trezor Suite | The six option areas. Each acts on a different thing: me, this lobby, this wallet, the watcher, the servers, my hosting. |
| A coloured toggle in a status bar that is both the state and the control. Colour says whose server. | Sparrow | Connections. Green for own server, gold for a public one. One glance. |
| The privacy cost of the default written next to the choice ("your privacy is shared"). | Sparrow | Connections, and choice of host. |
| "Test Connection" with the result in the dialog. | Sparrow | Connections. Also a "test my conditions against current lobbies" button. |
| App settings and wallet settings are physically separate (a dialog versus a tab inside the wallet). | Sparrow | Lobby terms. Put them inside the lobby, read-only, never in the app settings. |
| Fork and lag put in words ("Server is lagging (N blocks)"). | Electrum | Connections. A stale chain server is a safety issue for a factory. |
| Notice area on the home, plus a count on the Notifications entry. | Phoenix | Things needing attention. |
| View-only when the key is absent. | Trezor Suite | A member can check the lobby and watcher state without unlocking signing. |

### (c) Patterns to avoid

| Pattern | Seen in | Why avoid |
|---|---|---|
| Hiding the mechanism completely. | Muun | The cost comes back as fees the user cannot see or control. Gazpacho's whole point is that the member sets the limits. |
| A flat settings list where unrelated things are neighbours. | BlueWallet | Gazpacho has six areas that must not blur. A flat list would mix "my conditions" with "network". |
| Settings spread over three unrelated places. | Electrum (Preferences, Network, Wallet menu) | Users cannot guess where a thing lives. Have one map. |
| Icon-only bottom tabs. | Zeus | New words (lobby, host, conditions) need labels. |
| History hidden behind a drawer on the home. | Zeus, Muun | For Gazpacho, "what the app did while I was away" is the main trust signal. Keep it on the home. |
| Everything visible at once. | Sparrow | Praised by experts, rated 6/10 for ease. Wrong default for a phone wallet. |
| Balance tucked in a status bar. | Electrum desktop | Balance is the first question. |
| A hidden debug door (click a title several times). | Trezor Suite (recalled) | Fine for developers. Not for anything a host or member needs. |
| A status sentence the server can write. | Electrum (historic) | Was used for phishing. Never show host-supplied free text as if the app said it. Lobby terms from a host must be rendered as structured fields. |
| Security and network in one group. | Phoenix (Electrum server and Tor sit under Security with the recovery phrase) | Gazpacho wants Connections apart from Wallet options. |
| Two fee checks where the second quietly overrides the first. | Phoenix ("Skip absolute fee check") | A limit that sometimes does not apply is hard to trust. If Gazpacho has overrides, show them on the same screen as the limit. |
| Trade or upsell actions in the main navigation. | Trezor Suite | Dilutes the home. |

### (d) Guidance for three layout concepts

The six option areas, named here for short:

1. **My conditions** (personal joining limits)
2. **Lobby terms** (set by the host, read-only to members)
3. **Wallet** options (keys, backup, on-chain funds, network)
4. **Watching** options (away behaviour, watchtower, reminders, deadlines)
5. **Connections** (chain servers)
6. **Hosting** options

#### Concept 1: "Wallet first" (Phoenix, Zeus, Muun style)

Skeleton (phone):

- Bottom tabs with labels: **Wallet**, **Lobbies**, **Watch**, **Settings**. Four at most.
- A fifth tab, **Host**, appears only when hosting is switched on (the Zeus conditional-block idea).
- A small connection dot in the top bar of every tab. Tap opens Connections.

Home (Wallet tab), top to bottom:

1. Top bar: connection dot, lobby chip ("In lobby: [host name], ends in 41 days").
2. Balance. One number. Tap for the split (spendable now, on-chain, waiting).
3. One status sentence about the automation (Phoenix style): "Auto-join is on. Will join when a lobby fits your conditions."
4. Notice cards, at most two shown, with "See all (n)".
5. Send and Receive.
6. Activity list, including automatic actions ("Signed lobby update, within your conditions").

Where the six areas live:

| Area | Place |
|---|---|
| My conditions | Lobbies tab, pinned at the top as a summary card ("Max fee … , size … , lifetime …"). Tap to edit. One switch (auto-join) plus the few main limits. "More limits" opens a second screen. |
| Lobby terms | Inside a lobby's page in the Lobbies tab. Read-only fields with a lock icon and "Set by the host". Each term shows a tick or cross against my conditions. |
| Wallet | Settings tab > Wallet. Backup as a staged status line at the top (Muun style). Danger zone at the bottom. |
| Watching | Its own tab, **Watch**. Top: "Last checked [time]. No issues." Then deadlines, then reminders, then watchtower settings. |
| Connections | Settings tab > Connections, and reachable from the dot on every screen. |
| Hosting | Hidden until "Act as a host" is turned on in Settings. Then a Host tab. |

Strength: least to learn. Risk: the Lobbies tab carries two areas (my conditions and lobby terms). Keep them visually different: mine are editable cards, the host's are locked rows.

#### Concept 2: "Desktop power wallet" (Sparrow, Electrum style)

Skeleton (desktop window):

- Left column of labelled tabs: **Overview**, **Send**, **Receive**, **Lobbies**, **My conditions**, **Watching**, **Activity**, **Wallet**.
- A **Hosting** group below a divider, with its own sub-tabs, shown when hosting is on.
- Bottom status bar, always present: connection toggle with colour by server type (Sparrow), chain height and lag in words (Electrum), watcher state ("Watching, last check 2 min ago"), next deadline.
- App-level preferences in a separate dialog: Connections, Display, Advanced.

Home (Overview tab):

- Left: balance split, current lobby with time left.
- Right: a table of pending and recent automatic actions with the rule that allowed each.
- Top strip: attention items, each with a button.

Where the six areas live:

| Area | Place |
|---|---|
| My conditions | Own left tab. A form with all limits visible, each with a live "n lobbies fit" count and a "Test against current lobbies" button. |
| Lobby terms | Lobbies tab. A table of lobbies; selecting one shows a read-only terms panel beside my conditions, row for row (a comparison, like Sparrow's diagram before signing). |
| Wallet | Own left tab (keys, backup, on-chain funds), like Sparrow's per-wallet Settings tab. |
| Watching | Own left tab, and summarised in the status bar. |
| Connections | Preferences dialog > Connections, opened by clicking the status bar toggle. Includes "Test Connection" and the privacy cost of a public server. |
| Hosting | Separate group in the left column: Offered lobbies, Terms I set, Members, Liquidity. |

Strength: every area has one obvious home, and a host can see everything. Risk: too much for a member. Rated-6/10 territory. Use only as the desktop or host-facing form.

#### Concept 3: "Suite with simple and advanced levels" (Trezor Suite style)

Skeleton:

- Desktop: left sidebar. Phone: bottom menu. Same entries: **Home**, **Lobbies**, **Activity**, **Settings**.
- A role switcher at the top-left, where Suite has its device and wallet switcher: **Member** or **Host**. Switching role changes the sidebar and the dashboard.
- Settings is one screen with tabs by what they act on: **My conditions**, **Wallet**, **Watching**, **Connections**, and **Hosting** (only in the Host role).
- Each settings tab has a "Basic" part shown by default and an "Advanced" part folded at the bottom. One app-wide switch, "Show advanced options", unfolds them all. No hidden doors.
- Each tab that can destroy something ends with a "Danger area".

Home (dashboard), top to bottom:

1. Banner row for things needing attention.
2. Balance card.
3. "Your lobby" card: host, end date, capacity to send and receive in plain words.
4. "Checks" card: backup done, watching on, own server or public, conditions set. Each is a tick or a "Fix" button.
5. Recent activity.

Where the six areas live:

| Area | Place |
|---|---|
| My conditions | Settings > My conditions. Basic: auto-join switch, max fee, max lifetime. Advanced: the rest. |
| Lobby terms | Not in Settings at all. Lobbies > [lobby] > Terms, read-only. This keeps "set by the host" away from anything the member can edit. |
| Wallet | Settings > Wallet. Backup status and "Check backup" at the top. On-chain funds and network under Advanced. Danger area last. |
| Watching | Settings > Watching. Basic: reminders on or off, what to do near a deadline. Advanced: watchtower choice. |
| Connections | Settings > Connections. Basic: "Automatic" or "My own server". Advanced: server list, proxy. Status shown in the sidebar foot. |
| Hosting | Settings > Hosting, plus a Host dashboard, both only in the Host role. |

Strength: the clearest separation of the six areas, and it scales from phone to desktop. Risk: conditions are buried in Settings, when they are the core of the product. Fix by also showing the conditions summary on the Lobbies page with an "Edit" link.

### Short recommendation

- Use Concept 1 for the phone and for members.
- Use Concept 3's settings split (by what the setting acts on) inside it.
- Keep Concept 2's status bar idea everywhere, as a one-line strip: connection, watcher, next deadline.
- Keep lobby terms out of Settings in every concept.

---

## C. What I could not check

- Any screenshot or running app.
- Phoenix FAQ and iOS interface. Current fee amounts.
- Zeus header contents, channel bar drawing, the last 18,000 characters of its strings, and whether the newest release changed the embedded node.
- BlueWallet header, drawer on tablets, and whether an advanced mode switch still exists.
- Muun's history sheet and any server-status display.
- Sparrow's full left-tab list and the blue colour for a private Electrum server (one snippet only).
- Electrum's phone interface, the wording of its connection mode labels, and whether zero-conf or watchtower options appear elsewhere in the desktop app.
- Trezor Suite's dashboard security card, Tor and backend indicator, banners, and the hidden debug tab.
- All praise and criticism items rest on one or two review sites each.

## D. Sources

| Key | URL |
|---|---|
| S1 | https://acinq.co/blog/phoenix-splicing-update |
| S2 | https://raw.githubusercontent.com/ACINQ/phoenix/master/phoenix-android/src/main/res/values/strings.xml |
| S3 | https://raw.githubusercontent.com/ACINQ/phoenix/master/phoenix-android/src/main/res/values/important_strings.xml |
| S4 | https://raw.githubusercontent.com/ACINQ/phoenix/master/phoenix-android/src/main/kotlin/fr/acinq/phoenix/android/settings/SettingsMenuView.kt |
| S5 | https://raw.githubusercontent.com/ACINQ/phoenix/master/phoenix-android/src/main/kotlin/fr/acinq/phoenix/android/home/HomeView.kt |
| S6 | https://bitcoindiy-site.vercel.app/reviews/phoenix-wallet |
| S7 | https://docs.zeusln.app/ |
| S8 | https://raw.githubusercontent.com/ZeusLN/zeus/master/views/Settings/Settings.tsx |
| S9 | https://raw.githubusercontent.com/ZeusLN/zeus/master/views/Wallet/Wallet.tsx |
| S10 | https://raw.githubusercontent.com/ZeusLN/zeus/master/locales/en.json |
| S11 | https://nobsbitcoin.com/zeus-v0-9-3 |
| S13 | https://raw.githubusercontent.com/BlueWallet/BlueWallet/master/screen/settings/Settings.tsx |
| S14 | https://raw.githubusercontent.com/BlueWallet/BlueWallet/master/loc/en.json |
| S15 | https://raw.githubusercontent.com/BlueWallet/BlueWallet/master/screen/wallets/WalletsList.tsx |
| S16 | https://bluewallet.io/sunsetting-lndhub and https://bitcoinmagazine.com/business/bluewallet-to-sunset-custodial-lightning-wallet-service (search summary only) |
| S17 | https://bitcoindiy-site.vercel.app/reviews/bluewallet |
| S18 | https://muun.com/ |
| S19 | https://raw.githubusercontent.com/muun/apollo/master/android/apolloui/src/main/res/values/strings.xml |
| S20 | https://blog.muun.com/lightning-payments-easier-than-ever/ |
| S21 | https://bitcoindiy-site.vercel.app/reviews/muun |
| S22 | https://stacker.news/items/131436 (search summary only) |
| S23 | https://sparrowwallet.com/docs/quick-start.html |
| S24 | https://sparrowwallet.com/docs/connect-node.html |
| S25 | https://sparrowwallet.com/features/ |
| S26 | https://sparrowwallet.com/docs/faq.html |
| S27 | https://raw.githubusercontent.com/sparrowwallet/sparrow/master/src/main/resources/com/sparrowwallet/sparrow/app.css |
| S28 | https://bitcoindiy-site.vercel.app/reviews/sparrow-wallet |
| S29 | https://electrum.readthedocs.io/en/latest/faq.html |
| S30 | https://raw.githubusercontent.com/spesmilo/electrum/master/electrum/gui/qt/main_window.py |
| S31 | https://raw.githubusercontent.com/spesmilo/electrum/master/electrum/gui/qt/network_dialog.py |
| S32 | https://raw.githubusercontent.com/spesmilo/electrum/master/electrum/gui/qt/settings_dialog.py |
| S33 | https://raw.githubusercontent.com/spesmilo/electrum/master/electrum/gui/qt/channels_list.py |
| S34 | https://electrum.readthedocs.io/en/latest/watchtower.html |
| S35 | https://money.com/electrum-crypto-wallet-review/ , https://decrypt.co/31553/electrum-wallet-review-no-frills-design-with-strong-features , https://www.malwarebytes.com/blog/news/2019/04/electrum-bitcoin-wallets-under-siege (search summary only) |
| S36 | https://trezor.io/guides/trezor-suite/trezor-suite-settings |
| S37 | https://trezor.io/guides/trezor-suite/getting-to-know-trezor-suite |
| S38 | https://coinbureau.com/review/trezor-hardware-wallet-review |
| S39 | https://support.stackedbitcoin.com/learn/saving-in-bitcoin/a-self-custody-lightning-dca-strategy (search summary only) |
| S40 | https://www.spark.money/tools/zeus-vs-phoenix-lightning-comparison and https://stacker.news/items/740549 (search summary only) |
| S41 | https://community.umbrel.com/t/sparrow-wallet-desktop/6898 (search summary only) |
| S42 | https://stadicus.github.io/raspibolt-dev/guide/bitcoin/desktop-wallet.html (search summary only) |
| S43 | https://trezor.io/get-to-know-trezor-suite-app (search summary only; direct fetch gave 404) |
