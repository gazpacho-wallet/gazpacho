# Interface research: node dashboards and peer-to-peer markets

Date: 2026-11-11. Purpose: inform the Gazpacho wallet layout.

## How to read this file

- `[V Sn]` = VERIFIED. I read it this session in source `Sn` (list at the end).
- `[V* Sn]` = VERIFIED ONLY FROM A SEARCH SNIPPET. I saw it quoted in search results but did not open the page. Treat as weak.
- `[R]` = RECALLED. From my own knowledge. Not checked this session. May be out of date.
- Many verified facts come from the products' own text files (menu definitions and interface strings in their GitHub repositories). These give exact labels and order. They do not show the visual layout. I did not view any screenshot or run any product.
- Wording rule kept: hosting, providing liquidity, fees. Where a product uses yield words (for example "APR" in Lightning Pool), that is quoted as their label, not suggested for Gazpacho.

## What I could not check

- `bisq.wiki` failed to load on every try (offer book page, Bisq Easy page, Reputation page). Bisq facts come from the Bisq source text files and `docs.bisq.network` instead.
- No screenshots were inspected. All layout claims (left, right, top) are from documentation text or are RECALLED.
- Umbrel's Lightning app interface: only the app store page and search snippets. Its source file path I tried returned "not found".
- ThunderHub home and settings page contents: only file names and the menu file were readable.
- Amboss Magma web app screens: the documentation is written for the API. Columns and filters of the web listing are not documented there.
- RoboSats order book documentation page does not exist under the address I tried. Column names come from the interface text file.
- Start9 pages on the top-level menu of StartOS returned empty. I have the documentation chapter list and three feature pages.
- LNbits: only the README and one admin page.
- Interface praise and criticism: very little independent material found. Most of section 6 for each product is weak or RECALLED.
- Whether Lightning Pool is still actively operated: not checked. A search for a shutdown found nothing either way.

---

## 1. ThunderHub

**Navigation**

| Group | Items in order |
|---|---|
| Main | Home, Dashboard, Peers, Channels, Transactions, Forwards, Chain, Tools |
| Amboss | Services, Magma |
| Taproot Assets | Assets, Channels, Transactions, Tools, Trading (Beta) |
| Tools | Swap |
| Bottom / mobile | Settings |

- The side menu order above is from the menu source file. `[V S10]`
- "Home" and "Dashboard" are two separate entries. `[V S10]`
- The dashboard is described as "customizable". `[V S9]`
- Settings is in the mobile menu; on desktop a settings block sits at the bottom of the side bar. `[V S10]`
- Older versions had menu entries named Rebalance and Stats. `[V* S50]`

**First screen**

- The documentation lists under "Monitor": balances (Lightning and on-chain), node address, graphs of invoices, payments and forwards, channel list, history. `[V S9]`
- Home shows an account balance block, quick action buttons (send, receive, open channel), then reports for forwards and liquidity. `[R]`
- Channels are drawn as two-sided bars, local on one side and remote on the other. `[R]`

**Settings groups**

- The settings folder has these parts: Interface, Privacy, Security, Notifications, Dashboard, Amboss. `[V S11]`
- Display options: light or dark theme, and sats / BTC / fiat units. `[V S9]`
- "Privacy" hides amounts on screen. `[R]`

**Health and attention**

- A warning is shown when a trade would push on-chain funds below the set reserve. `[V S12]`
- Pending channels have their own place: "Channels → Pending". `[V S12]`
- Each channel row has a note icon for a personal note. `[V S12]`

**Its Magma trading screen (a small market inside a console)**

- An offer shows: asset, rate, size bounds, peer public key. `[V S12]`
- Orders are grouped by state: Open, Pending, Filled, Cancelled. `[V S12]`
- Buy flow: pick an offer, request a quote, accept and execute. The quote is signed and has an expiry. `[V S12]`
- Incoming requests are checked against the user's own price source and rejected automatically if out of range. `[V S12]`

**Praise and criticism**

- A third-party comparison calls it an LND-focused dashboard with a "polished UI". `[V* S49]`
- It works with LND only. `[V* S49]`
- Often preferred for its clean look and channel bars; criticised for splitting "Home" and "Dashboard" and for hiding advanced actions in "Tools". `[R]`

---

## 2. Ride The Lightning (RTL)

**Navigation (LND version)**

| Top item | Sub-items in order |
|---|---|
| Dashboard | |
| On-chain | |
| Lightning | Peers/Channels, Transactions, Routing, Reports, Graph Lookup, Sign/Verify, Backup, Network |
| Services | Loop |
| Node Config | |
| Help | |

- Order is from the menu source file. `[V S14]`
- The Core Lightning version adds "Liquidity Ads" and "Fee Rates" under Lightning. `[V S14]`
- The last Lightning item changes name by persona: "Network" for Operator, "Node/Network" for Merchant. `[V S14]`

**First screen: two home pages by persona**

| Operator home | Merchant home |
|---|---|
| General node information | On-chain and Lightning balances |
| On-chain and Lightning balances | Inbound channel capacity |
| Channel capacity with local-remote balances and a "Balance score" | Outbound channel capacity |
| Routing fee earned and transactions routed | Receive and pay Lightning transactions |
| Channel status: Active, Pending, Inactive, Closing | |

- Both lists are from the feature document. `[V S13]`
- The persona is a per-node setting ("userPersona"). `[V S15]`
- A settings toggle switches persona "to change the dashboard layout". `[V S13]`

**Settings groups**

- Fiat conversion toggle; default node (for several nodes); persona switch; day-night mode; colour themes. `[V S13]`
- One RTL can manage several nodes and several node software types (LND, Core Lightning, Eclair). `[V S15]`
- Node Config has tabs for node-level and application-level settings. `[R]`

**Health and attention**

- Channel status counts on the operator home are the main health signal. `[V S13]`
- Lists can be exported to CSV. `[V S13]`
- A "Help" entry gives basic in-product documentation. `[V S13]`

**Praise and criticism**

- Described by a node distribution as working on phone and tablet, not just desktop. `[V* S49]`
- Covers the widest set of node software. `[V* S49]`
- Often called complete but dense: many tables, technical words at the top level (Graph Lookup, Sign/Verify). `[R]`

---

## 3. Umbrel (umbrelOS and its Lightning Node app)

**umbrelOS**

- Reached in a browser at `umbrel.local`. `[V S17]`
- Has a home screen with widgets "to see things at a glance", an App Store, Files, Settings and a "Live Usage" view of processor, memory and storage per app. `[V S17]`
- One search box (Ctrl+K) finds files, apps and settings. `[V S17]`
- Settings mentioned: two-factor sign-in, list of signed-in devices, remote access, language. `[V S17]`
- Home is a grid of app icons with a dock at the bottom (Home, App Store, Files, Settings, Live Usage, Widgets). `[R]`

**Lightning Node app**

- "Advanced Settings" covers: node name, larger channels, channel size limits, routing fees, routing strategy, watchtower services, performance tuning. `[V S16]`
- Wallet apps connect to it through a connection link (lndconnect). `[V S16]`
- Dashboard shows on-chain balance, Lightning balance and a channel summary. `[V* S18]`
- Widget labels include "Max send" and "Max receive". `[V* S18]`
- Channel backup is reached from a three-dot menu on the Lightning page. `[V* S18]`
- Layout is two cards side by side, "Bitcoin Wallet" and "Lightning Wallet", each with Send and Receive, and the channel list below. `[R]`
- There is no side menu inside the app; everything else is behind one menu button. `[R]`

**Praise and criticism**

- Praised as the most approachable node interface: very few numbers, large cards, one-click install. `[R]`
- Criticised by operators for hiding detail, so they install ThunderHub or RTL beside it. `[R]`
- Both ThunderHub, RTL and Lightning Terminal are offered in the Umbrel App Store. `[V* S18]`

---

## 4. Start9 (StartOS)

**Navigation**

- The documentation chapters group the system as: Services (Marketplace, Installing, Updating, Interfaces, Instructions, Actions, Health Checks, Tasks, Dependencies), Connecting, Networking, Backups, System. `[V S19]`
- System chapter covers: Logs, Server Name, SSH, SMTP, WiFi, Internationalization, Kiosk Mode, Updating, Change Password. `[V S19]`
- Top-level menu is Services, Marketplace, Updates, Backups, Notifications, System. `[R]`

**Service page**

- Actions appear "in the sidebar of the service details page". `[V S22]`
- An action is a button, sometimes with a checked form, that replaces a command-line step. `[V S22]`
- Unavailable actions are greyed out or hidden; some show a warning first. `[V S22]`
- Dependencies are listed on the service page and the system prompts to install a missing one. `[V* S19]`

**Health and attention: the strongest part of this product**

| Mechanism | What it does |
|---|---|
| Health checks | Shown on the dashboard beside each running service. Five states: Waiting, Starting, Loading, Success, Error. `[V S20]` |
| "Loading" state | A long task shown as progress, not pass/fail. `[V S20]` |
| Tasks | Prompts to act. "They appear on the dashboard and guide you through setup, configuration, and ongoing maintenance." `[V S21]` |
| Task levels | Required (service stays stopped), Important (runs, but problems may occur), Recommended (optional). `[V S21]` |
| Task completion | A task points to one action and clears itself when that action is done. It can come back if the condition returns. `[V S21]` |

**Praise and criticism**

- Praised for explaining state in words (health checks with messages) and for guided setup. `[R]`
- Criticised for slow, plain screens and for the certificate-trust step during setup. `[R]`
- "Trusting Your Root CA" is a numbered getting-started step. `[V S19]`

---

## 5. Bisq 1 (offer book)

**Navigation**

- Top bar in order: Market, Buy, Sell, Portfolio, Funds, Support, Settings, Account, DAO. `[V S23]`
- Buy and Sell are separate top-level screens, each with its own offer list. `[V S23]`

**First screen and standing information**

- Balance is always split three ways: "Available balance", "Reserved in offers", "Locked in trades". `[V S23]`
- A footer shows chain and network state: "Synced with {node} at block {n}", "(via Tor)", fee rate, and "Bitcoin network peers: {n} / Bisq network peers: {n}". `[V S23]`
- Start-up shows a four-step count: "(1/4) Connecting to Tor network..." to "(4/4) Initial data received". `[V S23]`

**Offer book layout**

| Element | Label |
|---|---|
| Columns | Price; amount "{currency} (min - max)"; payment method; "Deposit BTC (%)"; "Trader"; "Account info" `[V S23]` |
| Filters | "Choose currency", "Choose payment method", and a switch "Offers matching my accounts" `[V S23]` |
| Count | "No. of offers: {n}" `[V S23]` |
| Row action | "Take offer" (green button) `[V S23] [V S24]` |
| Create | "Create offer" button, top right `[V S23] [V S24]` |

- The "Take Offer" buttons are disabled until the user has a matching payment account. `[V S24]`
- A disabled offer explains why, for example "This offer uses a payment method you haven't set up yet." `[V S23]`
- Deposit help text: "Deposit paid by each trader to guarantee the trade. Will be returned when the trade is completed." `[V S23]`
- A price "deviation from market" percentage is shown beside the price. `[R]`
- Columns sort by clicking the header; the default sort is best price first. `[R]`

**Fixed terms of an offer**

- Price, amount range (min to max), payment method, and deposit percentage are set by the maker. `[V S23] [V S24]`
- The maker sets the buyer's security deposit percentage when creating the offer. `[V S23]`
- Buyers usually post about 15% deposit; the minimum is 0.006 BTC. `[V S24]`
- An offer is only available while the maker's Bisq is online. `[V S24]`

**Taker's own limits versus maker's terms**

- The taker's side lives in "Account" (payment accounts). The offer book then filters by "Offers matching my accounts". `[V S23]`
- The taker chooses only the amount inside the maker's range ("Set amount"). `[V S23]`
- Unsigned accounts have a low buy limit (0.01 BTC) until signed by a trusted peer. `[V S24]`

**Creating an offer**

- Steps on one page: "Set amount and price", set deposit, then "Fund your offer". `[V S23]`
- The funding box shows the make-up of the total: "({0} security deposit, {1} trade fee, {2} mining fee)". `[V S23]`
- Button: "Review: Place offer to {buy/sell} bitcoin". Success: "Your offer has been published". `[V S23]`

**Moment of commitment**

- Two buttons in sequence: "Review: Take offer to buy bitcoin", then "Confirm: Take offer to buy bitcoin". `[V S23] [V S24]`
- The review shows the offer details and says "Make sure these details are correct." After confirm, the taker cannot back out. `[V S24]`
- The funding box shows the same three-part make-up of the total. `[V S23]`
- Failure reasons are specific sentences: maker offline, already taken, price out of tolerance, and so on. `[V S23]`

**Reputation shown**

- An "Account info" column (account age and signing state) and a check-mark for peers who can sign. `[V S23] [V S24]`
- Identity is an onion address; a maker can put a taker's onion address on an ignore list. `[V S23]`
- Hovering the trader icon shows number of past trades with you. `[R]`

**Praise and criticism**

- Third-party listings say the interface is "more involved" than a normal exchange and hard for beginners. `[V* S49]`
- One user post calls it too complicated to recommend to a novice. `[V* S49]`
- Experienced users like that every cost is itemised before commitment. `[R]`

---

## 6. Bisq 2 / Bisq Easy

**Navigation**

- Left menu in order: Dashboard, Bisq Easy, Bisq MuSig, Reputation, Contacts, Trade protocols, Wallet, Learn, Chat, Support, User options, Settings, Network. `[V S27]`
- "Reputation" is its own top-level entry. `[V S27]`
- A top panel shows the wallet "Balance". `[V S27]`

**Two doors into the market**

| Door | Text |
|---|---|
| Left: "Best for beginners" | "The trade wizard guides you through your first Bitcoin trade." Button: "Start trade wizard" `[V S26]` |
| Right: "For experienced traders" | "Browse the offerbook for the best offers or create your own offer." Button: "Open offerbook" `[V S26]` |

- Wizard steps in order: "Offer type", "Amount @ price", "Payment methods", "Select offer", "Review". `[V S26]`

**Offer book**

- Columns: "Peer profile", "Price", "{currency} amount", "Payment", "Settlement". `[V S26]`
- Filters: "Buy from" / "Sell to"; "My offers only"; "Only offers" / "Only messages"; "Only favourites" for markets. `[V S26]`
- Each currency has its own market. `[V* S29]`
- The offer book is built on chat: offers and messages share one stream. `[V S26]`

**Commitment**

- Review screen title "Review trade", block "Trade details", with fiat payment method, bitcoin settlement method, trade price, and the line "No trade fees in Bisq Easy". Button: "Confirm take offer". `[V S26]`
- The review can refuse: "The seller's reputation does not cover this trade amount at the current market prices." `[V S26]`

**Deposits and reputation**

- No security deposits in Bisq Easy. `[V* S29]`
- Reputation replaces the deposit. It is on the seller's side only. `[V S26] [V* S29]`
- The seller's reputation score sets the largest amount they may sell: "Your reputation score of {0} allows you to trade a maximum of ...". `[V S26]`
- The buyer is told what score a seller needs to take their offer. `[V S26]`
- Shown to others as 0 to 5 stars, a rank among active users. `[V* S29]`
- Trades are capped (about 600 USD). `[V* S29]`
- Reputation is earned by burning or bonding the project token, or from account age in Bisq 1. `[R]`

**Health and attention**

- Network panel shows transport (Clear-net, Tor, I2P) and "Requesting network data" / "Network data received". `[V S27]`
- A notification panel says "New trade message for trade '{id}'" with one button: "Go to 'Open Trades'". `[V S27]`

**Praise and criticism**

- A 2026 review calls the interface "streamlined" compared with the original. `[V* S49]`
- Fourteen left-menu entries is a lot; chat-based offers confuse some users. `[R]`

---

## 7. RoboSats

**Navigation**

- Bottom tabs: Offers, Garage, Order, Settings, More. `[V S35]`
- There is no dashboard. The tabs follow the life of one trade. `[V S35]`
- Create-order is a tab or button beside Offers. `[R]`

**Order book**

- Columns: Amount, Currency, Payment Method, Premium, Price, Bond, Expiry, Destination, Timer, Sats now. `[V S35]`
- Table tools: "Add filter", "Show filters", "Manage columns", "Sort by ASC", "Sort by DESC". `[V S35]`
- Prices already include each order's premium. `[V S33]`
- A footer shows the market's 24-hour premium (a weighted median of completed orders). `[V S33]`
- Other views: a depth chart and a map. `[R]`
- The first column shows the maker's robot avatar and nickname with an activity dot. `[R]`

**Fixed terms of an order (maker form)**

| Field | Note |
|---|---|
| "Buy or Sell Bitcoin?" | `[V S35]` |
| Amount, or "Amount Range" | `[V S35]` |
| "Fiat Payment Method(s)" | `[V S35]` |
| "Premium over Market (%)" | Relative by default; an explicit sats price is the other choice. `[V S33] [V S35]` |
| "Public Duration (HH:mm)" | How long the order is listed. `[V S35]` |
| "Escrow/Invoice Timer (HH:mm)" | Deadline after match. `[V S35]` |
| "Fidelity Bond Size" | Default 3%, maker can set 2% to 15%. `[V S31] [V S35]` |
| "Description", "Password" | `[V S35]` |
| "Enable advanced options" | Hides the last several fields until asked. `[V S35]` |

- Below the button a plain sentence restates the order: "Buy BTC for 100 USD at a 5% premium". `[V S33]`
- After publishing, the maker sees a "Premium Rank" from 0% to 100% among public orders in that currency. `[V S33]`

**Taker's side**

- The taker chooses only the amount (inside the maker's range): "Enter amount of fiat to exchange for bitcoin". `[V S35]`
- There is no saved taker profile. The taker filters the book each visit. `[V S35]`

**Commitment and bonds**

- Taking an order means paying the taker bond. At that point "The contract is final". `[V S30]`
- The bond is a hold invoice. Text: "This is a hold invoice, it will freeze in your wallet. It will be charged only if you cancel or lose a dispute." `[V S35]`
- Time limits are short and visible: ten minutes for the maker to lock the bond, four minutes for the taker. If the taker does not proceed the order is "made public again". `[V S31]`
- The bond is lost for: losing a dispute, one-sided cancel, missing the invoice deadline, seller not confirming. Half of a lost bond goes to the honest side. `[V S31]`
- A maker who cancels before being taken loses nothing. `[V S31]`
- Cancel warning: "If the order is cancelled now you will lose your bond." `[V S35]`
- Trade size is limited: 20,000 to 4,000,000 sats. `[V S34]`

**Identity and record**

- Each user has a "Garage" of robots made from one master key. `[V S32]`
- Robots are one-time: the app "automatically rotates to a fresh robot after each completed trade". `[V S32]`
- Text: "Each robot is a one-time identity. This robot has already completed a trade and cannot be used to create new orders." `[V S35]`
- Text: "Reusing trading identity degrades your privacy against other users, coordinators and observers." `[V S35]`
- So the trader has no record. The record sits on the coordinator (the long-lived party). `[V S35]`
- Coordinator card shows: description, maker fee, taker fee, "Lifetime contracted volume", public buy and sell order counts, and a privacy-practice note. `[V S35]`
- Coordinator ratings are published over Nostr and checked by the app: "Verifying all ratings might take some time"; "Invalid ratings will be filtered." `[V S35]`
- Only someone who traded can rate: "You need to enable nostr to rate your coordinator." `[V S35]`
- Warning before locking a bond: "Make sure you research and trust "{coordinator}" before locking your bond." `[V S35]`
- The label for choosing a coordinator is "Select Host". `[V S35]`

**Settings**

- Settings page options: Coordinators (enable or disable each), Light / Dark, Mainnet / Testnet, connection method (built-in, API, Orbot). `[V S35]`

**Health and attention**

- Status texts: "Connecting to Tor network", "Connected to Tor network", "Connection error", "Coordinator offline", "The Bitcoin price is not synchronized." `[V S35]`
- Notifications are opt-in with a privacy warning: "by enabling telegram notifications you might lower your level of anonymity." `[V S35]`

**Praise and criticism**

- Users call it "very simple" and quick; it needs only a Tor browser while Bisq needs installed software. `[V* S49]`
- Criticised for small trade limits and for needing trust in the coordinator. `[V S34] [V S35]`
- Short timers stress users who step away. `[R]`

---

## 8. Amboss Magma

**What it is**

- A market for Lightning channels. Sellers list capacity; buyers buy inbound capacity. `[V S37]`
- Payment is by hold invoice: the seller is paid only after the channel is confirmed open. `[V S37]`
- Everything is public, unlike Lightning Pool's blind auction. `[V S46]`

**Fixed terms of an offer: three clearly separate groups**

| Group | Fields | Meaning |
|---|---|---|
| Size | total amount, min amount, max amount, locked amount | What is for sale and how much is already reserved. `[V S38]` |
| Fees | fixed, variable (ppm), marketplace fee | What the buyer pays. `[V S38]` |
| Promises | base fee cap, fee rate cap, minimum block length | "the guarantees the seller is locking in". `[V S38]` |
| Conditions | rules about the buyer | Who may buy. `[V S38]` |

- Minimum block length example: 4320 blocks is about 30 days. `[V S38]`
- Seller conditions on buyers: node capacity, channel count, address type, already-has-a-channel-with-me, rank. Each is condition + operator + value. All must pass. `[V S38] [V S42]`
- When an order is made, fees and promises are copied from the offer and locked for that order. `[V S38]`
- Changing an offer affects only new orders. `[V S42]`
- An offer can be switched ENABLED / DISABLED. Orders in progress finish. `[V S42]`
- The older web form had: Total Size, Min Size, Max Size, Variable Fee (ppm), Fixed Fee (sats), Channel Duration, Max Fee Rate (ppm), Max Base Fee (sats). `[V S45]`

**Buyer's side**

- Two routes: place a manual order against one chosen offer, or ask Magma to match ("buy") against the whole market. `[V S41]`
- Buyer options are few: amount, private channel or not, reliability tier only. `[V S38] [V S41]`
- Automatic matching weighs price, seller reliability, and the seller's conditions on the buyer. `[V S41]`
- A size estimate is shown before ordering but "isn't a binding quote". `[V S44]`
- The listing columns and filters of the web page are not documented. `[V S41]`

**Standing arrangement: subscriptions**

- A subscription is a monthly budget (5 to 1,000 USD). Magma decides when and from whom to buy, through the month. `[V S43]`
- The user sees: active or not, cancels-at-period-end, monthly amount, period end date. `[V S43]`
- Cancelling is a toggle that takes effect at the end of the paid period and can be undone before then. `[V S43]`
- The only stated limit is the monthly amount. No per-channel caps. `[V S43]`

**Order life cycle**

| Happy path state | Who acts |
|---|---|
| Waiting for seller approval | Seller `[V S39]` |
| Waiting for buyer payment | Buyer `[V S39]` |
| Waiting for channel open | Seller `[V S39]` |
| Seller sent transaction / waiting for confirmation | Chain `[V S39]` |
| Valid channel opening | First success `[V S39]` |
| Channel monitoring finished | Final success: the lock period was honoured `[V S39]` |

- Failure states name the party at fault: "seller failed to react", "buyer failed to pay", "seller failed to open channel", "invalid channel opening". `[V S39]`
- Each waiting state has one deadline. The documentation says to read the deadline, not assume a duration. `[V S39]`
- An order keeps tracking "blocks until can be closed". `[V S38]`

**Reputation**

- Two scores per node, one as seller and one as buyer, each 0 to 100. `[V S40]`
- Based only on that node's Magma orders in the last 90 days; recent orders count most. `[V S40]`
- Parts: completion (most important) and quality (response time, open time, keeping the channel open for the full term, keeping fees inside the promised cap). `[V S40]`
- New nodes start in the middle, not at zero. `[V S40]`
- One failure lowers the score in proportion; it does not wipe it out. Old failures fade. `[V S40]`
- One buyer can cause at most one counted failure against a seller. `[V S40]`
- Everyone sees the number on the offer. The other party in an order sees the full breakdown. Each node sees its own breakdown. `[V S40]`
- The earlier score mixed in network-wide signals and could fall to zero after one bad order. It was replaced because of that. `[V S40]`

**Health and attention**

- Notifications by Telegram or email, switched on per event type ("Magma Marketplace Events"). `[V S45]`
- The seller gets a notification when an order comes in and must act before the deadline. `[V S45] [V S39]`

**Praise and criticism**

- Praised for openness: buyers "choose whom to buy from" using their own filters. `[V S46]`
- Praised for requiring sellers to promise not to raise fees. `[V S46]`
- Criticised because sellers must respond by hand (or run automation), and because the marketplace operator can disable offers ("ADMIN_DISABLED"). `[V S42] [R]`

---

## 9. Lightning Pool and Lightning Terminal

**Navigation (Lightning Terminal)**

- Side menu in order: Home; under "Liquidity": Loop, Loop History, Pool; under "Connect": Lightning Node Connect; then Settings. `[V S7]`
- Settings sections: General (Bitcoin Unit, Channel Balance Mode, Network Explorers), My Node. `[V S7]`
- "Channel Balance Mode" asks what the node is "Optimize[d] For". `[V S7]`
- The modes are receiving, sending, or routing, and they change which channel balance is coloured as good or bad. `[R]`

**First screen (Terminal)**

- Node ranking and health checks, recent transactions, summary of fees earned and payments forwarded. `[V S8]`
- Loop page tiles: "Total Inbound Liquidity", "Total Outbound Liquidity". Channel rows: "Can Receive", "Can Send", "In Fee %", "Uptime %", "Peer/Alias", "Capacity". `[V S7]`

**Pool page: one screen, four areas**

| Area | Contents |
|---|---|
| Account | Status, "Expires in", Current Balance, Open Orders, Pending Balance, Available Balance; buttons Fund Account, Renew Account, Close. `[V S7]` |
| Order form | See next table. `[V S7]` |
| Batches | "Next Batch" countdown, "Next Fee", "Previous Rate", "Change", "Node Tier", "Earned", "Paid"; a row per cleared batch: Batch ID, Tx Fee, # Orders, Volume, Cleared Rate. `[V S7]` |
| Orders and leases | Orders list with filter Open / Filled / All; columns Type, Liquidity, Duration, Rate (bps), Status, Created On; "Cancel Order". Selecting a filled order shows its leases (channels). `[V S7]` |

- The account block is in the left bar; orders are in the main area with "filled channel leases" under them. `[V S3]`
- The node's tier (T1 = ranked) shows in the top right corner. `[V S3]`

**The standing order (the most relevant pattern for Gazpacho)**

| Form field | Bid (wants inbound) | Ask (provides liquidity) |
|---|---|---|
| Amount | "Desired Inbound Liquidity" | "Offered Outbound Liquidity" `[V S7]` |
| Price | "Bid Premium" (a maximum) with a "Suggested" value | "Ask Premium" (a minimum) `[V S7] [V S1]` |
| "Channel Duration" | fixed choices set by the market | same `[V S7] [V S1]` |
| "Minimum Channel Size" | smallest acceptable fill | same `[V S7]` |
| Behind "View Additional Options" | "Max Batch Fee Rate", "Min Node Tier" | "Max Batch Fee Rate" `[V S7]` |
| Computed, read-only | "Execution Fee", "Worst Case Chain Fee", "Per Block Fixed Rate", "Interest Rate", "Annual Rate (APR)" | same `[V S7]` |
| Button | "Place Bid Order" | "Place Ask Order" `[V S7]` |

- An order is a set of limits, not a choice of counterparty. The bidder's rate is "the maximum rate the taker will pay". `[V S1]`
- "Max batch fee rate" is a limit on chain cost. If the current fee is higher, the order just waits and is looked at again later. `[V S1] [V S2]`
- This lets patient users leave orders that "only be considered for matchmaking in times of low chain fees". `[V S2]`
- "Min node tier" is the bidder's quality limit: tier 1 matches only with nodes judged good; 0 accepts all. `[V S1]`
- Allow and deny lists of node IDs are also order fields. `[V S1]`
- Setting minimum channel size to the full amount makes the order all-or-nothing. `[V S1]`
- Orders can be partly filled; the list shows units left unfilled. `[V S1]`
- A new order has state "ORDER_SUBMITTED". It can be cancelled at any time before it fills. `[V S1]`

**Batch auction**

- The market clears "every 10 minutes". If nothing matches, "nothing happens, and we just wait for the next batch." `[V S2]`
- One clearing price for everyone in the batch. A bidder pays "that amount or less"; an asker receives "that amount or more". `[V S2]`
- Three costs: premium (buyer to seller), execution fee, chain fee for one's own share. `[V S2]`
- The seller must be online when the batch clears "or the match won't be included". The software must stay in contact with the auction server to check and sign. `[V S5]`

**Commitment**

- The command line shows a breakdown before submitting: amount, duration, total premium, rate, execution fee, max batch fee rate, max chain fee; then asks to confirm. A "force" flag skips it. `[V S1]`
- "Max chain fee" is described as a worst case that is "unlikely to be fully paid". `[V S1]`
- In the web form the computed costs sit in the form itself; the documentation describes no separate confirm screen. `[V S3]`
- Commitment is therefore to the limits. The final price and counterparty are only known after the batch. `[V S2]`

**Deposit: the account**

- Funds are placed in an on-chain account before ordering, so users are "unable to spoof orders". `[V S4]`
- The account is shared-signature with the auctioneer and has an expiry after which the user alone can spend. `[V S4]`
- Sellers must hold enough to cover what they offer; buyers only enough for fees. `[V S3]`
- Warnings: orders stop matching when the account is close to expiry (below 144 blocks); "Your account expired! Please renew your account." `[V S7]`

**Reputation**

- Sellers must be on a node ranking list to sell by default. `[V S5]`
- Sellers cannot choose or refuse a buyer. `[V S5]`
- A seller who closes early is banned from the market. `[V S5]`

**Sidecar (buying for someone else)**

- A ticket is passed between provider and recipient. With "auto", each side runs one command and the rest happens in the background at the next batch. `[V S6]`

**Praise and criticism**

- Early press said it grew faster than expected and users saw it as efficient for placing capital. `[V* S49]`
- A forum post criticises it as a central service. `[V* S49]`
- The form speaks in "per block fixed rate", "bps" and "APR", which needs finance knowledge. `[V S7]`
- The account, its expiry and renewal add a second thing to manage beside the order. `[V S7] [V S5]`
- The hidden requirement to be online at clearing is only in the FAQ. `[V S5]`

---

## 10. LNbits (brief)

- Each wallet has its own keys, a transaction table, a spending chart and CSV export. `[V S47]`
- Non-core features are extensions; you install only what you need. `[V S47]`
- For the super user the side bar shows "Settings" and "Users" between "Wallets" and "Extensions". `[V S48]`
- Server settings include funding sources, payments, site customisation and "reset to defaults". `[V S48]`
- A role badge shows in the top left. `[V S48]`
- Side bar is Wallets (list, add wallet), Extensions, then admin items. `[R]`
- Praised for simplicity and extensions; criticised because it is an accounts layer on someone's node, so it is custodial for sub-users. `[R]`

---

# Synthesis

## (a) Shared patterns

1. **Left side menu, six to eight entries, settings last.** ThunderHub, RTL, Bisq 2 and Lightning Terminal all do this. `[V S10] [V S14] [V S27] [V S7]`
2. **Home shows money first, then capacity, then earnings, then channel state.** RTL's operator home lists them in exactly that order. `[V S13]`
3. **Capacity is said as "can send / can receive".** Terminal and Umbrel use these words rather than "local / remote". `[V S7] [V* S18]`
4. **Two home screens for two roles.** RTL has Operator and Merchant personas. Bisq Easy has a wizard door and an offer-book door. `[V S13] [V S26]`
5. **Offer row = who, price, amount range, method, deposit, action button.** Bisq 1, Bisq Easy and RoboSats agree. `[V S23] [V S26] [V S35]`
6. **The maker fixes everything; the taker picks only an amount inside a range.** Bisq, RoboSats, Magma. `[V S23] [V S35] [V S38]`
7. **Money is always shown in three states: free, reserved by an open offer, locked in a deal.** Bisq and Pool. `[V S23] [V S7]`
8. **Commitment is two steps: review, then confirm.** The review shows every cost and a plain warning that there is no way back. `[V S24] [V S26]`
9. **A deposit or bond is shown as a percentage, with a sentence saying when it comes back.** `[V S23] [V S31]`
10. **Advanced fields are hidden behind one link.** "View Additional Options" (Pool), "Enable advanced options" (RoboSats). `[V S7] [V S35]`
11. **My orders are listed by state: Open / Filled / All (or Open / Pending / Filled / Cancelled).** `[V S7] [V S12]`
12. **A status line for connections is always visible.** Bisq footer; RoboSats Tor status. `[V S23] [V S35]`
13. **The record belongs to the long-lived party.** Coordinator (RoboSats), seller (Bisq Easy), node (Magma). The short-lived party has none. `[V S35] [V S26] [V S40]`

## (b) Patterns worth borrowing, and the Gazpacho problem each solves

| # | Pattern | Source | Gazpacho problem it solves |
|---|---|---|---|
| 1 | Split an offer into **Size, Fees, Promises, Conditions** as four labelled groups | Magma `[V S38]` | Lobby terms are many numbers. Grouping them makes "what I pay", "what the host promises" and "who may join" readable at a glance. |
| 2 | **Promises are copied into the deal and locked** | Magma `[V S38]` | Lobby terms are signed and fixed. Show them as a locked card with the host's signature, never as editable fields. |
| 3 | **"Offers matching my accounts" switch** on the book, on by default, with a reason on each non-matching row | Bisq `[V S23] [V S24]` | Host terms versus member conditions. The member's conditions are a filter over the lobby list. A lobby that fails shows which condition it fails ("fee above your limit"). |
| 4 | **Member's side lives in its own place** (Bisq "Account"), separate from the book | Bisq `[V S23]` | Keeps "my conditions" from being confused with "this lobby's terms". Two screens, two colours, two words. |
| 5 | **Standing order form: amount, max price, duration, minimum size; extra limits behind one link; computed worst-case cost shown in the form** | Pool `[V S7] [V S1]` | A member's conditions that can fill without the member present. The form states limits, the app shows the worst case it could sign. |
| 6 | **A chain-fee limit that makes the order wait instead of fail** | Pool `[V S1] [V S2]` | Fits the 0.1 sat/vB preference. "Wait for low fees" is a normal state, not an error. |
| 7 | **A quality limit on the other side as a single field** ("Min Node Tier") | Pool `[V S1]` | "Only join hosts with at least this record" as one member condition. |
| 8 | **Orders list with Open / Filled / All and a Cancel button; show "next batch" countdown** | Pool `[V S7]` | The member sees the standing order is alive, what it is waiting for, and can withdraw it. For Gazpacho the countdown is the lobby deadline. |
| 9 | **Plain sentence that restates the order under the button** | RoboSats `[V S33]` | "Join a lobby of at least 20 members, channel 500,000 sats or more, total fees at most 3,000 sats, lasting up to 6 months." One sentence the user can check. |
| 10 | **Deadline per waiting state, with the party who must act named** | Magma `[V S39]` | Lobby fill (target, minimum, deadline), host funding, signing round. Each step says who acts and by when. |
| 11 | **Failure states that name the party at fault** | Magma `[V S39]` | "Host did not fund in time" feeds the host's record without any member identity. |
| 12 | **Host record from the host's own deals only, last 90 days, 0 to 100, with a breakdown; starts in the middle; one bad deal does not wipe it; one counterparty counts at most once** | Magma `[V S40]` | Showing a host's record. The "counts at most once" rule also limits fake reports from throwaway members. |
| 13 | **One-time identity for the short-lived side; the app rotates it automatically and warns against reuse** | RoboSats `[V S32] [V S35]` | Members need no long-lived identity. A fresh key per lobby. |
| 14 | **Host card with fees, lifetime volume, open offers, and ratings published on Nostr that the app verifies and filters** | RoboSats `[V S35]` | Host proofs are already on Nostr. Show "verified" and "filtered" counts so the user knows the app checked them. Only a member who was in a factory can rate. |
| 15 | **Reputation as a cap on size, with the refusal explained at review** | Bisq Easy `[V S26]` | A new host could be limited to small lobbies. The limit is explained, not just enforced. |
| 16 | **Deposit placed before listing so offers cannot be fake** | Pool `[V S4]`, RoboSats `[V S31]` | A host's proof of funds before a lobby is listed. Say plainly when it is released. |
| 17 | **Three money states always visible: available / reserved / locked** | Bisq `[V S23]` | Wallet: available; set aside for a lobby; in a factory (with end date). |
| 18 | **Tasks with three levels (Required, Important, Recommended) that clear themselves** | StartOS `[V S21]` | "Things needing attention": back up phrase, come online before a deadline, renew, set a watchtower. Required ones block; recommended ones do not nag. |
| 19 | **Health checks with five named states and a message, including a "Loading" progress state** | StartOS `[V S20]` | Connections: chain server, host node link, Nostr relays. "Loading" suits chain sync. |
| 20 | **Persona switch that changes the home screen** | RTL `[V S13]` | One app, two roles. Member home and Host home, same menu. |
| 21 | **Two doors: guided wizard or full book** | Bisq Easy `[V S26]` | First-time member gets a wizard that ends in a standing order. Experienced user opens the lobby list. |
| 22 | **Monthly budget with "ends at period end, can undo" cancel** | Magma subscriptions `[V S43]` | Renewal at factory end: "rejoin automatically under my conditions" as a toggle, with the end date shown. |
| 23 | **Rank feedback after posting** ("Premium Rank") | RoboSats `[V S33]` | Tell a host how their terms compare with other open lobbies. Tell a member how many open lobbies match their conditions right now. |
| 24 | **Dashboard option "Optimize For" that changes what counts as good** | Terminal `[V S7]` | Member cares about "can receive / can send"; host cares about fill and fees earned. Same data, different emphasis. |

## (c) Patterns to avoid

| Avoid | Seen in | Why |
|---|---|---|
| Prices as "per block fixed rate", "bps", "ppm" | Pool `[V S7]`, Magma `[V S38]` | Needs finance knowledge. Show sats and a plain percent. |
| "APR" and "Interest Rate" labels | Pool `[V S7]` | Reads as an investment product. Gazpacho says fees for providing liquidity. |
| An online requirement that is only in the FAQ | Pool `[V S5]` | If the member or host must be online at signing, say it on the order itself. |
| A second object to manage beside the order (account with its own expiry and renewal) | Pool `[V S7] [V S5]` | Two clocks confuse. Keep one clock per thing. |
| A score that drops to zero after one failure, or mixes in unrelated network signals | Magma's old score `[V S40]` | Unfair, and impossible to explain. |
| Long-lived identity for the short-lived side | Warned against by RoboSats `[V S35]` | Links a member's joins together. |
| Technical tools at the top level of the menu (Graph Lookup, Sign/Verify) | RTL `[V S14]` | Pushes daily tasks down. Put them under "Advanced". |
| Two entries that sound the same ("Home" and "Dashboard") | ThunderHub `[V S10]` | Users cannot guess the difference. |
| More than about eight side-menu entries | Bisq 2 has thirteen or more `[V S27]` | Hard to scan. |
| Offers mixed into a chat stream | Bisq Easy `[V S26]` | Terms get lost between messages. Lobby terms must be structured. |
| Very short timers at commitment (4 and 10 minutes) | RoboSats `[V S31]` | Gazpacho signs automatically, but any manual step needs generous, visible time. |
| Hiding rows that do not match with no explanation | General risk | Users think the market is empty. Show them greyed, with the reason. |
| An estimate that looks like a quote | Magma notes its estimate "isn't a binding quote" `[V S44]` | Gazpacho terms are signed, so always mark numbers as "signed term" or "estimate". |
| The operator able to disable or block offers | Magma "ADMIN_DISABLED" `[V S42]`, Bisq "blocked by the Bisq developers" `[V S23]` | Listings are on Nostr. Do not design a state the app cannot honestly have. |
| No separate confirm for a standing order | Pool web form `[V S3]` | A standing order lets the app sign later. It deserves the strongest review screen in the app. |

## (d) Guidance for the two layout concepts

### Concept 1: "Console"

Style: ThunderHub / RTL / Umbrel. A side menu and a dashboard. Best when the user thinks "this is my wallet and my channel; the lobby is how I got it".

**Navigation skeleton (side menu, top to bottom)**

1. Home
2. Wallet
3. My channel (the factory I am in: balance, end date, host)
4. Lobbies (browse; my conditions shown as a bar on top)
5. Hosting (hidden or collapsed until switched on)
6. Activity (payments, joins, signings, things the app did while I was away)
7. Settings

A status strip sits at the bottom of the side menu: chain server, host link, relays, watchtower. One dot each, StartOS-style states. (Pattern 19; Bisq footer.)

**Home screen (member persona)**

| Row | Content | Borrowed from |
|---|---|---|
| 1 | Balance. Under it "Can send" and "Can receive". | Umbrel, Terminal |
| 2 | Three money states: Available / Set aside for a lobby / In factory until [date] | Bisq |
| 3 | "Needs attention" list with Required / Important / Recommended | StartOS Tasks |
| 4 | My channel card: host name and record, end date, next deadline | RTL channel status |
| 5 | My conditions card: one sentence, state (Watching / Waiting for low fees / Matched / Signed), "N lobbies match now" | Pool order row, RoboSats sentence and rank |
| 6 | Recent activity, with "done while you were away" marked | Pool batches |

**Home screen (host persona, via a switch as in RTL)**

| Row | Content |
|---|---|
| 1 | Liquidity provided, fees earned (period chooser) |
| 2 | Lobbies: open (fill bar: joined / minimum / target, deadline), funded, running, ended |
| 3 | Needs attention (fund by, sign by, renewal coming) |
| 4 | My record as members see it, with breakdown |

**Where the six option areas live**

| Option area | Place in Console |
|---|---|
| Personal conditions | Settings → My conditions. Also editable from the Home card and the bar on Lobbies. One source of truth, three doors. |
| Lobby terms | Hosting → New lobby (a form in four groups: Size, Fees, Promises, Who may join). Read-only copy on each lobby's detail page. |
| Wallet | Side menu → Wallet. Backup, recovery phrase and units under Settings → Wallet. |
| Watching | Settings → Watching (away mode, watchtower, reminders). Deadlines themselves appear on Home under "Needs attention". |
| Connections | Settings → Connections (chain servers, host's node link, relays). Live state in the status strip. |
| Hosting | Its own side-menu entry. Switching it on is in Settings → Hosting (so a member never sees host screens by accident). |

Strengths: familiar to node operators; health and deadlines are always in view; hosting scales into a full operator view.
Weakness: conditions sit in Settings, so the idea "my conditions are a live order" is weaker. The Home card must carry it.

### Concept 2: "Market"

Style: Bisq offer book / Magma / Pool. Hosts' lobbies are offers. A member's conditions are a standing order. Best when the user thinks "I am shopping for a channel, or letting the app shop for me".

**Navigation skeleton (top tabs or short side menu)**

1. Lobbies (the offer book: home screen)
2. My order (my conditions as a standing order, and its history)
3. My channel (what I hold now; Bisq calls this Portfolio)
4. Host (create lobby, my lobbies, record)
5. Wallet
6. Settings

A footer line shows connection state in words, as Bisq does: "Chain: synced at block N · Host link: connected · Relays: 4 of 5".
A top panel shows balance at all times, as Bisq 2 does.

**Home screen: the lobby book**

- Top: **My conditions bar.** One sentence plus state and an Edit button. A switch "Only lobbies matching my conditions" (on by default) and a count "7 of 23 match".
- Table, one row per lobby:

| Column | Notes |
|---|---|
| Host | Name, record score, "verified" mark for checked Nostr proofs |
| Channel size | Fixed, or min – max |
| Total fees | In sats, and as a percent of channel size |
| Lifetime | In days or months, with end date |
| Members | Fill bar: joined / minimum / target |
| Closes in | Deadline countdown |
| Match | Tick, or the one condition that fails |
| Action | "Join" (or "Auto" when the standing order will take it) |

- Sort by clicking a header. Default: matching first, then soonest deadline.
- Row click opens the lobby page: terms in four groups (Size, Fees, Promises, Who may join), host card (record breakdown, past factories, fees), and a side-by-side check "Lobby term | Your limit | OK?".
- First visit: two doors as in Bisq Easy. "Set my conditions and let the app join for me" (wizard) or "Browse lobbies".

**My order screen (the standing order)**

- Form in Pool's shape: channel size wanted; most I will pay in total fees; longest and shortest lifetime; smallest lobby I accept. "More limits" link: highest chain fee rate, minimum host record, hosts I allow or refuse.
- Read-only block: worst-case total cost; what the app may sign without me; until when the order stands.
- Review then confirm. The confirm text states that the app will sign for any lobby inside these limits.
- State list below: Open / Filled / All. Each past fill links to the lobby it joined. Cancel is always available while open.

**Host tab**

- "Create lobby" laid out as a mirror of the lobby page, so the host sees what members will see. After publishing: "N members' conditions match these terms" is not knowable privately, so show instead the rank of these terms among open lobbies (RoboSats "Premium Rank" idea).
- My lobbies by state: Open (fill bar, deadline) / Funding / Running / Ended. Fees earned per lobby.
- My record, as members see it.

**Where the six option areas live**

| Option area | Place in Market |
|---|---|
| Personal conditions | "My order" tab. Summary bar on the Lobbies screen. Never in Settings. |
| Lobby terms | Host → Create lobby. Read-only on every lobby page, grouped the same way. |
| Wallet | Wallet tab. Balance in the top panel. Three money states shown there. |
| Watching | Split. Deadlines and reminders live with the thing they belong to (lobby row, My channel). Away mode and watchtower are in Settings → Watching. |
| Connections | Settings → Connections. Live state in the footer line. |
| Hosting | Host tab, always visible but showing a short "Become a host" page until switched on. |

Strengths: makes the host-terms / member-conditions split the centre of the app; the standing order is a first-class thing; the host record is seen where the choice is made.
Weakness: after joining, most days nothing happens in a market. "My channel" must then become the landing screen, or the app feels empty. Health and deadlines need the footer and a "needs attention" badge, since there is no dashboard.

### A note that applies to both

- Use two fixed words and never swap them: **terms** (the host's, signed, fixed) and **conditions** (the member's, private, adjustable). The products studied blur this (Magma calls the seller's rules about buyers "conditions"). `[V S38]`
- At every commitment show the same three-column check: lobby term, my condition, pass or fail.
- Mark every number as "signed term" or "estimate".
- State the online requirement on the order itself.
- Host record: host-only deals, recent window, breakdown on tap, one member counts once. Members: fresh identity per lobby.

---

## Sources

| ID | Address |
|---|---|
| S1 | https://docs.lightning.engineering/lightning-network-tools/pool/orders |
| S2 | https://docs.lightning.engineering/lightning-network-tools/pool/batch_execution |
| S3 | https://docs.lightning.engineering/lightning-network-tools/lightning-terminal/pool |
| S4 | https://docs.lightning.engineering/lightning-network-tools/pool/accounts |
| S5 | https://docs.lightning.engineering/lightning-network-tools/pool/faq |
| S6 | https://docs.lightning.engineering/lightning-network-tools/pool/sidecar_channels |
| S7 | https://raw.githubusercontent.com/lightninglabs/lightning-terminal/master/app/src/i18n/locales/en-US.json |
| S8 | https://docs.lightning.engineering/lightning-network-tools/lightning-terminal/introduction |
| S9 | https://docs.thunderhub.io/ |
| S10 | https://raw.githubusercontent.com/apotdevin/thunderhub/master/src/client/src/layouts/navigation/Navigation.tsx |
| S11 | https://github.com/apotdevin/thunderhub/tree/master/src/client/src/views/settings |
| S12 | https://thunderhub-docs.vercel.app/taproot-assets/magma-trading |
| S13 | https://github.com/Ride-The-Lightning/RTL/blob/master/.github/docs/Application_features.md |
| S14 | https://raw.githubusercontent.com/Ride-The-Lightning/RTL/master/src/app/shared/models/navMenu.ts |
| S15 | https://github.com/Ride-The-Lightning/RTL |
| S16 | https://apps.umbrel.com/app/lightning |
| S17 | https://umbrel.com/umbrelos |
| S18 | Search snippets only: Umbrel community posts and an Umbrel app definition file (community.umbrel.com; apps.umbrel.com listings) |
| S19 | https://docs.start9.com/start-os/0.4.0.x/toc.html (and search snippets of docs.start9.com/start-os/dependencies.html) |
| S20 | https://docs.start9.com/start-os/0.4.0.x/health-checks.html |
| S21 | https://docs.start9.com/start-os/0.4.0.x/tasks.html |
| S22 | https://docs.start9.com/start-os/0.4.0.x/actions.html |
| S23 | https://raw.githubusercontent.com/bisq-network/bisq/master/core/src/main/resources/i18n/displayStrings.properties (first 100,000 characters only) |
| S24 | https://docs.bisq.network/getting-started |
| S25 | https://bisq.network/getting-started/ |
| S26 | https://raw.githubusercontent.com/bisq-network/bisq2/main/i18n/src/main/resources/bisq_easy.properties |
| S27 | https://raw.githubusercontent.com/bisq-network/bisq2/main/i18n/src/main/resources/application.properties |
| S28 | https://bisq.network/bisq-easy/ |
| S29 | Search snippets only: https://bisq.wiki/Bisq_Easy and https://bisq.wiki/Reputation (pages would not load) |
| S30 | https://learn.robosats.org/docs/trade-pipeline/ |
| S31 | https://learn.robosats.org/docs/bonds/ |
| S32 | https://learn.robosats.org/docs/robots/ |
| S33 | https://learn.robosats.org/docs/premium/ |
| S34 | https://learn.robosats.org/docs/limits/ |
| S35 | https://raw.githubusercontent.com/RoboSats/robosats/main/frontend/static/locales/en.json |
| S36 | https://github.com/RoboSats/robosats |
| S37 | https://docs.amboss.tech/magma |
| S38 | https://docs.amboss.tech/magma/orders-and-offers |
| S39 | https://docs.amboss.tech/magma/order-lifecycle |
| S40 | https://docs.amboss.tech/magma/reputation |
| S41 | https://docs.amboss.tech/magma/liquidity-marketplace |
| S42 | https://docs.amboss.tech/magma/create-offers |
| S43 | https://docs.amboss.tech/magma/subscriptions |
| S44 | https://docs.amboss.tech/magma/buy-liquidity |
| S45 | https://github.com/AmbossTech/workshop (archived) |
| S46 | https://voltage.cloud/blog/how-to-sell-liquidity-and-earn-sats-with-your-lightning-node |
| S47 | https://github.com/lnbits/lnbits |
| S48 | https://docs.lnbits.org/guide/admin_ui.html |
| S49 | Search snippets only: spark.money comparison pages, saashub.com listings, Nostr and Stacker News posts, CoinDesk 2020 article on Pool, mynodebtc.com RTL listing, a 2026 Bisq review on a mirror site of unclear reliability |
| S50 | Search snippets only: MiniBolt guide route list and Umbrel community posts about ThunderHub |

Notes on source quality:

- S7, S10, S14, S23, S26, S27, S35 are source files read through a summarising fetch tool. Labels are quoted as the tool returned them. Order within a list is as returned.
- S23 was cut off at 100,000 of about 321,000 characters. Bisq 1 strings beyond that point were not seen.
- S13 and S45 may describe older versions of the products.
- S40 mentions a change dated November 2026, so Magma's reputation rules are very recent.
