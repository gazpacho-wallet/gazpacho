# The lobby: how a factory forms

Design note 2, 2026-11-11. Based on `LOBBY-research.md` and the owner's decisions. Items marked **(open)** are in `OPEN-QUESTIONS.md`.

## The idea

Creating a factory needs the host and every member online at the same moment to sign. The lobby is the waiting room. It works like a game server: a host opens a lobby with rules, people join, and it starts when its conditions are met.

Nobody has money at risk in a lobby. Members put in nothing at creation, and the host signs its funding only after the whole tree is signed. The cost of bad behaviour is wasted time and, for the host, idle capital.

## Stages

| Stage | What happens | Who moves it on |
|---|---|---|
| Draft | The host sets the rules | Host |
| Open | Listed; members join by connecting directly to the host | Members joining; the start rule |
| Ready check | Each member's app confirms it is present and its conditions hold | Timer |
| Signing | The group signing rounds; up to three attempts | The signing engine |
| Funding | The host funds the factory | Host; the chain |
| Active | The factory is live | |
| Cancelled / Failed | Too few members, or signing could not complete | |

**Timing.** A lobby has two clocks, both set by the host.

- *Gathering* is long. A lobby can stay open for hours or days. Members join whenever they like, set their conditions, and can leave the app running to act for them.
- *Signing* is short and happens at the scheduled start. The secrets used in a signing round are never stored, so each member's app must keep running from the first signing step to the second. If anyone drops out in between, the round restarts for everyone. A short window keeps that rare and cheap.

A host that wants a slower pace can lengthen the signing timers and accept more restarts. It is one mechanism with different timer values, not two designs.

**Who can find it, and who can join.** Two separate settings:

| | Open to anyone | By invitation |
|---|---|---|
| **Listed on Nostr** | A public lobby | Visible, but a seat needs an invitation |
| **Unlisted** | Anyone with the link can join | Private in practice |

Invitations are links, shown as QR codes. The host also sets what share of seats may go to members who bring nothing.

**Start rule:** never below the minimum size. Then either everyone present is ready, or the host starts, or the closing time arrives.

**No-shows:** members who do not answer in a signing attempt are removed together and the round reruns with those who remain, plus anyone waiting on standby.

## What protects a member

1. **Member-set conditions, locked in.** A member chooses conditions once: minimum number of members, minimum channel size, fee ceilings, a rule profile, and so on. The app marks the member ready only while every condition holds. If the host changes the rules so that one fails, the app un-readies or leaves.
2. **The check at signing is the real guarantee.** Whatever happened in the lobby, the app checks the actual tree it is asked to sign against the member's conditions and against the safety rule, and refuses if either fails. Nothing said in a lobby can carry a member into a factory they did not agree to.
3. **Host terms are signed and versioned**, so a member can show what was offered.

## Dealing with troublemakers

Decided for the first version:

- **No voting and no vote-to-remove.** Every member signs for themselves, the host chooses who is in the tree, and identities cost nothing, so a vote cannot bind anyone and can be bought with fake members. The owner agreed to drop it for now.
- **The host removes people.** It is the host's lobby and the host's capital.
- **Each member has a personal block list.** A member's app can refuse to sign a tree that contains someone on it. This is the one removal power that cannot be overridden: any single member can decline, for any reason.
- **Names, chat and rule-change requests** are three settings the host can switch off. With all off, members see only a head-count, and personal block lists have nothing to act on.
- **Names** are temporary and exist only for that lobby, unless a member chooses otherwise.
- **Optional self-identification.** A member may attach an identity to their seat. A Nostr key or a Lightning node key is proven by signing the lobby's challenge with it. A free-text field is allowed and is always shown as unverified.
- **History is kept locally.** Each app remembers who showed up and signed and who stalled, and shows it to its own user. There is no global blacklist.
- **Proof of who broke a round.** Every signing message is signed by its sender. A wrong partial signature can be proven to anyone; silence cannot.

Later, as the owner expects, joining may require something scarce: control of coins, a record of signing in earlier factories, an identity the member chooses to bring. These must stay options a host can set, because a stricter host competes with someone who self-hosts with looser rules.

**Adding rules later.** A new joining rule usually has to look at balances, coins or other state to decide whether something is safe to sign. So adding one is normally a change to the code that decides what is safe to sign, not only to a separate rules layer (owner's correction, 2026-11-11). That code is therefore kept as one module with defined inputs and its own tests, and a new rule is a reviewed change to it. Only rules that cannot affect signing, such as how a lobby is displayed or filtered, are plain settings.

## Why not threshold signatures

A threshold key (for example FROST) lets a majority sign without the minority. For the output that holds everyone's money that is the opposite of what we want: a majority, which could be fake members or the host with friends, could spend a member's money without that member. The factory key stays "everyone signs", because that is what makes it safe to share.

Threshold keys remain useful where one party splits its own key: a host run by several operators, or a member spreading their key across devices.

## Removing someone from a live factory

Once a factory is live, "removing" a member can only mean one of two things, and neither takes their money:

- they agree to leave, by co-signing a close or by paying their balance out; or
- their branch of the tree is published, which puts their balance on chain in their own control.

Any change that needs everyone's signature, such as closing early, can be stopped by a single member. The design does not fight this with votes. It limits how often everyone is needed: day-to-day changes need only the members of one leaf or branch, and a member who will not cooperate at wind-down is left to the timeout tree while the others move on.

## Profiles

Named presets of rules. All four ship in the first release.

| Profile | For | In short |
|---|---|---|
| Safety | Cautious users | Simple operation only; optional features off |
| Standard | Most public lobbies | The defaults |
| Starter | People arriving with no funds | Small channels, low requirements, limited seats |
| Circle | People who know each other | Unlisted and by invitation |

## What is public

A listing on Nostr carries what rarely changes: the terms the host has fixed, the acceptable range for the others, size limits, the start time and an expiry after which the listing disappears. It never says who joined.

Anything live, such as how full the lobby is, is asked of the host directly. This keeps relays quiet and reveals less. The cost is that asking tells the host someone is interested and from which network address; connecting over Tor avoids the second.

A host may publish the factories it has funded as a track record, since the funding is on chain anyway. Whether a member can prove past participation in the same way is being looked into; it would link that member's factories together, so it could only be by choice.

The existing host proofs show control of one channel or one coin. A proof sized to the lobby a host advertises is still to be designed.

## A separate library

The lobby, the signing round engine and the proof-of-fault scheme together are a general tool for coordinating large group signatures. They are written with no dependence on the factory code, so they can be split out as their own library.

## First version

- Gathering and signing timers; scheduled start with minimum and maximum size.
- Listed or unlisted; open or by invitation, with QR invitations.
- Member conditions and the check at signing.
- Host removal, personal block lists, local history.
- Switches for names, chat and rule-change requests. Chat itself may follow the first release.
- Optional self-identification.
- Signed signing messages; up to three signing attempts.
- All four profiles.

Next (issue 3): a deposit to deter people who join and never sign. Later: standby seats, joining requirements based on coins or history, member track records.

New rules arrive through the proposal process in `proposals/`.
