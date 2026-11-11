# The lobby: how a factory forms

Design note 1, 2026-11-11. Based on `LOBBY-research.md` and the owner's decisions. Items marked **(open)** are in `OPEN-QUESTIONS.md`.

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
- **Chat.** People can talk a problem through. Optional, and carried by the host connection.
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

Named presets of rules. Proposed by the research; details **(open)**:

| Profile | For | In short |
|---|---|---|
| Safety | Cautious users | Simple operation only; optional features off |
| Standard | Most public lobbies | The defaults |
| Starter | People arriving with no funds | Small channels, low requirements, limited seats |
| Circle | People who know each other | Invitation only |

## What is public

**(open)** The earlier host-list design published only how to reach a host, and kept factory details off Nostr on purpose. Listing lobbies there reverses that. The proposal: a lobby listing carries the terms, size limits and start time; who has joined stays between the host and the members.

The existing host proofs show control of one channel or one coin. They do not show the host can fund the lobby it advertises. A proof sized to the lobby is **(open)**.

## A separate library

The lobby, the signing round engine and the proof-of-fault scheme together are a general tool for coordinating large group signatures. They are written with no dependence on the factory code, so they can be split out as their own library.

## First version

- Scheduled start with minimum, maximum and closing time.
- Member conditions and the check at signing.
- Host removal, personal block lists, local history.
- Signed signing messages.
- Up to three signing attempts.
- One profile (Standard), with Safety next.

Later: deposits, standby seats, chat, further profiles, joining requirements based on coins or history.
