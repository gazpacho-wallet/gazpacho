# The lobby engine: records and decisions

Notes for `core/lobby/` (branch `lobby`). They list what the engine stores
and what it decided where `spec/messages.md` (draft 2), `spec/terms.md`
(draft 2) and `spec/journal.md` were silent or differ, so that the
specifications can be amended or the code changed. Nothing here overrides a
specification.

## 1. Records

All records belong to the Lobby area 0x0001 of `spec/journal.md` section 9
and use the numbers listed there, with one addition, `lobby_state`, now
registered in `spec/journal.md` section 9.1 (this pull request). Checked
against sections 9 and 9.1: no clash.

| Type | Name | Kept by | In journal.md |
|---|---|---|---|
| `0x00010002` | `lobby_opened` | Host | Listed |
| `0x00010004` | `terms_version` | Host | Listed. The engine first used a new type for this (`0x00010018`, "current signed"); it now uses the listed one |
| `0x00010006` | `seat` | Host | Listed |
| `0x00010008` | `freeze` | Both | Listed |
| `0x0001000a` | `lobby_ended` | Both | Listed |
| `0x0001000c` | `terms_received` | Member | Listed |
| `0x0001000e` | `joined` | Member | Listed |
| `0x00010010` | `ready_sent` | Member | Listed |
| `0x00010012` | `host_fault` | Member | Listed |
| `0x00010014` | `start_sent` | Host | Listed |
| `0x00010016` | `start_received` | Member | Listed |
| `0x00010018` | `lobby_state` | Both | **New**, registered in `journal.md` 9.1. The signing engine's outcome. Host: the lobby moved to Open after a failed signing attempt (a retry), to Funding, or to Active; saved before the `lobby_status` that shows it. Member: its round's outcome, so that a restart never hands the finished check to the signing engine again (decision 29) |

**Layouts.** `spec/journal.md` section 9 says each record is a TLV stream
whose field numbers are fixed with the code tables (its open point 3). The
engine uses fixed layouts instead, below; they become TLV fields when those
numbers are fixed. Integers are big-endian; "blob" is a `u16` length then the
bytes; saved messages are whole Lightning messages (type 52791 first).

| Record | Layout |
|---|---|
| `lobby_opened` | blob outer record, outer signature (64), blob current record, current signature (64) |
| `terms_version` | blob current record, its signature (64) |
| `seat` | contribution key (33), factory key (33), `bind_by_factory` (64), `bind_by_contribution` (64), seat state (`u8`), `min_members` (`u16`), version readied for (`u32`), join sequence (`u64`), blob of the seat's latest `ready` (at most 256 bytes) |
| `freeze` | `check_id` (32), version (`u32`), current digest (32), blob of the signed `ready_check`; read back only if that check names the same three values and nothing follows it |
| `lobby_ended` | state (`u8`: 6 Cancelled, 7 Failed; 0 on the member for its own leave), reason (`u16`), blob of the signed `cancel` (empty for a leave) |
| `terms_received` | as `lobby_opened` (the outer record, then the current record the member readies for) |
| `joined` | the signed `join` bytes. The key epoch and index are the program's (`journal.md` lists them here; the engine is given its keys) |
| `ready_sent` | the signed `ready` bytes; for an `unready`, one byte: its reason (1 conditions, 2 the user's choice) |
| `host_fault` | fault (`u8`: 1 two values under one version, 2 a new version or a check at other values after the freeze), blob evidence a, blob evidence b (current records with their signatures, or digest and version) |
| `start_sent` | `check_id` (32), the time the signing budget began (`u64`, Unix ms: the first start of the lobby, the same in every later attempt), `u16` n ≥ 1, then n × (contribution key (33), blob of that seat's signed `start`); each start names the record's check |
| `start_received` | the signed `start` bytes |
| `lobby_state` | state (`u8`: 1 Open, 4 Funding, 5 Active). Host: Funding or Active may follow `lobby_ended` (a creation the signing engine completed stands, decision 26). Member: 1 is a retry, followed by the spent start's `check_id` (32): its saved start is spent, and its answer too if it is to that check (an answer to a later check stands, decision 29); 4 and 5 (alone) the creation's state |

## 2. Decisions to confirm or overrule

1. **Standby seats change messages.md 6.3.** 6.3 accepts a `join` only while
   the lobby is Open. With standby seats configured (`standbys` > 0), the host
   also accepts joins during a ready check and during signing, up to
   `target + standbys` seats, so that late arrivals can fill a gap left by a
   no-show (owner decision 10, `LOBBY.md` "standbys"). Without standbys 6.3
   holds as written. Joins are never accepted from Funding on. A seat chosen
   in the running attempt cannot join again until the round is resolved,
   also after its `leave` (it is held, decision 20): so it never comes back
   with other keys under the same check, and a restart never hands the
   signing engine other participants under one `check_id` (review B, B1). A
   restored host refuses a `seat` record that changes such a seat's keys.
   **6.3 is amended accordingly in this pull request.**
2. **Crypto is a port.** The engine signs and verifies through a port
   (sign, verify, point check), so it holds no key and the core isolation
   check passes on it. Its SHA-256 and its terms library are core/tree's
   (decision 24).
3. **Inputs are whole Lightning messages**, with the peer's BOLT 8 key given
   on connect. "Refuse" (messages.md 1) is a BOLT 1 `warning` followed by a
   `GZ_NOTE_CLOSE` notice naming the peer, because the core frame has no
   close action.
4. **The hand-off to the signing engine** is `gazpacho/lobby_handoff.h`, a
   header of its own that both engines include (it needs only `action.h` and
   core/tree's `terms.h`). `begin` gets the started set (host), the frozen
   records with both host signatures, the pinned key, the decoded terms and
   values, the check, the build parameters (from `gz_tree_params`), and on the
   member its whole conditions (`gz_terms_limits_t`) and its `min_members`
   hint. `begin` is idempotent per `check_id`: after a restart both sides call
   it again with `resume` = 1 (decision 26). The member's `signers` comes from
   the host's `start`; the signing engine takes the count from `round_propose`
   and refuses a mismatch. `cancel` is called whenever the lobby ends by a
   `cancel`, on both sides; `member_left` when a chosen seat leaves while
   Signing (decision 20). The outcome comes back through
   `gz_lobby_host_round_result` and `gz_lobby_member_round_result` with
   `GZ_LOBBY_ROUND_FUNDING`, `_ACTIVE`, `_RETRY` and `_FAILED` (renamed from
   `GZ_ROUND_*`, which clashed with `signing.h`): the program routes the
   signing engine's outcome there. `may_ack` stays the signing engine's; the
   hand-off gives it what `gz_tree_may_ack` needs. The signing engine
   (branch `signing-wire`, PR 33 and successors) is not merged; the interface
   is stubbed in the tests, which check every binding, signature and build
   parameter it receives.
5. **Refusals of a join.** A join refused as invalid (a binding that does not
   verify, a key another seat or the host uses, another factory key for an
   existing seat) gets seat state 7 with reason 5. A join refused because the
   lobby is closed or full or a limit applies gets seat state 7 with no
   reason; the member then tries again every 1.5 s, at most 30 times per
   connection. Reason 5 reuses `round_abort`'s "an invalid message" code;
   messages.md 6.7 names no code for this. The host checks the cheap
   conditions (state, seats taken, one join per connection, the creation
   limits) before any signature, and closes a connection at its 3rd join
   refused as invalid or its 32nd refused for a limit (review A, F8;
   messages.md 6 as amended; review B, the 32nd).
6. **Invitation-only** (owner decision 10) is a host that is not listed: its
   lobby is never named in answers to scope-zero `hello`, so a member needs
   the identifier from an invitation.
7. **Removal** is allowed while Open and during a ready check, never once
   signing has begun. A removed key cannot join again. Two gaps, noted for
   the specification (review A, S6): the removed member is told only seat
   state 6, without the `reason` messages.md 6.7 mentions (no code is
   defined for a removal), and only the contribution key is barred: the same
   factory key can come back under a new contribution key.
8. **A ready check is not resumed** after a host restart: the host returns to
   Open (still frozen) and checks again when the start rule next holds.
   After a check that does not lead to a start, a new check starts only after
   a seat event since that check began (a saved seat change, or a Ready
   seat's reconnect), or at the deadline timer. A connection from a key
   without a Ready seat never applies the start rule, and a seat whose
   `min_members` exceeds the target is not counted by it, so neither a
   stranger nor an unsatisfiable `min_members` can make the members sign
   check after check (review A, F6). When a check starts nobody, the rule is
   applied again as its window closes: a seat event during the check allows
   a new check at once, and without one the failed-check guard waits (review
   B, b20).
9. **The start rule counts** seats that are Ready for the latest (or frozen)
   values and connected now (LOBBY.md: "only members whose software is
   connected and ready count").
10. **`lobby_status` is sent to a seat only when what it says has changed**,
    and at most once a second per seat (messages.md 6.7 gives the rate only).
11. **A member resends its saved state messages** (`join`, `ready`,
    `unready`, `leave`) when a status shows a seat state other than its own,
    at most three times per connection: `join` and `ready` when the host shows
    no seat or Joined at the version it is ready for; `unready` when the host
    shows Ready (Open or a check) and the member is not ready; `leave` when it
    left and the host shows Joined or Ready (review A, F2).
12. **Slice 1 sizes:** at most 32 seats (target plus standbys) and 48
    connections per host, of which at most 16 for keys that hold no seat: a
    17th such connection, or any connection when the table is full, pushes
    out a connection without a seat, never a seated one: one that has said
    nothing yet first, then the oldest, as the transport does (review A, F7;
    review B, B7). A saved `ready`, `start`, `ready_check` or `cancel` is at most 256
    bytes (a ready larger than that is not taken; a larger signed `cancel` is
    not taken either, review A, m17).
13. **Any error from an engine call is fatal for the node**, like a refused
    action list (runner.h): the program stops the node and rebuilds it from
    storage. Action lists of at least 256 slots and 512 KiB are needed. A
    user command that is merely mistimed (unready when not ready, leave when
    ended, removal once Signing or of no seat, new values after the freeze,
    cancel from Funding on, an outcome in the wrong state) is not an error:
    it returns `GZ_OK`, changes nothing and gives `GZ_NOTE_COMMAND_REFUSED`
    with the command and the lobby state (review A, F10). `GZ_ERR_ARGUMENT`
    stays for a NULL pointer or a value outside its range.
14. **The 4 × target creation limit** (messages.md 6) counts every seat ever
    created, rejoins included; a restarted host takes the count from the
    largest join sequence in its `seat` records. The rate limit is a bucket of
    `target` creations refilled at one a second (messages.md 6 as amended,
    review A, S5): a burst of honest joins passes, the average stays one a
    second. It is memory only; a restart starts full. **For the
    specification (review A, S4):** keys cost nothing, so one outsider who
    joins and leaves with new keys can spend the 4 × `target` creations in
    about as many seconds, after which the lobby can seat nobody. Counting
    creations per address or per connection age, or exempting keys that
    readied, would close this; it is a specification change and is not made
    here.
15. **A user's unready is kept**: the member does not ready again by itself,
    across new versions and a restart, until its conditions are set again.
    An unready, for the user or for the member's conditions, also withdraws
    a check the member answered: a `start` for it is saved as evidence and
    never handed to the signing engine, and `gz_lobby_member_may_sign` says
    no, so the signing engine aborts a `round_propose` for it, also one that
    comes without a `start` (messages.md 6.5 and 7.2; review A, F1).
16. **A member that left is told nothing more** and joins nothing again in
    that lobby; a later `join` with a new key is the program's choice. It
    still answers a reconnect with `hello`, so that a lost `leave` is resent
    (decision 11). A member removed, or refused as invalid, ends in memory
    only: after a restart it joins again and is refused again, one round trip
    per restart (review A, S7).
17. **Contract v2, node rule 6 (the reconnect step).** At `PEER_CONNECTED` the
    member sends `hello` and nothing else; it resends its saved state messages
    only when the host's `lobby_status` shows a seat state other than its own
    (decision 11, at most three times a connection). The host pushes nothing on a
    connect: it answers `hello` with `terms_offer`, `lobby_status` and, while
    Signing and the seat was chosen, its saved `start`. Rule 3: the engine
    never saves "sent"; the only acknowledgements it keeps are the peer's own
    saved messages (`seat`, `start_received`).
18. **`hello` limits per member key** (messages.md 6.1 as updated): one answer
    a second and more than 20 ignored `hello`s in 10 minutes, counted across
    the key's connections. The host keeps them for the 64 most recent keys;
    a key pushed out of that table starts afresh. They are in memory only: a
    host restart resets them (contract v2 section 3 accepts this).
19. **A connection that sends neither `hello` nor `join` within 60 s is
    closed** (a warning, then `GZ_NOTE_CLOSE`), and one whose key holds no
    seat is closed 10 minutes after it came up, hello or not (review A, F7).
    One timer serves every connection; it is set when one comes up, or a seat
    is given up, and none is armed. Messages on a connection the engine asked
    to close are ignored.
20. **Seats for the transport.** The host gives `GZ_NOTE_SEATED` (the
    member's contribution key and 1 or 0) after the save that makes a key
    hold a seat or stop holding one (join, leave, removal), and again for
    every seat in `gz_lobby_host_resume`, before any member reconnects. A
    chosen seat that leaves while Signing is saved as Left but stays seated
    until the round is resolved (an outcome, or the end of the lobby), and
    the signing engine is told (`member_left`): the member may still have to
    abort, resend partial signatures or ask for the round's status (review A,
    S1). The
    program applies it with `gz_peers_set_seated_key` (transport PR 23, not
    merged when this was written) until contract v2's `SET_SEATED` action (P4)
    replaces the notice. The engine calls no function outside the core, so
    this is a notice and not a call.
21. **The party's own network** is core/tree's policy (`gz_terms_policy_t`),
    applied by both sides: signet only today. The merged contract allows
    testnet4, and the lobby no longer has a setting of its own for it, so that
    the two libraries never disagree (review A, F4): **noted for the tree
    stream**, which adds testnet4 to `gz_terms_policy_t` when it is wanted;
    the lobby then follows with no change. The engine does not see `init`;
    the transport checks it.
22. **After a restore** the member is given its current keys. Records whose
    saved `join` names another factory key belong to a seat of an older
    epoch: the engine does not resume that seat (nor its `ready`, `start` or
    own leave) and joins again with the current keys (`safety-rule.md` C12,
    messages.md 2: "a restored member ... has no old seat: it joins again").
    The restore marker and the start fence of `ports.h` are the node's; the
    lobby engine reads only the records the node hands it.
23. **Not yet against contract v2's P4.** Peers are still `uint64_t` ids and
    messages whole Lightning messages, as on `main` today; links, `SEND` with
    kind and scope, and `CONNECT`, `DISCONNECT` and `SET_SEATED` arrive with
    P4. The engine has no view objects yet (contract v2 section 11, kinds 2
    and 3): its notices are listed in `lobby.h`, each after the save of what
    it reports (node rule 8), and their mapping to the view is left to the
    program's pull request.
24. **One terms library: core/tree's** (review A, F4). The lobby's copy of
    the terms code and of SHA-256 is gone; the lobby calls `gz_terms_receive`
    (terms.md 7 steps 1 to 6, the pinned key included), `gz_terms_version_rule`
    and `gz_terms_classify`, and decodes its own saved records with
    `gz_terms_decode_outer` and `gz_terms_decode_current` under the same
    policy. So the two libraries link and include together, and a member never
    joins a lobby its signing check would refuse (an unfundable tree, a
    minimum above 256). A member's conditions are `gz_terms_limits_t` (0 is
    "no limit" for a fixed term; a listed adjustable limit of 0 is a real
    bound) plus the looser option and the `min_members` hint of `ready`. The
    lobby adds only `gz_lobby_classify`, which names the deciding term for its
    notices: the smallest type whose limit alone gives the class, found with
    core/tree's own comparison. **Noted for the tree stream:** core/tree's
    limits have no wind-down limit, so the lobby's is gone; and
    `gz_terms_version_rule` calls any other record a breach once frozen,
    where messages.md 6.2 ignores a version lower than the accepted one (the
    lobby keeps 6.2's reading).
25. **Answered for the frozen values only** (review A, S2, S3). A member joins
    a lobby that fits or fits only now. It is ready by itself only if the
    lobby fits (or fits only now with the looser option), but it answers a
    `ready_check` whose values fit, because the check is the host's signed
    freeze: after it a "fits only now" lobby whose frozen values fit is, in
    effect, a fit (terms.md 9). After the freeze a seat that went back to
    Joined readies by itself again for the frozen values, as messages.md 6.4
    allows.
26. **Restarts around the hand-off** (review A, F3). A member restarted
    between `start` and `round_propose` hands its saved start to the signing
    engine again from `gz_lobby_member_resume` (`resume` = 1), if it is still
    ready for that check; a host restarted in Signing does the same for its
    saved start from `gz_lobby_host_resume`. The signing engine treats `begin`
    as idempotent per `check_id`, and ignores `begin` for a check it has
    already finished (any outcome), as `lobby_handoff.h` states (review B,
    B2). A host restarted in Signing sets its deadline timer again, and so
    does a retry while the deadline is ahead, so that a lobby back in Open
    still ends at its deadline (review B, B4). **The signing budget**
    (terms.md 3, one for all attempts) has one owner at a time (review B,
    B3, the owner's coordinator's decision). The lobby saves the time of its
    first `start` in `start_sent`. Once it hands a round to the signing
    engine, the signing engine alone owns the budget and reports
    `GZ_LOBBY_ROUND_FAILED` when it is spent; the lobby never cancels a round
    in Signing for it. The lobby's `GZ_LOBBY_TIMER_BUDGET` covers only the
    phases before a hand-off: after a retry, if the lobby is Open or in a
    check when the budget is spent, it ends the lobby with `cancel` reason 3.
    A Funding or Active outcome is always accepted, also after the lobby
    ended by a `cancel` (the host's own, while Signing): a creation the
    signing engine completed is never refused, and the lobby then shows
    Funding or Active and resends no `cancel`.
27. **A ready the change limit refuses changes nothing in memory** (review A,
    F5): the seat is restored as saved, and the host answers `lobby_status`
    either way (messages.md 6.4). Moves that take a seat out (`unready`,
    `leave`) are never limited (review B, B6): only a move into Ready counts
    against the limit, so a withdrawn seat is never chosen and a chosen
    seat's `leave` always reaches the signing engine.
28. **The choice of signers with standbys** (review A, S8). The code follows
    messages.md 6.9 exactly: cut to the target in order of joining, then drop
    every seat whose `min_members` exceeds the count. With standbys, answered
    seats beyond the target are therefore never used to refill places the
    drop leaves. A seat whose `min_members` exceeds the target can never be
    met: it is left out before the cut (as the start rule already leaves it
    out), so k such seats that joined early cost no one a place (review B,
    B5; messages.md 6.9 amended). **Proposed for the specification:** drop
    first, then cut, which uses the standbys decision 1 exists for; review B
    showed the loss (scenario S12). Not changed here beyond the above.
29. **The signing outcome is saved on both sides** (review B, B2, the owner's
    coordinator's decision). The member saves its round's outcome in its own
    `lobby_state` record: a retry spends its saved start, and the answer to
    that start's check, so a start for it resent by a host that is behind is
    ignored. The record names that check: the Retry itself names none, and a
    member that answered the next check before its signing engine reported
    the retry keeps that answer (confirmation review, N1). Funding or Active
    are its creation's state. So
    `gz_lobby_member_resume` never hands a finished check to the signing
    engine again, and the shown state survives a restart. A crash can still
    lose that save, so the hand-off stays idempotent: `begin` for a finished
    check is ignored by the signing engine (`lobby_handoff.h`).
