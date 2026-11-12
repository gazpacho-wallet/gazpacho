# The lobby engine: records and decisions

Notes for `core/lobby/` (branch `lobby`). They list what the engine stores
and what it decided where `spec/messages.md` (draft 2), `spec/terms.md`
(draft 2) and `spec/journal.md` were silent or differ, so that the
specifications can be amended or the code changed. Nothing here overrides a
specification.

## 1. Records

All records belong to the Lobby area 0x0001 of `spec/journal.md` section 9
and use the numbers listed there, with one addition. Checked against
`spec/journal.md` on `main` (sections 9 and 9.1): no clash.

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
| `0x00010018` | `lobby_state` | Host | **New, to be registered.** The lobby moved to Open after a failed signing attempt (a retry), to Funding, or to Active. Saved before the `lobby_status` that shows it |

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
| `start_sent` | `check_id` (32), `u16` n ≥ 1, then n × (contribution key (33), blob of that seat's signed `start`); each start names the record's check |
| `start_received` | the signed `start` bytes |
| `lobby_state` | state (`u8`: 1 Open, 4 Funding, 5 Active) |

## 2. Decisions to confirm or overrule

1. **Standby seats change messages.md 6.3.** 6.3 accepts a `join` only while
   the lobby is Open. With standby seats configured (`standbys` > 0), the host
   also accepts joins during a ready check and during signing, up to
   `target + standbys` seats, so that late arrivals can fill a gap left by a
   no-show (owner decision 10, `LOBBY.md` "standbys"). Without standbys 6.3
   holds as written. Joins are never accepted from Funding on.
2. **Crypto is a port.** The engine signs and verifies through a port
   (sign, verify, point check), so it holds no key and the core isolation
   check passes on it. It has its own SHA-256.
3. **Inputs are whole Lightning messages**, with the peer's BOLT 8 key given
   on connect. "Refuse" (messages.md 1) is a BOLT 1 `warning` followed by a
   `GZ_NOTE_CLOSE` notice naming the peer, because the core frame has no
   close action.
4. **The hand-off to the signing engine** is `gz_lobby_signing_t`: `begin`
   with the started set, the frozen records and digests and the build
   parameters; `cancel` with the lobby and the reason whenever the lobby ends
   by a `cancel`, on both sides. The outcome comes back through
   `gz_lobby_host_round_result` (Funding, Active, retry without named seats,
   failed: cancel reason 3).
5. **Refusals of a join.** A join refused as invalid (a binding that does not
   verify, a key another seat or the host uses, another factory key for an
   existing seat) gets seat state 7 with reason 5. A join refused because the
   lobby is closed or full or a limit applies gets seat state 7 with no
   reason; the member then tries again every 1.5 s, at most 30 times per
   connection. Reason 5 reuses `round_abort`'s "an invalid message" code;
   messages.md 6.7 names no code for this.
6. **Invitation-only** (owner decision 10) is a host that is not listed: its
   lobby is never named in answers to scope-zero `hello`, so a member needs
   the identifier from an invitation.
7. **Removal** is allowed while Open and during a ready check, never once
   signing has begun. A removed key cannot join again.
8. **A ready check is not resumed** after a host restart: the host returns to
   Open (still frozen) and checks again when the start rule next holds.
   After a check that does not lead to a start, a new check starts only after
   a seat changes, a seat reconnects, or the deadline timer fires.
9. **The start rule counts** seats that are Ready for the latest (or frozen)
   values and connected now (LOBBY.md: "only members whose software is
   connected and ready count").
10. **`lobby_status` is sent to a seat only when what it says has changed**,
    and at most once a second per seat (messages.md 6.7 gives the rate only).
11. **A member resends its saved `join` and `ready`** when a status shows the
    host lost them (no seat, or Joined at the version it is ready for), at most
    three times per connection.
12. **Slice 1 sizes:** at most 32 seats (target plus standbys) and 48
    connections per host; a saved `ready`, `start` or `ready_check` is at most
    256 bytes (a ready larger than that is not taken).
13. **Any error from an engine call is fatal for the node**, like a refused
    action list (runner.h): the program stops the node and rebuilds it from
    storage. Action lists of at least 256 slots and 512 KiB are needed.
14. **The 4 × target creation limit** (messages.md 6) counts every seat ever
    created, rejoins included; a restarted host takes the count from the
    largest join sequence in its `seat` records.
15. **A user's unready is kept**: the member does not ready again by itself,
    across new versions and a restart, until its conditions are set again.
16. **A member that left is told nothing more** and joins nothing again in
    that lobby; a later `join` with a new key is the program's choice.
