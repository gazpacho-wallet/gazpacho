# Example rule request (not a submitted SIP)

This is a filled-in sample of `template-rule.md`, to show the level of detail expected. It describes the lobby start rule already planned for Gazpacho.

---

# SIP-XXXX: Lobby start rule with target, minimum and deadline

- Category: Rule
- Status: Example only
- Author: Gazpacho project
- Created: 2026-11-11

## The rule in one sentence

A host may open a lobby that starts at once when it reaches a target size, starts at a deadline if it has reached a minimum size, and is cancelled at the deadline otherwise.

## Who sets it and who checks it

| | |
|---|---|
| Set by | Host |
| Where it is published | Lobby listing and host's terms |
| Checked by | Host's software starts the lobby; each member's software checks the size against the member's own conditions |
| Checked when | Continuously while the lobby is open, and again at signing |

## Settings

| Name | Type | Range | Default | Meaning |
|---|---|---|---|---|
| `target_members` | count | 2 to the host's maximum | 50 | Reaching this starts the lobby immediately |
| `minimum_members` | count | 2 to `target_members` | 30 | Fewer than this at the deadline and the lobby does not start |
| `deadline` | time | | 3 hours after opening | When the lobby starts or is cancelled |
| `on_shortfall` | choice | cancel, or carry members over to the host's next lobby | cancel | What happens below the minimum |

## What it needs to know

- How many members are seated and whose software is connected and ready. The host knows this directly; a member is told by the host and cannot verify the count until signing.
- Each member's own minimum, held by that member's software.

## Effect on what is safe to sign

At signing, a member's software counts the members in the tree it is asked to sign. It refuses if the count is below the host's published minimum or below the member's own. So a host cannot start a smaller factory than promised without every member's software noticing.

## Why it is wanted

A factory's on-chain cost is shared among its members, so a host needs enough of them to make it worthwhile, and members want to know they are not joining an empty factory. A deadline lets everyone plan.

## How it could be abused

- **A host inflates the count** to attract members. Limit: the true count is visible in the tree at signing, and members' software refuses a short tree.
- **Fake members fill a lobby** to trigger an early start and then do not sign. Limit: non-signers are removed and the round reruns; if the count falls below the minimum the lobby does not start. This wastes time, not money.
- **A member holds a seat and never readies.** Limit: only connected, ready members count toward the start.

## Who it shuts out

Nobody. A host that wants no minimum sets it to 2.

## Privacy

The target, minimum and deadline are public in the listing. The live count is given by the host on request.

## Tests

- Lobby reaches the target before the deadline: starts immediately.
- Lobby is between minimum and target at the deadline: starts.
- Lobby is below the minimum at the deadline: cancelled, or carried over, as set.
- Members drop during signing and the count falls below the minimum: does not start.
- With the member-side count check removed, a host starting a short tree goes undetected; the test for this must then fail.
