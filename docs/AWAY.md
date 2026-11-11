# When the member is away

Working note, 2026-11-11. A member has duties that fall on dates: open the app before an old state could cost them, sign when the factory rotates, leave before the factory expires. This note lists the ways to meet those duties when the person is not at the app, and what each needs. Nothing here beyond the first row of each table is in the first release.

## Telling the person

| Channel | What it needs | State |
|---|---|---|
| Countdowns inside the app | Nothing extra | First release |
| A Nostr message to an identity the user gives | Care not to link that identity to the wallet for others | Later |
| Email | A mail service, and holding addresses | Later |
| Phone push notifications, alarms | A mobile app | Later, with the mobile app |

The schedule engine in the core computes every date. All of the above only display or deliver what it produces.

## Acting without the person

| Way | What it does | What it needs | Main risk | Checked? |
|---|---|---|---|---|
| The app stays running and acts by itself | Answers an old state, signs a rotation that meets the member's conditions, exits before expiry | A machine that stays on, and conditions set in advance | The keys are on a machine that is always on | Design only |
| A watcher holding pre-signed responses | Publishes the response to an old state | The app hands over one response per state. No keys leave the app | The watcher learns something about the channel; it must be kept up to date | Design only; issue 2 |
| A watcher holding keys | Could also sign rotations | Trust in the watcher | It can spend. Avoid unless the watcher is the member's own machine | Not recommended |
| A hardware signing device | Keeps keys off the computer | A device that supports the group-signing scheme the factory uses, and a way to approve without a person for unattended use | Device support is not confirmed | Not checked |

## What only the member can do

- **Signing a rotation into a new factory** needs the member's key. A watcher without keys cannot do it. If the member is away, the fallback is the automatic exit before expiry, or the host publishing the member's branch.
- **Changing conditions.** Anything acting for the member acts only within the conditions the member set.

## To investigate

1. Which duties can be met with pre-signed transactions alone, and how many must be handed over.
2. Whether hardware signing devices support the group-signing scheme, and unattended use.
3. How the app tells the member that a watcher has fallen behind.
4. Phone operating-system limits on background work, for the mobile app.
