# Brief for every layout concept

You are building ONE layout concept for the Gazpacho wallet as a single self-contained HTML mock-up. Seven concepts are being built in parallel by different builders from this same brief, so that the owner can compare arrangements on identical content. Yours must be a complete, honest, well-reasoned design, not a sketch.

## Read first (all local, all required)

1. `C:\pirq\gazpacho\docs\ux\options-map.html`: every option, in scopes. The "Version 2" section wins where it disagrees with the tables below it. It ends with the sixteen moments.
2. `C:\pirq\gazpacho\notes\ux\research-wallets.md`, `research-node-market.md`, `research-lobbies-consent.md`: what real products do. Use the parts relevant to your concept; the last one ends with a checklist of testable interface rules that apply to every concept.
3. `C:\pirq\gazpacho\notes\ux\gap-check.md`, sections B and C.
4. `C:\pirq\gazpacho-ui\web\css\gazpacho.css` for the colour tokens (cream background, tomato red accent, light and dark). Reuse the palette so the seven look like one product in different arrangements. You may restyle layout freely.

## What Gazpacho is

A non-custodial Lightning wallet. One **host** and many **members** share one on-chain output, a **factory**. The host pays for everything; a member starts with a balance of zero and a channel it can receive into. Hosts open **lobbies** with fixed, signed **terms** and a start rule (target, minimum, deadline). Members keep personal **conditions**. When a lobby starts, each member's app signs by itself, in seconds, if the terms are inside that member's conditions and the safety checks pass; otherwise it refuses and says why. Afterwards the member has dates to keep. Before a factory ends, members move to the host's next factory or leave. A member can always leave alone, without the host, which takes days and uses the chain. The same app can be a host.

## Hard rules

- Words: host, member, lobby, factory, terms (host's), conditions (mine), hosting, providing liquidity, fees, receiving room. NEVER "staking", "stake", "yield", "APR", "interest", "earn rewards".
- Conditions and terms: two objects, two looks. Conditions are editable controls in my voice. Terms are a sealed card with no inputs. They meet only in a fit check with the columns: term, this lobby, my limit, fits or not. A failing row is a sentence with both numbers.
- Filters hide rows; conditions refuse to sign. Different words, never one panel.
- Always present on every screen: the test-network marker ("Signet: test coins, no value"), a status strip (connection, watching, next date, automatic joining state), and Pause.
- Every countdown says what happens at zero. Dates in both forms (in 6 days; 17 Nov).
- A refusal has four parts: what happened, the two numbers, that nothing moved, what to do next.
- "My money" on the home: can send, can receive, what I could take out alone (amount, cost, time).
- Host controls are invisible until host mode is on.
- Nothing is promised beyond this brief. In particular: do NOT say a member can be away for two weeks. Say "how long you can safely be away depends on the factory; this one: about 1 day unless something watches for you" and mark it OPEN. Do not say a late host forfeits everything. Mark seat cost, fee kinds, and "new version or new lobby when terms change" as OPEN where they appear.
- No "never a setting" item may appear as a switch (see the map).
- Host-written free text is shown as labelled, quoted host text, never as the app speaking.
- Open decisions and things not in the first release are shown with small "open" or "later" tags, not hidden.

## Common fake data (use exactly this so concepts compare)

- Me: member name in lobbies "Lemon-39". On chain: 48,000 sats. Network: Signet.
- Live factory: "Tomato Garden, factory 12", host Tomato Garden (12 factories funded), 50 members. Channel 500,000 sats; can send 182,400; can receive 317,600; host's spare liquidity on my leaf 250,000. Take out alone: about 181,200 after about 1,200 in fees, about 6 days. Factory ends 8 Dec 2026 (26 days); move window opens in 16 days; today is 12 Nov 2026, block 330,437.
- Lobbies listed: "Tomato Garden, daily factory" (Standard; target 50, minimum 30, deadline in 2 h; 38 ready; channel 500,000; joining fee 1,000 sats; payment fee 0.05%; receiving-room fee 0.3%; life 33 days; leaving alone 6 days) fits. "Quiet Harbour" (Safety; 20/12/tomorrow 09:00; 9 ready; channel 300,000; fee 500; life 30 days; leaving alone 3 days) fits. "Big Pepper" (Standard; 200/120/6 h; 131 ready; channel 2,000,000; joining fee 5,000; life 90 days) does not fit: "Joining fee is 5,000 sats. Your limit is 2,000 sats." and "Lifetime is 90 days. Your limit is 45 days." "Circle of Friends" (Circle; invitation only). Fourteen listed in total; three fit.
- My conditions: profiles Safety and Standard; fewest members 20; smallest channel 200,000; joining fee up to 2,000; payment fee up to 0.1%; receiving-room fee up to 0.5%; life 7 to 45 days; leaving alone up to 7 days; automatic joining: off by default, with the "tell me" and "join by itself" choices and a budget of 1 factory at a time.
- A refusal to show: at signing, "The tree offered has 28 members. Your limit is at least 30... " (pick consistent numbers), nothing moved.
- Activity: joined lobby; signed (17 signatures in 4 seconds); refused Big Pepper; received 21,000 sats; paid 3,600 sats (fee 2); answered nothing; "while the app was closed (9 hours): nothing needed you".
- Host mode example: my lobby "My first lobby" at 22 of 30 ready, funding needed 22.5 million sats at minimum and 37.5 million at target; wallet has 42 million.

## What to build

One file, your assigned path under `C:\pirq\gazpacho\docs\ux\`. Requirements:

- Self-contained: inline CSS and JS only, no external requests of any kind, no frameworks, no images other than inline SVG. Works from a `file://` address.
- Clickable: real navigation between screens inside the file (show/hide sections; keep the address hash in step so screens can be linked). Light and dark by `prefers-color-scheme` plus a toggle. Usable at 360 px and at 1280 px wide; no sideways scrolling.
- A slim bar at the very top, outside the mock-up: concept letter and name, the products it is modelled on, a "Moments" menu that jumps to each of the sixteen moments, a member/host mode switch, and a link back to `index.html`.
- All sixteen moments reachable. Where a moment is a state rather than a screen (signing, refusal, attention, left behind), provide a way to switch the mock-up into that state from the Moments menu.
- Every option in the map appears somewhere, in exactly one place. Long option lists may be shown as real, readable form screens; do not replace them with "…".
- At the bottom of the file, a section "About this concept" outside the mock-up: the navigation skeleton as a small tree; where each of the seven scopes lives; which patterns were borrowed from which product (name them, and say verified or recalled per the research files); the concept's honest strengths and weaknesses; what you would change after seeing it.
- Text as text nodes; plain language; short sentences; no jargon without an explanation on first use.

Quality bar: this should look and read like the work of a senior product designer who knows Bitcoin wallets. Favour clarity over decoration. Do not copy any product's branding or artwork; borrow arrangement patterns only.

## Check your own work

Write and run a small Python check (standard library only, kept in your scratch area, not in the repository) that confirms: the file parses; there are no `http://`, `https://`, `src=` or `url(` references to outside resources; every in-file link target exists; each of the sixteen moments has a reachable target; none of the forbidden words appears; "14 days" and "two weeks" do not appear as absence promises. Fix what it finds. Report the result.

Create only your one HTML file in the repository. Do not commit, push or post. Final reply: the path, the navigation skeleton in six lines, the three best ideas in your concept, its three weakest points, and the check result.

## Owner decisions made after this brief was first written (these override anything above)

1. **No host mode and no role question.** Everyone can always do both. Never ask "member or host?" at first run or anywhere else, and do not hide hosting behind a switch. Hosting is an ordinary first-level area that is always visible ("Host a factory" or "Hosting"). Before the person has hosted anything it shows a short, calm starting page: what hosting needs (funds and a linked Lightning node) and a "Write terms" button. It must not clutter the member's home: host items appear on the home only once the person has a lobby or factory of their own. Replace the top bar's member/host mode switch with a Moments-menu state "I also host", which fills the hosting area with the sample lobby. One home, not two: a hosting section appears on it when there is something to show.
2. **Buying receiving room (buying liquidity, splicing, channels opened on demand) is version 1.1.0, not 1.0.0.** Keep those screens but hide them by default: reachable only through a clearly marked "Preview 1.1.0" toggle in the Moments menu, and every such screen carries a "1.1.0" tag. In the normal view, "can receive" shows the room left, with one line: "More receiving room can be bought from version 1.1.0." The conditions and the lobby term that relate to it (receiving-room fee limit, automatic buying, receiving-room fee) likewise appear only in the 1.1.0 preview.
3. **Terms: outer rules are fixed; values move only inside signed ranges, then freeze.** A lobby's outer rules (its profile, every fixed term, and the allowed range of each adjustable term) never change; a change means a new lobby. Inside a range the host may move the current value until the ready check, when everything freezes. The sealed terms card shows, for an adjustable term, the current value and its range, for example "Joining fee: 1,000 sats now; may move between 500 and 1,500 until the ready check". The fit check compares my limit with the WHOLE range by default, so I can never be switched at the last moment; a row can read "fits at any value the host may choose". Offer the looser choice as one condition: "Ready me while the current value fits; un-ready me if it moves outside my limit." Show a short rules fingerprint on the card ("Rules fingerprint 7f3a…c21e, signed by the host") with one line saying the app signs only for these exact rules. Remove any "open" tag about "new version or new lobby".
5. **Safety wording rules, from the independent critique (`notes/ux/critique.md`).** All seven first concepts broke these. Every sentence about safety, absence or what the app does alone must follow them:
   - **Leaving alone is conditional.** Never "the app always leaves alone in time" or "makes sure of that". Say: "While it is running and has funds for fees, the app starts leaving alone in time. If it is closed, nothing acts for you unless something watches." Never "this cannot be switched off" without the condition.
   - **Being away too long is not harmless.** After the safe absence has passed, never "nothing was lost", "your money has not moved", "your coins are not lost". Say what is true: "Nothing appears to have gone wrong while you were away. Check below." and show what the app checked.
   - **An unfinished signing round is its own state.** Once my partial signatures have gone out and no result came back, never "nothing moved", "nothing was signed", "you are back in line", "you need do nothing". Say: "Signing did not finish. The app treats both the old and the new state as possible and keeps watching both until it is settled." Only before my partial signatures go out may a failed start say "nothing was signed; you are back in line".
   - **Timed levels do not wait.** Never "nothing is lost by a short delay", "the steps wait for you", "it does so when you next open it". Some steps have deadlines that pass whether the app is open or not.
   - **No blanket "your money is safe".** Say what the protection is and what it needs: "You can leave alone without the host. It takes about 6 days and costs about 1,200 sats in fees."
   - **Public servers can mislead, not steal.** Never "your coins are never at risk from them". Say: "Public servers cannot spend your coins. A server that lies could hide a payment or a deadline from you; the app compares at least two to catch this."
   - **A cheating host:** never imply the member gains. Say "If the host publishes an old state, the app answers it and the old state's outputs go to their rightful owners."
   - **Restore:** a restored wallet never publishes from an old backup. It waits for the host or for current data from the chain. Do not also promise it leaves alone from the backup.
   - **Leaving alone must finish before the factory ends,** not on the end date. The start date is the end date minus the time leaving takes minus a margin.
6. **Other critique fixes that apply to any concept:**
   - Pause and the test-network marker stay on screen while scrolling (fixed, not in the scrolled content).
   - An editable condition never sits next to a host's signed term except in the fit check.
   - "Fewest members" is compared with the lobby's signed **minimum**, not its target.
   - No "Remove a member" control for a host after the ready check; before it, removal is the host's right in its own lobby (LOBBY.md), so keep it there only, labelled.
   - At least two chain servers can never be removed below two; "my own node" does not remove the comparison.
   - Frozen records in Activity are frozen copies, not live views.
   - Each lobby has its own fingerprint.
   - Nothing about receiving room outside the 1.1.0 preview, including in host earnings totals and Moments links that switch the preview on silently.

4. **Fees in 1.0.0:** a fee on each payment (a base amount plus a proportion), and an optional joining fee, flat or a share of the chain cost with a ceiling, taken from the first payment received. Tag the joining-fee collection method "open". A recurring fee at each move is "open". The receiving-room fee is 1.1.0 only.
