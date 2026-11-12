# Critique of the seven layout concepts

Independent review, 12 Nov 2026. I built none of the seven.

Each concept was checked against:
- the brief and its owner decisions;
- options map Version 2;
- `docs/ux/decisions.md`;
- the 25 checklist rules in `research-lobbies-consent.md`;
- the drafts `spec/safety-rule.md` and `spec/signing-round.md`.

**How it was checked**

- **Markup and script.** I read the HTML and script of each file. One separate review pass per concept walked all sixteen moments in the markup and script. I re-checked the load-bearing findings myself by searching the files. These checks are listed in "What I could not check" at the end.
- **In a browser.** I served the folder read-only on 127.0.0.1 and drove Chromium with Playwright:
  - every in-file link in every concept, at 360 px and 1280 px, checked for sideways scrolling;
  - whether Pause and the Signet marker stay on screen after scrolling;
  - screenshots of home, a lobby that does not fit, and signing, light at 360 px and dark at 1280 px.

**What the browser showed**

- No concept scrolls sideways at either width.
- Dark mode works in all seven.
- No script errors.
- In C, D and G, Pause stays on screen when you scroll. In A, B, E and F it scrolls away with the top of the page. It is still reachable, but not always visible.

The headline: **every concept has the same three safety gaps** (section 4). The choice of layout matters less than fixing those sentences.

---

## 1. Scores

1 = poor, 5 = nothing to fix. The criteria:

- **a** Scopes cannot be confused
- **b** Safe join with defaults
- **c** Unattended signing and automatic joining
- **d** Most urgent thing visible
- **e** Member and host without clutter
- **f** Phone width
- **g** Honest about what is not protected
- **h** Room to grow
- **i** Everyday use
- **j** Visual and verbal quality

| Concept | a | b | c | d | e | f | g | h | i | j | **Total** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A Wallet first | 4 | 4 | 3 | 3 | 4 | 4 | 2 | 3 | 4 | 4 | **35** |
| B Console | 4 | 4 | 4 | 3 | 4 | 3 | 2 | 4 | 4 | 3 | **35** |
| C Desktop power | 3 | 3 | 3 | 3 | 4 | 2 | 2 | 4 | 3 | 3 | **30** |
| D Lobby browser | 4 | 4 | 3 | 4 | 4 | 3 | 2 | 3 | 3 | 4 | **34** |
| E Offers | 4 | 3 | 4 | 3 | 4 | 3 | 2 | 3 | 3 | 4 | **33** |
| F Suite | 4 | 4 | 4 | 3 | 4 | 3 | 2 | 3 | 4 | 4 | **35** |
| G Built from research | 4 | 4 | 4 | 4 | 4 | 3 | 2 | 4 | 4 | 4 | **37** |

The spread is small: 30 to 37. Criterion g is 2 for all seven, because each one has at least one sentence the specifications contradict (section 4). It does not separate them.

### Evidence, one sentence per score

**A Wallet first**
- a 4: The sealed card and the editable conditions look different, and "Not in Settings, on purpose" explains why. But the Fennel Yard lobby row and "Enter an invitation" both land on my conditions screens.
- b 4: Profiles alone are enough, and the whole range is the default. But "Review and join" sits above the sealed card and the fit check.
- c 3: Budget and worst case are clear. But automatic joining is never shown running ("Automatic joining: off" in every state), and there is no total amount.
- d 3: A banner for each state is good. But the strip and Pause scroll away on a phone, and the strip shows 28 Nov rather than the nearer "open within about 1 day".
- e 4: The Host tab has a calm starting page, and hosting reaches the home only with a lobby. The cost is a fifth phone tab.
- f 4: Phone-first: a 412 px frame, bottom tabs, a fixed-layout fit table, no overflow in the browser.
- g 2: "Your coins are never at risk from them" (public servers) and "Nothing was lost" (left behind) are wrong.
- h 3: "All my factories" exists. But the home has one balance and one factory card.
- i 4: Send review with fee and stuck deadline, pending with "at zero", and "keep the app open to receive". The deadline numbers disagree (2 days vs 3 days).
- j 4: Calm and plain, with slips: "as you told it to", "Yes*", and the 1.1.0 line repeated five times.

**B Console**
- a 4: A separate menu entry for each scope. But "Its terms" on my open lobby opens the editing form, and #payments puts my fee limit beside the host's fee term.
- b 4: Profiles only, and whole-range fit. But Quiet Harbour "Fits" unexplained, and the Join facts sit far below the sealed card on a phone.
- c 4: #auto-review shows "the most it permits" before it takes effect, with a table of every state. The worst case leaves out exit costs.
- d 3: The strip shows counts ("2 required · 2 important"), not the urgent item, and it scrolls away.
- e 4: No role question, and host items are gated. One leak: "Only a host sets funds aside" on the member's home.
- f 3: Five full-width strip lines plus a Pause row (about 180 px) above every screen at 360 px.
- g 2: "Nothing was lost" after four days away, and "You can always leave alone".
- h 4: The factories list (in, moving to, hosted, past), a ladder, and clean 1.1.0 gating.
- i 4: Pay and Receive are one click from Home. But the "about 4 hours" deadline contradicts the "at least 144 blocks" refusal.
- j 3: Dense grey hints, and the data contradicts itself across scenes (try times, backup age 9 days vs 1 day).

**C Desktop power**
- a 3: Each scope has a tab. But the pay review checks the host's 0.05% against my 0.5% routing limit instead of my 0.1% condition.
- b 3: First run skips showing and checking the 24 words. Quiet Harbour (minimum 12) "fits" while Chili Yard (minimum 10) is refused for the same reason.
- c 3: "Join by itself" takes effect on click, with no confirmation and no total. "Running" exists only as an examples table.
- d 3: The status bar with Pause is sticky. But the urgent strip scrolls away, and the Preferences overlay covers the strip, the status bar and Pause.
- e 4: Hosting sits below a divider, and the home panel is host-only.
- f 2: One breakpoint. Fourteen stacked cards before the lobby detail, tree and ladder drawings with unreadable text, and the relative date dropped from the status bar.
- g 2: "If the app is closed, the steps wait for you" and the restore claim about the end-date payout are wrong.
- h 4: The Factories table already holds several factories and roles.
- i 3: Pay, Make invoice, Quiet Harbour's Join and "Open a lobby" are inert buttons.
- j 3: For a "check the work" concept, too many arithmetic errors (12,000 pending on top of a full 500,000; "9 have a higher joining fee" when 5 do).

**D Lobby browser**
- a 4: A blue sealed card against the tomato-edged conditions. But the Join card lists terms in the conditions colour, and automatic joining has two controls.
- b 4: Good defaults and "at most 1,500 sats". But Join sits above the fit check.
- c 3: The Play button starts "Looking (tell me)" while the radio says Off, and skips the budget card.
- d 4: A sticky bottom strip with Pause and a reason on every screen. But #attention has no link from inside the app, and the at-zero text is hidden at 620 px or less.
- e 4: Hosting is a calm first-level tab. One leak: "Set aside 0 sats. Only hosts set money aside".
- f 3: Cramped five tabs, a tall strip, four-column fit tables.
- g 2: "nothing is lost by a short delay" while leaving alone is wrong under timed levels.
- h 3: A Favourite hosts tab and the preview. The factory, the move and leaving alone hang off Home.
- i 3: Pay and Receive are only on Home. The browser is the centre of gravity.
- j 4: Plain, consistent numbers. Small contradictions remain (30 vs 20, weekdays, 2-day vs 1-day steps).

**E Offers**
- a 4: Three distinct looks (blue mine, gold sealed, green host). But two "highest fee per payment" options sit in two scopes.
- b 3: The members row compares my limit with the target, not the minimum (script: `l.target>=c.members`). So Quiet Harbour passes and is later refused. The safe absence is deferred until after joining.
- c 4: A live one-sentence instruction, a review, a history, and "Stop this instruction". No running or nothing-fits preset.
- d 3: The urgent line is always there. But there is no "open the app by" item, Pause scrolls away, and a 20-hour watcher gap is filed as "Soon".
- e 4: Calm hosting start. But "Sign the terms and open the lobby" does nothing.
- f 3: Signet bar, money line, urgent line, seven chips over 2 to 3 rows, then a three-line footer.
- g 2: "Nothing is lost", "The app always leaves alone in time", "Your 182,400 sats are safe".
- h 3: "All my factories" exists. But "My channel" is singular.
- i 3: Pay and Receive are one level down, and the menu opens with Lobbies.
- j 4: Calm and well typed. Trading words ("Filled") and an Activity history that contradicts itself.

**F Suite**
- a 4: Settings tabs map one-to-one to scopes. Hosting options are split between Settings and Hosting.
- b 4: Only profiles at first run, a whole-range fit check, "Most it costs you 1,500 sats".
- c 4: Budget summary and "It needs the app open and running at each start". No total, and Pause does not say it leaves unstarted lobbies.
- d 3: A tier bar exists. But the strip is fixed text that is wrong in first run, leaving and after-end states, and it scrolls away.
- e 4: Hosting is in the sidebar with a calm start. The phone bar gives Hosting a tab and pushes Activity into "More".
- f 3: Strip pills, Pause and the top bars stack before any content at 360 px.
- g 2: "or it does so the next time you open it" (leaving), an impossible at-risk timeline, and a restore contradiction.
- h 3: Factory slots exist. The home and the strip assume one factory.
- i 4: Pay in 3 steps with an honest review. But "Payments stop while … moving" vs "Paying and receiving work during the move".
- j 4: Calm, precise copy. Sloppy numbers (earnings sum, 4,548,000 vs 4,500,000).

**G Built from research**
- a 4: A table of where each scope lives. But "profile" has two meanings, and the two payment-fee limits sit on two screens.
- b 4: Whole range by default, fingerprint line, "this app signs for you without asking". But the first-run profile choice is not wired, and the join review says "Open the app by: about daily" with no date.
- c 4: Two separate consents, a budget, a worst case, a list of standing instructions with Cancel. No unfinished state.
- d 4: The only concept where Pause and the Signet marker stay on screen after scrolling at both widths. But its mock state goes stale ("2 public servers agree" under a "servers disagree" banner).
- e 4: Hosting is set apart. The home section appears only with a lobby.
- f 3: Three sticky layers. On a phone, explanatory parts of the chips are hidden.
- g 2: "Your money is safe", "Your money is not lost", "You can always take your money out". But also the best honest lines: "you could lose money", "What the app needs: to run now and then".
- h 4: Two factories at once, a host ladder, a full 1.1.0 preview.
- i 4: Pay review with breakdown, a refused payment with both numbers. Receive is a tab inside Pay.
- j 4: Senior voice and careful arithmetic. But the "frozen" records are live copies of today's table, and two lobbies share one fingerprint.

---

## 2. Moment walk: problems shared by most concepts

Each concept's full sixteen-moment walk was done. Here are the findings that matter for the final design.

| Moment | Shared problem | Concepts |
|---|---|---|
| 1 First run | The status strip shows a live factory 12 and "next date 28 Nov" to someone with no wallet. Profiles shown without their numbers (checklist rule 4). "Custom" relabelling only described, not built (rule 5). | All seven (strip: B, D, F, G, and C partly) |
| 3 Joining | The Join button or join facts sit above or far below the fit check. On a phone you can commit before seeing the terms (rule 9). | A, B, C, D |
| 3 Joining | Quiet Harbour (minimum 12) "fits" my "at least 20", but is then refused or "not counted". The whole-range rule is applied to fees but not to member count. | A, B, C, D, E, F |
| 4 Automatic joining | "Running" and "why nothing fits" are shown as example sentences, not as states. Only G and E compute it live. | A, C, E (partly) |
| 5 Signing | No state for a round where my partial signatures went out and no result came back. | All seven |
| 7 Payments | Two limits named almost alike: "highest fee per payment" (the host's fee, a condition) and "highest fee I pay per payment" (routing). C's pay review mixes them up. | All seven |
| 9 Attention | "Act now" used for items with no date (servers disagree, host silent), against rule 21. A neighbour leaving filed as low priority, though it starts a race. | C, E, F |
| 10 Left behind | Leaving alone starts 2 Dec, takes 6 days, ends 8 Dec, which is the end date: no margin. | B, D, E, F (A and G land on 7 Dec, one day of margin) |
| 13 Hosting | The button to sign terms and open the lobby is inert or disabled with no reason. The lobby exists only through the Moments toggle. | C, E, G |
| 13 Hosting | "Remove" a member before the start: allowed by the map, but against checklist rule 23 ("no kicking"). | C, D, F |
| Mock-up state | Moments toggles and states never reset, so later moments contradict earlier ones (host on, preview on, signing stays). | A, B, G (worst), F |

Dead ends worth naming:
- E "Sign the terms and open the lobby" does nothing.
- C Quiet Harbour Join, Pay, Make invoice and "Open a lobby" do nothing.
- A "Enter an invitation" goes to a conditions screen with no invitation field.
- B and D lobby details "not drawn" for most lobbies.
- D #attention cannot be reached from inside the app.
- E restore waits for the host with no way forward.

---

## 3. Rule violations

**Clean in all seven:**
- No "stake", "staking", "yield", "APR", "interest" or "earn rewards". The only matches were "Paprika", "approve" and the map's own word "Earnings".
- No "14 days" or "two weeks".
- No member/host role question and no host mode inside any mock-up.
- No switch for any "never a setting" item. Mainnet is a disabled option or absent everywhere.
- Host free text is labelled and quoted everywhere, with two minor exceptions:
  - E `#factory`: "11 ended as agreed." is the host's claim shown in the app's voice.
  - Lobby names are host-written but shown as plain headings (all).

**Found:**

| File | Rule | Exact text or element |
|---|---|---|
| concept-g-blend.html, host terms preview "As members will see it" (line 1487) | Buying receiving room only in the 1.1.0 preview | "Receiving-room fee 0.3%", with no gate and no tag |
| concept-f-suite.html `#host-earnings` | Same | "Plus spare liquidity not yet sold: 31,000,000 sats inside factories." The total "Result 166,100 sats" includes the hidden receiving-room fees of 6,900. The Moments link `#room` silently turns the preview on. |
| concept-e-offers.html `#scopes` | Same | "Limits, joining, moving, buying room by itself. Never in Settings." and "My channel: pay, receive, buy receiving room" |
| concept-d-lobby.html `#factory`, `#host-factory` | Same | "the host sells no more receiving room"; "stops sales of receiving room" |
| concept-a-wallet.html | "One line" rule | "More receiving room can be bought from version 1.1.0." appears five times. Minor. |
| concept-b-console.html `#payments`; concept-g-blend.html `#scr-pay` | Conditions and terms in one panel (rule 1) | An editable fee limit beside "the host's payment fee … (signed term)" |
| concept-b-console.html `#host` | Terms editable after opening | "Its terms" on an open lobby links to the editing form. Host-only, not member-reachable. |
| concept-c-power.html, D, F | Rule 23 | "Remove a member before the start" (D), "Remove" buttons (C, F) |
| concept-g-blend.html status strip | Not in the map; near "answering an old state" | The connection chip is a one-tap switch: "Offline by your choice. Nothing can be signed or received". It leaves "Watching: this app" unchanged, which is wrong. |
| concept-c-power.html `#prefs-connections` | Near the two-server rule | "My own node. Nobody outside sees what you ask." beside "The app always compares at least two servers run by different operators". One of the two is false. |
| concept-d-lobby.html `#set-connections` | Near the two-server rule | "Remove" on both servers lets you drop to one |
| concept-a-wallet.html, B, C, E, F, G | Always present | The strip and Pause scroll away (A, B, E, F). C's Preferences dialog covers them. G's chips go stale. |
| All | Dates in both forms; countdown with "at zero" | Many single-form dates, mostly in hosting ("Planned, 19 Nov", "ends 15 Dec 2026"). Many lobby-row countdowns have no outcome at zero. |
| E, G, A, C | Rule 3 (host and signed mark on every term) | Lobby rows and the next factory's terms at the move carry no signed mark (E, F, G). G and F have no fingerprint at the move. |
| concept-g-blend.html `#scr-factory`, `#scr-activity` | Rule 19 (record as it was) | `data-clone="fit-tomato"`: the "frozen" record is a copy of today's live table, still saying "may move". "7f3a…c21e" is used for two different lobbies. |
| concept-e-offers.html Activity | Rule 19 | The Big Pepper entry renders against current conditions |
| A, C, E | Rule 13 | No total amount before automatic joining takes effect (C has no confirmation at all) |
| F | Owner decision 1, wording | "I also host" sits in the top bar, not in the Moments menu. It is outside the mock-up, so this is harmless. |

---

## 4. Safety statements that go beyond the specifications

Three problems appear in all seven concepts.

**1. "The app leaves alone in time" with no condition.** All seven say it, often with "This cannot be switched off". The specification needs the app running (or a watcher) and fee funds the member has (safety-rule C3, section 8). The behaviour is fixed; the outcome is not. Examples:
- A: "The app leaves alone in time, before a factory ends. This cannot be switched off." Also "It still watches, and still answers and leaves in time." (paused)
- B: "on 2 Dec it started leaving alone, so your coins are on chain before the factory ends on 8 Dec." This is also wrong arithmetic: it lands on 8 Dec.
- C: "By then you have moved or left; the app makes sure of that."
- D: "Fixed: the app leaves alone in time, by itself."
- E: "The app always leaves alone in time."
- F: "If nothing else works, the app leaves alone in time." Also "It still watches and still leaves in time."
- G: "the app leaves alone in time. This cannot be switched off."

Suggested wording: "Before the factory ends, the app starts leaving alone by itself. It can only do this while it is running and has coins for fees."

**2. No unfinished round.** No concept shows what happens after my partial signatures went out and no result came back. Several say the opposite:
- A, F: "If a start fails because another member did not answer, the app says so, names nobody, and puts you back in line."
- B `#joined@signing`: "If another member does not answer, the host starts again without them; you need do nothing."
- E `#move`: "Try 1 of 4 did not finish … Nobody is blamed and nothing moved."
- F `#move-waiting`: "Nothing moved. You are still safely in factory 12. You need to do nothing."
- D `#room` (1.1.0): "You and the host are signing the change", then failed: "Nothing was signed and nothing moved."
- B `#room`: "You and the host sign", then "Nothing was signed. You paid nothing."

signing-round sections 7 and 10: once partial signatures are sent, no message moves the member to Aborted, and both outcomes stay live. "Nothing moved" is right only for refusals at the check stage (before nonces). Every concept uses it correctly there.

**3. Left behind or away for days: "nothing is lost".** The member was away four days. Under a timed level, safe absence is under a day, and losing the race is loss, not delay (safety-rule section 8).
- A: "Your money. Nothing was lost. Your 182,400 sats are still yours in factory 12."
- B: "Nothing was lost: your 182,400 sats are still yours in factory 12."
- C: "Nothing is lost. Your 182,400 sats are still yours".
- D: "Your money has not moved. 182,400 sats are still yours in factory 12."
- E: "The group moved on without you. The app is leaving alone. Nothing is lost."
- F: "Your coins are not lost. They are still yours in factory 12".
- G: "Your money is not lost: about 181,200 sats will be on chain by about 7 Dec."

Honest version: "While the app was closed, no old state was published. The app is now leaving alone. It must run during the next 6 days."

**Other statements stronger than the specifications**

| File and place | Exact text | Why |
|---|---|---|
| D `#leave` | "the next step waits until you open the app; nothing is lost by a short delay" | Wrong. Under a timed level a step late can lose the race. |
| C `#factory-leaving` | "If the app is closed, the steps wait for you; the end date does not." | Wrong, same reason |
| F `#leave-days` | "It must be open, or it does so the next time you open it." | Wrong, same reason |
| E `#leaving` | "If the app is closed then, it does so when you next open it." | Wrong, same reason |
| A `#set-connections` | "Your coins are never at risk from them; your privacy is shared." (public servers) | Wrong. A false chain view for about a day loses the race (sections 8, 10). |
| A `#attention`; G home attention | "Your money is safe: you could still leave alone." / "Your money is safe: you can take it out alone." | Too strong. It ignores the race, fees and the chain view. |
| D, G at-risk | "Your money has not moved." (servers disagree) | The app cannot know this when its chain view is in doubt |
| A, C, E attention example | "The app answered … Your 182,400 sats are safe." / "Your sats are safe." | Answering is not winning. Safe only once the newest state is buried. |
| G `#scr-factory` | "The app answers, takes what the rules give you" (host caught cheating) | Implies the member gains. The penalty is a deterrent, not exit value (section 6.6). No concept says a late host forfeits everything. |
| B, C, D, F, G glossary or factory | "Publishing one is cheating; the app answers it." / "The app answers it with the newer state." | Missing "and must get it confirmed within about a day; an older state can win" |
| B, C, D, E, F, G | "You can always leave alone" / "always possible" / "You can always take your money out" | The brief's own wording, but safety-rule section 10 lists fees, relay rules, a lost record and a false chain view. Suggest: "You can leave without the host. It takes days, uses the chain and needs coins for fees." |
| A `#restore`; F `#restore-wait`; C `#wallet-restore`; G restore | "If the host never answers, the app can still leave alone using the backup … It never publishes an old state from a backup." | Self-contradictory. A host can return an old backup (section 10, C12). C adds an end-date payout claim the spec contradicts (section 6.7). |
| B, C `#host-setup` | "The app refuses to start when it sees another copy." | Two devices and snapshots are listed as not protected |
| E, F, G, B | "the 12,000 sats come back by themselves" / "at the latest" | With an uncooperative host, getting them back needs the chain |
| E, G, F first run | "You need no coins to join." / "You put in no funds of your own." | True for joining. But C3 needs coins for fees to win a race. Owner question 6. |
| A `#set-watching`; G home | "open the app at least about once a day" | The spec says under a day. Once a day leaves no margin. |
| E `#instruction` | "A new one for every lobby. Nothing links your factories together." | Moving to the host's next factory links them, and the host sees addresses |
| C `#lobby-refused` | "This was not caused by you, and it does not count against you." | The host can assert blame (signing-round section 9) |

**Correct and worth keeping:**
- "How long you can safely be away depends on the factory; this one: about 1 day unless something watches for you." Tagged open, in all seven.
- G: "if the host published an old state while the app was closed, nobody would answer it in time, and you could lose money."
- B: "you could lose coins."
- D: "Next thing to do: open the app again by 13 Nov (in about 1 day)."
- G and F: "What the app needs: to run now and then during the 6 days."
- A, D, F, G host side: "what a host who is late here loses is not decided" (open).

---

## 5. Best idea from each concept

| Concept | Idea worth keeping | Where |
|---|---|---|
| A | "Not in Settings, on purpose" with "The app decides these alone". It explains in plain text why conditions and terms are not settings, and lists every never-a-setting item. Also the Activity "What 'Signed' keeps on record" panel. | `#settings`, `#activity` |
| B | Automatic joining as a standing permission separate from consent for each join, with a worst-case panel before it starts and a table of every state the status line can show. Plus the "Where the other things live" table. | `#auto`, `#auto-review`, `#settings` |
| C | Activity columns "Who decided" and "Rule that allowed it". Dates that say where they come from ("End block 334,181, less 864 blocks…, less my margin of 144"). | `#activity`, `#factory-dates` |
| D | Rows that do not fit stay listed, greyed, each with its own sentence. A separate "Fits only now" label for a lobby that fits only at the current value. A bottom strip that always gives a state and a reason. | `#lobbies`, `#strip` |
| E | The standing instruction as one live sentence with a history ("What this instruction has done"). The signing screen as a checklist: same fingerprint, frozen values inside limits, tree inside conditions, "Each one is saved before it is sent". | `#instruction`, `#signing` |
| F | The Checks card: one four-line card that is the newcomer's path and later the ten-second health read. A "What the app will do by itself" card on Home, in sentences. | `#home-day`, `#always` |
| G | The live "why" line ("3 of 14 fit. The limit that excludes most is your highest joining fee: 6 lobbies ask more"), recalculated as you type. Previewing the alerts before joining. A "What happens at zero" sentence on every date. Pause and Signet that never scroll away. | `#scr-conditions`, `#scr-join`, `#scr-factory` |

---

## 6. Recommendation

**Base: G.** It scores highest (37). It wins on c, d, h and i. It is the only concept where the always-present controls really stay on screen at both widths. Its live why-line, alert preview and "what happens at zero" sentences meet the most checklist rules. Its main faults are data and state bugs in the mock-up (stale chips, cloned "frozen" records), not layout.

**Take into G:**
1. **From A:** the phone shell. Bottom tabs and the 412 px phone-first frame, which scored best on f. Also the "Not in Settings, on purpose" block in Settings.
2. **From E:** the signing screen as a visible checklist, in place of G's signing card. The standing instruction's history list, under G's Automatic joining.
3. **From C:** "Who decided" and "Rule that allowed it" in Activity. Date provenance on the factory's dates (behind a "Where this date comes from" link, not on the main view).
4. **From D:** greyed non-fitting rows, each with its failing sentence, and the "Fits only now" label in the lobby list.
5. **From F:** the Checks card on Home for a newcomer, and the "What the app will do by itself" card.
6. **From B:** the table of status-line states on the Automatic joining page, and the "Where the other things live" table in Settings.
7. **Fix in G itself:**
   - Make frozen records real snapshots, and give each lobby its own fingerprint.
   - Add a fingerprint and sealed card at the move.
   - Gate the 0.3% receiving-room fee in the host preview.
   - Remove the offline switch from the strip, or make it say that watching stops.
   - Wire the first-run profile choice.
   - Rename one "profile" (see question 2).

**Equally good; the choice is taste:**
- A, B and F (35 each) differ mainly in shell: wallet tabs, console sidebar, or suite sidebar with "More". Any could carry the same content.
- The home layout (one big balance in A, three tiles in G, dashboard in F) is a taste call once "my money" has all three numbers.

**Before any of this,** the section 4 sentences must be rewritten in whichever concept is chosen. They are the same in all seven.

---

## 7. Open questions for the owner

1. **"Fits only now".** D's label for a lobby that fits at the current value but not over the whole range. Do we show such lobbies as fitting when the looser condition is on? What exact words?
2. **Two meanings of "profile".** Lobby profiles (Safety, Standard, Starter, Circle) against G's presets for my conditions (Cautious, Everyday, Wide). Rename one; "preset" or "starting point" for mine.
3. **Do hosting funds share the personal wallet?** Several concepts show 42,000,000 and 48,000 as the same "on chain" balance, or drop one:
   - E's top line switches to 42,000,000 when hosting.
   - G's home ignores the 22,500,000 set aside.
   - C and G show 42M in one place and 48,000 in another.

   One wallet with "set aside" as a third place, or a separate host wallet?
4. **Host tab cost on phones.** A gives Hosting a fifth tab. F pushes Activity into "More" to fit it. G puts it in the header. Is a bottom tab for hosting worth its place for members who never host?
5. **Fewest members: minimum or target?** Six concepts pass Quiet Harbour (minimum 12) for my "at least 20" and then refuse or "do not count" me. Should the fit check compare with the minimum (whole range, consistent with fees) and fail the row? Or show "ready but not counted" as its own fit state?
6. **Must a member hold on-chain coins for fees to join a factory with timed levels?** Safety-rule C3 says the race needs fee funds the member has. Every concept says "you need no coins to join".
7. **When does leaving alone start?** Four concepts land the exit on the end date with no margin. The last move try (1 Dec) collides with the start of leaving. The timeline needs one rule: exit time plus margin, counted back from the earliest host-only timeout, not the end date.
8. **The "open the app by" cadence.** Should the strip's "next date" be the "open the app by" date (about a day) rather than 28 Nov? Is "about once a day" acceptable advice when safe absence is under a day?
9. **The unfinished round.** What does the app say, and what does it do with payments, after it has signed and heard nothing back? This is needed for start, move and (1.1.0) receiving room.
10. **Removing a member before the start.** The map allows it. Checklist rule 23 forbids kicking. Which wins?
11. **An offline switch.** G has one in the strip. Is going offline a choice we offer at all, given it stops watching?
12. **The two payment-fee limits.** Merge them, or name them so they cannot be confused: "host's fee I accept" against "most I pay to route a payment".
13. **The numbers behind each profile.** Rule 4 cannot be met until they are fixed. All concepts tag them open.
14. **A pending payment with an uncooperative host.** Can we promise a return date at all?
15. **Restore when the host never answers.** What may the app do? Every concept that answers this contradicts itself.

---

## 8. What I could not check

- **Interactive states.** I did not click through every one in the browser myself. The browser checks were automatic:
  - every link at 360 px and 1280 px for overflow;
  - whether Pause and the Signet marker stay visible;
  - console errors;
  - 42 screenshots of three screens per concept, light at 360 px and dark at 1280 px.

  The full walk of the sixteen moments was done from markup and script, one review pass per concept. I re-checked these findings myself:
  - E's members-against-target comparison (`l.target>=c.members`);
  - D's "nothing is lost by a short delay";
  - A's "never at risk from them";
  - G's ungated 0.3% and its `data-clone` records;
  - the leaves-in-time and "nothing lost" sentences in all seven, by search.
- **Real devices.** No real phone and no touch. 360 px was emulated in Chromium.
- **Accessibility.** No screen reader or keyboard check.
- **Sources.** I did not re-check the "verified/recalled" tags on borrowed patterns against the research files.
- **Specifications.** Both are unreviewed drafts. My safety verdicts are only as good as those drafts.

**Files I did not remove:**
- My browser session wrote a console log and a page snapshot into `C:\pirq\gazpacho\.playwright-mcp\`. That folder already existed and was untracked.
- `tools/build-ux-viewer.py` appeared as untracked during the review. It is not mine.

---

## Concept H

`docs/ux/concept-h-recommended.html`: G as the base, with the borrowings from A to F named in section 6, and fixes for the findings against G. I reviewed it the same way as the other seven.

- **Markup and script.** One review pass walked all sixteen moments in the markup and script. I re-checked its main findings myself.
- **In a browser.** I served the folder read-only on 127.0.0.1, then stopped the server. I followed all 61 in-file links at 360 px and 1280 px, and took screenshots in light and dark.

Browser results:
- No sideways scrolling.
- No script errors.
- Dark mode works.
- Pause and the Signet marker stay on screen while you scroll each screen, at both widths.

The builder says 33 of 33 checks pass. That is not true in full; the details follow.

### H.1 Scores (same ten criteria, same scale)

| Concept | a | b | c | d | e | f | g | h | i | j | **Total** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | 4 | 4 | 3 | 3 | 4 | 4 | 2 | 3 | 4 | 4 | 35 |
| B | 4 | 4 | 4 | 3 | 4 | 3 | 2 | 4 | 4 | 3 | 35 |
| C | 3 | 3 | 3 | 3 | 4 | 2 | 2 | 4 | 3 | 3 | 30 |
| D | 4 | 4 | 3 | 4 | 4 | 3 | 2 | 3 | 3 | 4 | 34 |
| E | 4 | 3 | 4 | 3 | 4 | 3 | 2 | 3 | 3 | 4 | 33 |
| F | 4 | 4 | 4 | 3 | 4 | 3 | 2 | 3 | 4 | 4 | 35 |
| G | 4 | 4 | 4 | 4 | 4 | 3 | 2 | 4 | 4 | 4 | 37 |
| **H** | 4 | 4 | 4 | 4 | 4 | 3 | **4** | 4 | 4 | **3** | **38** |

H gains two points on honesty (g) and loses one on quality (j). Everything else is level with G. Its lead comes almost entirely from the safety wording.

Evidence, one sentence each:
- a 4: Sealed card against "I accept at most" controls is clean. The routing limit moved to Settings. But the 1.1.0 room screen puts my limit beside a signed term, and Settings has two overlapping tables of where things live.
- b 4: Presets show every number, the whole range is the default, Join comes after the fit check, and "fewest members" is compared with the minimum. But 12 of 14 lobby rows have no Open, including two that fit (Olive Grove, Basil Bay).
- c 4: Two consents, a worst case (6,000 sats), Stop, and a history. But the budget contradicts itself: "1 factory at a time, 3 joins in total" against "Its budget of 1 factory was then used, so it ended".
- d 4: Pause and Signet are sticky, and the risk chip now says "Servers disagree". But the "act now" and "left behind" states still show "Next date: 28 Nov (in 16 days)", and there is no "leaving alone" state in the strip.
- e 4: No role question and a calm hosting start. Home still says "set aside 0 sats" while Hosting holds 22,500,000.
- f 3: Bottom tabs below 860 px. But the sticky block on top (header, strip, up to two alert bars) is tall, strip chips scroll sideways and hide their text, and fit tables have four fixed columns at about 320 px.
- g 4: Almost every sentence now follows decision 5. The few left are listed in H.3.
- h 4: Several factories, a host ladder, a gated 1.1.0, and each lobby's own fingerprint.
- i 4: Clear pay review and pending payment with "If the host does not cooperate, getting it back may need the chain". A refused payment's fix is now a trip to Settings, Wallet.
- j 3: Plain words, but heavier than G. Home repeats itself (the Checks card, the "will do" card and the To-do list carry the same backup and watching items), and a designer's state table sits inside the product.

### H.2 The findings against G

| G finding | In H |
|---|---|
| Two meanings of "profile" | **Fixed.** Mine are now presets (Cautious, Everyday, Wide). |
| Two payment-fee limits on two screens | **Fixed.** Renamed "routing limit" and moved to Settings, Wallet. The Pay review shows it read-only beside the host's term. |
| First-run profile choice not wired | **Fixed.** |
| Join review "Open the app by: about daily", no date | **Fixed.** "Open the app by 13 Nov 14:00 (in 1 day)". |
| No unfinished-signing state | **Fixed.** See H.5. |
| Mock state goes stale | **Partly.** The risk chip is fixed, and Moments links now reset state. Ordinary in-app links still carry a phase: after "Signing", the Home tab still shows "Signing. Keep the app open". The "act now" and "left behind" states still show the 12 Nov strip date. With no factory, the strip still says "If closed, open again within about 1 day". |
| Phone: chip text hidden, three sticky layers | **Not fixed.** |
| Safety overstatements | **Mostly fixed.** The leftovers are in H.3. |
| "Frozen" records were live copies (`data-clone`) | **Fixed.** Saved copies with their own fingerprints. The one remaining clone is the join review, which should be live. |
| Two lobbies shared one fingerprint | **Fixed.** Five distinct fingerprints. |
| Factory 13 at the move: no sealed card or fingerprint | **Fixed.** Sealed card, "e5c4…1f38", "signs the move only for these exact rules". |
| Ungated "Receiving-room fee 0.3%" in the host preview | **Fixed.** |
| One-tap offline switch in the strip | **Partly.** Moved to Watching, with honest text. The strip chip still draws a switch graphic, and Settings still calls it "state and switch in the strip". |
| Editable limit beside a signed term on Pay | **Fixed** on Pay. The 1.1.0 room screen still breaks checklist rule 1. |
| "Sign terms and open the lobby" disabled with no reason | **Fixed.** "Signing is off until the funds are enough…" |
| Host preview shows no ranges | **Not fixed.** "Joining fee 1,000 sats", "Payment fee 0.05%": no range and no base, so it is not what members see. |
| Home ignores host funds | **Not fixed.** "set aside 0 sats" on Home against 22,500,000 in Hosting. |
| "takes what the rules give you" | **Fixed.** "the old state's outputs go to their rightful owners". |
| "You put in no funds of your own" | **Fixed.** Now qualified with fees for leaving alone. |
| "Will join again … from 28 Nov" budget logic | **Partly.** Reworded, but a new contradiction (see c above). |
| Connection chip "green for my own server" never set | **Not fixed.** The script only sets on or off. The About still claims green. |
| "Act now" state mixes 29 Nov and 12 Nov | **Not fixed.** |
| Static lobby-page fit check disagrees with the list after a change | **Not fixed.** After "why nothing fits" (limit 400), the list says "Does not fit" while the join review says "Every row fits". |
| Restore promised leaving from an old backup | **Fixed.** Waits for the host or the chain; the rest is tagged open. |

### H.3 Decisions 5 and 6, read for meaning

Decision 6 items, all met:
- Pause and Signet are fixed on screen.
- Fewest members is compared with the minimum. Quiet Harbour no longer fits; the builder added a filler lobby to keep "3 of 14".
- "Remove from lobby" only before the ready check, and labelled.
- Chain servers cannot be removed below two, and "my own node" still compares with a public server.
- Frozen records are saved copies.
- Each lobby has its own fingerprint.
- Nothing about receiving room outside the preview, including host earnings and Moments links.

One edge on removal: "Force this member's path on chain" in a host's live factory is a removal after the ready check. The spec allows it (H6), but it is not explained.

Sentences still stronger than the specifications:

| Where | Exact text | Why |
|---|---|---|
| `#factory`, "Where this date comes from" for "Open the app by 13 Nov" | "the shortest timed step on my path is 144 blocks (about 1 day), counted from its last check at block 330,437." | The date uses the whole step with no margin. Safety-rule section 7: safe absence is the step "less a margin"; section 8: "under a day". |
| strip, home factory card, join review | "If closed, open again within about 1 day" / "again within about a day each time it is closed" | Same problem. H's own home says it right: "open it again well within a day". Use that everywhere. |
| `#joined` signing | "The app will not close during these seconds" | An app cannot stop being closed. Say "asks before closing". |
| `#joined` unfinished (start) | "If the host publishes the funding transaction, the factory goes live." | C11: live only when the app holds the signed tree and the funding is confirmed to its depth. Without the result the app must not treat it as live. "Old and new state" also fits a start poorly: a new factory has no old state. |
| `#move` left behind (away about 3 days, beyond the safe absence) | "The app was not running at any of the three tries. While it was closed, no old state of factory 12 was published." | Decision 5 wants "Nothing appears to have gone wrong while you were away. Check below." with what was checked. It also does not say how the app started leaving on 1 Dec if it was closed. |
| home, before any factory | "There is nothing to lose today; this becomes urgent when funds arrive." | 48,000 sats are already on chain in this wallet, and the 24 words protect them. |
| home tiers | "Payments are paused by the host … this clears itself." | Nothing promises that. |
| home "my money" | "Needs no one's help." (take out alone) | Drops "needs the app running and coins for fees". The factory page has it. |
| host factory | "From 13 Nov their apps start leaving alone, if they are running" | Drops "and have coins for fees" (minor). |
| backup danger area | "Without your 24 words and a factory backup, the 182,400 sats … would be lost for good." | Ignores the host's copy shown just above (slightly wrong). |
| `#scr-onchain`, Watching | "Without a reserve, leaving alone depends on fees set in advance." | Too weak against C3 (fees decide a race). It also conflicts with the owner's newer answer (H.7). |

Rule breaks that are not safety wording:
- "Required" is used for "Payments are paused by the host … No date given … Nothing to do but wait". The same list says "This style is used only for a required action with a date" (rule 21).
- "Move now" for an action that happens only at the 18:00 try.
- Activity refusals (Big Pepper, Cucumber Lane) lack the next step.
- The cancelled state lost G's "not your doing" (rule 18).
- Dates in one form: "ends 15 Dec 2026", "ends 10 Feb 2027", "to 3 Jan 2027", "my lobby closes 18:00 (in 6 h)" with no outcome at zero.
- Temporary member names (Fig-12, Kale-80, Mint-45) appear in both a lobby and a factory, against "names last for one lobby".

### H.4 Borrowings: as good as the source, or worse

| Borrowing | Verdict |
|---|---|
| A: phone shell | **Worse.** A is phone-first (412 px frame, full-bleed below 440 px, Host as a fifth tab). H is desktop-first with an optional frame, no full-bleed rule, a tall sticky top, and no Hosting tab. |
| A: "Not in Settings, on purpose" | **Wording better** (conditions on what the app does alone). **Placement worse:** it sits under a second table that lists the same things. |
| E: signing as a checklist | **As good.** Nearly verbatim, with the payment-fee freeze added. The strip next to it says "37 other members" for a 50-member tree. |
| E: standing-instruction history | **Worse.** It contradicts H's budget, and "Each entry links to the full record in Activity" is false: the entries are not links. |
| C: "Who decided" / "Rule that allowed it" | **As good.** Collapses well on phones. |
| C: "Where this date comes from" | **As good or better.** Real block arithmetic on each date. It also exposes the no-margin "open by" date. |
| D: greyed rows, each with a sentence | **About as good.** Every failing sentence joined, but the rows lack Open links. |
| D: "Fits only now" | **Worse.** It shows only after switching to "the current value". Then it is counted in the fit total ("4 of 14") and sorted among the fits. The owner's answer is to list it with the lobbies that do not fit. |
| F: Checks card | **Worse.** In F it replaced the to-do list; in H it repeats it. It says "This factory: safe away about 1 day" when there is no factory. |
| F: "What the app will do by itself" | **Wording better** (conditional). **Bulkier:** 7 items against 3, one of which ("Sign nothing new while paused") is not done by itself. |
| B: table of automatic-joining states | **As good as B**, but it is still designer documentation inside a product screen. |
| B: "Where the other things live" | **Worse.** B had one table; H has two overlapping ones. |

### H.5 The "Signing did not finish" state

- **Reachable** from the Moments menu and from the lobby's state control (start), and on the move screen (a move try). It is shown in the strip and in Activity. The 1.1.0 room flow says when it would turn into this state.
- **Honest, and consistent with signing-round section 10:**
  - It says the app sent its signatures and no result came back.
  - It "treats both the old and the new state as possible and keeps watching both until it is settled".
  - Payments in factory 12 pause until it is settled. Section 10 allows either keeping both current or stopping use of the channel.
  - The next move try is offered only "if it settles as not moved", which fits rule C10 (one open round per output).
  - It names what the app checked: last heard from the host 14:00:04, chain checked up to block 330,449.
  - It states that "nothing was signed" applies only before signatures go out.
  - It never says "nothing moved" after signing.
- **Two faults:** the start version's "If the host publishes the funding transaction, the factory goes live" (see H.3), and old/new-state wording on a start, where there is no old state.
- **New open question:** what the app does if the last move try (30 Nov 18:00) is unfinished when leaving alone must start (1 Dec 12:00). Nothing in H covers that collision.

### H.6 Leaving alone and "where this date comes from"

The arithmetic is right:
- End block 334,180, less 864 blocks (6 days) that leaving alone takes, less a 144-block margin, gives block 333,172.
- Block 333,172 is 2,735 blocks after today's 330,437: about 19 days, so about 1 Dec 12:00.
- Leaving alone then finishes about 7 Dec, a day before the 8 Dec end.

The other factories are consistent too:
- The daily lobby: tries 5 to 7 Dec, leave from 8 Dec, done 14 Dec, ends 15 Dec.
- The host's factory 3: leave from 13 Nov, done 19 Nov, ends 20 Nov.

Two cautions:
- The 864 blocks are the timelocks. Safety-rule section 7 also adds a confirmation allowance for each transaction (its "largest unknown"). The one-day margin is all that covers it, and the text should say so.
- The deadline in C5 is the earliest moment anyone else gains a claim on the path. For this factory that is the end date, but the provenance should name it that way.

The only wrong date is the "open the app by" date (H.3).

### H.7 To-do: where H predates the owner's answers in decisions.md section 6

These are not counted against H's score.

1. **On-chain reserve.** The owner's answer is no reserve required or recommended in 1.0.0. H recommends one in several places:
   - `#scr-onchain`: "Fee reserve recommended: 20,000" and "Sending more than 28,000 would take you below the fee reserve".
   - Home tiers: "Fee reserve is low … Recommended: 20,000".
   - Watching: "Recommended 20,000 (a placeholder figure)".

   Remove these, and add a "speed up a stuck transaction" action (pay-to-anchor). The wording "if it is running and has coins for fees", required by decision 5, now needs rethinking: with no reserve, what does the member have when a race starts? **Owner question:** safety-rule C3 still requires fee funds for a race under a timed level. The no-reserve answer and C3 must be reconciled before the wording can be final.
2. **Hosting on phones.** The answer is a Hosting tab always, with "header until you host" offered as a setting. H puts Hosting in the header on phones and calls the question still open. Add the tab, add the setting under Settings, Application, and leave the comparison to testers.
3. **Payout destinations.** The 1.0.0 answer is one wallet, with coins coming back to it and an amount set aside for hosting. H says "Whether hosting funds share one wallet … is not decided" (Hosting home, write-terms screen), and its Home shows set aside 0. Then:
   - Add a 1.1.0-tagged choice of a fresh derived address per factory.
   - Add a 1.1.0-or-later outside-wallet payout, proven before use, fixed before the factory forms.
   - Both belong in the join review and the conditions, behind the preview.
4. **"Fits only now".** List it with the lobbies that do not fit, one tap showing the numbers, and leave it out of the fit count.
5. **Coverage (decisions.md section 5, 1.1.0).** A "covered" figure under "my money" and a warning tier, in the 1.1.0 preview only. H has neither.

### H.8 What H made worse than G

- Home is longer and repeats itself (Checks, the "will do" card and To-do).
- Settings has two overlapping tables of where things live.
- Fixing a refused payment now means a trip to Settings ("raise your limit below" before).
- G's ordinary failed move try ("44 of 50 signed … next try 29 Nov") is gone; only the unfinished case is left.
- The cancelled state lost "not your doing"; Activity refusals lost "Nothing to do".
- The phone shell is weaker than A's, which it was meant to adopt.
- Sentences are heavier throughout. The decision-5 conditions are right, but they are repeated in full in many places. Say them once per screen and link.

### H.9 Verdict

H is the best of the eight, mostly because its safety wording is now close to the specifications and the unfinished-signing state is honest. It is not ready as-is. Before the next round:
1. Fix the "open the app by" margin.
2. Fix the remaining sentences in H.3.
3. Apply the five to-dos in H.7.
4. Rebuild the phone shell from A.
5. Cut the repetition on Home and in Settings.

### H.10 What I could not check

- I did not click through every interactive state by hand. The browser checks covered every link, overflow, the sticky controls, console errors and ten screenshots. The full moment walk was from markup and script, and I re-checked its main findings.
- No real phone, touch, screen reader or keyboard check.
- I did not verify the builder's own "33 of 33" check script; it was not in the repository.
- The safety verdicts rest on the unreviewed spec drafts.
- My browser session added one more console log to `C:\pirq\gazpacho\.playwright-mcp\`. I left it there.
