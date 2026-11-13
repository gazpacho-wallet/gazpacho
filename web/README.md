# Gazpacho screens (prototype)

The screens of Gazpacho's local web interface, running on fake data. Open `index.html` in a browser, straight from disk; nothing needs to be built, installed or served, and no request leaves this folder.

This is a prototype. No keys, no network and no coins are involved, and none of the safety checks the screens describe exist behind it yet. The screens say so on every page.

## How the files are organised

| File | What it holds |
|---|---|
| `index.html` | The frame: prototype line, header, navigation, the place a screen is drawn, and the script tags in load order |
| `css/gazpacho.css` | The one stylesheet. Colours follow `docs/design.html`; light and dark themes are CSS variables |
| `js/util.js` | Helpers with no knowledge of the wallet: building DOM nodes, formatting sats, blocks and times |
| `js/api-mock.js` | The pretend program. Defines `window.gzApi`, and `window.gzMockDemo` for the demo panel |
| `js/ui.js` | Shared pieces: notices, pills, numbers with explanations, form fields, countdowns, the confirmation dialog, toasts |
| `js/tree.js` | The factory tree as an SVG picture and as words |
| `js/screens/*.js` | One file per screen. Each registers itself in `gz.screens` |
| `js/demo.js` | The demo controls panel (prototype only) |
| `js/app.js` | Start-up, the hash router, the frame, live redraws |
| `API.md` | The calls the screens make: a proposal for the real local API |
| `tests/check_screens.py` | Opens every screen in every demo state and checks it |

Scripts are plain `<script>` tags that share one global, `window.gz`. There are no ES module imports, because those fail from a `file://` address in some browsers.

## Rules the code keeps

- **Screens use only `window.gzApi`.** They never reach into the mock. Every call returns a Promise.
- **The program decides, the screens show.** Whether a lobby meets the member's conditions, which date is most urgent, whether an invoice can be paid: the API answers with codes and numbers, and the screens hold the wording.
- **Text is inserted as text.** DOM nodes are built with `gz.util.h`; nothing is assigned to `innerHTML`. Names and descriptions come from other people.
- **No inline script or style**, so the real server can send a strict content security policy.
- **A countdown always says what happens at zero** (`gz.ui.countdown` takes the sentence as a required argument).
- **A control that does nothing says so**: `gz.ui.notInPrototype("…")`.

## A screen

```js
gz.screens.wallet = {
  title: "Wallet (on chain)",            // browser tab title
  topics: ["wallet", "chain"],           // live-update topics that redraw it
  render: function (params, status) {    // returns a Promise of a DOM node
    return gzApi.getWallet().then(function (wallet) { /* build and return a node */ });
  }
};
```

The router draws a "Loading…" line if `render` is slow, and an error panel with a "Try again" button if it rejects. On a live update it redraws the screen and puts back focus, scroll position and anything typed but not yet saved.

Routes: `#/home`, `#/lobbies`, `#/lobby/<id>`, `#/conditions`, `#/factory`, `#/pay`, `#/host`, `#/wallet`, `#/settings`, `#/first-run`.

## The mock and the demo controls

`api-mock.js` keeps a small pretend world and moves it once a second: lobbies fill, a full lobby goes through the ready check, signing and funding, blocks arrive, exits advance, payments settle. Its chain makes a block every 30 seconds instead of every ten minutes.

The "Demo controls" button (bottom right) jumps between situations, mines blocks, pauses the clock, and makes the program stop answering or answer slowly. A situation can also be chosen in the address: `index.html?state=factory-live#/factory`. The situations are `first-run`, `empty`, `in-lobby`, `lobby-starting`, `conditions-not-met`, `factory-live`, `winding-down`, `host-gone`, `exiting`, `servers-disagree`, `hosting-lobby`, `hosting-factory`.

Numbers in the mock that the design has not settled (tree shapes, fees, the length of the winding-down period) are invented and marked as such in the code.

## Replacing the mock with the real program

1. Write `js/api-client.js` defining `window.gzApi` with the same functions as `API.md`, each making a request to the local program and returning a Promise of the decoded JSON. `subscribe` opens the event stream.
2. In `index.html`, load it in place of `api-mock.js` and remove `demo.js`. `app.js` skips the demo panel when it is absent.
3. Remove the prototype line from `index.html`, the "(prototype only)" example buttons, and each `notInPrototype` control as its feature arrives.

No screen file should need to change for step 1 or 2. If one does, the API proposal was wrong and `API.md` should be corrected with it.

## Checking

```
pip install playwright && playwright install chromium
python3 web/tests/check_screens.py --shots /tmp/shots --axe path/to/axe.min.js
```

The script opens every screen in every situation at 360, 768 and 1280 pixels wide, in light and dark, from a `file://` address. It fails on a console error, a failed request, a request outside this folder, sideways scrolling, a control the Tab key cannot reach, or an axe-core violation (when `--axe` is given), and then clicks through a few journeys. It is not wired into the CI workflow yet.
