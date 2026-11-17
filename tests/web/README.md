# The interface in a browser

TEST ONLY. These Playwright tests drive the interface (`web/`) in a real browser against `gz-api-fake`, the API server with the fake backend, which is not a wallet. They are the Slice 1 walkthrough of `spec/local-api.md` 23.1 item 1 as far as it can run before the program is wired to the API (P6): every flow goes through the real HTTP server, its browser checks, its sessions and its event stream; only the wallet behind it is pretend.

| File | What it covers |
|---|---|
| `first-run.spec.mjs` | The start link and its token; create a wallet with the six suggested words; the 24 words (shown on request, hidden with the tab, gone after Done, after leaving and on `pagehide`); the backup check and a failed check; restore, a wrong word, a weak passphrase; no start link; the hijack warning |
| `signin.spec.mjs` | A wrong passphrase and the delay; sign-out against lock; lock during a call; idle sign-out with events flowing; a fresh sign-in on demand; a second tab |
| `flows.spec.mjs` | Add a host by address; terms and fit; join; the waiting view; the signing moment; a refusal at the app's own check; signing that did not finish; funding; the live factory; conditions (tighten, loosen); several lobbies; pause; host a lobby (preview, open with the passphrase, seats, removal, a member seen to leave at its check, early start, funding by itself, live); cancel; node busy; the chain view in doubt; the event stream dropping and resuming; the program not answering |
| `signing.spec.mjs` | Draft 5: the passphrase with a ready under `at_join`, a locked seat after a restart and "Mark ready in all", the signing setting saved for the next start, Slice 1 accountability, the host's locked seats, a junk start token |
| `tabs.spec.mjs` | Three tabs on one session: the third, over the stream cap, follows relayed events and takes over when a streaming tab closes, or after 30 s when the streaming tabs crash during the signing moment |
| `quality.spec.mjs` | The headers the files are served with; no request to any other host; mainnet refused; unknown states; keyboard; labels; phone width; contrast in light and dark |
| `helpers.mjs` | Starts `gz-api-fake --story` and sends it the story's lines; a forwarder that plays a failing tunnel; the page fixture |
| `check_static.py` | Not a browser test: the static rules for the files in `web/` (CTest `web_static_check`) |

Every test's page is watched by the fixture in `helpers.mjs`: each request must go to the local API's own origin, no address may carry a fragment, a secret-looking query or a 64-hex segment, and the page must raise no script error and no content-security-policy report.

The fake's story is driven over its standard input (`tools/gz-api-fake/main.c`): `step` moves the lobbies on by one stage; the other lines are listed at `gz_fake_cmd` in `ports/api/fake/fake_backend.h`.

Run on a server or in CI, never on a workstation holding a wallet:

    cmake -B build && cmake --build build --target gz-api-fake
    cd tests/web
    npm ci
    npx playwright install chromium
    GZ_API_FAKE=$PWD/../../build/ports/api/gz-api-fake npx playwright test
    GZ_BROWSERS=chromium,firefox,webkit ...     # where those engines install

To click through the screens yourself against the fake, with the story moving on by itself every three seconds:

    ./build/ports/api/gz-api-fake --data-dir ./gz-demo-data --story --auto-ms 3000

and open the file it names. The sign-in passphrase of a `--locked` run is the fixture in `ports/api/fake/fake_backend.h`.
