# Browser checks for the local API (spec/local-api.md 23.6)

TEST ONLY. These Playwright tests drive real browsers against `gz-api-fake`
(the fake backend, not a wallet). They cover what can be checked before the
interface (stream S10) exists:

| Test | Spec item |
|---|---|
| sessionStorage per origin, port included | 23.6 T1, 23.2 item 4 |
| BroadcastChannel does not cross ports | T2 |
| another port cannot call the API, even adding the header | 23.2 items 3, 4, 12 |
| no image and no frame from another origin | items 11, 14 |
| EventSource cannot authenticate | item 12 |
| the page's own `fetch()` passes the Origin check; Clear-Site-Data recorded | item 36, T4 |
| first run from the redirect file: served while no wallet exists, the token once | T5, item 37 |

Not here, because they need the interface or a desktop: T3 (SharedWorker
under `require-corp`), T6 (snap and Flatpak browsers, `/proc/*/cmdline`
polled by a second user), T7 (session restore), T8 (password managers), T9
(clipboard), T10 (Safari's fetch metadata), T11 (Local Network Access prompt),
T12 (other kernels and the SSH tunnel's account; `tests/api/test_peer.c`
covers the build server as root), T13 (back/forward cache with the words
screen).

Run on a server or in CI, never on a workstation holding a wallet:

    cd tests/api/browser
    npm install --no-save @playwright/test@1.49.1
    npx playwright install chromium
    GZ_API_FAKE=/path/to/build/gz-api-fake npx playwright test
    GZ_BROWSERS=chromium,firefox,webkit ...     # where those engines install
