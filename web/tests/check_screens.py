#!/usr/bin/env python3
"""Open every screen of the Gazpacho prototype in every demo state and check it.

For each demo state, screen, width (360, 768, 1280) and theme (light, dark):
  - the screen draws, with no console errors and no uncaught exceptions;
  - no request fails, and no request leaves the web/ folder;
  - the page does not scroll sideways.
At one width per state and screen:
  - every visible control can be reached with the Tab key;
  - if axe-core is given, it reports no accessibility violations.
Then a few journeys click through the mock to check that it moves.

Needs Python 3 and Playwright with Chromium:
    pip install playwright && playwright install chromium
Run:
    python3 web/tests/check_screens.py [--shots DIR] [--axe path/to/axe.min.js] [--quick] [--only PART]

Exit status is 0 when everything passed, 1 otherwise.
"""

import argparse
import pathlib
import sys

from playwright.sync_api import sync_playwright

WEB = pathlib.Path(__file__).resolve().parent.parent
INDEX = (WEB / "index.html").as_uri()
ALLOWED_PREFIX = WEB.as_uri()

STATES = [
    "first-run", "empty", "in-lobby", "lobby-starting", "conditions-not-met", "factory-live",
    "winding-down", "host-gone", "exiting", "servers-disagree", "hosting-lobby", "hosting-factory",
]
ROUTES = [
    "home", "lobbies", "lobby/lobby-tomato", "lobby/lobby-quiet", "conditions", "factory",
    "pay", "host", "wallet", "settings", "first-run",
]
WIDTHS = [360, 768, 1280]
THEMES = ["light", "dark"]

READY = "document.querySelector('#view') && !document.querySelector('#view').hasAttribute('aria-busy') && document.querySelector('#view').children.length > 0"

# Lists every visible control, presses Tab until focus comes back round, and
# returns the controls focus never landed on. Radio buttons count as a group.
KEYBOARD_JS = """
async () => {
  const visible = el => el.getClientRects().length > 0 && el.checkVisibility({ visibilityProperty: true, contentVisibilityAuto: true });
  const all = [...document.querySelectorAll('a[href], button, input, select, textarea, summary, [tabindex]')]
    .filter(el => !el.disabled && el.getAttribute('tabindex') !== '-1' && visible(el) && !el.closest('dialog:not([open])'));
  const key = el => el.type === 'radio' ? 'radio:' + el.name : null;
  const seen = new Set();
  const groups = new Set();
  return { count: all.length, mark: (window.__kb = { all, seen, groups, key }) && true };
}
"""
KEYBOARD_STEP_JS = """
() => {
  const kb = window.__kb, el = document.activeElement;
  if (el && el !== document.body) { kb.seen.add(el); if (kb.key(el)) kb.groups.add(kb.key(el)); }
}
"""
KEYBOARD_RESULT_JS = """
() => {
  const kb = window.__kb;
  return kb.all.filter(el => !kb.seen.has(el) && !(kb.key(el) && kb.groups.has(kb.key(el))))
    .map(el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + ' "' + (el.textContent || el.value || '').trim().slice(0, 40) + '"');
}
"""

AXE_JS = """
async () => {
  const result = await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] } });
  return result.violations.map(v => v.id + ': ' + v.help + ' [' + v.nodes.slice(0, 3).map(n => n.target.join(' ')).join(' | ') + ']' + (v.nodes.length > 3 ? ' and ' + (v.nodes.length - 3) + ' more' : ''));
}
"""


class Checker:
    def __init__(self, args):
        self.args = args
        self.failures = []
        self.checks = 0
        self.problems = []   # console errors and bad requests for the page being checked

    def fail(self, where, what):
        self.failures.append(f"{where}: {what}")
        print(f"  FAIL {where}: {what}")

    def watch(self, page):
        page.on("console", lambda m: self.problems.append("console " + m.type + ": " + m.text) if m.type in ("error", "warning") else None)
        page.on("pageerror", lambda e: self.problems.append("uncaught: " + str(e)))
        page.on("requestfailed", lambda r: self.problems.append("request failed: " + r.url))
        page.on("request", lambda r: self.problems.append("request outside web/: " + r.url)
                if not r.url.startswith(ALLOWED_PREFIX) else None)

    def open(self, page, state, route):
        page.goto("about:blank")
        self.problems.clear()
        page.goto(f"{INDEX}?state={state}#/{route}")
        page.wait_for_function(READY, timeout=10000)
        page.evaluate("window.gzMockDemo.setPaused(true)")
        page.wait_for_timeout(120)
        page.wait_for_function(READY, timeout=10000)

    def basics(self, page, where):
        self.checks += 1
        for problem in self.problems:
            self.fail(where, problem)
        overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
        if overflow > 0:
            widest = page.evaluate("""() => { let worst = null, max = innerWidth;
                for (const el of document.querySelectorAll('body *')) { const r = el.getBoundingClientRect();
                  if (r.right > max + 0.5 && getComputedStyle(el).position !== 'fixed') { max = r.right; worst = el; } }
                return worst ? worst.tagName + '.' + worst.className + ' "' + worst.textContent.slice(0, 40) + '"' : 'unknown'; }""")
            self.fail(where, f"scrolls sideways by {overflow}px; widest element: {widest}")
        if not page.evaluate("!!document.querySelector('#view h1')"):
            self.fail(where, "no main heading was drawn")

    def shot(self, page, name):
        if self.args.shots:
            page.screenshot(path=str(pathlib.Path(self.args.shots) / (name + ".png")), full_page=True)

    def keyboard(self, page, where):
        self.checks += 1
        info = page.evaluate(KEYBOARD_JS)
        page.evaluate("document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0)")
        for _ in range(info["count"] + 12):
            page.keyboard.press("Tab")
            page.evaluate(KEYBOARD_STEP_JS)
        for missed in page.evaluate(KEYBOARD_RESULT_JS):
            self.fail(where, "not reachable with Tab: " + missed)

    def axe(self, page, where):
        if not self.args.axe:
            return
        self.checks += 1
        page.add_script_tag(path=self.args.axe)
        for violation in page.evaluate(AXE_JS):
            self.fail(where, "axe: " + violation)

    # ----- every screen in every state -----

    def sweep(self, browser):
        widths = [360, 1280] if self.args.quick else WIDTHS
        for width in widths:
            for theme in THEMES:
                context = browser.new_context(viewport={"width": width, "height": 800}, color_scheme=theme)
                page = context.new_page()
                self.watch(page)
                for state in STATES:
                    routes = ["first-run"] if state == "first-run" else ROUTES
                    for route in routes:
                        where = f"{state} /{route} {width}px {theme}"
                        try:
                            self.open(page, state, route)
                            self.basics(page, where)
                            self.shot(page, f"{state}__{route.replace('/', '-')}__{width}__{theme}")
                            if (width == 1280 and theme == "light") or (width == 360 and theme == "dark"):
                                self.axe(page, where)
                            if width == 1280 and theme == "light":
                                self.keyboard(page, where)
                        except Exception as error:  # a timeout or a crash is a failure of that screen
                            self.fail(where, "could not be checked: " + str(error).splitlines()[0])
                context.close()
                print(f"swept {width}px {theme}: {len(self.failures)} failures so far")

    # ----- states that need a click to reach -----

    def extras(self, browser):
        for width in ([360, 1280] if self.args.quick else WIDTHS):
            for theme in THEMES:
                context = browser.new_context(viewport={"width": width, "height": 800}, color_scheme=theme)
                page = context.new_page()
                self.watch(page)
                tag = f"{width}__{theme}"
                check_axe = (width == 1280 and theme == "light") or (width == 360 and theme == "dark")

                def step(name, state, route, action):
                    where = f"extra {name} {width}px {theme}"
                    try:
                        self.open(page, state, route)
                        action()
                        page.wait_for_timeout(350)
                        self.basics(page, where)
                        self.shot(page, f"extra__{name}__{tag}")
                        if check_axe:
                            self.axe(page, where)
                    except Exception as error:
                        self.fail(where, "could not be checked: " + str(error).splitlines()[0])

                step("program-not-answering", "factory-live", "home", lambda: page.evaluate("window.gzMockDemo.setFailing(true)"))
                step("leave-alone-dialog", "factory-live", "factory", lambda: page.get_by_role("button", name="Leave this factory alone").click())
                step("join-dialog", "empty", "lobby/lobby-tomato", lambda: page.get_by_role("button", name="Join this lobby").click())
                step("stat-explanation-open", "factory-live", "factory", lambda: page.get_by_role("button", name="What “Leaving alone would take” means").click())
                step("send-review", "factory-live", "pay", lambda: (
                    page.get_by_role("button", name="Fill in an example (prototype only)").click(),
                    page.get_by_role("button", name="Check this invoice").click()))
                step("send-refused", "factory-live", "pay", lambda: (
                    page.get_by_role("button", name="Fill in one that is too large (prototype only)").click(),
                    page.get_by_role("button", name="Check this invoice").click()))
                step("receive-invoice", "factory-live", "pay", lambda: (
                    page.get_by_label("Amount", exact=True).fill("12000"),
                    page.get_by_role("button", name="Create invoice").click()))
                step("lobbies-filter-empty", "empty", "lobbies", lambda: (
                    page.get_by_label("Only lobbies within my conditions").check(),
                    page.get_by_label("Profile").select_option("safety")))
                step("first-run-phrase", "first-run", "first-run", lambda: page.get_by_role("button", name="Create a wallet").click())
                step("first-run-restore", "first-run", "first-run", lambda: page.get_by_role("button", name="Restore a wallet").click())
                step("host-mode-off", "empty", "host", lambda: None)
                step("host-create-form", "empty", "host", lambda: page.get_by_role("button", name="Turn on host mode").click())
                step("menu-open", "factory-live", "home", lambda: page.get_by_role("button", name="Menu").click() if width < 900 else None)
                # Last, because the panel stays open for the rest of the browser session.
                step("demo-controls-open", "factory-live", "home", lambda: page.get_by_role("button", name="Demo controls").click())
                context.close()

    # ----- journeys: the mock is alive -----

    def journeys(self, browser):
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()
        self.watch(page)
        self.problems.clear()

        def journey(name, work):
            self.checks += 1
            try:
                work()
                for problem in self.problems:
                    self.fail("journey " + name, problem)
            except Exception as error:
                self.fail("journey " + name, " / ".join(str(error).splitlines()[:3]) or type(error).__name__)
                self.shot(page, "journey-failed__" + name.replace(" ", "-").replace(",", ""))
            self.problems.clear()

        def fresh(state, route):
            page.goto("about:blank")
            page.goto(f"{INDEX}?state={state}#/{route}")

        def first_run():
            fresh("first-run", "first-run")
            page.get_by_role("button", name="Create a wallet").click()
            page.get_by_text("example").first.wait_for()
            assert page.locator(".phrase li").count() == 12
            assert page.get_by_role("button", name="Continue").is_disabled()
            page.get_by_label("I have written these words down").check()
            page.get_by_role("button", name="Continue").click()
            page.get_by_role("button", name="Finish").click()
            page.get_by_role("heading", name="Home").wait_for()

        def lobby_to_factory():
            fresh("lobby-starting", "lobby/lobby-tomato")
            page.get_by_text("You are in and ready.").wait_for()
            page.get_by_text("Signing now. Keep the app open.").wait_for(timeout=40000)
            page.get_by_text("Everyone has signed.").wait_for(timeout=30000)
            page.evaluate("window.gzMockDemo.mine(2)")
            page.get_by_text("The factory is live.").wait_for()
            page.get_by_role("link", name="Go to the factory").click()
            page.get_by_text("The tree, with your path").wait_for()

        def refuse_and_join():
            fresh("empty", "lobby/lobby-quiet")
            page.get_by_text("The app will not join this lobby.").wait_for()
            assert page.get_by_role("button", name="Join this lobby").is_disabled()
            fresh("empty", "lobby/lobby-tomato")
            page.get_by_role("button", name="Join this lobby").click()
            page.get_by_role("button", name="Join and lock my conditions").click()
            page.get_by_text("You are in and ready.").wait_for()
            fresh("in-lobby", "conditions")
            page.get_by_text("Your conditions are locked in.").wait_for()

        def leave_alone():
            fresh("factory-live", "factory")
            page.get_by_role("button", name="Leave this factory alone").click()
            confirm = page.get_by_role("button", name="Publish and leave")
            assert confirm.is_disabled()
            page.get_by_label("I understand this closes my channel").check()
            confirm.click()
            page.get_by_text("You are leaving this factory alone.").wait_for()
            page.evaluate("window.gzMockDemo.mine(900)")
            page.get_by_text("You have left the factory.").wait_for()

        def pay_and_receive():
            fresh("factory-live", "pay")
            page.get_by_role("button", name="Fill in an example (prototype only)").click()
            page.get_by_role("button", name="Check this invoice").click()
            page.get_by_role("button", name="Pay 2,500 sats").click()
            page.get_by_text("On its way").wait_for()
            page.get_by_text("On its way").wait_for(state="detached", timeout=15000)
            page.get_by_label("Amount", exact=True).fill("5000")
            page.get_by_role("button", name="Create invoice").click()
            page.get_by_text("Waiting to be paid.").wait_for()
            page.get_by_text("Paid.", exact=True).wait_for(timeout=20000)

        def host_a_lobby():
            fresh("hosting-lobby", "host")
            page.get_by_role("button", name="Cancel this lobby").click()
            page.get_by_role("button", name="Cancel the lobby").click()
            page.get_by_label("Lobby name").fill("Test lobby")
            page.get_by_label("Target", exact=True).fill("6")
            page.get_by_label("Minimum", exact=True).fill("3")
            page.get_by_role("button", name="Open this lobby").click()
            page.get_by_role("dialog").get_by_role("button", name="Open the lobby").click()
            page.get_by_role("heading", name="Your lobby: Test lobby").wait_for()
            page.get_by_text("You have funded the factory.").wait_for(timeout=60000)
            page.evaluate("window.gzMockDemo.mine(2)")
            page.get_by_role("heading", name="Your factory: Test lobby, factory 1").wait_for()

        def rotation():
            fresh("winding-down", "factory")
            page.get_by_role("button", name="Move to the next factory").click()
            page.get_by_role("button", name="Sign and move").click()
            page.get_by_role("heading", name="Tomato Garden, factory 13").wait_for(timeout=20000)

        def theme_toggle():
            fresh("factory-live", "home")
            page.get_by_role("button", name="Theme: system").click()
            page.get_by_role("button", name="Theme: light").click()
            assert page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"

        journey("first run", first_run)
        journey("lobby fills, signs, funds, confirms", lobby_to_factory)
        journey("refusal, join, locked conditions", refuse_and_join)
        journey("leave alone to the end", leave_alone)
        journey("pay and receive", pay_and_receive)
        journey("host opens a lobby and funds", host_a_lobby)
        journey("rotation", rotation)
        journey("theme toggle", theme_toggle)
        context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shots", help="folder to save a screenshot of every screen in")
    parser.add_argument("--axe", help="path to axe.min.js, to run accessibility checks")
    parser.add_argument("--quick", action="store_true", help="only 360 and 1280 pixels wide")
    parser.add_argument("--only", choices=["sweep", "extras", "journeys"], help="run one part of the checks")
    args = parser.parse_args()
    if args.shots:
        pathlib.Path(args.shots).mkdir(parents=True, exist_ok=True)

    checker = Checker(args)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for part in ("sweep", "extras", "journeys"):
            if args.only in (None, part):
                getattr(checker, part)(browser)
        browser.close()

    print(f"\n{checker.checks} checks, {len(checker.failures)} failures")
    for failure in checker.failures:
        print("  " + failure)
    return 1 if checker.failures else 0


if __name__ == "__main__":
    sys.exit(main())
