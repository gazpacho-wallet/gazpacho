#!/usr/bin/env python3
"""Fill the expandable sections and the hidden context block of docs/design.html.

The page's visible text and diagrams are written by hand. Between marker comments
such as <!--gz:safety--> and <!--/gz:safety--> this script inserts collapsed
<details> blocks rendered from the Markdown documents, so the page can carry the
full detail without drifting from its sources. Run it after editing any source:

    python tools/build-design-page.py

Requires the "markdown" package.
"""
import io, json, os, re, sys, datetime
import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(ROOT, "docs", "design.html")

def read(rel):
    return io.open(os.path.join(ROOT, rel), encoding="utf-8").read()

def section(rel, heading):
    """Body of one heading in a Markdown file, up to the next heading of the same or a higher level."""
    lines = read(rel).split("\n")
    if heading == "*":            # whole file without its title line
        body = lines[1:] if lines and lines[0].startswith("# ") else lines
        return "\n".join(body).strip()
    if heading == "^":            # from after the title to the first second-level heading
        out = []
        for ln in lines[1:]:
            if ln.startswith("## "): break
            out.append(ln)
        return "\n".join(out).strip()
    level = len(heading) - len(heading.lstrip("#"))
    try:
        i = lines.index(heading)
    except ValueError:
        sys.exit("heading not found in %s: %s" % (rel, heading))
    out = []
    for ln in lines[i + 1:]:
        m = re.match(r"^(#+) ", ln)
        if m and len(m.group(1)) <= level: break
        out.append(ln)
    return "\n".join(out).strip()

def render(md):
    html = markdown.markdown(md, extensions=["tables", "fenced_code"])
    return html.replace("<table>", '<div class="tw"><table>').replace("</table>", "</table></div>")

def details(title, source_note, md):
    return ('<details class="more"><summary>%s</summary><div class="more-body">%s'
            '<p class="src">From <code>%s</code></p></div></details>') % (title, render(md), source_note)

# key -> list of (summary shown on the page, file, heading)
BLOCKS = {
 "status": [
  ("What the trial run of the reference code found", "docs/KNOWLEDGE-BASE.md", "## 4. What the reference code does today"),
 ],
 "source": [
  ("Where the code comes from, in full", "docs/DESIGN.md", "## 2. Where the code comes from"),
 ],
 "signing": [
  ("The six messages of a signing round", "spec/signing-round.md", "## 3. Messages"),
  ("The steps, one by one", "spec/signing-round.md", "## 4. Steps"),
  ("Rules for the one-time signing secrets", "spec/signing-round.md", "## 6. Rules for secret nonces"),
  ("Proving who broke a round", "spec/signing-round.md", "## 7. Who broke the round"),
  ("Never left half-finished", "spec/signing-round.md", "## 8. Never left half-finished"),
  ("Open points on the signing round", "spec/signing-round.md", "## 12. Open points"),
 ],
 "safety": [
  ("The nine checks a member's software runs", "spec/safety-rule.md", "## 3. The checks"),
  ("What the member is owed, operation by operation", "spec/safety-rule.md", "## 4. What the member is owed"),
  ("How exit value and exit time are worked out", "spec/safety-rule.md", "## 5. Exit value"),
  ("The host's side", "spec/safety-rule.md", "## 7. The host's side"),
  ("What the rule does not protect against", "spec/safety-rule.md", "## 8. What this rule does not protect against"),
  ("Open points on the safety rule", "spec/safety-rule.md", "## 10. Open points"),
 ],
 "factory": [
  ("How SuperScalar is meant to work", "docs/KNOWLEDGE-BASE.md", "## 3. How SuperScalar is meant to work"),
  ("Every decision about the factory", "docs/DESIGN.md", "## 7. The factory"),
 ],
 "storage": [
  ("Storage and backup", "docs/DESIGN.md", "## 9. Storage and backup"),
 ],
 "lobby": [
  ("Stages, timing and the start rule in full", "docs/LOBBY.md", "## Stages"),
  ("What protects a member in a lobby", "docs/LOBBY.md", "## What protects a member"),
  ("Dealing with troublemakers", "docs/LOBBY.md", "## Dealing with troublemakers"),
  ("Why the factory key is never a threshold key", "docs/LOBBY.md", "## Why not threshold signatures"),
  ("Removing someone from a live factory", "docs/LOBBY.md", "## Removing someone from a live factory"),
  ("What is public, and host proofs", "docs/LOBBY.md", "## What is public"),
 ],
 "sips": [
  ("Categories of SIP", "docs/sips/README.md", "## Categories"),
  ("Life of a SIP", "docs/sips/README.md", "## Life of a SIP"),
 ],
 "hostnode": [
  ("Every Lightning node compared", "docs/HOST-NODES.md", "^"),
  ("Order of work, and what to verify for each", "docs/HOST-NODES.md", "## To verify before building each adapter"),
 ],
 "away": [
  ("Reminders, and acting while the member is away", "docs/AWAY.md", "*"),
 ],
 "testing": [
  ("The seven levels of testing", "docs/TESTING.md", "## Levels"),
  ("What the simulator does", "docs/TESTING.md", "## The simulator"),
  ("The nine invariants", "docs/TESTING.md", "## Invariants"),
  ("Regtest scenarios", "docs/TESTING.md", "## Regtest scenarios"),
  ("The bar for a release candidate", "docs/TESTING.md", "## Before a release candidate"),
 ],
 "reference": [
  ("Glossary", "docs/KNOWLEDGE-BASE.md", "## 2. Words we use"),
  ("How sure we are of each claim", "docs/KNOWLEDGE-BASE.md", "## 6. How sure we are"),
  ("Risks we are carrying", "docs/KNOWLEDGE-BASE.md", "## 7. Risks we are carrying"),
  ("Open questions", "docs/OPEN-QUESTIONS.md", "*"),
 ],
}

# Not shown on the page. Carried in the page source so that a reader working from
# the HTML alone (a person viewing source, or an AI) has the full background.
CONTEXT_FILES = ["docs/KNOWLEDGE-BASE.md", "docs/DESIGN.md", "docs/OPEN-QUESTIONS.md", "docs/PLAN.md",
                 "docs/LOBBY.md", "docs/TESTING.md", "docs/HOST-NODES.md", "docs/AWAY.md",
                 "spec/safety-rule.md", "spec/signing-round.md", "docs/sips/README.md", "docs/RECORD.md"]
SOURCES = [
 ["SuperScalar original design (ZmnSCPxj)", "https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143"],
 ["SuperScalar with pseudo-Spilman leaves (ZmnSCPxj)", "https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242"],
 ["SuperScalar reference implementation", "https://github.com/8144225309/SuperScalar"],
 ["Lightning messaging specification (BOLT 1)", "https://github.com/lightning/bolts/blob/master/01-messaging.md"],
 ["MuSig2 (BIP 327)", "https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki"],
 ["LSP transport (bLIP-50)", "https://github.com/lightning/blips/blob/master/blip-0050.md"],
 ["LND invoices interface", "https://github.com/lightningnetwork/lnd/blob/master/lnrpc/invoicesrpc/invoices.proto"],
 ["Core Lightning releases", "https://github.com/ElementsProject/lightning/releases"],
]

def main():
    page = io.open(PAGE, encoding="utf-8").read()
    for key, items in BLOCKS.items():
        a, b = "<!--gz:%s-->" % key, "<!--/gz:%s-->" % key
        if a not in page or b not in page:
            sys.exit("marker missing in design.html: " + key)
        body = "\n".join(details(t, f, section(f, h)) for t, f, h in items)
        i = page.index(a) + len(a); j = page.index(b)
        page = page[:i] + "\n" + body + "\n" + page[j:]
    ctx = {
        "about": "Background for readers of this page's source. Not displayed. The Markdown files in the repository are authoritative; this is a copy taken when the page was built.",
        "repository": "https://github.com/gazpacho-wallet/gazpacho",
        "built": datetime.date.today().isoformat(),
        "reading_order": ["docs/KNOWLEDGE-BASE.md", "docs/DESIGN.md", "spec/safety-rule.md", "spec/signing-round.md", "docs/LOBBY.md", "docs/TESTING.md", "docs/OPEN-QUESTIONS.md", "docs/RECORD.md"],
        "wording": "Say host (the papers say LSP) and member (client). Never say staking; say hosting, providing liquidity, fees.",
        "sources": [{"title": t, "url": u} for t, u in SOURCES],
        "documents": {f: read(f) for f in CONTEXT_FILES},
    }
    blob = json.dumps(ctx, ensure_ascii=False, indent=1).replace("</", "<\\/")
    a, b = "<!--gz:context-->", "<!--/gz:context-->"
    if a not in page or b not in page:
        sys.exit("marker missing in design.html: context")
    i = page.index(a) + len(a); j = page.index(b)
    page = page[:i] + '\n<script type="application/json" id="gazpacho-context">\n' + blob + "\n</script>\n" + page[j:]
    io.open(PAGE, "w", encoding="utf-8", newline="\n").write(page)
    print("design.html rebuilt: %d expandable sections, %d documents embedded" % (sum(len(v) for v in BLOCKS.values()), len(CONTEXT_FILES)))

if __name__ == "__main__":
    main()
