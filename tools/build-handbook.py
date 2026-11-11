#!/usr/bin/env python3
"""Build docs/handbook.html: every project document in one self-contained page.

Collapsed, the page is a table of contents you can scan. Expanded, it is the
complete text of the project's documents. Nothing is typed into the page by hand:
it is generated from the Markdown files, so it cannot drift from them.

    python tools/build-handbook.py

Requires the "markdown" package. The output needs no server; open it from disk.
"""
import io, json, os, re, sys, html, datetime
import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "handbook.html")

# (short name for the side menu, file, one-line description shown when collapsed)
CHAPTERS = [
 ("Start here", "docs/KNOWLEDGE-BASE.md", "Terms, facts, decisions in force, and how sure we are of each claim."),
 ("Plan", "docs/PLAN.md", "The mission, the decisions in force in one table, and the milestones."),
 ("Design", "docs/DESIGN.md", "The design currently in force, consolidated."),
 ("Safe-to-sign rule", "spec/safety-rule.md", "Specification: the checks run before every signature."),
 ("Signing round", "spec/signing-round.md", "Specification: messages, steps, one-time secrets, proving who broke a round."),
 ("The lobby", "docs/LOBBY.md", "How a factory forms: start rule, member conditions, troublemakers, what is public."),
 ("Host's Lightning node", "docs/HOST-NODES.md", "The nodes a host can link to and how hard each is."),
 ("While you are away", "docs/AWAY.md", "Reminders, and ways to act when the member is not at the app."),
 ("Testing", "docs/TESTING.md", "Levels, the simulator, invariants, scenarios, the bar for a release candidate."),
 ("SIPs: the process", "docs/sips/README.md", "SuperScalar Improvement Proposals: how rules and features are proposed and decided."),
 ("SIPs: rule template", "docs/sips/template-rule.md", "The form for requesting a rule."),
 ("SIPs: worked example", "docs/sips/example-rule-request.md", "A filled-in rule request: the lobby start rule."),
 ("SIPs: general template", "docs/sips/template-general.md", "The form for protocol, process and informational proposals."),
 ("Open questions", "docs/OPEN-QUESTIONS.md", "What is still undecided, and who settles it."),
 ("Hand-off to SuperScalar", "docs/handoff/2026-11-11-to-superscalar.md", "Findings and requests for the SuperScalar repository."),
 ("Record", "docs/RECORD.md", "Background: the dated history of drafts, findings, reviews and decisions. Earlier sections are superseded where later ones differ."),
 ("Lobby research", "docs/LOBBY-research.md", "Background: how comparable systems gather people and handle those who stall, with sources."),
 ("Starting assessment", "docs/ASSESSMENT.md", "Background: what existed at the start. Its estimates are superseded."),
]

SOURCES = [
 ("SuperScalar original design (ZmnSCPxj)", "https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories/1143"),
 ("SuperScalar with pseudo-Spilman leaves (ZmnSCPxj)", "https://delvingbitcoin.org/t/superscalar-laddered-timeout-tree-structured-decker-wattenhofer-factories-with-pseudo-spilman-leaves/1242"),
 ("SuperScalar reference implementation", "https://github.com/8144225309/SuperScalar"),
 ("Lightning messaging specification (BOLT 1)", "https://github.com/lightning/bolts/blob/master/01-messaging.md"),
 ("MuSig2 (BIP 327)", "https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki"),
 ("LSP transport (bLIP-50)", "https://github.com/lightning/blips/blob/master/blip-0050.md"),
 ("LND invoices interface", "https://github.com/lightningnetwork/lnd/blob/master/lnrpc/invoicesrpc/invoices.proto"),
 ("Core Lightning releases", "https://github.com/ElementsProject/lightning/releases"),
]

def read(rel):
    return io.open(os.path.join(ROOT, rel), encoding="utf-8").read()

def render(md):
    h = markdown.markdown(md, extensions=["tables", "fenced_code"])
    h = re.sub(r"<(/?)h[1-3]>", r"<\1h4>", h)
    return h.replace("<table>", '<div class="tw"><table>').replace("</table>", "</table></div>")

def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def split(md):
    """Title, text before the first '## ', and a list of (heading, body) for each '## ' section."""
    lines = md.split("\n")
    title = lines[0][2:].strip() if lines and lines[0].startswith("# ") else ""
    intro, secs, cur, fence = [], [], None, False
    for ln in lines[1:]:
        if ln.startswith("```"): fence = not fence
        if ln.startswith("## ") and not fence:
            cur = [ln[3:].strip(), []]; secs.append(cur)
        elif cur is None: intro.append(ln)
        else: cur[1].append(ln)
    return title, "\n".join(intro).strip(), [(h, "\n".join(b).strip()) for h, b in secs]

CSS = """
:root{--bg:#fbf6ee;--card:#fff;--ink:#231a15;--mute:#6f6258;--line:#e6dac9;--tomato:#c8321f;--tomato-soft:#fbe3dc;--green:#2f7d4f;--gold:#b7791f;--gold-soft:#fbefd2;--grey-soft:#efe9df}
@media (prefers-color-scheme:dark){:root{--bg:#17120f;--card:#211a16;--ink:#f3ebe2;--mute:#b3a597;--line:#3a2f28;--tomato:#ff7a63;--tomato-soft:#44201a;--green:#6fcf97;--gold:#f0c060;--gold-soft:#3d3015;--grey-soft:#2b231e}}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:16.5px/1.6 system-ui,"Segoe UI",sans-serif}
.top{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);padding:8px 14px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.top b{font-size:18px}.top b span{color:var(--tomato)}
.top input{flex:1;min-width:160px;max-width:340px;font:inherit;font-size:15px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink)}
.top button{font:inherit;font-size:14px;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--ink);cursor:pointer}
#count{color:var(--mute);font-size:14px}
.wrap{display:grid;grid-template-columns:270px minmax(0,1fr);max-width:1240px;margin:0 auto}
nav{position:sticky;top:52px;align-self:start;max-height:calc(100vh - 52px);overflow:auto;padding:14px 10px 30px 14px;font-size:14.5px;border-right:1px solid var(--line)}
nav a{display:block;padding:3px 8px;border-radius:6px;color:var(--ink);text-decoration:none}
nav a:hover{background:var(--grey-soft)}
nav a.ch{font-weight:700;margin-top:8px}
nav a.sec{color:var(--mute);padding-left:18px;font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
nav .group{font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--tomato);margin:16px 8px 2px}
main{padding:18px 20px 90px;min-width:0}
.lead{color:var(--mute);margin:4px 0 14px}
section.chapter{margin:0 0 34px;scroll-margin-top:60px}
section.chapter>h2{font-size:24px;margin:0 0 2px}
section.chapter>.desc{color:var(--mute);margin:0 0 6px}
section.chapter>.file{font-size:13px;color:var(--mute);margin:0 0 10px}
.intro{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:4px 16px;margin:8px 0}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:6px 0;scroll-margin-top:60px}
summary{cursor:pointer;padding:9px 14px;font-weight:600}
summary:hover{background:var(--grey-soft);border-radius:10px}
details[open]>summary{border-bottom:1px solid var(--line);border-radius:10px 10px 0 0;color:var(--tomato)}
.body{padding:4px 16px 10px}
.body h4{font-size:16.5px;margin:14px 0 4px}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:15px;margin:8px 0}
th,td{text-align:left;vertical-align:top;padding:7px 9px;border-bottom:1px solid var(--line)}
th{font-size:13px;color:var(--mute)}
code{background:var(--grey-soft);padding:1px 5px;border-radius:5px;font-size:.92em}
pre{background:var(--grey-soft);padding:12px 14px;border-radius:9px;overflow-x:auto;font-size:14px}
pre code{background:none;padding:0}
a{color:var(--tomato)}
.hide{display:none!important}
mark{background:var(--gold-soft);color:inherit;border-radius:3px}
@media (max-width:860px){.wrap{grid-template-columns:1fr}nav{position:static;max-height:none;border-right:0;border-bottom:1px solid var(--line)}nav a.sec{display:none}}
"""

JS = """
var D=[].slice.call(document.querySelectorAll('main details'));
function openTo(id){var el=document.getElementById(id);if(!el)return;if(el.tagName==='DETAILS')el.open=true;el.scrollIntoView();}
document.getElementById('openall').onclick=function(){D.forEach(function(d){if(!d.classList.contains('hide'))d.open=true})};
document.getElementById('closeall').onclick=function(){D.forEach(function(d){d.open=false})};
document.querySelectorAll('nav a').forEach(function(a){a.addEventListener('click',function(){var id=a.getAttribute('href').slice(1);setTimeout(function(){openTo(id)},0)})});
if(location.hash)openTo(location.hash.slice(1));
window.addEventListener('hashchange',function(){openTo(location.hash.slice(1))});
var q=document.getElementById('q'),count=document.getElementById('count');
q.addEventListener('input',function(){
  var t=q.value.trim().toLowerCase(),n=0;
  D.forEach(function(d){
    if(!t){d.classList.remove('hide');d.open=false;return}
    var hit=d.textContent.toLowerCase().indexOf(t)>=0;
    d.classList.toggle('hide',!hit);d.open=hit;if(hit)n++;
  });
  document.querySelectorAll('section.chapter').forEach(function(s){
    var any=!t||s.querySelector('details:not(.hide)')||s.querySelector('.intro')&&s.querySelector('.intro').textContent.toLowerCase().indexOf(t)>=0;
    s.classList.toggle('hide',!any);
  });
  count.textContent=t?(n+' section'+(n===1?'':'s')+' match'):'';
});
"""

def main():
    nav, body, total = [], [], 0
    background_started = False
    for i, (name, rel, desc) in enumerate(CHAPTERS, 1):
        title, intro, secs = split(read(rel))
        cid = "c%d" % i
        if desc.startswith("Background") and not background_started:
            nav.append('<div class="group">Background</div>'); background_started = True
        elif i == 1:
            nav.append('<div class="group">Current</div>')
        nav.append('<a class="ch" href="#%s">%s</a>' % (cid, html.escape(name)))
        out = ['<section class="chapter" id="%s"><h2>%s</h2><p class="desc">%s</p><p class="file">%s · <code>%s</code></p>'
               % (cid, html.escape(name), html.escape(desc), html.escape(title), rel)]
        if intro:
            out.append('<div class="intro">%s</div>' % render(intro))
        for j, (h, b) in enumerate(secs, 1):
            sid = "%s-%s" % (cid, slug(h)[:40] or str(j))
            nav.append('<a class="sec" href="#%s" title="%s">%s</a>' % (sid, html.escape(h), html.escape(h)))
            out.append('<details id="%s"><summary>%s</summary><div class="body">%s</div></details>' % (sid, html.escape(h), render(b)))
            total += 1
        out.append("</section>")
        body.append("\n".join(out))
    ctx = {"about": "Not displayed. Sources and conventions for readers working from this file alone. The full text of every document is in the page itself, inside the collapsed sections.",
           "repository": "https://github.com/gazpacho-wallet/gazpacho",
           "built": datetime.date.today().isoformat(),
           "wording": "Say host (the papers say LSP) and member (client). Never say staking; say hosting, providing liquidity, fees.",
           "authoritative": "The Markdown files in the repository. This page is generated from them by tools/build-handbook.py.",
           "chapters": [{"name": n, "file": f, "summary": d} for n, f, d in CHAPTERS],
           "sources": [{"title": t, "url": u} for t, u in SOURCES]}
    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gazpacho Handbook</title>
<style>%s</style>
</head>
<body>
<div class="top"><b><span>Gazpacho</span> handbook</b>
<input id="q" type="search" placeholder="Find in all sections" aria-label="Find in all sections">
<button id="openall">Open all</button><button id="closeall">Close all</button><span id="count"></span></div>
<div class="wrap">
<nav aria-label="Contents">%s</nav>
<main>
<p class="lead">Every project document in one file. Closed, it is a list of contents; open a line to read that part, or use "Open all" for the complete text. Built on %s from the repository's documents. The illustrated summary with diagrams is <a href="design.html">design.html</a>.</p>
%s
</main>
</div>
<script type="application/json" id="gazpacho-context">
%s
</script>
<script>%s</script>
</body>
</html>
""" % (CSS, "\n".join(nav), datetime.date.today().isoformat(), "\n".join(body),
       json.dumps(ctx, ensure_ascii=False, indent=1).replace("</", "<\\/"), JS)
    io.open(OUT, "w", encoding="utf-8", newline="\n").write(page)
    print("handbook.html built: %d chapters, %d sections, %d KB" % (len(CHAPTERS), total, len(page) // 1024))

if __name__ == "__main__":
    main()
