#!/usr/bin/env python3
"""Build docs/ux/viewer.html: all layout concepts in one self-contained page.

Each concept file is embedded as base64 and shown in its own iframe (blob URL),
created the first time it is opened and kept, so each concept keeps its state
while you flip. Run again after any concept changes:

    python tools/build-ux-viewer.py
"""
import base64
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
UX = ROOT / "docs" / "ux"

CONCEPTS = [
    ("A", "Wallet first", "Phoenix, Zeus, Muun", "concept-a-wallet.html"),
    ("B", "Console", "ThunderHub, Ride The Lightning, Umbrel", "concept-b-console.html"),
    ("C", "Desktop power wallet", "Sparrow, Electrum", "concept-c-power.html"),
    ("D", "Lobby browser", "Steam server browser, Wasabi, Jam", "concept-d-lobby.html"),
    ("E", "Offers and a standing instruction", "Bisq, Lightning Pool, RoboSats", "concept-e-offers.html"),
    ("F", "Suite with two levels", "Trezor Suite, Ledger Live", "concept-f-suite.html"),
    ("G", "Built from the research", "All three research reports", "concept-g-blend.html"),
    ("H", "Recommended blend", "G as the base, with the best part of each other concept", "concept-h-recommended.html"),
]

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gazpacho layout concepts</title>
<style>
:root{--chrome:rgba(28,22,17,.82);--chrome-ink:#f6eee2;--accent:#e2574c;--edge:rgba(255,255,255,.18)}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:#1b1612;overflow:hidden;font:15px/1.4 system-ui,Segoe UI,Roboto,sans-serif}
#stage{position:fixed;inset:0}
#stage iframe{position:absolute;inset:0;width:100%;height:100%;border:0;background:#faf6ef;display:none}
#stage iframe.on{display:block}
.ctl{position:fixed;z-index:10;opacity:0;transition:opacity .18s ease;pointer-events:auto}
body.show .ctl{opacity:1}
.zone{top:50%;transform:translateY(-50%);width:72px;height:180px;display:flex;align-items:center;justify-content:center}
#prev{left:0}#next{right:0}
.zone button{width:52px;height:96px;border-radius:14px;border:1px solid var(--edge);background:var(--chrome);color:var(--chrome-ink);
font-size:34px;line-height:1;cursor:pointer;box-shadow:0 6px 22px rgba(0,0,0,.35);backdrop-filter:blur(6px)}
.zone button:hover{background:var(--accent);color:#fff}
#bar{top:10px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:12px;padding:7px 10px 7px 16px;border-radius:999px;
background:var(--chrome);color:var(--chrome-ink);border:1px solid var(--edge);box-shadow:0 6px 22px rgba(0,0,0,.35);backdrop-filter:blur(6px);
max-width:calc(100vw - 24px);white-space:nowrap}
#title{font-weight:700;overflow:hidden;text-overflow:ellipsis}
#title small{font-weight:400;opacity:.75;margin-left:8px}
#dots{display:flex;gap:5px}
#dots button{width:26px;height:26px;border-radius:50%;border:1px solid var(--edge);background:transparent;color:var(--chrome-ink);font:700 12px system-ui;cursor:pointer;padding:0}
#dots button.on{background:var(--accent);border-color:var(--accent);color:#fff}
#dots button:hover{border-color:#fff}
#hint{bottom:12px;left:50%;transform:translateX(-50%);padding:5px 12px;border-radius:999px;background:var(--chrome);color:var(--chrome-ink);
font-size:12.5px;border:1px solid var(--edge);pointer-events:none;white-space:nowrap}
@media (max-width:640px){#title small{display:none}.zone{width:52px}.zone button{width:40px;height:72px;font-size:26px}#hint{display:none}}
</style>
</head>
<body>
<div id="stage"></div>

<div class="ctl zone" id="prev"><button type="button" aria-label="Previous concept">&#8249;</button></div>
<div class="ctl zone" id="next"><button type="button" aria-label="Next concept">&#8250;</button></div>
<div class="ctl" id="bar"><span id="title"></span><span id="dots"></span></div>
<div class="ctl" id="hint">Flip: the arrows, the letters, or the [ and ] keys</div>

<script>
const CONCEPTS = __CONCEPTS__;
const DATA = __DATA__;

const stage = document.getElementById('stage');
const frames = {};
let cur = 0;

function decode(b64){
  const bin = atob(b64), bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

function frameFor(i){
  if (frames[i]) return frames[i];
  const f = document.createElement('iframe');
  f.title = 'Concept ' + CONCEPTS[i][0] + ': ' + CONCEPTS[i][1];
  /* A blob address gives each concept its own document URL, so its in-page
     links (#screen) stay inside it instead of resolving against this page. */
  const url = URL.createObjectURL(new Blob([decode(DATA[i])], {type: 'text/html'}));
  f.addEventListener('load', () => hook(f));
  f.src = url;
  stage.appendChild(f);
  frames[i] = f;
  return f;
}

/* Pointer and key events inside a concept do not reach this page by
   themselves, so listen inside each frame (same origin, srcdoc). */
function hook(f){
  let d;
  try { d = f.contentDocument; } catch (e) { return; }
  if (!d) return;
  d.addEventListener('mousemove', e => {
    const r = f.getBoundingClientRect();
    moved(e.clientX + r.left, e.clientY + r.top);
  }, {passive:true});
  d.addEventListener('keydown', key);
}

function go(i){
  cur = (i + CONCEPTS.length) % CONCEPTS.length;
  const f = frameFor(cur);
  for (const k in frames) frames[k].classList.toggle('on', frames[k] === f);
  const c = CONCEPTS[cur];
  const t = document.getElementById('title');
  t.textContent = c[0] + ' · ' + c[1];
  const s = document.createElement('small'); s.textContent = c[2]; t.appendChild(s);
  document.querySelectorAll('#dots button').forEach((b, j) => b.classList.toggle('on', j === cur));
  document.title = 'Gazpacho layouts: ' + c[0] + ' ' + c[1];
  try { history.replaceState(null, '', '#' + c[0]); } catch (e) {}
  flash();
}

/* Showing and hiding the controls.
   - Hidden by default.
   - Shown when the mouse travels more than a threshold within a short window,
     then hidden again quickly once the mouse rests.
   - Shown for as long as the pointer is over a control's area. */
const THRESHOLD = 70, WINDOW_MS = 260, HIDE_MS = 900;
let hovering = 0, hideT = 0, trail = [];

function show(){ document.body.classList.add('show'); }
function scheduleHide(){
  clearTimeout(hideT);
  hideT = setTimeout(() => { if (!hovering) document.body.classList.remove('show'); }, HIDE_MS);
}
function flash(){ show(); scheduleHide(); }

function moved(x, y){
  const now = performance.now();
  trail.push([now, x, y]);
  while (trail.length && now - trail[0][0] > WINDOW_MS) trail.shift();
  let dist = 0;
  for (let i = 1; i < trail.length; i++) dist += Math.hypot(trail[i][1] - trail[i-1][1], trail[i][2] - trail[i-1][2]);
  if (dist > THRESHOLD) { show(); trail = []; }
  if (document.body.classList.contains('show')) scheduleHide();
}
document.addEventListener('mousemove', e => moved(e.clientX, e.clientY), {passive:true});

document.querySelectorAll('.ctl').forEach(el => {
  el.addEventListener('mouseenter', () => { hovering++; show(); clearTimeout(hideT); });
  el.addEventListener('mouseleave', () => { hovering = Math.max(0, hovering - 1); scheduleHide(); });
});

/* A hidden arrow still sits over the page edge. Only act on a click when the
   arrow is visible, so a click near the edge of a concept never flips by surprise. */
function visible(){ return document.body.classList.contains('show'); }
document.querySelector('#prev button').addEventListener('click', () => { if (visible()) go(cur - 1); });
document.querySelector('#next button').addEventListener('click', () => { if (visible()) go(cur + 1); });

const dots = document.getElementById('dots');
CONCEPTS.forEach((c, i) => {
  const b = document.createElement('button');
  b.type = 'button'; b.textContent = c[0]; b.title = c[1];
  b.addEventListener('click', () => go(i));
  dots.appendChild(b);
});

function key(e){
  const t = e.target, tag = t && t.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (t && t.isContentEditable)) return;
  if (e.key === '[') { go(cur - 1); e.preventDefault(); }
  else if (e.key === ']') { go(cur + 1); e.preventDefault(); }
}
document.addEventListener('keydown', key);

const start = CONCEPTS.findIndex(c => c[0] === (location.hash || '').slice(1).toUpperCase());
go(start >= 0 ? start : 0);
</script>
</body>
</html>
"""


def main():
    meta, data = [], []
    for letter, name, basis, fname in CONCEPTS:
        path = UX / fname
        if not path.exists():
            print(f"skipped {fname}: not built yet")
            continue
        raw = path.read_bytes()
        meta.append([letter, name, basis])
        data.append(base64.b64encode(raw).decode("ascii"))
    page = PAGE.replace("__CONCEPTS__", json.dumps(meta)).replace("__DATA__", json.dumps(data))
    out = UX / "viewer.html"
    out.write_text(page, encoding="utf-8", newline="\n")
    print(f"{out} written: {len(meta)} concepts, {len(page) // 1024} KB")


if __name__ == "__main__":
    main()
