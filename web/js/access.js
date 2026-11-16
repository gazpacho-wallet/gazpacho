// SPDX-License-Identifier: MIT
/* Getting in (spec/local-api.md 4.3, 12): first run, the 24 words, the backup
   check, the passphrase, sign-in, and the files-behind choice.

   Secrets. The 24 words and the passphrase live only in the fields and text
   nodes of the screen that shows or collects them and in one variable of
   that screen. They are never logged, never put in page storage, a URL or
   the title, and they are cleared when the screen closes, the page is
   hidden for good or frozen, and at a 10-minute ceiling (12.7). */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;
  var CEILING_MS = 600000;
  var MANAGER = "A password manager may keep this passphrase. Set it to match this exact address, port included: one that matches by name alone could offer it to a page on another port of this computer.";
  var ASKED = "Gazpacho asks for your 24 words only when you restore a wallet, or right after showing them to you. It never asks for them anywhere else.";

  /* ---- the 24 words, shown ---- */
  /* words: the array from the answer. It is shown only after "Show the words",
     taken out of the page while the tab is hidden, and wiped on done(), on
     leaving the screen and at the ceiling. */
  function wordsView(words, onGone) {
    var list = h("ol", { class: "words", "aria-label": "Your 24 words" });
    var toggle = ui.button("Show the words", function () { if (words.length) { shown = !shown; draw(); } });
    var note = h("p", { class: "small mute", role: "status" });
    var shown = false, gone = false;
    var timer = setTimeout(function () { clear(); note.textContent = "The words were cleared from this page after 10 minutes. To see them again, use Settings, Wallet, with your passphrase."; }, CEILING_MS);
    function draw() {
      u.clear(list);
      if (shown) words.forEach(function (w) { list.appendChild(h("li", {}, w)); });
      toggle.textContent = shown ? "Hide the words" : (list.getAttribute("data-seen") ? "Show again" : "Show the words");
      if (shown) list.setAttribute("data-seen", "1");
      toggle.hidden = gone;
    }
    function hide() { if (document.visibilityState === "hidden" && shown) { shown = false; draw(); } }
    function clear() {
      if (gone) return;
      gone = true;
      shown = false;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", hide);
      u.wipe(words);
      draw();
      if (onGone) onGone();
    }
    list.addEventListener("copy", function (ev) { ev.preventDefault(); });
    document.addEventListener("visibilitychange", hide);
    gz.app.onLeave(clear);
    draw();
    return {
      clear: clear,
      node: h("div", {},
        ui.notice("warn", "Before you show them,", "make sure nobody can see your screen and that it is not being shared or recorded."),
        list, ui.actions(toggle), note,
        h("ul", { class: "small" },
          h("li", {}, "Write them on paper, in order, and keep the paper somewhere safe. Anyone who has them has your keys."),
          h("li", {}, "Do not photograph them, take a screenshot, or type them into any other app. This page has no copy button and never puts them on the clipboard."),
          h("li", {}, "They bring back your keys and on-chain coins, not your place in a factory."),
          h("li", {}, ASKED)))
    };
  }

  /* ---- the 24 words, typed (the check and restore screens only) ---- */
  function wordInputs(positions) {
    var grid = h("div", { class: "wordin" }), suggest = h("div", { class: "suggest", "aria-live": "polite" }), inputs = [];
    function offer(input) {
      var v = input.value.trim().toLowerCase(), n = 0, i, list = gz.bip39 || [];
      u.clear(suggest);
      if (v.length < 2) return;
      for (i = 0; i < list.length && n < 6; i++) {
        if (list[i].indexOf(v) === 0 && list[i] !== v) {
          n++;
          suggest.appendChild(pick(input, list[i]));
        }
      }
    }
    function pick(input, word) {
      return h("button", { type: "button", class: "btn small", onclick: function () { input.value = word; u.clear(suggest); input.focus(); } }, word);
    }
    positions.forEach(function (p) {
      var f = ui.field("Word " + p, { type: "text", autocomplete: "off", autocorrect: "off", autocapitalize: "off", spellcheck: "false", "data-word": p });
      f.input.addEventListener("input", function () { offer(f.input); });
      inputs.push(f.input);
      grid.appendChild(f.wrap);
    });
    function clear() { inputs.forEach(function (i) { i.value = ""; }); u.clear(suggest); }
    return {
      node: h("div", {}, grid, suggest),
      clear: clear,
      /* reads the fields once, into a new array, and empties them */
      take: function () {
        var out = inputs.map(function (i) { return i.value.trim().toLowerCase(); });
        clear();
        return out;
      },
      focus: function () { if (inputs[0]) inputs[0].focus(); }
    };
  }

  /* ---- no wallet, and no start link: the code from the terminal ---- */
  function noWallet(err) {
    var msg = h("div", {}), f = ui.field("First-run code", { type: "text", class: "code", autocomplete: "off", autocapitalize: "characters", spellcheck: "false", maxlength: "11", placeholder: "ABCDE-FGHJK" });
    var go = h("button", { type: "submit", class: "btn primary" }, "Use this code");
    var form = h("form", { novalidate: true }, f.wrap, msg, ui.actions(go));
    if (err) u.add(msg, ui.error(err));
    form.addEventListener("submit", function (ev) {
      var code = f.input.value.trim().toUpperCase();
      ev.preventDefault();
      f.input.value = "";
      if (!/^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(code)) { u.clear(msg); u.add(msg, ui.notice("warn", "Type the code first.", "It has 10 letters and digits, shown as two groups of five.")); return; }
      ui.run(go, msg, function () { return api.start({ code: code }).then(gz.app.enter); });
    });
    gz.app.gate(h("div", { class: "card" },
      h("h1", {}, "Open Gazpacho from the program"),
      h("p", {}, "There is no wallet here yet. To make one, open Gazpacho from the program itself: it opens this page with a start link that works once. If the program printed a code instead, type it here."),
      form,
      h("p", { class: "small mute" }, "No code? Start Gazpacho again, or type the code it prints. For a new code, run ", h("code", {}, "gazpacho first-run-code"), " in a terminal on this computer. A code works once, for 10 minutes.")));
  }

  /* A start link used before the person used it (4.3): said loudly, in place of every other screen. */
  function hijack() {
    gz.app.gate(h("div", { class: "card danger", role: "alert" },
      h("h1", {}, "Do not use this wallet"),
      h("p", {}, "Someone may have used this program's start link before you. If you did not just set up Gazpacho in another tab or window, do not use this wallet and do not send coins to it. Stop Gazpacho and delete its data folder, then start again.")));
  }

  /* ---- sign-in: the wallet passphrase ---- */
  function signIn(reason) {
    var s = api.session || {}, locked = s.wallet === "locked" || s.wallet === "files_behind";
    var f = ui.passField("Wallet passphrase", false), msg = h("div", {}), head = h("p", { id: "locked-headline" });
    var go = h("button", { type: "submit", class: "btn primary", id: "signin-go" }, locked ? "Unlock" : "Sign in");
    var form = h("form", { novalidate: true }, f.wrap, msg, ui.actions(go));
    var why = { signed_out: "You were signed out.", ended: "This session ended.", you: "You signed out.", locked: "The wallet was locked.",
      check_failed: "The words did not match, so Gazpacho signed this browser out. Sign in to check again, with three other words." };
    form.addEventListener("submit", function (ev) {
      var pass = f.input.value;
      ev.preventDefault();
      f.input.value = "";
      u.clear(msg);
      if (!pass) { u.add(msg, ui.notice("warn", "Type your passphrase first.")); return; }
      go.disabled = true;
      u.add(msg, h("p", { role: "status" }, "Checking…"));
      api.signIn(pass).then(function () {
        pass = "";
        return gz.app.enter();
      }, function (e) {
        pass = "";
        go.disabled = false;
        u.clear(msg);
        u.add(msg, ui.error(e));
        if (e.code === "rate_limited") ui.holdOff(go, e.params.retry_after_s || 1, msg);
        f.input.focus();
      });
    });
    if (locked) {
      api.get("/status", { noSession: true, background: true }).then(function (st) {
        head.textContent = W.headline(st);
        head.setAttribute("data-code", st.watching && st.watching.headline ? String(st.watching.headline.code) : "");
      }, function () { head.textContent = "Locked."; });
    } else {
      head.textContent = "The wallet is still unlocked and keeps working. This browser is signed out.";
    }
    gz.app.gate(h("div", { class: "card" },
      h("h1", {}, locked ? "Unlock Gazpacho" : "Sign in"),
      reason && why[reason] ? ui.notice(reason === "check_failed" ? "bad" : "", why[reason]) : null,
      head, form,
      h("p", { class: "small mute" }, "Nobody can recover this passphrase for you. If you have lost it, your 24 words still bring the wallet back."),
      h("p", { class: "small mute" }, MANAGER),
      h("p", { class: "small mute" }, ASKED)));
    f.input.focus();
  }

  /* ---- files older than the wallet's last saved state (4.7) ---- */
  function filesBehind() {
    var msg = h("div", {});
    var restore = ui.button("Start these files as a restore", function () {
      ui.askPassphrase({
        title: "Start these files as a restore?",
        why: "Gazpacho will start on these files with new keys, so no key used after them can come back. This cannot be undone. Type your passphrase to go on.",
        button: "Start as a restore",
        run: function (pass) { return api.call("POST", "/wallet/start-as-restore", { confirm: "restore_new_keys", passphrase: pass }); }
      }).then(function () { return api.refreshSession().then(gz.app.enter); }, function (e) { u.clear(msg); u.add(msg, ui.error(e)); });
    }, "danger");
    var stay = ui.button("Stay locked", function () { api.signOut(); }, "primary");
    gz.app.gate(h("div", { class: "card" },
      h("h1", {}, "These files are older than this wallet"),
      ui.notice("bad", "Gazpacho has not started the wallet.", "These files are older than this wallet's last saved state. Gazpacho can start them as a restore, with new keys, or stay locked so you can put the newer files back."),
      h("p", {}, "If you have a newer copy of Gazpacho's data folder, choose Stay locked, put the newer files back, and unlock again. Nothing on disk changes while it stays locked."),
      msg, ui.actions(stay, restore)));
  }

  /* ---- first run: the steps ---- */
  var STEPS = ["Make a wallet, or bring one back", "Choose your passphrase", "Write down the 24 words", "Check the words", "Say what you will accept", "Find a lobby, or host one"];

  function frame(cur, body) {
    var ol = h("ol", { class: "steps" });
    STEPS.forEach(function (title, i) {
      ol.appendChild(h("li", { class: i < cur ? "done" : i === cur ? "cur" : null, "aria-current": i === cur ? "step" : null },
        h("h2", {}, title), i === cur ? body : null));
    });
    gz.app.wide(h("div", {},
      h("p", { class: "crumb" }, "First run"),
      h("h1", {}, "Welcome to Gazpacho"),
      h("p", { class: "lead" }, "A wallet for small, fast bitcoin payments (Lightning), where you hold your own keys. You share one on-chain output, a factory, with a host and other members. The host funds it; you start with a balance of zero. This wallet can join lobbies and host them: there is nothing to choose."),
      ol));
  }

  function sixWords() {
    var out = [], i, list = gz.effWords || [];
    for (i = 0; i < 6; i++) out.push(list[u.randomBelow(list.length)]);
    return out;
  }

  function stepChoose(setup) {
    var nets = (setup.networks || []).filter(function (n) { return !n.available; }).map(function (n) {
      return n.id === "mainnet" ? "Real bitcoin (mainnet) is switched off in this release." : n.id + " is not offered yet.";
    });
    frame(0, h("div", {},
      ui.actions(ui.button("Make a new wallet", function () { stepPass("create", null); }, "primary"),
        ui.button("Restore from 24 words", function () { stepRestore(); })),
      h("p", { class: "small mute" }, "Network: " + (setup.network === "signet" ? "Signet, test coins with no value. " : String(setup.network) + ". ") + nets.join(" "))));
  }

  function stepRestore() {
    var positions = [], i, w, msg = h("div", {});
    for (i = 1; i <= 24; i++) positions.push(i);
    w = wordInputs(positions);
    gz.app.onLeave(w.clear);
    frame(0, h("div", {},
      h("p", {}, "Type your 24 words in order, one in each field. They bring back your keys and your on-chain coins."),
      h("p", { class: "small mute" }, ASKED),
      w.node, msg,
      ui.actions(ui.button("Next: choose a passphrase", function () {
        var words = w.take();
        if (words.some(function (x) { return !x; })) {
          u.clear(msg);
          u.add(msg, ui.notice("warn", "Type all 24 words.", "The fields were emptied; type them again from your paper."));
          u.wipe(words);
          return;
        }
        stepPass("restore", words);
      }, "primary"), ui.button("Back", function () { w.clear(); api.get("/wallet/setup").then(stepChoose); })),
      h("p", { class: "small mute" }, "The words do not bring back factories. Factories this wallet was in are neither known nor watched until a backup is brought back, which a later release adds.")));
    w.focus();
    gz.app.onLeave(w.clear);
  }

  /* The passphrase: six generated words first, or the person's own (storage 14). */
  function stepPass(mode, words) {
    var six = sixWords(), own = false, msg = h("div", {});
    var box = h("p", { class: "sixwords", id: "sixwords" }, six.join(" "));
    var typed = ui.passField("Type the six words once, with a space between them", true, "So you know you have them written down.");
    var p1 = ui.passField("Your own passphrase", true), p2 = ui.passField("The same passphrase again", true);
    var count = h("p", { class: "small mute", role: "status" });
    var go = h("button", { type: "submit", class: "btn primary" }, mode === "create" ? "Make the wallet" : "Restore the wallet");
    var other = ui.button("Make six other words", function () { six = sixWords(); box.textContent = six.join(" "); });
    var swap = ui.button("Choose my own", function () { own = !own; draw(); });
    var made = h("div", {}), mine = h("div", {});
    var form = h("form", { novalidate: true }, made, mine, msg, ui.actions(go, swap), h("p", { class: "small mute" }, MANAGER));
    function forget() {
      u.wipe(six);
      box.textContent = "";
      typed.input.value = p1.input.value = p2.input.value = "";
      if (words) u.wipe(words);
    }
    function draw() {
      made.hidden = own;
      mine.hidden = !own;
      swap.textContent = own ? "Use six words Gazpacho makes" : "Choose my own";
    }
    u.add(made, [
      h("p", {}, "Gazpacho has made a passphrase for you: six words. Write it down with your 24 words, or keep it in a password manager. You will type it each time you open Gazpacho on this computer. It locks every file Gazpacho keeps here."),
      box, ui.actions(other), typed.wrap]);
    u.add(mine, [
      h("p", {}, "At least 15 characters. Nobody can recover it for you. If you forget it, your 24 words still bring the wallet back on this computer."),
      p1.wrap, count, p2.wrap]);
    p1.input.addEventListener("input", function () {
      var n = Array.from(p1.input.value.normalize("NFC")).length;
      count.textContent = n < 15 ? n + " of 15 characters." : n + " characters.";
    });
    form.addEventListener("submit", function (ev) {
      var a, b;
      ev.preventDefault();
      u.clear(msg);
      if (own) {
        a = p1.input.value.normalize("NFC");
        b = p2.input.value.normalize("NFC");
      } else {
        a = six.join(" ");
        b = typed.input.value.trim().replace(/\s+/g, " ").normalize("NFC");
        if (b !== a) { u.add(msg, ui.notice("bad", "That is not the six words shown.", "Type them exactly, with one space between words.")); typed.input.value = ""; return; }
      }
      p1.input.value = p2.input.value = typed.input.value = "";
      if (!a) { u.add(msg, ui.notice("warn", "Type a passphrase first.")); return; }
      go.disabled = true;
      u.add(msg, h("p", { role: "status" }, "Making the wallet… this takes about a second."));
      (mode === "create"
        ? api.call("POST", "/wallet/create", { confirm: "create_wallet", passphrase: a, confirm_passphrase: b })
        : api.call("POST", "/wallet/restore", { words: words, passphrase: a, confirm_passphrase: b })
      ).then(function (r) {
        a = b = "";
        forget();
        if (mode === "create") { stepWords(r.words); return null; }
        return api.refreshSession().then(gz.app.enter);
      }, function (e) {
        a = b = "";
        go.disabled = false;
        u.clear(msg);
        u.add(msg, ui.error(e));
        if (e.code === "rate_limited") ui.holdOff(go, e.params.retry_after_s || 1, msg);
        if (e.code === "bad_words") { forget(); u.add(msg, ui.actions(ui.button("Type the 24 words again", stepRestore, "primary"))); }
      });
    });
    frame(1, form);
    draw();
    gz.app.onLeave(forget);
  }

  function stepWords(words) {
    var v, body = h("div", {});
    frame(2, body);
    v = wordsView(words, null);
    u.add(body, [v.node, ui.actions(
      ui.button("I wrote them down: check them", function () { v.clear(); stepCheck(false); }, "primary"),
      ui.button("Done, check later", function () { v.clear(); stepPreset(false); }))]);
  }

  /* Setup was left before it finished (a closed tab, a restart): the wallet exists (4.3). */
  function stepResume() {
    var msg = h("div", {}), body = h("div", {});
    frame(2, body);
    u.add(body, [
      h("p", {}, "This wallet was made, but setting it up was not finished. Your 24 words can be shown again with your passphrase."),
      msg,
      ui.actions(
        ui.button("Show the 24 words", function () { revealInto(body, msg, function () { stepCheck(false); }); }),
        ui.button("Check the words", function () { stepCheck(false); }, "primary"),
        ui.button("Go on without checking", function () { stepPreset(false); }))]);
  }

  /* Ask for the passphrase, fetch the words (reveal carries the passphrase in
     its own request, 12.3), and show them in `into`. */
  function revealInto(into, msg, after) {
    ui.askPassphrase({
      title: "Show the 24 words",
      why: "Type your passphrase. Make sure nobody can see your screen and nothing is recording it.",
      button: "Show the words",
      run: function (pass) { return api.call("POST", "/wallet/phrase/reveal", { confirm: "show_words", passphrase: pass }); }
    }).then(function (r) {
      var v = wordsView(r.words, null);
      u.clear(into);
      u.add(into, [v.node, ui.actions(ui.button("Done", function () { v.clear(); after(); }, "primary"))]);
    }, function (e) { u.clear(msg); u.add(msg, ui.error(e)); });
  }

  function checkForm(onOk, extra) {
    var box = h("div", {}, h("p", { role: "status" }, "Loading…"));
    api.call("POST", "/wallet/phrase/check-start", {}).then(function (c) {
      var w = wordInputs(c.positions), pf = ui.passField("Wallet passphrase", false, "The check opens your words for one comparison, so it needs the passphrase."), msg = h("div", {});
      var go = h("button", { type: "submit", class: "btn primary" }, "Check");
      var form = h("form", { novalidate: true },
        h("p", {}, "Type words " + c.positions.join(", ").replace(/, ([^,]*)$/, " and $1") + " from your paper."),
        h("p", { class: "small mute" }, ASKED + " Checks left today: " + u.number(c.checks_left_today) + "."),
        w.node, pf.wrap, msg, ui.actions(go, extra || null));
      gz.app.onLeave(function () { w.clear(); pf.input.value = ""; });
      form.addEventListener("submit", function (ev) {
        var words = w.take(), pass = pf.input.value.normalize("NFC");
        ev.preventDefault();
        pf.input.value = "";
        u.clear(msg);
        if (!pass || words.some(function (x) { return !x; })) {
          u.wipe(words);
          u.add(msg, ui.notice("warn", "Type the three words and your passphrase.", "The fields were emptied; type them again."));
          return;
        }
        go.disabled = true;
        api.call("POST", "/wallet/phrase/check", { check_id: c.check_id, passphrase: pass, words: words }).then(function (r) {
          pass = "";
          u.wipe(words);
          if (r.ok) { onOk(); return; }
          /* Never which word was wrong. A failed check ends the session (12.3). */
          api.dropSession("check_failed");
        }, function (e) {
          pass = "";
          u.wipe(words);
          go.disabled = false;
          u.add(msg, ui.error(e));
          if (e.code === "rate_limited") ui.holdOff(go, e.params.retry_after_s || 1, msg);
        });
      });
      u.clear(box);
      box.appendChild(form);
      w.focus();
    }, function (e) { u.clear(box); u.add(box, ui.error(e)); if (extra) u.add(box, ui.actions(extra)); });
    return box;
  }

  function stepCheck() {
    frame(3, checkForm(function () { stepPreset(true); },
      ui.button("Skip for now", function () { stepPreset(false); })));
  }

  function presetNumbers(c) {
    var parts = [], k;
    for (k in c) {
      if (typeof c[k] === "number" && W.conditionNames[k]) parts.push(W.conditionNames[k].toLowerCase() + " " + u.number(c[k]) + " " + (W.conditionUnits[k] || ""));
    }
    return parts.join("; ") + ".";
  }

  function stepPreset(checked) {
    var body = h("div", {}, h("p", { role: "status" }, "Loading…"));
    frame(4, body);
    api.get("/conditions").then(function (c) {
      var rows = h("tbody", {}), msg = h("div", {}), chosen = "everyday";
      (c.presets || []).forEach(function (p) {
        var id = "preset-" + p.id;
        rows.appendChild(h("tr", {},
          h("td", {}, h("input", { type: "radio", name: "preset", id: id, value: p.id, checked: p.id === chosen, onchange: function () { chosen = p.id; } }), " ",
            h("label", { for: id }, p.id.charAt(0).toUpperCase() + p.id.slice(1))),
          h("td", {}, presetNumbers(p.conditions || {}))));
      });
      u.clear(body);
      u.add(body, [
        checked === "restored" ? ui.notice("ok", "Your wallet is restored.", "Its on-chain coins are in this wallet again.") :
          checked ? ui.notice("ok", "Checked.", "Your words are written down correctly.") : ui.notice("", "The words are not checked yet.", "A task stays on Home until they are."),
        h("p", {}, "These are your conditions. The app joins and signs only inside them. Pick a preset, a starting set of numbers. You can change any number later on Conditions."),
        h("div", { class: "tablewrap" }, h("table", { class: "prof" }, h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Preset"), h("th", { scope: "col" }, "The numbers it sets"))), rows)),
        msg,
        ui.actions(ui.button("Use this preset", function () {
          var btn = this;
          ui.run(btn, msg, function () {
            return api.call("POST", "/wallet/finish-setup", { preset: chosen, find: "browse" }).then(stepDone);
          });
        }, "primary"))]);
    }, function (e) { u.clear(body); u.add(body, ui.error(e)); });
  }

  function stepDone() {
    function open(hash) { location.hash = "#" + hash; gz.app.startApp(); }
    frame(5, h("div", {},
      h("p", {}, "A lobby is where a host gathers members before a factory starts. Its terms are fixed and signed by the host."),
      ui.actions(ui.button("Add a host by its address", function () { open("/lobbies"); }, "primary"),
        ui.button("Host a lobby", function () { open("/host"); }),
        ui.button("Go to Home", function () { open("/"); })),
      h("p", { class: "small mute" }, "After you join, you wait until the lobby starts. Then the app signs by itself, and the factory goes live after a few confirmations. This wallet can also host from today. Hosting is always in the main menu."),
      h("p", { class: "dedi" }, "Gazpacho is dedicated to the developers who paid for our freedom to hold our own keys.")));
  }

  function setup(info, restored) {
    if (info.state === "none") { stepChoose(info); return; }
    if (restored) { stepPreset("restored"); return; }
    api.get("/backup").then(function (b) {
      if (b.words && b.words.checked_at) stepPreset(true);
      else stepResume();
    }, function () { stepResume(); });
  }

  gz.access = {
    noWallet: noWallet, hijack: hijack, signIn: signIn, filesBehind: filesBehind, setup: setup,
    wordsView: wordsView, checkForm: checkForm, revealInto: revealInto, ASKED: ASKED
  };
})();
