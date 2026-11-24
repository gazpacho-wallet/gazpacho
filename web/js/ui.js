// SPDX-License-Identifier: MIT
/* Shared pieces of the screens: notices, the passphrase dialog, the sealed
   terms card, the fit check, dates. Everything is built with gz.util.h, so
   every value from the program is inserted as text. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words;

  function notice(kind, strong, text) {
    return h("div", { class: "notice" + (kind ? " " + kind : "") }, strong ? h("b", {}, strong) : null, text ? h("span", {}, " ", text) : null);
  }

  function error(e) {
    if (e && e.code === "cancelled") return null;
    return h("div", { class: "notice bad", role: "alert", "data-code": e && e.code ? e.code : "error" }, W.errorText(e));
  }

  function toast(text) {
    var box = document.getElementById("toasts"), t = h("div", { class: "toast" }, text);
    box.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, 6000);
  }

  function actions() {
    var el = h("div", { class: "actions" }), i;
    for (i = 0; i < arguments.length; i++) u.add(el, arguments[i]);
    return el;
  }

  function button(label, onclick, cls) {
    return h("button", { type: "button", class: "btn" + (cls ? " " + cls : ""), onclick: onclick }, label);
  }

  /* Run a promise-returning action from a button: the button is disabled while
     it runs, and a failure is shown in `where` (an element) in plain words. */
  function run(btn, where, fn) {
    var p;
    if (btn.disabled) return null;
    btn.disabled = true;
    if (where) { u.clear(where); where.removeAttribute("data-keep"); }
    try { p = fn(); } catch (e) { p = Promise.reject(e); }
    return Promise.resolve(p).then(function (r) {
      btn.disabled = false;
      return r;
    }, function (e) {
      btn.disabled = false;
      /* a live redraw may have replaced the box while the call ran: write to the one on screen */
      if (where && !where.isConnected && where.id && document.getElementById(where.id)) where = document.getElementById(where.id);
      if (where) {
        u.add(where, error(e instanceof gz.api.ApiError || (e && e.code) ? e : { code: "internal" }));
        where.setAttribute("data-keep", "");     /* a live redraw carries it over (app.js) */
      }
      return null;
    });
  }

  /* After rate_limited: the button stays off until the delay has passed, and says so. */
  function holdOff(btn, seconds, where) {
    var left = Math.max(1, Math.ceil(seconds)), line = h("p", { class: "small mute", role: "status" });
    btn.disabled = true;
    if (where) where.appendChild(line);
    (function tick() {
      if (!btn.isConnected) return;
      if (left <= 0) {
        btn.disabled = false;
        if (line.parentNode) line.parentNode.removeChild(line);
        return;
      }
      line.textContent = "You can try again in " + W.waitText(left) + ".";
      left -= 1;
      setTimeout(tick, 1000);
    })();
  }

  var fieldNo = 0;
  /* A labelled input. Returns { wrap, input }. */
  function field(label, attrs, hint) {
    var id = "f" + (++fieldNo), input, wrap;
    attrs = attrs || {};
    attrs.id = id;
    input = h(attrs.rows ? "textarea" : "input", attrs);
    wrap = h("div", { class: "field" }, h("label", { for: id }, label), input, hint ? h("p", { class: "small mute" }, hint) : null);
    return { wrap: wrap, input: input };
  }

  function passField(label, fresh, hint) {
    return field(label, { type: "password", autocomplete: fresh ? "new-password" : "current-password", autocapitalize: "off", spellcheck: "false" }, hint);
  }

  /* Ask for the wallet passphrase in a dialog and hand it to o.run. The field
     is emptied as soon as the request is sent (12.7). Resolves with run's
     result; rejects with { code: "cancelled" } if the person closes it. */
  var openDialogs = [];      /* the passphrase dialogs on screen, dropped with the session (12.7) */
  function dropDialogs() {
    openDialogs.slice().forEach(function (drop) { drop(); });
  }

  function askPassphrase(o) {
    return new Promise(function (resolve, reject) {
      var f = passField("Wallet passphrase", false);
      var msg = h("div", {});
      var go = h("button", { class: "btn primary", type: "submit" }, o.button || "Continue");
      var cancel = button("Cancel", function () { finish(); reject({ code: "cancelled" }); });
      var form = h("form", { novalidate: true },
        h("h2", { id: "ask-title" }, o.title), h("p", {}, o.why), o.extra || null, f.wrap, msg, actions(go, cancel));
      var dlg = h("dialog", { class: "dlg", "aria-labelledby": "ask-title" }, form);
      function drop() { finish(); reject({ code: "cancelled" }); }
      openDialogs.push(drop);
      function finish() {
        var i = openDialogs.indexOf(drop);
        if (i >= 0) openDialogs.splice(i, 1);
        f.input.value = "";
        if (dlg.open) dlg.close();
        if (dlg.parentNode) dlg.parentNode.removeChild(dlg);
      }
      form.addEventListener("submit", function (ev) {
        var pass = f.input.value.normalize("NFC");
        ev.preventDefault();
        f.input.value = "";
        u.clear(msg);
        if (!pass) { u.add(msg, notice("warn", "Type your passphrase first.")); f.input.focus(); return; }
        go.disabled = true;
        u.add(msg, h("p", { role: "status" }, "Checking…"));
        Promise.resolve().then(function () { return o.run(pass); }).then(function (r) {
          finish();
          resolve(r);
        }, function (e) {
          go.disabled = false;
          u.clear(msg);
          if (e && (e.code === "wrong_passphrase" || e.code === "rate_limited" || e.code === "passphrase_not_checked")) {
            u.add(msg, error(e));
            if (e.code === "rate_limited") holdOff(go, e.params.retry_after_s || 1, msg);
            f.input.focus();
          } else {
            finish();
            reject(e);
          }
        });
      });
      dlg.addEventListener("cancel", function (ev) { ev.preventDefault(); finish(); reject({ code: "cancelled" }); });
      document.body.appendChild(dlg);
      dlg.showModal();
      f.input.focus();
    });
  }

  /* A yes/no question in a dialog. Resolves true or false. */
  function confirm(o) {
    return new Promise(function (resolve) {
      var yes = button(o.yes || "Yes", function () { done(true); }, o.danger ? "danger" : "primary");
      var no = button(o.no || "Cancel", function () { done(false); });
      var dlg = h("dialog", { class: "dlg", "aria-labelledby": "confirm-title" },
        h("h2", { id: "confirm-title" }, o.title), o.body || null, actions(yes, no));
      function done(v) {
        if (dlg.open) dlg.close();
        if (dlg.parentNode) dlg.parentNode.removeChild(dlg);
        resolve(v);
      }
      dlg.addEventListener("cancel", function (ev) { ev.preventDefault(); done(false); });
      document.body.appendChild(dlg);
      dlg.showModal();
      no.focus();
    });
  }

  function facts(pairs) {
    var dl = h("dl", { class: "facts" });
    pairs.forEach(function (p) {
      if (!p) return;
      dl.appendChild(h("div", {}, h("dt", {}, p[0]), h("dd", {}, p[1], p[2] ? h("span", { class: "mute" }, p[2]) : null)));
    });
    return dl;
  }

  /* A value from a fit row or a term: a number, a word, a list or a range. */
  function value(v) {
    if (v === null || v === undefined) return "none";
    if (typeof v === "number") return u.number(v);
    if (typeof v === "string") return v;
    if (Array.isArray(v)) return v.map(value).join(", ");
    if (typeof v === "object") {
      if ("minimum" in v && "target" in v) return "at least " + u.number(v.minimum) + ", target " + u.number(v.target);
      if ("min" in v && "max" in v) {
        if (v.min === v.max) return u.number(v.min);
        return u.number(v.min) + " to " + u.number(v.max) + ("now" in v ? " (now " + u.number(v.now) + ")" : "");
      }
    }
    return "unknown value";
  }

  /* 13.4: the fit check, row by row, both sides on every row. */
  function fitTable(fit) {
    var table = h("table", { class: "fit" },
      h("caption", {}, W.known(W.fitClass, fit.class) + (fit.compared_with === "whole_range" ? ", compared with the host's whole range" : ", compared with the host's current values")),
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Term"), h("th", { scope: "col" }, "The lobby offers"), h("th", { scope: "col" }, "Your limit"), h("th", { scope: "col" }, "Result"))));
    var body = h("tbody", {});
    (fit.rows || []).forEach(function (r) {
      body.appendChild(h("tr", { class: r.result === "fails" ? "fail" : null },
        h("th", { scope: "row" }, W.known(W.fitTerms, r.term)),
        h("td", { "data-k": "Offers" }, value(r.offered)),
        h("td", { "data-k": "Your limit" }, value(r.yours)),
        h("td", { class: r.result === "fits" ? "yes" : r.result === "fails" ? "no" : "now" }, W.known(W.fitResults, r.result))));
    });
    table.appendChild(body);
    return h("div", { class: "tablewrap" }, table);
  }

  function range(r, now, unit) {
    if (!r) return "none";
    if (r.min === r.max) return u.number(r.min) + " " + unit;
    return u.number(r.min) + " to " + u.number(r.max) + " " + unit + (typeof now === "number" ? "; now " + u.number(now) + ". The host may move it inside this range until the ready check" : "");
  }

  /* 13.3: the host's sealed terms. Read-only everywhere; the host's own words
     are quoted as the host's, never in the app's voice. */
  function terms(t, title) {
    var o = t.outer || {}, cur = t.current && t.current.values ? t.current.values : {}, r = t.ranges || {}, d = t.derived || {};
    return h("section", { class: "sealed", "aria-label": title || "Terms" },
      h("header", {}, h("p", {}, h("b", {}, title || "Terms"),
        "Set and signed by host ", u.quoted(t.host && t.host.alias), " · ",
        t.signatures_checked ? "signature checked by this app" : "preview, not signed yet", " · you cannot change these")),
      t.fingerprint_short ? h("p", { class: "fp" }, "Fingerprint ", h("code", {}, t.fingerprint_short)) : null,
      h("div", { class: "grp" }, h("h3", {}, "The start"), facts([
        ["Starts", "at " + u.number(o.target) + " ready members, or at the deadline with " + u.number(o.minimum) + " or more"],
        ["Closes", u.dateTime(o.deadline_at)],
        ["If too few are ready", o.on_shortfall === "cancel" ? "the lobby is cancelled; nothing is signed" : W.known({}, o.on_shortfall)]
      ])),
      h("div", { class: "grp" }, h("h3", {}, "What you get"), facts([
        ["Channel size", u.sats(o.channel_sat)],
        ["Factory life", u.plural(o.lifetime_blocks, "block"), u.blocksAsTime(o.lifetime_blocks)],
        ["Leaving alone takes at most", u.plural(d.exit_blocks, "block"), u.blocksAsTime(d.exit_blocks)],
        ["Lobby type", String(o.profile)]
      ])),
      h("div", { class: "grp" }, h("h3", {}, "What it costs"), facts([
        ["Joining fee", range(r.joining_fee_sat, cur.joining_fee_sat, "sats")],
        ["Payment fee, fixed part", range(r.fee_base_msat, cur.fee_base_msat, "msat")],
        ["Payment fee, share", range(r.fee_ppm, cur.fee_ppm, "per million")]
      ])),
      o.description && o.description.text ? h("div", { class: "grp" }, h("h3", {}, "The host's note"),
        h("blockquote", { class: "hosttext" }, u.quoted(o.description), h("small", {}, "Written by the host. Gazpacho checks signatures, not what a note says."))) : null);
  }

  /* 7.2: dates, each with what happens at zero and where it comes from. */
  function dates(list) {
    var ul = h("ul", { class: "dates" });
    (list || []).forEach(function (d) {
      var prov = d.provenance && d.provenance.code ? W.lookup(W.provenance, d.provenance.code) : null;
      ul.appendChild(h("li", {},
        h("b", {}, W.known(W.dateKinds, d.kind)), " block " + u.number(d.due_height) +
          (typeof d.blocks_left === "number" && d.blocks_left >= 0 ? ", in " + u.plural(d.blocks_left, "block") + " (" + u.blocksAsTime(d.blocks_left) + ")" : ", passed") + ". ",
        d.at_zero ? h("span", {}, W.known(W.atZero, d.at_zero.code) + ".") : null,
        h("details", { class: "src" }, h("summary", {}, "Where this date comes from"),
          h("p", {}, d.source === "signed_term" ? "From the host's signed terms." : "Worked out by this app.", prov ? " " + prov + "." : ""))));
    });
    return ul;
  }

  function pill(text, colour) { return h("span", { class: "pill " + (colour || "grey") }, text); }

  gz.ui = {
    notice: notice, error: error, toast: toast, actions: actions, button: button, run: run, holdOff: holdOff,
    field: field, passField: passField, askPassphrase: askPassphrase, dropDialogs: dropDialogs, confirm: confirm, facts: facts, value: value,
    fitTable: fitTable, terms: terms, dates: dates, pill: pill
  };
})();
