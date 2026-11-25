// SPDX-License-Identifier: MIT
/* Finding a lobby and joining it; the waiting view; the signing moment and
   its refusals. Calls: POST /discovery/query, GET /discovery/queries/{id},
   GET /lobbies, GET /lobbies/{id}, POST …/join, PUT …/ready, POST …/leave. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;
  var draftHost = "";          /* what is typed in "add a host", kept across live redraws */
  var queryNote = null;        /* the last query's outcome, shown until the next one */
  var rids = {};               /* request ids, kept until their call has an outcome (7.4) */

  /* The same request id is sent again after "node busy" or a lost connection,
     so a retry can never act twice; any other outcome ends the id. The key
     names the body too (the digest, ready or not), so a kept id is never sent
     with a different body, which the program refuses (7.4). */
  function acting(key, send) {
    if (!rids[key]) rids[key] = u.requestId();
    gz.app.busy++;            /* no live redraw under a call in flight: its outcome must stay on screen */
    return send(rids[key]).then(function (r) {
      gz.app.busy = Math.max(0, gz.app.busy - 1);
      delete rids[key];
      return r;
    }, function (e) {
      gz.app.busy = Math.max(0, gz.app.busy - 1);
      if (e.code !== "node_busy" && e.code !== "view_pending" && e.code !== "request_in_progress" && e.code !== "unreachable" && e.code !== "node_stopped" && e.code !== "cancelled") delete rids[key];
      throw e;
    });
  }
  gz.acting = acting;

  /* The node-wide signing setting (14.3); at_join when it cannot be read, so the
     page asks for the passphrase rather than promise signing it may not do. */
  function signingSetting() {
    return api.get("/signing").catch(function () { return { member_signing: "at_join" }; });
  }
  function atJoin(sg) { return !sg || sg.member_signing !== "auto"; }

  /* A seat is locked (14.3 rule 3) while the status holds unlock_to_take_part for it. */
  function lockedIds() {
    var s = gz.app.status || {}, ids = [];
    (s.attention || []).forEach(function (a) {
      if (a.code === "unlock_to_take_part" && a.lobby_id && ids.indexOf(a.lobby_id) < 0) ids.push(a.lobby_id);
    });
    return ids;
  }

  /* Ready with the passphrase, asked in a dialog and emptied as soon as it is sent (12.7). */
  function readyWithPassphrase(l, title) {
    return ui.askPassphrase({
      title: title, button: "Mark ready", why: W.signing.at_join,
      run: function (pass) {
        return acting("ready:" + l.id + ":true:" + l.terms.current.digest, function (rid) {
          return api.act("PUT", "/lobbies/" + l.id + "/ready", { request_id: rid, ready: true, seen_current_digest: l.terms.current.digest, passphrase: pass });
        });
      }
    });
  }

  /* "Mark ready in all" (14.4 rule 7), after review M1. The digest sent for
     each lobby is the one drawn on this screen, beside that lobby's terms. A
     lobby whose values moved since the seat readied is listed with the change
     and left out; a change after the drawing is refused by the program
     (terms_changed) and listed the same way. One request id per press, kept
     after node busy, so a retry is a replay (7.4). */
  function changeText(tc) {
    return (tc && tc.changes || []).map(function (c) {
      return W.known(W.fitTerms, c.term) + " from " + ui.value(c.from) + " to " + ui.value(c.to);
    }).join("; ");
  }

  function readyAll(locked) {
    var msg = h("div", { id: "ready-all-msg" }), list = h("ul", { class: "log", id: "locked-list" }), send = [], key;
    var btn = h("button", { type: "button", class: "btn primary", id: "ready-all" }, "Mark ready in all");
    if (!locked.length) return null;
    locked.forEach(function (l) {
      var moved = !!l.terms_change && l.terms_change.effect !== "still_fits", r = l.terms.ranges || {};
      if (!moved) send.push({ lobby_id: l.id, seen_current_digest: l.terms.current.digest });
      list.appendChild(h("li", { "data-lobby": l.id, "data-moved": moved ? "yes" : "no" },
        h("a", { href: "#/lobby/" + l.id }, u.quoted(l.name)), " ",
        moved ? h("span", { class: "moved" }, "Left out: the terms changed since you readied (" + changeText(l.terms_change) + "). Review them in the lobby.")
          : h("span", { class: "mute" }, "Joining fee " + ui.value(r.joining_fee_sat) + " sats, a channel of " + u.sats(l.terms.outer.channel_sat) + ".")));
    });
    key = "ready-all:" + send.map(function (x) { return x.lobby_id + "=" + x.seen_current_digest; }).join(",");
    btn.disabled = !send.length;
    btn.addEventListener("click", function () {
      ui.run(btn, msg, function () {
        return ui.askPassphrase({
          title: "Mark ready in all", button: "Mark ready", why: W.signing.at_join,
          run: function (pass) {
            return acting(key, function (rid) { return api.call("POST", "/lobbies/ready", { request_id: rid, passphrase: pass, lobbies: send }); });
          }
        }).then(function (r) {
          var ok = 0, bad = [];
          (r && r.results || []).forEach(function (x) {
            var code = x.error && x.error.code;
            if (x.status === 202) { ok++; return; }
            bad.push(h("li", { "data-lobby": x.lobby_id, "data-code": code || "error" },
              h("a", { href: "#/lobby/" + x.lobby_id }, String(x.lobby_id)), ": ",
              code === "terms_changed" ? "not readied: the terms changed since this page was drawn. Review them in the lobby." : W.errorText(x.error || {})));
          });
          ui.toast("Ready again in " + u.plural(ok, "lobby").replace("lobbys", "lobbies") + ".");
          gz.app.refreshStatus(false).then(function () { gz.app.redraw(); });
          if (bad.length) {
            /* a live redraw may have replaced the card meanwhile: write to the one on screen, kept over redraws */
            var box = msg.isConnected ? msg : document.getElementById("ready-all-msg") || msg;
            u.add(box, [ui.notice("warn", "Some lobbies were not readied."), h("ul", { id: "ready-all-left" }, bad)]);
            box.setAttribute("data-keep", "");
          }
        });
      });
    });
    return h("section", { class: "card", id: "locked-seats" }, h("h2", {}, "Locked seats"),
      h("p", {}, u.plural(locked.length, "seat") + " of yours " + (locked.length === 1 ? "is" : "are") + " locked. " + W.LOCKED_SEAT),
      list, msg, ui.actions(btn));
  }

  function failing(fit) {
    return (fit && fit.rows ? fit.rows : []).filter(function (r) { return r.result === "fails" || r.result === "fits_now_only"; }).map(function (r) {
      return W.known(W.fitTerms, r.term) + ": the lobby offers " + ui.value(r.offered) + "; your limit is " + ui.value(r.yours) + ".";
    });
  }

  function fill(ready, target) {
    var tenths = target > 0 ? Math.max(0, Math.min(10, Math.round(ready * 10 / target))) : 0;
    return h("div", { class: "fillbar w" + tenths, role: "img", "aria-label": u.number(ready) + " ready of " + u.number(target) }, h("i", {}));
  }

  /* ---- the list ---- */
  function addHost() {
    var f = ui.field("Add a host by its address", { type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", placeholder: "host key@address:port", value: draftHost },
      "The host gives you this: its key, then @, then its address and port. Asking a host shows it this computer's network address.");
    var msg = h("div", { id: "query-note" }, queryNote);
    var go = h("button", { type: "submit", class: "btn primary" }, "Ask this host");
    var form = h("form", { novalidate: true, class: "card" }, f.wrap, msg, ui.actions(go));
    f.input.addEventListener("input", function () { draftHost = f.input.value; });
    function settle(q, tries) {
      return api.get("/discovery/queries/" + q.query_id).then(function (r) {
        if (r.state === "asking" && tries < 35) {
          return new Promise(function (ok) { setTimeout(ok, 1000); }).then(function () { return settle(q, tries + 1); });
        }
        return r;
      });
    }
    form.addEventListener("submit", function (ev) {
      var host = f.input.value.trim();
      ev.preventDefault();
      if (!host) { u.clear(msg); u.add(msg, ui.notice("warn", "Type the host's address first.")); return; }
      ui.run(go, msg, function () {
        u.add(msg, h("p", { role: "status" }, "Asking the host…"));
        return api.call("POST", "/discovery/query", { host: host }).then(function (q) { return settle(q, 0); }).then(function (r) {
          if (r.state === "answered") {
            queryNote = ui.notice("ok", "The host answered.", u.count((r.lobbies || []).length, "lobby", "lobbies") + " found. It is now on your list of known hosts.");
            draftHost = "";
          } else {
            queryNote = ui.notice("bad", "The host did not give its lobbies.",
              r.failed_because === "key_mismatch" ? "The machine at that address has a different key from the one you typed." :
              r.failed_because === "timed_out" ? "It did not answer within 30 seconds." :
              r.failed_because === "host_unreachable" ? "Nothing answers at that address." : "The query is still running; look again in a moment.");
          }
          gz.app.redraw();
        });
      });
    });
    return form;
  }

  function row(l) {
    var fits = l.fit && l.fit.class === "fits", why = failing(l.fit);
    return h("li", { class: fits ? null : "nofit", "data-lobby": l.id },
      h("div", { class: "nm" }, h("a", { href: "#/lobby/" + l.id }, u.quoted(l.name)), " ",
        ui.pill(W.known(W.stages, l.stage), "blue"), " ",
        l.you && l.you.seat !== "none" ? ui.pill(W.known(W.seats, l.you.seat), "green") : null,
        h("small", {}, "Host: ", u.quoted(l.host && l.host.alias), " · ", l.host ? String(l.host.address) : "")),
      h("div", { class: "row" },
        h("span", {}, h("b", {}, "Ready "), u.number(l.counts.ready) + " of " + u.number(l.start_rule.target) + " (starts with " + u.number(l.start_rule.minimum) + " or more)"),
        h("span", {}, h("b", {}, "Channel "), u.sats(l.channel_sat)),
        h("span", {}, h("b", {}, "Joining fee "), ui.value(l.joining_fee_sat) + " sats"),
        h("span", {}, h("b", {}, "Leaving alone "), u.plural(l.exit_blocks, "block"))),
      h("div", { class: "small" }, h("b", {}, W.known(W.fitClass, l.fit ? l.fit.class : null) + ". "), why.join(" ")));
  }

  gz.screens.lobbies = {
    title: "Lobbies", nav: "lobbies", topics: ["lobby", "conditions", "discovery", "status"],
    render: function () {
      /* The status first: it names the locked seats (unlock_to_take_part), and a
         live redraw may come before the strip's own read of it has returned. */
      return gz.app.refreshStatus(true).then(lobbiesRender);
    }
  };

  function lobbiesRender() {
      return Promise.all([api.get("/lobbies?show=all&sort=fit"), Promise.all(lockedIds().map(function (id) {
        return api.get("/lobbies/" + id).catch(function () { return null; });
      }))]).then(function (both) {
        var page = both[0], locked = both[1].filter(Boolean);
        var fit = h("ul", { class: "lob", id: "lobbies-fit" }), rest = h("ul", { class: "lob", id: "lobbies-rest" }), nf = 0, nr = 0;
        (page.items || []).forEach(function (l) {
          if (l.fit && l.fit.class === "fits") { nf++; fit.appendChild(row(l)); } else { nr++; rest.appendChild(row(l)); }
        });
        return h("div", {},
          h("h1", {}, "Lobbies"),
          h("p", { class: "lead" }, "A lobby is where a host gathers members before a factory starts. You can be in several lobbies at once."),
          readyAll(locked),
          addHost(),
          h("h2", {}, "Lobbies that fit your conditions"),
          nf ? fit : h("p", { class: "mute" }, nr ? "None of the lobbies the app knows fits your conditions." : "The app knows no lobby yet. Add a host by its address."),
          nr ? h("div", {}, h("h2", { class: "sep" }, "Do not fit, or fit only now"), rest) : null);
      });
  }

  /* ---- one lobby ---- */
  function outcome(l) {
    var o = l.you.outcome, r = l.round;
    if (!o) return null;
    switch (o.code) {
    case "refused_at_check":
      return ui.notice("bad", "Did not sign.", (Array.isArray(o.failures) && o.failures.length ? W.failuresText(o.failures) + " " : "") +
        (o.which && o.which !== "conditions" ? W.known(W.refusedWhich, o.which) + " " : "") +
        "The app refused at its own check, before sending anything. Nothing was signed. Nothing moved.");
    case "aborted_before_signatures": return ui.notice("warn", "Signing stopped before any signature.", "Nothing was signed. Nothing moved.");
    case "refused_by_host": return ui.notice("warn", "The host refused your seat.", "Nothing was signed. Nothing moved.");
    case "not_chosen": return ui.notice("", "Not chosen.", "The lobby started without you. Not your doing. Nothing was signed. Nothing moved.");
    case "cancelled": return ui.notice("warn", "Lobby cancelled.", (o.not_your_doing ? "Not your doing. " : "") + "Nothing was signed. Nothing moved.");
    case "left": return ui.notice("", "You left this lobby.", (o.reason === "paused" ? "Pause made the app leave. " : o.reason === "conditions_tightened" ? "Your tighter conditions made the app leave. " : "") + "Nothing was signed.");
    case "removed": return ui.notice("warn", "The host removed your seat", "before the ready check. Nothing was signed. Nothing moved.");
    case "signing_unfinished":
      return h("div", {}, ui.notice("bad", "Signing did not finish.", "Your app sent its signatures and no result came back. It treats both outcomes as possible and keeps watching until this is settled. Not live. Keep the app running." +
        (o.cancel_received ? " The host sent a cancel, which does not undo signatures already sent." : "")),
        r && r.unfinished_deadline ? ui.dates([r.unfinished_deadline]) : null);
    case "abandoned": return ui.notice("warn", "Start abandoned.", "Signatures went out, but the factory was not funded in time. You owe nothing and are owed nothing." + (o.still_watched ? " Gazpacho still watches in case the funding appears." : ""));
    case "dead": return ui.notice("warn", "This start can never be funded.", "The tree you signed can never be used. Nothing was owed.");
    case "started": return ui.notice("ok", "Signed and complete.", l.stage === "active" ? "The factory is live." : "Waiting for the host's funding. Not live yet.");
    default: return ui.notice("warn", "Unknown state (" + String(o.code) + ").", "This page does not know this outcome. See Activity.");
    }
  }

  function signing(l) {
    var r = l.round, list;
    if (!r) return null;
    list = h("ul", { class: "cl", id: "checks" });
    (r.checks || []).forEach(function (c) {
      list.appendChild(h("li", { "data-check": c.check, "data-ok": c.ok ? "yes" : "no" },
        h("span", { class: "ck" + (c.ok ? "" : " bad"), "aria-hidden": "true" }, c.ok ? "✓" : "✗"),
        h("span", {}, W.known(W.checks, c.check) + (c.ok ? "" : ": failed") + (c.params && typeof c.params.members === "number" ? " (" + u.count(c.params.members, "member", "members") + ")" : ""))));
    });
    return h("section", { class: "card", id: "signing" }, h("h2", {}, "The signing"),
      h("p", { id: "round-state" }, h("b", {}, W.known(W.rounds, r.state) + ". "),
        r.signatures ? u.number(r.signatures.done) + " of " + u.number(r.signatures.of) + " signatures. " : "",
        r.state === "checking" || r.state === "nonces_sent" || r.state === "signed" ? "Keep the app open." : ""),
      h("p", { class: "small mute" }, "The app checks these itself before it sends anything. If one fails, it refuses."),
      list);
  }

  function fundingCard(l) {
    var f = l.funding;
    if (!f) return null;
    return h("section", { class: "card", id: "funding" }, h("h2", {}, "The host's funding"),
      ui.facts([
        ["State", W.known(W.funding, f.state)],
        ["Confirmations", u.number(f.confirmations) + " of " + u.number(f.needed), f.confirmations >= f.needed ? null : "Not live until it has them all."],
        ["Transaction", u.shortHex(f.txid)]
      ]),
      f.deadline ? ui.dates([f.deadline]) : null,
      l.factory_id ? h("p", {}, h("a", { class: "btn", href: "#/factory/" + l.factory_id }, "Open the factory")) : null);
  }

  function joinBox(l, sg) {
    var msg = h("div", { id: "join-msg" }), cls = l.fit.class, r = l.terms.ranges || {}, ask = atJoin(sg);
    var btn = h("button", { type: "button", class: "btn primary", id: "join" }, "Join and be ready");
    var why = failing(l.fit);
    btn.disabled = cls !== "fits" || l.stage !== "open";
    btn.addEventListener("click", function () {
      var key = "join:" + l.id + ":" + l.terms.current.digest;
      function send(pass) {
        return acting(key, function (rid) {
          var body = { request_id: rid, seen_current_digest: l.terms.current.digest, ready: true };
          if (pass) body.passphrase = pass;
          return api.act("POST", "/lobbies/" + l.id + "/join", body);
        });
      }
      ui.run(btn, msg, function () {
        /* Under at_join the passphrase is asked in a dialog, which sits outside
           the view that live events redraw, and is emptied as it is sent
           (review M2; 12.7). A kept request id (after node busy) is sent
           again without it: a replay may omit it (7.4). */
        var p = ask && !rids[key] ? ui.askPassphrase({ title: "Join and be ready", button: "Join", why: W.signing.at_join, run: send }) : send(null);
        return p.then(function () { ui.toast("Joined. You are ready."); gz.app.refreshStatus(false); gz.app.redraw(); });
      });
    });
    return h("section", { class: "mine", id: "review" }, h("h2", {}, "Review and join"),
      ui.facts([
        ["It costs you at most", ui.value({ min: r.joining_fee_sat ? r.joining_fee_sat.max : 0, max: r.joining_fee_sat ? r.joining_fee_sat.max : 0 }) + " sats to join", "Taken later, from the first payment you receive. Members bring no coins."],
        ["You get", "a channel of " + u.sats(l.terms.outer.channel_sat)],
        ["It starts", "at " + u.number(l.start_rule.target) + " ready, or at the deadline with " + u.number(l.start_rule.minimum) + " or more; otherwise it is cancelled"]
      ]),
      ask ? ui.notice("", "Joining is your consent.", "When the lobby starts, the app signs for the terms you readied for, without asking again. If anything then differs from what you see here, it refuses before sending anything.")
        : ui.notice("", "Joining is your consent.", "When the lobby starts, the app signs by itself, without asking again. If anything then differs from what you see here, it refuses before sending anything."),
      ask ? h("p", { class: "small", id: "join-gate-words" }, "Joining ready asks for your passphrase. " + W.signing.at_join) : null,
      cls === "does_not_fit" ? ui.notice("bad", "Join is off: this lobby does not fit your conditions.", why.join(" ")) : null,
      cls === "fits_only_now" ? ui.notice("warn", "Join is off: this lobby fits only now.", "The host may move a value outside your limits before the start. " + why.join(" ")) : null,
      l.stage !== "open" ? ui.notice("warn", "This lobby is not open for joining any more.") : null,
      msg, ui.actions(btn, cls !== "fits" ? h("a", { class: "btn", href: "#/conditions" }, "See my conditions") : null));
  }

  function waiting(l, sg) {
    var msg = h("div", { id: "seat-msg" }), ready = l.you.seat === "ready", early = l.stage === "open";
    var locked = !ready && lockedIds().indexOf(l.id) >= 0;
    var toggle = h("button", { type: "button", class: "btn" + (locked ? " primary" : ""), id: "ready-toggle" }, ready ? "I am not ready" : locked ? "Mark ready" : "I am ready");
    var leaveBtn = h("button", { type: "button", class: "btn danger", id: "leave" }, "Leave this lobby");
    toggle.addEventListener("click", function () {
      ui.run(toggle, msg, function () {
        if (!ready && atJoin(sg)) {
          return readyWithPassphrase(l, locked ? "Mark ready again" : "Mark ready").then(function () { gz.app.refreshStatus(false); gz.app.redraw(); });
        }
        return acting("ready:" + l.id + ":" + !ready + ":" + l.terms.current.digest, function (rid) {
          return api.act("PUT", "/lobbies/" + l.id + "/ready", { request_id: rid, ready: !ready, seen_current_digest: l.terms.current.digest });
        }).then(function () { gz.app.refreshStatus(false); gz.app.redraw(); });
      });
    });
    leaveBtn.addEventListener("click", function () {
      ui.confirm({ title: "Leave this lobby?", body: h("p", {}, "You give up your seat. Nothing has been signed, so nothing is owed."), yes: "Leave", danger: true }).then(function (yes) {
        if (!yes) return;
        ui.run(leaveBtn, msg, function () {
          return acting("leave:" + l.id, function (rid) { return api.act("POST", "/lobbies/" + l.id + "/leave", { request_id: rid }); })
            .then(function () { ui.toast("You left the lobby."); gz.app.refreshStatus(false); gz.app.redraw(); });
        });
      });
    });
    return h("section", { class: "card", id: "waiting" }, h("h2", {}, "Your seat"),
      h("p", { id: "seat-line" }, h("b", {}, W.known(W.seats, l.you.seat) + ". "),
        l.you.seat === "joining" ? "Waiting for the host's answer." :
        l.you.seat === "chosen" ? "You are one of the members this start signs with." :
        locked ? W.LOCKED_SEAT :
        ready ? (l.you.counted ? "You are counted." : "You are not counted yet: fewer than " + u.number(l.fit.counted_from) + " are ready.") :
        "You are not counted until you say you are ready."),
      h("p", { id: "counts" }, u.number(l.counts.ready) + " ready of " + u.number(l.start_rule.target) + ". It starts at " + u.number(l.start_rule.target) + ", or at its deadline with " + u.number(l.start_rule.minimum) + " or more; otherwise it is cancelled and nothing is signed."),
      fill(l.counts.ready, l.start_rule.target),
      early && l.start_rule.deadline ? ui.dates([l.start_rule.deadline]) : null,
      l.you.conditions_copied_at ? h("p", { class: "small mute" }, "Your conditions were copied into this lobby when you joined (" + u.dateTime(l.you.conditions_copied_at) + "). The app checks the start against that copy.") : null,
      l.you.appear_as ? h("p", { class: "small mute" }, "You appear here as ", u.quoted(l.you.appear_as), ".") : null,
      !ready && atJoin(sg) && early ? h("p", { class: "small mute", id: "gate-words" }, W.signing.at_join) : null,
      msg, early ? ui.actions(toggle, leaveBtn) : null);
  }

  /* 14.6: what this member can know of the host's choices. In Slice 1 nothing
     is signed: no count, total or "nobody" line, and a removal is what the host said. */
  function accountability(a) {
    var body = [], c = a && a.counts;
    if (!a) return null;
    if (a.signed === true && c) {
      [["removed_by_host", "removed"], ["left", "saw leave"], ["refused_at_check", "saw refuse at their own check"]].forEach(function (k) {
        if (typeof c[k[0]] === "number") body.push(h("p", { "data-count": k[0] }, "The host signed that it " + k[1] + " " + u.count(c[k[0]], "seat", "seats") + "."));
      });
    } else {
      body.push(h("p", { id: "own-view" }, "Your app sees only what happened to your own seat. The host signs nothing about the others in this release, so no count is shown."));
    }
    (a.removal_reasons || []).forEach(function (r) {
      body.push(h("p", { class: "removal" }, (a.signed === true ? "The host signed: " : "The host said: "), u.quoted(r.reason)));
    });
    (a.contradictions || []).forEach(function (x) {
      body.push(ui.notice("bad", "Your app saw something the host's signed counts deny.", x.code === "own_removal_not_counted" ? "Your own removal is not in the host's count." : String(x.code)));
    });
    return h("section", { class: "card", id: "accountability" }, h("h2", {}, "What the host did"), body);
  }

  gz.screens.lobby = {
    title: "Lobby", nav: "lobbies", topics: ["lobby", "status", "conditions"],
    render: function (params) {
      var id = params[0];
      return Promise.all([api.get("/lobbies/" + id).catch(function (e) {
        if (e.code !== "not_found") throw e;
        /* a lobby this program hosts is under Hosting */
        return api.get("/host/lobbies/" + id).then(function () { gz.app.go("/host/lobby/" + id); return null; }, function () { throw e; });
      }), signingSetting()]).then(function (both) {
        var seat, inIt, l = both[0], sg = both[1];
        if (!l) return h("p", {}, "Opening…");
        seat = l.you ? l.you.seat : "none";
        inIt = seat === "joining" || seat === "joined_not_ready" || seat === "ready" || seat === "chosen";
        return h("div", { "data-stage": l.stage, "data-seat": seat, id: "lobby" },
          h("p", { class: "crumb" }, h("a", { href: "#/lobbies" }, "Lobbies")),
          h("h1", {}, u.quoted(l.name)),
          h("p", {}, ui.pill(W.known(W.stages, l.stage), l.stage === "active" ? "green" : "blue"), " ", ui.pill(W.known(W.seats, seat), inIt ? "green" : "grey"),
            " Host: ", u.quoted(l.host && l.host.alias), " · ", l.host ? String(l.host.address) : ""),
          outcome(l),
          inIt ? waiting(l, sg) : null,
          signing(l),
          fundingCard(l),
          accountability(l.accountability),
          l.terms_change ? ui.notice("warn", "The host moved a value.", "From version " + u.number(l.terms_change.from_version) + " to " + u.number(l.terms_change.to_version) + ". Read the terms below again.") : null,
          h("div", { class: "cols" },
            h("div", {}, ui.terms(l.terms, "Terms of this lobby")),
            h("div", {}, h("h2", {}, "Fit check"), ui.fitTable(l.fit), !inIt && l.stage !== "active" && l.stage !== "funding" ? joinBox(l, sg) : null)));
      });
    }
  };
})();
