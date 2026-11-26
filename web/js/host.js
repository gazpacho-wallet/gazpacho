// SPDX-License-Identifier: MIT
/* Hosting: always available, never a mode. Write terms with a live preview,
   open the lobby (the passphrase in the request), follow it, start it early,
   cancel it, remove a seat. Funding is published by the program itself.
   Calls: GET /host/lobbies, GET /wallet, POST /host/preview, POST /host/lobbies,
   GET /host/lobbies/{id}, POST …/start, POST …/cancel, DELETE …/seats/{seat}. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;

  gz.screens.host = {
    title: "Hosting", nav: "host", topics: ["host_lobby", "status", "wallet"],
    render: function () {
      return Promise.all([api.get("/host/lobbies"), api.get("/wallet")]).then(function (r) {
        var lobbies = r[0].items || [], w = r[1], ul = h("ul", { class: "log", id: "hosted" });
        lobbies.forEach(function (l) {
          ul.appendChild(h("li", {}, h("a", { href: "#/host/lobby/" + l.id }, u.quoted(l.name)), " ",
            ui.pill(W.known(W.stages, l.stage), l.stage === "active" ? "green" : "blue"),
            h("div", { class: "t" }, u.number(l.counts.ready) + " ready of " + u.number(l.terms.outer.target) + "; minimum " + u.number(l.terms.outer.minimum) + ".")));
        });
        return h("div", {},
          h("h1", {}, "Hosting"),
          h("p", { class: "lead" }, "Every wallet can host. You write the terms, members join, and you fund the factory; members bring no coins. Hosting needs the app to stay open until the factory is live."),
          h("section", { class: "card" }, h("h2", {}, "Coins for hosting"), ui.facts([
            ["On chain and free", u.sats(w.free_sat)],
            ["Set aside for lobbies you host", u.sats(w.set_aside_sat), "Free again if the lobby is cancelled."]
          ]), w.chain_view === "in_doubt" ? ui.notice("warn", "These figures may be old.", "The chain view is in doubt.") : null,
          h("p", { class: "small mute" }, "To host you need test coins in this wallet. ", h("a", { href: "#/settings" }, "Show an address to receive them"), ".")),
          h("section", { class: "card" }, h("h2", {}, "My lobbies"),
            lobbies.length ? ul : h("p", { class: "mute" }, "You host no lobby yet."),
            ui.actions(h("a", { class: "btn primary", href: "#/host/new", id: "write-terms" }, "Write terms for a lobby"))));
      });
    }
  };

  /* ---- write terms ---- */
  var draftState = null;     /* what is typed, kept while the screen is redrawn or revisited */
  var openRid = {};          /* request id per previewed draft (7.4) */

  function defaults() {
    return { name: "", description: "", target: 4, minimum: 3, hours: 6, channel_sat: 500000, lifetime_blocks: 4752,
      fee_now: 1000, fee_min: 500, fee_max: 1500, base_msat: 1000, ppm: 500, deadline_at: Math.floor(Date.now() / 1000) + 6 * 3600 };
  }

  function draftOf(d) {
    return {
      name: d.name, description: d.description, profile: "standard",
      target: d.target, minimum: d.minimum, deadline_at: d.deadline_at, on_shortfall: "cancel",
      ready_window_ms: 60000, signing_budget_ms: 600000, step_timeout_ms: 60000,
      lifetime_blocks: d.lifetime_blocks, winddown_blocks: 432,
      channel_sat: d.channel_sat, tree_feerate_sat_per_kvb: 100, shape: "default",
      joining_fee_sat: { now: d.fee_now, min: d.fee_min, max: d.fee_max },
      fee_base_msat: { now: d.base_msat, min: d.base_msat, max: d.base_msat },
      fee_ppm: { now: d.ppm, min: d.ppm, max: d.ppm },
      listed: true, switches: { names: false, chat: false, rule_requests: false },
      reserved: { spare_liquidity_sat: null, receiving_room_fee_ppm: null, admission: null, newcomer_seats_pct: null, invitation_only: null, move_window: null }
    };
  }

  gz.screens.hostNew = {
    title: "Write terms", nav: "host", topics: [],
    render: function () {
      var d = draftState || (draftState = defaults()), last = null, seq = 0, timer = null;
      var out = h("div", { id: "preview" }), msg = h("div", {});
      var open = h("button", { type: "submit", class: "btn primary", id: "open-lobby", disabled: true }, "Sign and open the lobby");
      var form = h("form", { novalidate: true, class: "mine" }, h("h2", {}, "The terms you set"));

      function num(key, label, unit, hint) {
        var f = ui.field(label, { type: "number", inputmode: "numeric", min: 0, step: 1, value: d[key], "data-key": key }, hint);
        f.input.addEventListener("input", function () {
          d[key] = /^\d+$/.test(f.input.value.trim()) ? Number(f.input.value.trim()) : 0;
          if (key === "hours") d.deadline_at = Math.floor(Date.now() / 1000) + d.hours * 3600;
          later();
        });
        if (unit) f.wrap.appendChild(h("span", { class: "unit" }, unit));
        return f.wrap;
      }
      function text(key, label, rows) {
        var f = ui.field(label, { type: "text", rows: rows || null, autocomplete: "off", value: rows ? null : d[key], "data-key": key });
        if (rows) f.input.value = d[key];
        f.input.addEventListener("input", function () { d[key] = f.input.value; later(); });
        return f.wrap;
      }
      function later() {
        open.disabled = true;
        clearTimeout(timer);
        timer = setTimeout(preview, 350);
      }
      function preview() {
        var mine = ++seq, draft = draftOf(d);
        api.call("POST", "/host/preview", draft).then(function (p) {
          var probs = h("ul", {}), cannot = h("ul", {});
          if (mine !== seq) return;
          last = { draft: draft, preview: p };
          (p.problems || []).forEach(function (pr) { probs.appendChild(h("li", { "data-problem": pr.code }, W.known(W.problems, pr.code))); });
          (p.cannot_open_because || []).forEach(function (c) { cannot.appendChild(h("li", { "data-cannot": c }, W.known(W.cannotOpen, c))); });
          u.clear(out);
          u.add(out, [
            (p.problems || []).length ? h("div", { class: "notice bad" }, h("b", {}, "The terms have problems."), probs) : null,
            h("section", { class: "card" }, h("h2", {}, "What it takes from this wallet"), ui.facts([
              ["Funding if it starts at the minimum", u.sats(p.funding_at_minimum_sat), p.covers && p.covers.minimum ? "This wallet covers it." : "This wallet does not cover it."],
              ["Funding if it starts at the target", u.sats(p.funding_at_target_sat), p.covers && p.covers.target ? "This wallet covers it. This amount is set aside when you open." : "This wallet does not cover it."],
              ["Chain fee, about", u.sats(p.chain_fee_estimate_sat)],
              ["On chain and free now", u.sats(p.wallet_free_sat)]
            ]), ui.dates((p.dates || []).concat(p.host_deadlines || []))),
            p.as_members_see_it ? ui.terms(p.as_members_see_it, "As members will see it") : null,
            p.can_open ? ui.notice("ok", "These terms can be opened.") : h("div", { class: "notice warn", id: "cannot-open" }, h("b", {}, "This lobby cannot be opened yet."), cannot)]);
          open.disabled = !p.can_open;
        }, function (e) {
          if (mine !== seq) return;
          u.clear(out);
          u.add(out, ui.error(e));
        });
      }

      u.add(form, [
        text("name", "Lobby name"), text("description", "A note for members (shown as your words)", 2),
        num("target", "Target: start at once when this many are ready", "members"),
        num("minimum", "Minimum: start at the deadline with at least this many", "members"),
        num("hours", "Closes in", "hours", "If fewer than the minimum are ready then, the lobby is cancelled and nothing is signed."),
        num("channel_sat", "Channel size for each member", "sats"),
        num("lifetime_blocks", "Factory life", "blocks"),
        num("fee_min", "Joining fee, lowest you may set", "sats"), num("fee_now", "Joining fee now", "sats"), num("fee_max", "Joining fee, highest you may set", "sats"),
        num("base_msat", "Payment fee, fixed part", "msat"), num("ppm", "Payment fee, share", "per million"),
        msg, ui.actions(open)]);

      form.addEventListener("submit", function (ev) {
        var snap = last;
        ev.preventDefault();
        if (!snap || !snap.preview.can_open) return;
        u.clear(msg);
        if (!openRid[snap.preview.draft_digest]) openRid[snap.preview.draft_digest] = u.requestId();
        ui.askPassphrase({
          title: "Sign and open this lobby?",
          why: "Opening sets aside " + u.sats(snap.preview.funding_at_target_sat) + ", the funding at the target. It is your consent to spend up to that amount when the lobby starts: the program then publishes the funding by itself, once every member's signed tree is complete and checked. Type your password to open.",
          button: "Sign and open",
          run: function (pass) {
            return api.call("POST", "/host/lobbies", { request_id: openRid[snap.preview.draft_digest], draft: snap.draft, draft_digest: snap.preview.draft_digest,
              confirm_funding_sat: snap.preview.funding_at_target_sat, passphrase: pass });
          }
        }).then(function (lobby) {
          delete openRid[snap.preview.draft_digest];
          draftState = null;
          ui.toast("The lobby is open.");
          gz.app.refreshStatus(false);
          gz.app.go("/host/lobby/" + lobby.id);
        }, function (e) {
          if (e.code !== "node_busy" && e.code !== "view_pending" && e.code !== "request_in_progress" && e.code !== "unreachable" && e.code !== "node_stopped" && e.code !== "cancelled") delete openRid[snap.preview.draft_digest];
          u.add(msg, ui.error(e));
          if (e.code === "draft_changed" || e.code === "confirm_mismatch") preview();
        });
      });

      preview();
      return Promise.resolve(h("div", {},
        h("p", { class: "crumb" }, h("a", { href: "#/host" }, "Hosting")),
        h("h1", {}, "Write terms"),
        h("p", { class: "lead" }, "These become the lobby's signed terms. Once opened, they cannot change: the joining fee can move only inside the range you set, and only until the ready check."),
        h("div", { class: "cols" }, h("div", {}, form), out)));
    }
  };

  /* ---- my lobby ---- */
  gz.screens.hostLobby = {
    title: "My lobby", nav: "host", topics: ["host_lobby", "status", "factory"],
    render: function (params) {
      var id = params[0];
      return api.get("/host/lobbies/" + id).then(function (l) {
        var msg = h("div", { id: "host-msg" }), o = l.terms.outer, open = l.stage === "open";
        var start = h("button", { type: "button", class: "btn primary", id: "start", disabled: !l.can_start_now }, "Start now");
        var cancel = h("button", { type: "button", class: "btn danger", id: "cancel" }, "Cancel this lobby");
        var seats = h("tbody", {}), anyLeft = false;

        start.addEventListener("click", function () {
          ui.run(start, msg, function () {
            return gz.acting("start:" + id, function (rid) {
              return api.act("POST", "/host/lobbies/" + id + "/start", { request_id: rid, confirm_funding_max_sat: l.funding.set_aside_sat },
                { why: "Starting early runs the ready check now and leads to spending up to " + u.sats(l.funding.set_aside_sat) + ", so Gazpacho asks for your password." });
            }).then(function () { ui.toast("The ready check is running."); gz.app.refreshStatus(false); gz.app.redraw(); });
          });
        });
        cancel.addEventListener("click", function () {
          ui.confirm({ title: "Cancel this lobby?", body: h("p", {}, "Members are told, nothing is signed, and the coins set aside are free again."), yes: "Cancel the lobby", no: "Keep it", danger: true }).then(function (yes) {
            if (!yes) return;
            ui.run(cancel, msg, function () {
              return gz.acting("cancel:" + id, function (rid) { return api.act("POST", "/host/lobbies/" + id + "/cancel", { request_id: rid }); })
                .then(function () { ui.toast("The lobby is cancelled."); gz.app.refreshStatus(false); gz.app.redraw(); });
            });
          });
        });

        (l.seats || []).forEach(function (s) {
          var rm = null;
          if (s.state === "left") anyLeft = true;
          if (s.can_remove) {
            rm = h("button", { type: "button", class: "btn small", "data-remove": s.seat }, "Remove");
            rm.addEventListener("click", function () {
              ui.confirm({ title: "Remove this member?", body: h("p", {}, "The member is told, with your removal signed. Only possible before the ready check."), yes: "Remove", danger: true }).then(function (yes) {
                if (!yes) return;
                ui.run(rm, msg, function () {
                  return gz.acting("seat:" + s.seat, function (rid) {
                    return api.act("DELETE", "/host/lobbies/" + id + "/seats/" + s.seat, { request_id: rid, confirm_seat: s.seat },
                      { why: "Removing a member changes who the lobby signs with, so Gazpacho asks for your password." });
                  }).then(function () { ui.toast("The member was removed."); gz.app.redraw(); });
                });
              });
            });
          }
          seats.appendChild(h("tr", { "data-seat-state": s.state }, h("th", { scope: "row" }, u.quoted(s.name)), h("td", {}, W.known(W.seats, s.state)), h("td", {}, rm)));
        });

        return h("div", { id: "host-lobby", "data-stage": l.stage },
          h("p", { class: "crumb" }, h("a", { href: "#/host" }, "Hosting")),
          h("h1", {}, u.quoted(l.name)),
          h("p", {}, ui.pill(W.known(W.stages, l.stage), l.stage === "active" ? "green" : "blue"), " ", ui.pill("You host", "gold")),
          h("section", { class: "card" }, h("h2", {}, "The start"),
            h("p", { id: "host-counts" }, h("b", {}, u.number(l.counts.ready) + " ready of " + u.number(o.target) + ". "), "Minimum " + u.number(o.minimum) + "."),
            h("p", {}, "The lobby starts by itself: at once when the target is ready, or at the deadline with the minimum or more. Below the minimum at the deadline, it is cancelled. You do not need to press anything."),
            open && !l.can_start_now ? h("p", { class: "small mute", id: "start-off" }, "Start now is off: " +
              ((l.start_blocked_by || []).indexOf("below_minimum") >= 0 ? "fewer than the minimum are ready." : (l.start_blocked_by || []).join(", ") + ".")) : null,
            open && l.can_start_now ? ui.notice("ok", "Enough members are ready.", "You can start now, or let it start by itself.") : null,
            msg, open ? ui.actions(start, cancel) : null),
          l.round ? h("section", { class: "card", id: "host-round" }, h("h2", {}, "The signing"),
            h("p", {}, h("b", {}, W.known(W.hostRounds, l.round.state) + ". "), u.number(l.round.answered) + " of " + u.number(l.round.of) + " members have answered." +
              (l.round.silent ? " " + u.count(l.round.silent, "member is", "members are") + " silent: the app's own observation, not proof." : "")),
            h("p", { class: "small mute" }, "Funding comes last. The app never signs the funding before every member's signed tree is complete and checked.")) : null,
          h("section", { class: "card", id: "host-funding" }, h("h2", {}, "Funding"), ui.facts([
            ["Needed at the minimum", u.sats(l.funding.needed_at_minimum_sat)],
            ["Needed at the target", u.sats(l.funding.needed_at_target_sat)],
            ["Set aside", u.sats(l.funding.set_aside_sat)],
            ["On chain and free", u.sats(l.funding.wallet_free_sat)],
            l.funding_tx ? ["Funding transaction", W.known(W.funding, l.funding_tx.state) + ", " + u.number(l.funding_tx.confirmations) + " of " + u.number(l.funding_tx.needed) + " confirmations", "Published by the app itself. " + u.shortHex(l.funding_tx.txid)] : null
          ]), l.factory_id ? h("p", {}, h("a", { class: "btn", href: "#/factory/" + l.factory_id }, "Open the factory")) : null),
          h("section", { class: "card" }, h("h2", {}, "Seats"),
            (l.seats || []).length ? h("div", { class: "tablewrap" }, h("table", { id: "seats" },
              h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Member"), h("th", { scope: "col" }, "Seat"), h("th", { scope: "col" }, h("span", { class: "sr" }, "Action")))), seats))
              : h("p", { class: "mute" }, "Nobody has joined yet."),
            l.counts.ready > (l.seats || []).length ? h("p", { class: "small mute" }, "Showing " + u.number((l.seats || []).length) + " of " + u.number(l.counts.ready) + " seats.") : null,
            anyLeft ? ui.notice("", "A member left at its own check.", "Its app refused before sending any signature, as it does when the offer is outside its conditions. Nothing was signed with it; the lobby went back to Open.") : null),
          ui.terms(l.terms, "The terms you signed"));
      });
    }
  };
})();
