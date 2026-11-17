// SPDX-License-Identifier: MIT
/* Home: my money, what the app is doing, my lobbies and factories, what needs
   me (in tiers), and the latest activity. Calls: GET /status, /lobbies,
   /factories, /host/lobbies, /activity, and /wallet/restore while restoring. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;

  function money(s) {
    var m = s.money || {}, grid = h("div", { class: "money" });
    grid.appendChild(h("div", {}, h("div", { class: "k" }, "On chain and free"),
      h("div", { class: "v", id: "money-free" }, u.number(m.on_chain_free_sat), " ", h("small", {}, "sats")),
      h("div", { class: "x" }, "In this wallet, outside any factory. ", h("a", { href: "#/settings" }, "Receive coins"))));
    if (m.set_aside_sat > 0) {
      grid.appendChild(h("div", {}, h("div", { class: "k" }, "Set aside for hosting"),
        h("div", { class: "v" }, u.number(m.set_aside_sat), " ", h("small", {}, "sats")),
        h("div", { class: "x" }, "Held for a lobby you host, at its target. Free again if it is cancelled.")));
    }
    grid.appendChild(h("div", {}, h("div", { class: "k" }, "Inside factories"),
      h("div", { class: "v" }, u.number(m.inside_factories_sat), " ", h("small", {}, "sats")),
      h("div", { class: "x" }, "This build has no channels yet, so nothing of yours is inside a factory. You cannot pay or receive yet.")));
    if (m.hosted_factories_sat > 0) {
      grid.appendChild(h("div", {}, h("div", { class: "k" }, "In factories you host"),
        h("div", { class: "v" }, u.number(m.hosted_factories_sat), " ", h("small", {}, "sats")),
        h("div", { class: "x" }, "Your own coins, funding factories you host, until they come back.")));
    }
    return h("div", {}, grid, m.chain_view === "in_doubt"
      ? ui.notice("warn", "These figures may be old.", "They are the last ones Gazpacho could trust, as of block " + u.number(m.as_of_height) + ". With the chain view in doubt it cannot tell whether anything changed since.")
      : null);
  }

  function attentionLink(a) {
    var p = a.params || {};
    if (a.code === "words_not_checked") return h("a", { href: "#/settings/words" }, "Check them");
    if (a.code === "host_can_start" && a.lobby_id) return h("a", { href: "#/host/lobby/" + a.lobby_id }, "Open the lobby");
    if (a.code === "refused_to_sign" && p.activity_id) return h("a", { href: "#/activity/" + p.activity_id }, "See the record");
    if (a.code.indexOf("chain_") === 0) return h("a", { href: "#/settings" }, "Connections");
    if (a.lobby_id) return h("a", { href: "#/lobby/" + a.lobby_id }, "Open the lobby");
    if (a.factory_id) return h("a", { href: "#/factory/" + a.factory_id }, "Open the factory");
    return null;
  }

  function todo(s) {
    var list = h("ul", { class: "tiers" }), items = s.attention || [];
    items.forEach(function (a) {
      list.appendChild(h("li", { "data-code": a.code },
        h("span", { class: "tier" + (a.tier === "at_risk" || a.tier === "act_now" ? " req" : a.tier === "important" ? " imp" : "") }, W.known(W.tiers, a.tier)),
        h("span", {}, W.known(W.attention, a.code), " ", attentionLink(a))));
    });
    return h("section", { class: "card", id: "todo" }, h("h2", {}, "To do"), items.length ? list : h("p", { class: "mute" }, "Nothing needs you now."));
  }

  function mine(lobbies, factories, hosted) {
    var ul = h("ul", { class: "log" }), n = 0;
    (lobbies.items || []).forEach(function (l) {
      if (!l.you || l.you.seat === "none") return;
      n++;
      ul.appendChild(h("li", {}, h("a", { href: "#/lobby/" + l.id }, u.quoted(l.name)), " ",
        ui.pill(W.known(W.stages, l.stage), l.stage === "active" ? "green" : "blue"), " ", ui.pill(W.known(W.seats, l.you.seat), "grey"),
        h("div", { class: "t" }, "Lobby you joined. " + u.number(l.counts.ready) + " ready; starts at " + u.number(l.start_rule.target) + ", or at its deadline with " + u.number(l.start_rule.minimum) + " or more.")));
    });
    (hosted.items || []).forEach(function (l) {
      n++;
      ul.appendChild(h("li", {}, h("a", { href: "#/host/lobby/" + l.id }, u.quoted(l.name)), " ",
        ui.pill(W.known(W.stages, l.stage), l.stage === "active" ? "green" : "blue"), " ", ui.pill("You host", "gold"),
        h("div", { class: "t" }, "Lobby you host. " + u.number(l.counts.ready) + " ready.")));
    });
    (factories.items || []).forEach(function (f) {
      n++;
      ul.appendChild(h("li", {}, h("a", { href: "#/factory/" + f.id }, u.quoted(f.name)), " ",
        ui.pill(W.known(W.factoryStates, f.state), f.state === "live" ? "green" : "gold"), " ", f.role === "host" ? ui.pill("You host", "gold") : null,
        h("div", { class: "t" }, "Factory with " + u.count(f.members, "member", "members") + ".")));
    });
    return h("section", { class: "card" }, h("h2", {}, "My lobbies and factories"),
      n ? ul : h("p", { class: "mute" }, "You are in no lobby and no factory."),
      ui.actions(h("a", { class: "btn primary", href: "#/lobbies" }, "Find a lobby"), h("a", { class: "btn", href: "#/host" }, "Host a lobby")));
  }

  function latest(act) {
    var ul = h("ul", { class: "log" });
    (act.items || []).slice(0, 3).forEach(function (a) {
      ul.appendChild(h("li", {}, h("span", { class: "t" }, u.dateTime(a.at) + " · "), W.known(W.activityKinds, a.kind),
        h("span", { class: "mute" }, " · decided by " + W.known(W.who, a.who_decided))));
    });
    return h("section", { class: "card" }, h("h2", {}, "Latest activity"), ul, h("p", {}, h("a", { href: "#/activity" }, "All activity")));
  }

  function restoring(r) {
    return h("section", { class: "card", id: "restoring" }, h("h2", {}, "Restoring this wallet"),
      ui.notice("warn", "Your balance is not confirmed yet.", "Gazpacho is reading the chain for this wallet's coins. Nothing can be joined or hosted until it has current data."),
      ui.facts([
        ["Stage", r.state === "scanning_chain" ? "Reading the chain" : r.state === "waiting_for_host" ? "Waiting for the host" : r.state === "done" ? "Done" : "unknown state (" + r.state + ")"],
        ["Coins found so far", u.sats(r.on_chain_found_sat)],
        ["Factories", W.known({ need_backup: "Not known and not watched. They come back only from a backup, which a later release adds.", none: "None", restored: "Restored" }, r.factories)]
      ]));
  }

  gz.screens.home = {
    title: "Home", nav: "home", topics: ["status", "lobby", "host_lobby", "factory", "activity", "wallet", "conditions", "chain"],
    render: function () {
      return gz.app.refreshStatus(true).then(function (s) {
        if (!s) throw new api.ApiError(0, null);
        return Promise.all([
          api.get("/lobbies?show=all"), api.get("/factories"), api.get("/host/lobbies"), api.get("/activity?limit=3"),
          s.wallet === "restoring" ? api.get("/wallet/restore") : null
        ]).then(function (r) {
          var d = W.doing(s);
          return h("div", {},
            h("h1", {}, "Home"),
            r[4] ? restoring(r[4]) : null,
            h("h2", {}, "My money"), money(s),
            h("p", { class: "next" + (s.doing && /unfinished|doubt|stopped|refused/.test(String(s.doing.code)) ? " loud" : ""), id: "next" },
              d.strong ? d.strong + " " : "", h("small", {}, d.rest)),
            h("div", { class: "cols" }, h("div", {}, mine(r[0], r[1], r[2])), h("div", {}, todo(s), latest(r[3]))));
        });
      });
    }
  };
})();
