// SPDX-License-Identifier: MIT
/* The factory: waiting for funding, then live. "Live" is said only when the
   program says so: published funding is not live (spec/local-api.md 22).
   Calls: GET /factories/{id}, GET /factories/{id}/dates. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;

  function tree(f) {
    var t = f.tree || {}, hv = f.host_view && f.host_view.tree ? f.host_view.tree : null, list = h("ul", {});
    (t.levels || []).forEach(function (lv, i) {
      list.appendChild(h("li", {}, "Level " + (i + 1) + ": each branch splits in " + u.number(lv.width) + (lv.kind === "fixed" ? "" : " (" + String(lv.kind) + ")") + "."));
    });
    (t.path || []).forEach(function (p) {
      list.appendChild(h("li", {}, "Your place at level " + u.number(p.level) + ": branch " + u.number(p.index + 1) + " of " + u.number(p.of) + ", with " + u.count(p.members_below, "member", "members") + " below it."));
    });
    if (hv) list.appendChild(h("li", {}, "The whole tree has " + u.count(hv.leaves, "leaf", "leaves") + " for " + u.count(hv.members, "member", "members") + "."));
    return h("section", { class: "card" }, h("h2", {}, "The tree"),
      h("p", {}, "The factory's coins are shared through a tree of transactions that every member signed. Depth " + u.number(t.depth) + "; " + (t.leaf === "one_member" ? "one member at each leaf." : String(t.leaf) + ".")),
      list);
  }

  gz.screens.factory = {
    title: "Factory", nav: "home", topics: ["factory", "status"],
    render: function (params) {
      var id = params[0];
      return Promise.all([api.get("/factories/" + id), api.get("/factories/" + id + "/dates")]).then(function (r) {
        var f = r[0], dates = r[1].dates || [], fu = f.funding || {}, live = f.state === "live";
        return h("div", { id: "factory", "data-state": f.state },
          h("p", { class: "crumb" }, h("a", { href: "#/" }, "Home")),
          h("h1", {}, u.quoted(f.name)),
          h("p", {}, ui.pill(W.known(W.factoryStates, f.state), live ? "green" : "gold"), " ", f.role === "host" ? ui.pill("You host", "gold") : ui.pill("Member", "grey"),
            " ", u.count(f.members, "member", "members")),
          live ? ui.notice("ok", "Live.", "The funding is buried and this app holds the whole signed tree.")
            : f.state === "awaiting_funding" ? ui.notice("warn", "Not live yet.", "Everyone signed. The factory is live only once the host's funding has " + u.number(fu.needed) + " confirmations. Keep the app open.")
            : ui.notice("warn", W.known(W.factoryStates, f.state) + ".", f.still_watched ? "Gazpacho still watches it." : ""),
          h("section", { class: "card", id: "factory-funding" }, h("h2", {}, "Funding"), ui.facts([
            ["Amount", u.sats(fu.amount_sat), f.role === "host" ? "Your coins: you funded this factory." : "The host's coins. Members bring none."],
            ["State", W.known(W.funding, fu.state)],
            ["Confirmations", u.number(fu.confirmations) + " of " + u.number(fu.needed)],
            ["Transaction", u.shortHex(fu.txid)]
          ])),
          h("section", { class: "card" }, h("h2", {}, "What is yours here"),
            f.channel ? h("p", {}, "Channel of " + u.sats(f.channel.capacity_sat) + ".")
              : h("p", {}, f.role === "host" ? "You funded it. This build has no channels yet, so no payments run through it." : "Nothing of yours is inside: this build has no channels yet. You cannot pay or receive, and there is nothing to take out.")),
          h("section", { class: "card", id: "factory-dates" }, h("h2", {}, "Dates"), dates.length ? ui.dates(dates) : h("p", { class: "mute" }, "No dates.")),
          tree(f),
          h("section", { class: "card" }, h("h2", {}, "Host"), ui.facts([
            ["Host", u.quoted(f.host && f.host.alias)],
            ["Link", f.host && f.host.link === "connected" ? "Connected" : f.host ? String(f.host.link) : "unknown"]
          ])),
          ui.terms(f.terms, "Terms of this factory"),
          f.saved_copy_activity_id ? h("p", {}, h("a", { href: "#/activity/" + f.saved_copy_activity_id }, "The terms as they were when you joined (a saved copy that never changes)")) : null);
      });
    }
  };
})();
