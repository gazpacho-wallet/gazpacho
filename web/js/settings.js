// SPDX-License-Identifier: MIT
/* Settings (the words, on-chain coins, watching, connections, lock and
   sign-out), Activity with its saved copies, and About.
   Calls: GET /backup, GET /wallet, POST /wallet/address, GET /settings/connections,
   POST /wallet/phrase/reveal, …/check-start, …/check, DELETE /session,
   POST /wallet/lock, POST /session/revoke-all, GET /activity, GET /activity/{id}. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;

  function lockBox(status) {
    var msg = h("div", { id: "lock-msg" }), watch = status && status.watching && status.watching.state !== "nothing_to_watch";
    var out = ui.button("Sign out", function () { api.signOut(); });
    var lock = h("button", { type: "button", class: "btn danger", id: "lock" }, "Lock the wallet");
    var all = ui.button("Sign out everywhere", function () {
      var btn = this;
      ui.run(btn, msg, function () {
        return api.act("POST", "/session/revoke-all", { confirm: "revoke_all" }, { why: "This signs out every window and cancels every code, so Gazpacho asks for your passphrase." })
          .then(function () { api.dropSession("you"); });
      });
    });
    out.id = "sign-out";
    lock.addEventListener("click", function () {
      ui.confirm({
        title: "Lock the wallet?", yes: "Lock", danger: true,
        body: h("div", {},
          h("p", {}, "While locked, Gazpacho joins nothing, signs nothing and answers no host until you type your passphrase."),
          watch ? h("p", { id: "lock-warning" }, h("b", {}, "While locked, nobody watches your factories and nothing leaves in time. "), "Nothing of yours is inside them to take out; Gazpacho checks what happened when you unlock.") : null)
      }).then(function (yes) {
        var body = { confirm: "lock_wallet" };
        if (!yes) return;
        if (watch) body.confirm_locked = "nobody_watching";
        ui.run(lock, msg, function () {
          return api.act("POST", "/wallet/lock", body, { why: "Locking while something needs watching is like going offline, so Gazpacho asks for your passphrase." }).then(function (r) {
            if (r && r.wallet === "locked") { api.dropSession("locked"); return; }
            ui.toast("Your signatures are out, so the lock waits until signing ends.");
            gz.app.refreshStatus(false);
          });
        });
      });
    });
    return h("section", { class: "card", id: "session-box" }, h("h2", {}, "Sign out and lock"),
      h("p", {}, "Signing out closes this browser's session; the wallet stays unlocked and keeps working. Locking drops the wallet's key from memory: it then does nothing for you until you unlock it."),
      msg, ui.actions(out, all, lock));
  }

  function chainBox(c) {
    var rows = h("tbody", {}), hosts = h("ul", { class: "log" });
    ((c.chain && c.chain.servers) || []).forEach(function (s) {
      rows.appendChild(h("tr", {}, h("th", { scope: "row" }, String(s.name)), h("td", {}, String(s.operator)),
        h("td", {}, s.state === "ok" ? "Answering" : W.known({ catching_up: "Still loading", lagging: "Behind", disagrees: "Disagrees", unreachable: "Not answering" }, s.state)),
        h("td", {}, typeof s.height === "number" ? u.number(s.height) : "")));
    });
    (c.hosts || []).forEach(function (x) {
      hosts.appendChild(h("li", {}, String(x.address), h("div", { class: "t" }, "Key " + u.shortHex(x.key) + " · " + (x.source === "added" ? "added by you" : x.source === "built_in" ? "built in" : String(x.source)))));
    });
    return h("section", { class: "card", id: "connections" }, h("h2", {}, "Connections"),
      h("p", { class: "small mute" }, "Gazpacho trusts its view of the chain only while two servers from two different operators agree."),
      h("div", { class: "tablewrap" }, h("table", {}, h("caption", {}, "Chain servers"),
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Server"), h("th", { scope: "col" }, "Operator"), h("th", { scope: "col" }, "State"), h("th", { scope: "col" }, "Block"))), rows)),
      h("h3", {}, "Hosts the app knows"), (c.hosts || []).length ? hosts : h("p", { class: "mute" }, "None yet. Add one on Lobbies."));
  }

  function chainCoins(w) {
    var msg = h("div", {}), addr = h("div", { id: "address" });
    var btn = ui.button("Show a new address", function () {
      var b = this;
      ui.run(b, msg, function () {
        return api.call("POST", "/wallet/address", {}).then(function (r) {
          u.clear(addr);
          u.add(addr, [h("pre", { class: "addr" }, r.address), h("p", { class: "small mute" }, "A new address each time. Send only Signet test coins to it.")]);
        });
      });
    });
    return h("section", { class: "card", id: "onchain" }, h("h2", {}, "On chain"), ui.facts([
      ["Free", u.sats(w.free_sat)], ["Not confirmed yet", u.sats(w.unconfirmed_sat)], ["Set aside for hosting", u.sats(w.set_aside_sat)],
      ["Coins", u.count((w.coins || []).length, "coin", "coins")]
    ]), w.chain_view === "in_doubt" ? ui.notice("warn", "These figures may be old.", "The chain view is in doubt, as of block " + u.number(w.as_of_height) + ".") : null,
    addr, msg, ui.actions(btn));
  }

  gz.screens.settings = {
    title: "Settings", nav: "settings", topics: ["status", "chain", "settings", "wallet"],
    render: function () {
      return Promise.all([api.get("/backup"), api.get("/wallet"), api.get("/settings/connections")]).then(function (r) {
        var b = r[0].words || {}, s = gz.app.status || {}, wt = s.watching || {};
        return h("div", {},
          h("h1", {}, "Settings"),
          h("section", { class: "card", id: "words-box" }, h("h2", {}, "The 24 words"),
            h("p", { id: "words-state" }, b.checked_at ? "Checked on " + u.dateTime(b.checked_at) + "." : "Not checked yet. Without them written down correctly, a lost computer is a lost wallet."),
            ui.actions(h("a", { class: "btn", href: "#/settings/words" }, "Show or check the words"))),
          chainCoins(r[1]),
          h("section", { class: "card", id: "watching" }, h("h2", {}, "Watching"),
            h("p", {}, h("b", {}, "Who watches: "), W.known(W.watching, wt.state) + "."),
            h("p", { class: "small mute" }, "Watching runs only while the app runs, unlocked. In this build nothing of yours is inside a factory, so there is nothing to take out.")),
          chainBox(r[2]),
          lockBox(s),
          s.interface && s.interface.peer_check === "unavailable" ? ui.notice("warn", "Other accounts on this computer can reach Gazpacho's page;", "your passphrase is what keeps them out.") : null,
          h("p", {}, h("a", { href: "#/about" }, "About Gazpacho")));
      });
    }
  };

  /* The words, from Settings: shown with the passphrase typed for that request; checked the same way. */
  gz.screens.words = {
    title: "The 24 words", nav: "settings", topics: [],
    render: function () {
      var body = h("div", { id: "words-body" }), msg = h("div", {});
      function menu() {
        u.clear(body);
        u.add(body, [msg, ui.actions(
          ui.button("Show the 24 words", function () { gz.access.revealInto(body, msg, function () { u.clear(msg); menu(); }); }, "primary"),
          ui.button("Check the words", function () {
            u.clear(body);
            body.appendChild(gz.access.checkForm(function () { u.clear(msg); u.add(msg, ui.notice("ok", "Checked.", "Your words are written down correctly.")); gz.app.refreshStatus(false); menu(); },
              ui.button("Cancel", menu)));
          }))]);
      }
      menu();
      return Promise.resolve(h("div", {},
        h("p", { class: "crumb" }, h("a", { href: "#/settings" }, "Settings")),
        h("h1", {}, "The 24 words"),
        h("p", { class: "lead" }, "Your 24 words bring back your keys and on-chain coins on any computer. Anyone who has them has your keys."),
        h("p", { class: "small mute" }, gz.access.ASKED),
        body));
    }
  };

  /* ---- activity ---- */
  var show = "all";

  function entry(a) {
    var p = a.params || {}, more = [];
    if (Array.isArray(p.failures)) more.push(W.failuresText(p.failures));
    if (p.nothing_signed === true) more.push("Nothing was signed. Nothing moved.");
    return h("li", { "data-kind": a.kind },
      h("span", { class: "t" }, u.dateTime(a.at) + " · "), h("b", {}, W.known(W.activityKinds, a.kind)),
      h("span", { class: "mute" }, " · decided by " + W.known(W.who, a.who_decided) + (a.rule && a.rule.code ? ", under " + W.known(W.rules, a.rule.code) : "")),
      more.length ? h("div", {}, more.join(" ")) : null,
      a.kind === "refused" || a.kind === "joined" ? h("div", {}, h("a", { href: "#/activity/" + a.id }, "The saved copy")) : null);
  }

  gz.screens.activity = {
    title: "Activity", nav: "activity", topics: ["activity"],
    render: function () {
      return api.get("/activity?show=" + show).then(function (page) {
        var ul = h("ul", { class: "log", id: "activity" }), tabs = h("nav", { class: "sub", "aria-label": "Show" });
        [["all", "Everything"], ["by_app", "Done by the app alone"], ["refusals", "Refusals"]].forEach(function (t) {
          tabs.appendChild(h("a", { href: "#/activity", "aria-current": show === t[0] ? "page" : null, onclick: function (ev) { ev.preventDefault(); show = t[0]; gz.app.go("/activity"); } }, t[1]));
        });
        (page.items || []).forEach(function (a) {
          if (show === "refusals" && a.kind !== "refused") return;
          if (show === "by_app" && a.who_decided !== "the_app") return;
          ul.appendChild(entry(a));
        });
        return h("div", {}, h("h1", {}, "Activity"),
          h("p", { class: "lead" }, "What happened, newest first: what you did, and everything the app did by itself, with who decided and the rule that allowed it."),
          tabs, ul.firstChild ? ul : h("p", { class: "mute" }, "Nothing here yet."));
      });
    }
  };

  gz.screens.activityOne = {
    title: "Saved copy", nav: "activity", topics: [],
    render: function (params) {
      return api.get("/activity/" + params[0]).then(function (a) {
        var sc = a.saved_copy, cond = h("ul", {}), k;
        if (sc && sc.conditions) {
          for (k in sc.conditions) cond.appendChild(h("li", {}, W.known(W.conditionNames, k) + ": " + ui.value(sc.conditions[k])));
        }
        return h("div", {},
          h("p", { class: "crumb" }, h("a", { href: "#/activity" }, "Activity")),
          h("h1", {}, W.known(W.activityKinds, a.kind)),
          h("ul", { class: "log" }, entry(a)),
          sc ? h("div", {},
            ui.notice("", "A saved copy.", "Stored on " + u.dateTime(sc.saved_at) + ", when this happened. It never changes, whatever the lobby or your conditions are today."),
            sc.terms ? ui.terms(sc.terms, "The terms, as they were") : null,
            sc.fit ? h("div", {}, h("h2", {}, "The fit check, as it was"), ui.fitTable(sc.fit)) : null,
            h("h2", {}, "Your conditions, as copied then"), cond) : h("p", { class: "mute" }, "This entry has no saved copy."));
      });
    }
  };

  gz.screens.about = {
    title: "About", nav: "settings", topics: [],
    render: function () {
      var v = api.version || {};
      return Promise.resolve(h("div", { class: "longtext" },
        h("p", { class: "crumb" }, h("a", { href: "#/settings" }, "Settings")),
        h("h1", {}, "About Gazpacho"),
        h("p", {}, "Program " + String(v.program) + ", local API " + String(v.api) + ", network " + String(v.network) + "."),
        h("h2", {}, "Dedication"),
        h("p", {}, "Gazpacho is dedicated to the developers who paid for our freedom to hold our own keys."),
        h("h2", {}, "Credits"),
        h("p", {}, "The SuperScalar design by ZmnSCPxj and its reference code; libsecp256k1 and libsecp256k1-zkp; OpenSSL's libcrypto; libsodium; llhttp; the Lightning and Bitcoin specifications; the EFF's large word list for the suggested passphrase (CC BY 3.0 US); the BIP 39 English word list."),
        h("h2", {}, "Licences"),
        h("p", {}, "Gazpacho is under the MIT licence. The licence texts of the libraries it is built on come with the program's source.")));
    }
  };
})();
