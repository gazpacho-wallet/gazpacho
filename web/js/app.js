// SPDX-License-Identifier: MIT
/* Start-up, the gate (first run, sign-in), the always-present strip, the
   router and live redraws. A screen is { nav, topics, render(params) } in
   gz.screens; render returns a Promise of a node. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;
  var view = document.getElementById("view");
  var main = document.getElementById("main");
  var app = { status: null, busy: 0 };
  var cleanup = [];         /* each clears secrets of the view on screen (12.7) */
  var current = null;       /* { screen, params, hash } */
  var drawNo = 0;
  var inApp = false;

  /* ---- views ---- */
  function leave() {
    var fns = cleanup;
    cleanup = [];
    fns.forEach(function (fn) { try { fn(); } catch (e) { /* the view is gone either way */ } });
  }
  app.onLeave = function (fn) { cleanup.push(fn); };

  /* A live redraw must not wipe what an action just said: a message box that
     holds an error (data-keep) is carried into the box of the same id. */
  function carry(node) {
    var keep = view.querySelectorAll("[data-keep]"), i, to;
    for (i = 0; i < keep.length; i++) {
      to = keep[i].id ? node.querySelector("#" + keep[i].id) : null;
      if (!to || to.firstChild) continue;
      while (keep[i].firstChild) to.appendChild(keep[i].firstChild);
      to.setAttribute("data-keep", "");
    }
  }

  function show(node, focus) {
    var h1;
    if (!focus && node.querySelector) carry(node);
    u.clear(view);
    view.appendChild(node);
    if (focus) {
      h1 = view.querySelector("h1");
      if (h1) { h1.setAttribute("tabindex", "-1"); h1.focus(); } else main.focus();
      window.scrollTo(0, 0);
    }
  }

  function gate(node) {
    leave();
    inApp = false;
    current = null;
    document.body.setAttribute("data-chrome", "gate");
    document.title = "Gazpacho";
    show(h("div", { class: "gate" }, node), true);
  }
  app.gate = gate;
  app.wide = function (node) {
    leave();
    inApp = false;
    current = null;
    document.body.setAttribute("data-chrome", "gate");
    show(h("div", { class: "wide" }, node), true);
  };

  /* ---- start-up ---- */
  function unreachable(e) {
    gate(h("div", { class: "card" }, h("h1", {}, "Gazpacho is not answering"),
      h("p", {}, W.errorText(e)),
      ui.actions(ui.button("Try again", function () { boot(null); }, "primary"))));
  }

  function refuse(title, text) {
    gate(h("div", { class: "card" }, h("h1", {}, title), h("p", {}, text)));
  }

  function boot(startToken) {
    api.boot().then(function (s) {
      var v = api.version || {};
      if (typeof v.api !== "string" || v.api.split(".")[0] !== "1") {
        refuse("This page and the program do not match", "Reload the page. If that does not help, restart Gazpacho.");
        return null;
      }
      /* Real bitcoin is refused: this interface works on test networks only. */
      if (v.network !== "signet" && v.network !== "testnet4") {
        refuse("Gazpacho does not run on mainnet", "This release works with test coins only (Signet). It will not open a wallet on a network with real bitcoin.");
        return null;
      }
      setNetwork({ id: v.network, test_coins: true });
      return decide(s, startToken);
    }).catch(unreachable);
  }

  function hijackOrPlain(s, e) {
    var launched = s && typeof s.first_run_launched_at === "number" ? s.first_run_launched_at : null;
    if ((e.code === "token_used" || e.code === "wallet_exists") && launched !== null && Date.now() / 1000 - launched < 600) {
      gz.access.hijack();
    } else if (s.wallet === "none") {
      gz.access.noWallet(e.code === "token_used" ? null : e);
    } else {
      gz.access.signIn(null);
    }
  }

  function decide(s, startToken) {
    if (s.signed_in) return enter();
    if (startToken) {
      /* the first-run start token (4.3): presented once, in a request body */
      return api.start({ start_token: startToken }).then(enter, function (e) { hijackOrPlain(s, e); });
    }
    if (s.wallet === "none") { gz.access.noWallet(null); return null; }
    if (s.handover) {
      return api.askOtherTabs().then(function (session) {
        if (!session) { gz.access.signIn(null); return null; }
        return api.adopt(session).then(function (s2) {
          if (s2.signed_in) return enter();
          gz.access.signIn(null);
          return null;
        });
      });
    }
    gz.access.signIn(null);
    return null;
  }

  /* A session exists: setup, the files-behind choice, or the app itself. */
  function enter() {
    var s = api.session || {};
    if (s.kind === "files_behind" || s.wallet === "files_behind") { gz.access.filesBehind(); return null; }
    return api.get("/wallet/setup").then(function (setup) {
      if (setup.state === "none" || setup.state === "created_not_finished") { gz.access.setup(setup); return; }
      startApp();
    }).catch(function (e) {
      if (e.code !== "not_signed_in" && e.code !== "wallet_locked") unreachable(e);
    });
  }
  app.enter = enter;

  app.signedOut = function (reason) {
    leave();
    app.busy = 0;
    inApp = false;
    app.status = null;
    api.refreshSession().then(function (s) {
      if (s.wallet === "none") gz.access.noWallet(null);
      else gz.access.signIn(s.wallet === "locked" && reason !== "check_failed" ? "locked" : reason);
    }, unreachable);
  };

  /* ---- the app: strip, router, live redraws ---- */
  function startApp() {
    inApp = true;
    document.body.setAttribute("data-chrome", "app");
    api.startEvents();
    refreshStatus(false).then(function () { route(true); });
  }
  app.startApp = startApp;

  function setNetwork(n) {
    var el = document.getElementById("network");
    el.hidden = false;
    el.textContent = n.id === "signet" ? "Signet: test coins, no value" : String(n.id) + (n.test_coins ? ": test coins, no value" : "");
  }

  function chip(label, text, href, dot) {
    return h(href ? "a" : "span", { class: "chip", href: href || null },
      dot ? h("span", { class: "dot " + dot }) : null, h("b", {}, label + ":"), " ", text);
  }

  function drawStrip() {
    var s = app.status, d, say = document.getElementById("doing"), pause = document.getElementById("pause");
    var chips = document.getElementById("chips"), alerts = document.getElementById("alerts"), ch, wt, st, state;
    if (!s || !s.doing) return;
    if (s.network) setNetwork(s.network);
    d = W.doing(s);
    u.clear(say);
    if (d.strong) say.appendChild(h("b", {}, d.strong + " "));
    u.add(say, d.rest + " ");
    if (s.doing.params && s.doing.params.factory_id) say.appendChild(h("a", { href: "#/factory/" + s.doing.params.factory_id }, "Open the factory"));
    else if (s.doing.lobby_id) say.appendChild(h("a", { href: "#/lobby/" + s.doing.lobby_id }, "Open the lobby"));
    state = s.pause ? s.pause.state : "off";
    pause.className = "pp" + (state === "on" ? " resume" : "");
    pause.disabled = state === "held_for_signing";
    pause.textContent = state === "on" ? "Resume" : state === "held_for_signing" ? "Pausing…" : "Pause";
    pause.title = state === "off" ? "Sign nothing new and join nothing until I resume" : state === "on" ? "Join and sign again" : "Pause takes effect when signing ends";
    pause.setAttribute("data-state", state);

    u.clear(chips);
    ch = s.connection && s.connection.chain ? s.connection.chain : {};
    chips.appendChild(chip("Chain", W.known(W.chain, ch.state) + (typeof ch.height === "number" ? ", block " + u.number(ch.height) : ""),
      "#/settings", ch.state === "agree" || ch.state === "lagging" ? "" : "bad"));
    wt = s.watching || {};
    chips.appendChild(chip("Watching", W.known(W.watching, wt.state), "#/settings", String(wt.state).indexOf("nobody") === 0 ? "bad" : null));
    chips.appendChild(chip("Next date", s.next_date ? W.dateText(s.next_date) + ". " + (s.next_date.at_zero ? W.known(W.atZero, s.next_date.at_zero.code) : "") : "none", null, null));
    if (s.hosting) {
      chips.appendChild(chip("Hosting", u.plural(s.hosting.lobbies_open, "lobby open").replace("lobby opens", "lobbies open") + ", " + u.plural(s.hosting.factories, "factory").replace("factorys", "factories"), "#/host", null));
    }
    st = api.streamState();
    chips.appendChild(h("span", { class: "chip", id: "live-chip", "data-state": st },
      h("span", { class: "dot " + (st === "open" ? "" : st === "too_many" ? "warn" : "bad") }), h("b", {}, "Live updates:"), " ",
      st === "open" ? "following the app" : st === "reconnecting" ? "reconnecting… what you see may be old" :
      st === "too_many" ? "too many windows are following this app; this one updates through another window" :
      st === "not_following" ? "Not following the app: what you see may be old" : "stopped"));

    u.clear(alerts);
    (s.attention || []).forEach(function (a) {
      if (a.tier !== "at_risk") return;
      alerts.appendChild(h("div", { class: "alertbar risk", role: "alert", "data-code": a.code },
        h("b", {}, "At risk: "), W.known(W.attention, a.code), " ",
        a.lobby_id ? h("a", { href: "#/lobby/" + a.lobby_id }, "What the app does") : h("a", { href: "#/settings" }, "Connections")));
    });
    if (s.lock && s.lock.state === "held_for_signing") {
      alerts.appendChild(h("div", { class: "alertbar info", role: "status" }, h("b", {}, "Locking when signing ends. "), "Your signatures are out, so the lock waits for the round to end."));
    }
    if (s.interface && s.interface.memory_locked === false) {
      alerts.appendChild(h("div", { class: "alertbar info" }, "Your system did not let Gazpacho keep its keys out of the swap file. Full-disk encryption protects against this."));
    }
  }

  function refreshStatus(background) {
    return api.get("/status", { background: background }).then(function (s) {
      app.status = s;
      drawStrip();
      return s;
    }).catch(function (e) {
      if (e.code === "not_signed_in" || e.code === "wallet_locked") return null;
      if (inApp) {
        u.clear(document.getElementById("alerts")).appendChild(h("div", { class: "alertbar risk", role: "alert", "data-code": e.code }, W.errorText(e)));
      }
      return null;
    });
  }
  app.refreshStatus = refreshStatus;

  var routes = [
    [/^\/?$/, "home"], [/^\/lobbies$/, "lobbies"], [/^\/lobby\/([A-Za-z0-9_-]{1,64})$/, "lobby"],
    [/^\/conditions$/, "conditions"], [/^\/activity$/, "activity"], [/^\/activity\/([A-Za-z0-9_-]{1,64})$/, "activityOne"],
    [/^\/host$/, "host"], [/^\/host\/new$/, "hostNew"], [/^\/host\/lobby\/([A-Za-z0-9_-]{1,64})$/, "hostLobby"],
    [/^\/factory\/([A-Za-z0-9_-]{1,64})$/, "factory"], [/^\/settings$/, "settings"], [/^\/settings\/words$/, "words"],
    [/^\/about$/, "about"]
  ];

  function parse() {
    var path = location.hash.replace(/^#/, ""), i, m;
    for (i = 0; i < routes.length; i++) {
      m = routes[i][0].exec(path);
      if (m) return { name: routes[i][1], params: m.slice(1), hash: path };
    }
    return { name: "home", params: [], hash: "/" };
  }

  function markNav(nav) {
    var links = document.querySelectorAll("[data-nav]"), i;
    for (i = 0; i < links.length; i++) {
      if (links[i].getAttribute("data-nav") === nav) links[i].setAttribute("aria-current", "page");
      else links[i].removeAttribute("aria-current");
    }
  }

  /* Draw the screen the address names. fresh: a navigation (focus moves to the
     heading); otherwise a live redraw (focus and scroll stay where they were). */
  function route(fresh) {
    var r, screen, no, focusId, scroll;
    if (!inApp) return;
    r = parse();
    screen = gz.screens[r.name];
    if (fresh || !current || current.hash !== r.hash) fresh = true;
    leave();                  /* the old view's secrets go before any redraw replaces it */
    current = { screen: screen, hash: r.hash };
    no = ++drawNo;
    markNav(screen.nav);
    document.title = screen.title + " · Gazpacho";
    focusId = !fresh && document.activeElement ? document.activeElement.id : null;
    scroll = window.scrollY;
    if (fresh) show(h("p", { role: "status" }, "Loading…"), false);
    /* a live redraw is caused by an event: its requests never refresh the idle timer (10.2) */
    (fresh ? Promise.resolve().then(function () { return screen.render(r.params); })
      : api.quietly(function () { return screen.render(r.params); })).then(function (node) {
      var el;
      if (no !== drawNo || !inApp) return;
      show(node, fresh);
      if (!fresh) {
        el = focusId ? document.getElementById(focusId) : null;
        if (el) el.focus();
        window.scrollTo(0, scroll);
      }
    }, function (e) {
      if (no !== drawNo || !inApp) return;
      if (e && (e.code === "not_signed_in" || e.code === "wallet_locked")) return;
      show(h("div", {}, h("h1", {}, screen.title), ui.error(e && e.code ? e : { code: "internal" }),
        ui.actions(ui.button("Try again", function () { route(true); }, "primary"))), fresh);
    });
  }
  app.redraw = function () { route(false); };
  app.go = function (hash) {
    if (location.hash === "#" + hash) route(true);
    else location.hash = "#" + hash;
  };

  window.addEventListener("hashchange", function () {
    /* a start token is read only at load; one that arrives later is taken out of the address and never presented */
    if (location.hash.indexOf("#start=") === 0) { history.replaceState(null, "", location.pathname); return; }
    route(true);
  });

  /* Live updates: an event names an area; the page asks again for what it shows.
     These requests never refresh the idle timer (10.2). */
  var pending = {}, flush = null;
  api.onEvent(function (ev) {
    if (!inApp) return;
    if (ev.topic === "stream_state") { drawStrip(); return; }
    pending[ev.topic] = true;
    if (flush) return;
    flush = setTimeout(function () {
      var topics = pending, redraw = false, t;
      pending = {};
      flush = null;
      if (topics.status || topics.chain || topics.reset || topics.wallet) refreshStatus(true);
      if (current && current.screen.topics) {
        /* a screen with no topics (the words, a form) is never drawn again under the person, not even on a reset */
        for (t in topics) if (current.screen.topics.length && (topics.reset || current.screen.topics.indexOf(t) >= 0)) redraw = true;
      }
      if (topics.wallet && app.status && app.status.wallet === "restoring") {
        api.get("/wallet/setup", { background: true }).then(function (setup) {
          if (setup.state === "created_not_finished") gz.access.setup(setup, true);
        }, function () { return null; });
      }
      if (redraw && !app.busy) route(false);
    }, 150);
  });

  /* Not following (10.3, review M5): while this tab has a lobby, it reads the
     status every 5 s until a stream or a relay returns, so a ready check is not
     missed. Background requests: they never refresh the idle timer (4.7). */
  setInterval(function () {
    var s = app.status;
    if (!inApp || !s || api.streamState() !== "not_following") return;
    if (!((s.lobbies && s.lobbies.length) || (s.doing && s.doing.lobby_id))) return;
    refreshStatus(true).then(function () {
      if (!app.busy && current && current.screen.topics && current.screen.topics.length && api.streamState() === "not_following") route(false);
    });
  }, 5000);

  /* ---- always-present controls ---- */
  document.querySelector("a.skip").addEventListener("click", function (ev) {
    ev.preventDefault();      /* the address holds the route, so the skip link moves focus itself */
    main.focus();
  });

  document.getElementById("more").addEventListener("click", function () {
    var strip = document.getElementById("strip"), open = !strip.classList.contains("open");
    strip.classList.toggle("open", open);
    this.setAttribute("aria-expanded", open ? "true" : "false");
  });

  document.getElementById("pause").addEventListener("click", function () {
    var btn = this, on = btn.getAttribute("data-state") !== "on";
    ui.run(btn, document.getElementById("alerts"), function () {
      return api.act("PUT", "/pause", on ? { on: true } : { on: false, confirm: "resume" },
        { why: "Resuming lets Gazpacho join and sign again, so it asks for your passphrase first." }).then(function (r) {
        if (r && r.left_lobbies && r.left_lobbies.length) ui.toast("Paused. Gazpacho left " + u.plural(r.left_lobbies.length, "lobby").replace("lobbys", "lobbies") + " that had not started.");
        else if (r && r.held_lobby) ui.toast("Pause pressed. It takes effect when signing ends.");
        else ui.toast(on ? "Paused." : "Resumed.");
        return refreshStatus(false).then(function () { route(false); });
      });
    });
  });

  (function theme() {
    var btn = document.getElementById("theme"), root = document.documentElement, saved = null;
    try { saved = localStorage.getItem("gz-theme"); } catch (e) { saved = null; }
    function apply(t) {
      var dark = t ? t === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      if (t) root.setAttribute("data-theme", t);
      btn.textContent = dark ? "Light" : "Dark";
      btn.setAttribute("aria-label", dark ? "Use the light theme" : "Use the dark theme");
    }
    apply(saved === "dark" || saved === "light" ? saved : null);
    btn.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") ? root.getAttribute("data-theme") === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
      var next = dark ? "light" : "dark";
      try { localStorage.setItem("gz-theme", next); } catch (e) { /* the choice lasts for this page only */ }
      apply(next);
    });
  })();

  /* The view's secrets go when the page is hidden for good or frozen (12.7). */
  window.addEventListener("pagehide", leave);
  document.addEventListener("freeze", leave);

  gz.app = app;

  /* The first-run start token arrives in the fragment (4.3): read it, take it
     out of the address at once, and present it only if it has the token's
     exact form. Nothing else is ever read from the fragment but a route. */
  (function () {
    var m = /^#start=([A-Za-z0-9_-]{43})$/.exec(location.hash), t = m ? m[1] : null;
    if (location.hash.indexOf("#start=") === 0) history.replaceState(null, "", location.pathname);
    boot(t);
  })();
})();
