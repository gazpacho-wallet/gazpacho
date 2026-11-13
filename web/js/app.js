/* Gazpacho screens: start-up, the hash router, the frame around every screen.

   A screen is an object in gz.screens:
     title   shown in the browser tab
     topics  the live-update topics that should redraw it
     render  function (params, status) returning a Promise of a DOM node
   Screens read and change things only through window.gzApi. */
(function () {
  "use strict";
  var gz = window.gz;
  var h = gz.util.h;
  var api = window.gzApi;

  var NAV = [
    { route: "home", label: "Home" },
    { route: "lobbies", label: "Lobbies" },
    { route: "conditions", label: "My conditions" },
    { route: "factory", label: "Factory" },
    { route: "pay", label: "Pay and receive" },
    { route: "host", label: "Host a factory" },
    { route: "wallet", label: "Wallet (on chain)" },
    { route: "settings", label: "Settings" }
  ];

  var ROUTES = {
    "home": "home", "lobbies": "lobbies", "lobby": "lobby", "conditions": "conditions", "factory": "factory",
    "pay": "pay", "host": "host", "wallet": "wallet", "settings": "settings", "first-run": "firstRun"
  };

  var THEMES = ["system", "light", "dark"];

  var view = document.getElementById("view");
  var main = document.getElementById("main");
  var current = { name: null, screen: null, params: [] };
  var renderCount = 0;
  var refreshTimer = null;
  var refreshWaiting = false;

  function parseHash() {
    var parts = window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
    var name = parts[0] || "home";
    return { name: ROUTES[name] ? name : "home", params: parts.slice(1) };
  }

  /* ----- the frame ----- */

  function paintNav(status) {
    var nav = document.getElementById("nav");
    var route = parseHash().name;
    var list = h("ul");
    var ready = status && status.wallet_exists;
    NAV.forEach(function (item) {
      var active = item.route === route || (item.route === "lobbies" && route === "lobby");
      var count = item.route === "home" && status ? status.attention.filter(function (a) { return a.level !== "info"; }).length : 0;
      list.appendChild(h("li", null, h("a", { href: "#/" + item.route, "aria-current": active ? "page" : null },
        item.label, count ? h("span", { class: "badge" }, count, h("span", { class: "sr" }, count === 1 ? " thing needs you" : " things need you")) : null)));
    });
    nav.replaceChildren(ready ? list : h("p", { class: "hint" }, "The other screens open once a wallet exists."));
  }

  function paintStatus(status, error) {
    var box = document.getElementById("top-status");
    if (error) { box.replaceChildren(gz.ui.pill("Local program not answering", "tomato")); return; }
    var chainPill = status.chain.state === "ok" ? null
      : gz.ui.pill(status.chain.state === "disagree" ? "Chain servers disagree" : "Chain view offline", "tomato");
    box.replaceChildren(
      gz.ui.pill(gz.ui.NETWORK_WORDS[status.network] + ": test coins, no value", "gold"),
      h("span", { class: "height" }, "Block " + gz.util.number(status.chain.height)));
    if (chainPill) box.appendChild(chainPill);
  }

  function refreshFrame() {
    return api.getStatus().then(function (status) {
      paintStatus(status); paintNav(status);
      return status;
    }, function (error) {
      paintStatus(null, error); paintNav(null);
      throw error;
    });
  }

  function applyTheme(theme) {
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    document.getElementById("theme-toggle").textContent = "Theme: " + theme;
    try { window.localStorage.setItem("gz-theme", theme); } catch (e) { /* not remembered, still applied */ }
  }

  function startTheme() {
    var theme = "system";
    try { theme = window.localStorage.getItem("gz-theme") || "system"; } catch (e) { /* use the system setting */ }
    if (THEMES.indexOf(theme) < 0) theme = "system";
    applyTheme(theme);
    document.getElementById("theme-toggle").addEventListener("click", function () {
      theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
      applyTheme(theme);
    });
  }

  function startMenu() {
    var toggle = document.getElementById("menu-toggle");
    var nav = document.getElementById("nav");
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", function (e) {
      if (e.target.closest("a")) { nav.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); }
    });
  }

  /* ----- drawing a screen ----- */

  function errorPanel(error) {
    return h("div", null,
      h("h1", null, "This screen could not be loaded"),
      gz.ui.notice("danger", "The screens could not get an answer from the Gazpacho program.",
        h("div", null,
          h("p", null, error && error.message ? error.message : "No reason was given."),
          h("p", null, "Your coins are not affected by this. The program that holds them is separate from these screens.")),
        [gz.ui.button("Try again", function () { draw(false); }, { kind: "primary" })]));
  }

  /* What the person was doing, so a live redraw does not disturb it. */
  function snapshot() {
    var active = document.activeElement;
    var inView = active && view.contains(active);
    var edits = [];
    var dirty = view.querySelectorAll("[data-dirty][id]");
    for (var i = 0; i < dirty.length; i++) {
      edits.push({ id: dirty[i].id, value: dirty[i].value, checked: dirty[i].checked });
    }
    return {
      focusId: inView ? active.id : null,
      focusText: inView && !active.id ? active.tagName + "|" + active.textContent : null,
      selection: inView && typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null,
      edits: edits,
      scroll: window.scrollY
    };
  }

  function restore(snap) {
    snap.edits.forEach(function (edit) {
      var el = document.getElementById(edit.id);
      if (!el) return;
      if (el.type === "checkbox" || el.type === "radio") el.checked = edit.checked; else el.value = edit.value;
      el.setAttribute("data-dirty", "1");
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    var target = snap.focusId ? document.getElementById(snap.focusId) : null;
    if (!target && snap.focusText) {
      var candidates = view.querySelectorAll("button, a, summary");
      for (var i = 0; i < candidates.length && !target; i++) {
        if (candidates[i].tagName + "|" + candidates[i].textContent === snap.focusText) target = candidates[i];
      }
    }
    if (target) {
      target.focus({ preventScroll: true });
      if (snap.selection && typeof target.setSelectionRange === "function") {
        try { target.setSelectionRange(snap.selection[0], snap.selection[1]); } catch (e) { /* not a text field */ }
      }
    }
    window.scrollTo(0, snap.scroll);
  }

  function draw(isRefresh) {
    var mine = ++renderCount;
    var route = parseHash();
    var screen = gz.screens[ROUTES[route.name]];
    var snap = isRefresh ? snapshot() : null;
    var loadingTimer = null;
    if (!isRefresh) {
      loadingTimer = setTimeout(function () {
        view.replaceChildren(h("p", { class: "loading", role: "status" }, "Loading…"));
      }, 250);
    }
    view.setAttribute("aria-busy", "true");

    refreshFrame().then(function (status) {
      if (!status.wallet_exists && route.name !== "first-run") {
        window.location.hash = "#/first-run";
        return null;
      }
      return screen.render(route.params, status);
    }).then(function (node) {
      clearTimeout(loadingTimer);
      if (mine !== renderCount || !node) return;
      current = { name: route.name, screen: screen, params: route.params };
      view.replaceChildren(node);
      view.removeAttribute("aria-busy");
      document.title = screen.title + " · Gazpacho (prototype)";
      if (snap) restore(snap);
      else { window.scrollTo(0, 0); main.focus({ preventScroll: true }); }
    }).catch(function (error) {
      clearTimeout(loadingTimer);
      if (mine !== renderCount) return;
      current = { name: route.name, screen: screen, params: route.params };
      view.replaceChildren(errorPanel(error));
      view.removeAttribute("aria-busy");
      document.title = "Not loaded · Gazpacho (prototype)";
    });
  }

  function scheduleRefresh() {
    if (document.querySelector("dialog[open]")) { refreshWaiting = true; return; }
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () { draw(true); }, 60);
  }

  function onEvent(event) {
    if (event.topic === "reset") { draw(false); return; }
    if (current.screen && current.screen.topics.indexOf(event.topic) >= 0) scheduleRefresh();
    else if (event.topic === "status" || event.topic === "chain") refreshFrame().catch(function () {});
  }

  gz.app = {
    /* Redraw the current screen after an action changed something. */
    redraw: function () { draw(true); },
    go: function (route) {
      if (window.location.hash === "#/" + route) draw(false); else window.location.hash = "#/" + route;
    },
    dialogClosed: function () {
      if (refreshWaiting) { refreshWaiting = false; scheduleRefresh(); }
    }
  };

  view.addEventListener("input", function (e) { if (e.isTrusted && e.target.id) e.target.setAttribute("data-dirty", "1"); });
  view.addEventListener("change", function (e) { if (e.isTrusted && e.target.id) e.target.setAttribute("data-dirty", "1"); });
  window.addEventListener("hashchange", function () { draw(false); });

  startTheme();
  startMenu();
  if (gz.demo) gz.demo.start();
  api.subscribe(onEvent);
  draw(false);
})();
