/* The demo controls panel. Prototype only: it is not part of the app and goes
   away with the mock. It talks to window.gzMockDemo, never to window.gzApi. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h;
  var mock = window.gzMockDemo;
  if (!mock) return;

  var open = false;
  var painted = null;      // the situation the panel last showed

  function remember(key, value) {
    try { window.sessionStorage.setItem(key, value); } catch (e) { /* not remembered */ }
  }

  function paint() {
    var root = document.getElementById("demo-root");
    var now = mock.current();
    painted = now.state;
    var toggle = h("button", { type: "button", class: "btn demo-toggle", id: "demo-toggle", "aria-expanded": String(open), "aria-controls": "demo-panel",
      onclick: function () { open = !open; remember("gz-demo-open", open ? "1" : ""); paint(); document.getElementById("demo-toggle").focus(); } },
      open ? "Hide demo controls" : "Demo controls");

    var states = h("div", { class: "demo-states" }, mock.states.map(function (s) {
      return h("button", { type: "button", class: "btn small", "aria-pressed": String(s.id === now.state), "data-state": s.id,
        onclick: function () {
          remember("gz-demo-state", s.id);
          mock.setState(s.id);
          if (s.id !== "first-run" && /first-run/.test(window.location.hash)) gz.app.go("home");
          paint();
          root.querySelector('[data-state="' + s.id + '"]').focus();
        } }, s.label);
    }));

    function tick(id, label, checked, onChange) {
      return h("div", { class: "check" }, h("input", { type: "checkbox", id: id, checked: checked, onchange: function (e) { onChange(e.target.checked); } }),
        h("label", { for: id }, label));
    }

    var panel = h("section", { class: "demo-panel", id: "demo-panel", "aria-label": "Demo controls, prototype only", hidden: !open },
      h("h2", null, "Demo controls"),
      h("p", { class: "hint" }, "Prototype only. Not part of the app. These jump the fake data between situations."),
      h("h3", null, "Situation"), states,
      h("h3", null, "Pretend chain"),
      h("p", { class: "hint" }, "Makes a block every " + now.block_every_s + " seconds by itself. A real block takes about ten minutes."),
      h("div", { class: "actions" },
        h("button", { type: "button", class: "btn small", onclick: function () { mock.mine(1); } }, "Mine 1 block"),
        h("button", { type: "button", class: "btn small", onclick: function () { mock.mine(144); } }, "Mine 144 blocks (about a day)")),
      tick("demo-paused", "Pause the pretend clock (lobbies, signing and blocks stand still)", now.paused, function (on) { mock.setPaused(on); }),
      h("h3", null, "Faults"),
      tick("demo-failing", "The local program is not answering", now.failing, function (on) { mock.setFailing(on); }),
      tick("demo-slow", "Slow answers", now.slow, function (on) { mock.setSlow(on); }));

    root.replaceChildren(toggle, panel);
  }

  gz.demo = {
    start: function () {
      try { open = window.sessionStorage.getItem("gz-demo-open") === "1"; } catch (e) { /* closed */ }
      paint();
      /* Repaint only when the situation changed behind the panel's back, for example when first run finishes. */
      window.gzApi.subscribe(function () { if (mock.current().state !== painted) paint(); });
    }
  };
})();
