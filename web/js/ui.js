/* Gazpacho screens: the shared pieces every screen is built from. */
(function () {
  "use strict";
  var gz = window.gz;
  var h = gz.util.h;
  var idCounter = 0;

  function nextId(prefix) { return prefix + "-" + (++idCounter); }

  /* ----- words ----- */

  var PROFILE_WORDS = {
    safety: { name: "Safety", about: "For cautious users. Simple operation only; optional features are off." },
    standard: { name: "Standard", about: "The defaults most public lobbies use." },
    starter: { name: "Starter", about: "For people arriving with no funds. Small channels, low requirements, limited seats." },
    circle: { name: "Circle", about: "For people who know each other. Unlisted and by invitation." }
  };

  var STAGE_WORDS = {
    open: "Gathering",
    ready_check: "Ready check",
    signing: "Signing",
    funding: "Waiting for funding",
    active: "Factory live",
    cancelled: "Cancelled",
    failed: "Failed"
  };

  var NETWORK_WORDS = { signet: "Signet", testnet4: "Testnet4", mainnet: "Mainnet" };

  /* ----- small pieces ----- */

  function pill(text, kind) { return h("span", { class: "pill " + (kind || "grey") }, text); }

  function amount(sat) {
    return h("span", { class: "amount" }, gz.util.number(sat), h("span", { class: "unit" }, " sats"));
  }

  function button(label, onClick, options) {
    options = options || {};
    return h("button", { type: options.type || "button", class: "btn " + (options.kind || ""), id: options.id,
      disabled: options.disabled, "aria-describedby": options.describedBy, onclick: onClick }, label);
  }

  function link(label, href, cls) { return h("a", { href: href, class: cls || "" }, label); }

  /* A control that exists in the design but does nothing here. It says so on its face. */
  function notInPrototype(label) {
    return button(label + " (not in the prototype)", function () {
      toast("“" + label + "” is not in the prototype.");
    }, { kind: "ghost" });
  }

  /* A coloured panel. kind: info (blue), ok (green), warn (gold), danger (tomato). */
  function notice(kind, title, body, actions) {
    return h("div", { class: "notice " + kind },
      title ? h("p", { class: "notice-title" }, title) : null,
      body ? (typeof body === "string" ? h("p", null, body) : body) : null,
      actions ? h("div", { class: "actions" }, actions) : null);
  }

  function empty(title, text, actions) {
    return h("div", { class: "card empty" }, h("h2", null, title), h("p", null, text),
      actions ? h("div", { class: "actions" }, actions) : null);
  }

  function card(title) {
    var rest = Array.prototype.slice.call(arguments, 1);
    return h("section", { class: "card" }, title ? h("h2", null, title) : null, rest);
  }

  /* A labelled number with an explanation. The explanation shows on hover,
     on keyboard focus, and stays open after a tap or click on the "?" button. */
  function stat(label, value, explanation, extra) {
    var tipId = nextId("tip");
    var tip = h("span", { class: "tip", id: tipId, role: "tooltip" }, explanation);
    var info = h("button", { type: "button", class: "info-button", "aria-label": "What “" + label + "” means",
      "aria-describedby": tipId, "aria-expanded": "false",
      onclick: function () {
        var open = tip.classList.toggle("open");
        info.setAttribute("aria-expanded", String(open));
      } }, "?");
    return h("div", { class: "stat" },
      h("div", { class: "stat-label" }, h("span", null, label), explanation ? info : null),
      h("div", { class: "stat-value" }, value),
      extra ? h("div", { class: "stat-extra" }, extra) : null,
      explanation ? tip : null);
  }

  /* A list of term and value pairs. rows: [label, value, optional explanation] */
  function facts(rows) {
    var dl = h("dl", { class: "facts" });
    rows.forEach(function (row) {
      if (!row) return;
      dl.appendChild(h("div", null,
        h("dt", null, row[0]),
        h("dd", null, row[1], row[2] ? h("span", { class: "hint" }, row[2]) : null)));
    });
    return dl;
  }

  function progress(value, max, label) {
    return h("progress", { value: Math.min(value, max), max: max, "aria-label": label });
  }

  /* A countdown always says what happens when it reaches zero. */
  function countdown(untilUnix, atZero) {
    var time = h("span", { class: "countdown", "data-until": untilUnix });
    paintCountdown(time);
    return h("span", null, time, h("span", { class: "at-zero" }, " ", atZero));
  }

  function paintCountdown(el) {
    var left = Number(el.getAttribute("data-until")) - Math.floor(Date.now() / 1000);
    el.textContent = left > 0 ? "in " + gz.util.duration(left) : "now";
  }

  setInterval(function () {
    var all = document.querySelectorAll(".countdown[data-until]");
    for (var i = 0; i < all.length; i++) paintCountdown(all[i]);
  }, 1000);

  /* ----- form fields ----- */

  /* options: id, label, hint, type, value, min, max, step, unit, required, readonly, choices (for a select) */
  function field(options) {
    var hintId = options.hint ? options.id + "-hint" : null;
    var input;
    if (options.choices) {
      input = h("select", { id: options.id, name: options.id, "aria-describedby": hintId, disabled: options.readonly });
      options.choices.forEach(function (choice) {
        input.appendChild(h("option", { value: choice[0], selected: String(choice[0]) === String(options.value) }, choice[1]));
      });
    } else if (options.type === "textarea") {
      input = h("textarea", { id: options.id, name: options.id, rows: options.rows || 3, "aria-describedby": hintId,
        readonly: options.readonly, spellcheck: "false", autocomplete: "off" });
      input.value = options.value || "";
    } else {
      input = h("input", { id: options.id, name: options.id, type: options.type || "text", min: options.min, max: options.max,
        step: options.step, "aria-describedby": hintId, required: options.required, readonly: options.readonly,
        inputmode: options.type === "number" ? "numeric" : null, autocomplete: "off" });
      input.value = options.value === undefined || options.value === null ? "" : options.value;
    }
    return h("div", { class: "field" },
      h("label", { for: options.id }, options.label),
      h("div", { class: "field-row" }, input, options.unit ? h("span", { class: "unit" }, options.unit) : null),
      options.hint ? h("p", { class: "hint", id: hintId }, options.hint) : null);
  }

  function checkbox(options) {
    var input = h("input", { type: options.radio ? "radio" : "checkbox", id: options.id, name: options.name || options.id,
      value: options.value, checked: options.checked, disabled: options.disabled,
      "aria-describedby": options.hint ? options.id + "-hint" : null });
    return h("div", { class: "check" }, input,
      h("div", null, h("label", { for: options.id }, options.label),
        options.hint ? h("p", { class: "hint", id: options.id + "-hint" }, options.hint) : null));
  }

  function value(id) {
    var el = document.getElementById(id);
    if (!el) return undefined;
    return el.type === "checkbox" || el.type === "radio" ? el.checked : el.value;
  }

  /* ----- messages ----- */

  function toast(text) {
    var box = document.getElementById("toasts");
    var el = h("p", { class: "toast" }, text);
    box.appendChild(el);
    setTimeout(function () { if (el.parentNode) box.removeChild(el); }, 6000);
  }

  /* Runs an action from a button: disables it while waiting and reports a failure in words. */
  function run(buttonEl, work, doneText) {
    if (buttonEl) { buttonEl.disabled = true; buttonEl.setAttribute("aria-busy", "true"); }
    return Promise.resolve().then(work).then(function (result) {
      if (doneText) toast(doneText);
      return result;
    }).catch(function (error) {
      toast("That did not work. " + (error && error.message ? error.message : "The program gave no reason."));
      return undefined;
    }).then(function (result) {
      if (buttonEl) { buttonEl.disabled = false; buttonEl.removeAttribute("aria-busy"); }
      return result;
    });
  }

  /* Asks before a risky action. Resolves true only if the person confirms. */
  function confirm(options) {
    return new Promise(function (resolve) {
      var titleId = nextId("dialog-title");
      var agree = options.mustTick ? checkbox({ id: nextId("dialog-agree"), label: options.mustTick }) : null;
      var ok = button(options.confirmLabel, function () { close(true); }, { kind: options.danger ? "danger" : "primary", disabled: !!agree });
      var cancel = button(options.cancelLabel || "Cancel", function () { close(false); });
      if (agree) agree.querySelector("input").addEventListener("change", function (e) { ok.disabled = !e.target.checked; });
      var dialog = h("dialog", { class: "dialog", "aria-labelledby": titleId },
        h("h2", { id: titleId }, options.title), options.body, agree, h("div", { class: "actions" }, cancel, ok));
      function close(answer) {
        dialog.close();
        document.body.removeChild(dialog);
        resolve(answer);
        gz.app.dialogClosed();
      }
      dialog.addEventListener("cancel", function (e) { e.preventDefault(); close(false); });
      document.body.appendChild(dialog);
      dialog.showModal();
      cancel.focus();
    });
  }

  function copyButton(text, what) {
    return button("Copy", function () {
      var done = function () { toast(what + " copied."); };
      var failed = function () { toast("Copying is blocked in this browser. Select the text and copy it by hand."); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, failed);
      else failed();
    }, { kind: "small" });
  }

  /* A placeholder where a QR code will be drawn. QR encoding is not in the prototype. */
  function qrPlaceholder(what) {
    return h("div", { class: "qr", role: "img", "aria-label": "Placeholder for a QR code of " + what },
      h("span", null, "QR code placeholder"), h("span", { class: "hint" }, "The real app draws " + what + " here."));
  }

  /* The one-sentence start rule with live numbers. */
  function startRuleSentence(lobby) {
    var rule = lobby.start_rule;
    return "Starts at " + rule.target + ", or at the deadline with " + rule.minimum + " or more; " +
      lobby.counts.ready + " ready here now.";
  }

  function shortfallSentence(lobby) {
    var rule = lobby.start_rule;
    return "At the deadline: it starts if " + rule.minimum + " or more are ready. Otherwise " +
      (rule.on_shortfall === "carry_over" ? "the people waiting are carried over to the host's next lobby." : "it is cancelled.");
  }

  gz.ui = {
    PROFILE_WORDS: PROFILE_WORDS, STAGE_WORDS: STAGE_WORDS, NETWORK_WORDS: NETWORK_WORDS,
    pill: pill, amount: amount, button: button, link: link, notInPrototype: notInPrototype, notice: notice,
    empty: empty, card: card, stat: stat, facts: facts, progress: progress, countdown: countdown,
    field: field, checkbox: checkbox, value: value, toast: toast, run: run, confirm: confirm,
    copyButton: copyButton, qrPlaceholder: qrPlaceholder, startRuleSentence: startRuleSentence,
    shortfallSentence: shortfallSentence, nextId: nextId
  };
})();
