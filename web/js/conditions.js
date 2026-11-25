// SPDX-License-Identifier: MIT
/* Conditions: my limits, in my voice. The program decides what fits and what
   loosens; this screen shows it as the numbers are typed.
   Calls: GET /conditions, POST /conditions/preview, PUT /conditions. */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util, h = u.h, W = gz.words, ui = gz.ui, api = gz.api;
  /* the limits Slice 1 compares (13.1) */
  var FIELDS = ["min_members", "min_channel_sat", "max_joining_fee_sat", "max_fee_base_msat", "max_fee_ppm",
    "min_life_blocks", "max_life_blocks", "max_exit_blocks", "min_confirmations"];

  gz.screens.conditions = {
    title: "Conditions", nav: "conditions", topics: [],
    render: function () {
      return api.get("/conditions").then(function (c) {
        var inputs = {}, preset = c.preset, loosens = [], timer = null, seq = 0;
        var fitline = h("p", { class: "fitline", id: "fitline", role: "status" });
        var warn = h("div", { id: "cond-warn" }), msg = h("div", { id: "cond-msg" });
        var save = h("button", { type: "submit", class: "btn primary", id: "save-conditions" }, "Save my conditions");
        var presetRow = h("div", { class: "actions", role: "group", "aria-label": "Presets" });
        var rows = h("div", {});

        function values() {
          var out = {}, k;
          for (k in c.conditions) out[k] = c.conditions[k];
          /* An empty field is no limit: null, as GET /conditions gives it (13.1). A field that
             is not a whole number is sent as -1, which the program refuses (bad_value), and the
             refusal is shown: a save that did not happen must never look like one that did. */
          FIELDS.forEach(function (f) {
            var v = inputs[f].value.trim();
            out[f] = v === "" ? null : /^\d+$/.test(v) ? Number(v) : -1;
          });
          return out;
        }

        function summary(fs) {
          u.clear(fitline);
          if (!fs) return;
          u.add(fitline, u.number(fs.fit) + " of " + u.count(fs.listed, "lobby", "lobbies") + " the app knows fit these conditions.");
          if (fs.excluded_most_by) {
            fitline.appendChild(h("small", {}, "The limit that excludes most: " + W.known(W.conditionNames, fs.excluded_most_by.condition) +
              " (yours: " + u.number(fs.excluded_most_by.yours) + "), which excludes " + u.count(fs.excluded_most_by.lobbies_excluded, "lobby", "lobbies") + "."));
          }
        }

        function preview() {
          var mine = ++seq;
          api.call("POST", "/conditions/preview", { conditions: values() }).then(function (p) {
            if (mine !== seq) return;
            loosens = p.loosens || [];
            summary(p.fit_summary);
            u.clear(warn);
            (p.would_leave || []).forEach(function (w) {
              warn.appendChild(ui.notice("warn", "Saving this makes the app leave a lobby you joined", "that would no longer fit. " + W.failuresText(w.failures || [])));
            });
            if (loosens.length) {
              warn.appendChild(ui.notice("", "This loosens: " + loosens.map(function (f) { return W.known(W.conditionNames, f).toLowerCase(); }).join(", ") + ".",
                "It widens what the app signs without asking, so saving asks for your passphrase. It applies to lobbies you join from now on, not to ones you are in."));
            }
            (p.problems || []).forEach(function (pr) { warn.appendChild(ui.notice("bad", "A value is not accepted.", String(pr.field) + ": " + String(pr.code))); });
            save.disabled = !c.editable;
          }, function (e) {
            if (mine !== seq) return;
            u.clear(warn);
            u.add(warn, ui.error(e));
          });
        }

        function changed() {
          preset = "custom";
          mark();
          clearTimeout(timer);
          timer = setTimeout(preview, 300);
        }

        function mark() {
          var b = presetRow.querySelectorAll("button"), i;
          for (i = 0; i < b.length; i++) b[i].setAttribute("aria-pressed", b[i].getAttribute("data-preset") === preset ? "true" : "false");
        }

        (c.presets || []).forEach(function (p) {
          presetRow.appendChild(h("button", { type: "button", class: "btn small", "data-preset": p.id, onclick: function () {
            var k;
            for (k in p.conditions) if (inputs[k]) inputs[k].value = String(p.conditions[k]);
            preset = p.id;
            mark();
            preview();
          } }, p.id.charAt(0).toUpperCase() + p.id.slice(1)));
        });

        FIELDS.forEach(function (f) {
          var lim = c.limits && c.limits[f] ? c.limits[f] : null, id = "cond-" + f;
          var input = h("input", { type: "number", inputmode: "numeric", id: id, min: lim ? lim[0] : 0, max: lim ? lim[1] : null, step: 1, value: c.conditions[f] });
          input.addEventListener("input", changed);
          inputs[f] = input;
          rows.appendChild(h("div", { class: "cond" }, h("label", { for: id }, W.conditionNames[f]),
            h("div", { class: "ctl" }, input, h("span", { class: "unit" }, W.conditionUnits[f]))));
        });

        var form = h("form", { novalidate: true, class: "mine" }, h("h2", {}, "My limits"),
          h("p", { class: "small mute" }, "Start from a preset, then change any number."), presetRow, rows, warn, msg, ui.actions(save));
        form.addEventListener("submit", function (ev) {
          ev.preventDefault();
          ui.run(save, msg, function () {
            return api.act("PUT", "/conditions", { conditions: values(), based_on_version: c.version, preset: preset, confirm_loosens: loosens },
              { why: "These conditions let the app sign more than before, so it asks for your passphrase." }).then(function (r) {
              var left = r.left_lobbies || [];
              ui.toast(left.length ? "Saved. The app left " + u.count(left.length, "lobby", "lobbies") + " that no longer fit." : "Saved.");
              gz.app.refreshStatus(false);
              gz.app.go("/conditions");
            }, function (e) {
              if (e.code === "changed_elsewhere" || e.code === "confirm_mismatch") setTimeout(function () { gz.app.go("/conditions"); }, 2500);
              throw e;
            });
          });
        });

        summary(c.fit_summary);
        mark();
        save.disabled = !c.editable;
        return h("div", {},
          h("h1", {}, "Conditions"),
          h("p", { class: "lead" }, "What you will accept. The app joins and signs only inside these limits, and refuses anything outside them before it sends a signature."),
          fitline,
          c.editable ? null : ui.notice("warn", "The app is signing right now.", "Conditions cannot change during those seconds."),
          form,
          (c.copied_into || []).length ? ui.notice("", "These conditions were copied into " + u.count(c.copied_into.length, "lobby", "lobbies") + " you joined.",
            "Tightening them makes the app leave a joined lobby that no longer fits. Loosening them changes only what you join from now on.") : null);
      });
    }
  };
})();
