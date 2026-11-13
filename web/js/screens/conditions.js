/* Screen: My conditions. The member's own limits, which the app will not sign outside. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var BLOCKS_PER_DAY = 144;

  function readForm() {
    var profiles = Object.keys(ui.PROFILE_WORDS).filter(function (id) { return ui.value("accept-" + id); });
    return {
      min_members: Number(ui.value("min-members")),
      min_channel_sat: Number(ui.value("min-channel")),
      max_join_fee_sat: Number(ui.value("max-join-fee")),
      max_payment_fee_ppm: Math.round(Number(ui.value("max-payment-fee")) * 10000),
      max_liquidity_fee_ppm: Math.round(Number(ui.value("max-liquidity-fee")) * 10000),
      max_exit_blocks: Math.round(Number(ui.value("max-exit-days")) * BLOCKS_PER_DAY),
      profiles: profiles
    };
  }

  function form(data) {
    var c = data.conditions;
    var locked = !!data.locked_by_lobby;
    var profiles = h("fieldset", null, h("legend", null, "Profiles I accept"),
      h("p", { class: "hint" }, "A profile is a named set of rules a host chooses for a lobby."),
      data.profiles.map(function (id) {
        return ui.checkbox({ id: "accept-" + id, label: ui.PROFILE_WORDS[id].name, hint: ui.PROFILE_WORDS[id].about,
          checked: c.profiles.indexOf(id) >= 0, disabled: locked });
      }));
    var exitHint = h("p", { class: "hint", id: "exit-blocks" });
    function paintExit() {
      var days = Number(ui.value("max-exit-days")) || 0;
      exitHint.textContent = "That is " + u.number(Math.round(days * BLOCKS_PER_DAY)) + " blocks. Each waiting period in a factory's tree adds 432 blocks, about 3 days.";
    }
    var el = h("form", { class: "card", novalidate: true, oninput: paintExit,
      onsubmit: function (e) {
        e.preventDefault();
        ui.run(document.getElementById("save-conditions"), function () {
          return api.saveConditions(readForm()).then(function () { gz.app.go("conditions"); });
        }, "Conditions saved. They apply to every lobby from now on.");
      } },
      h("h2", null, "Your conditions"),
      ui.field({ id: "min-members", label: "Members, at least", type: "number", min: 2, max: 512, value: c.min_members, unit: "members", readonly: locked,
        hint: "A factory's on-chain cost is shared by its members, and a larger factory is harder to single you out in." }),
      ui.field({ id: "min-channel", label: "Channel size, at least", type: "number", min: 0, step: 1000, value: c.min_channel_sat, unit: "sats", readonly: locked,
        hint: "The most you could hold or receive in the channel the host opens for you." }),
      ui.field({ id: "max-join-fee", label: "Joining fee, at most", type: "number", min: 0, step: 100, value: c.max_join_fee_sat, unit: "sats", readonly: locked,
        hint: "A one-off fee some hosts charge, taken from the first payment you receive." }),
      ui.field({ id: "max-payment-fee", label: "Fee on each payment, at most", type: "number", min: 0, step: 0.01, value: c.max_payment_fee_ppm / 10000, unit: "%", readonly: locked,
        hint: "What the host may charge to pass a payment on, as a share of the amount." }),
      ui.field({ id: "max-liquidity-fee", label: "Fee for extra receiving room, at most", type: "number", min: 0, step: 0.01, value: c.max_liquidity_fee_ppm / 10000, unit: "%", readonly: locked,
        hint: "What the host may charge when you buy room to receive more than your channel allows." }),
      ui.field({ id: "max-exit-days", label: "Leaving alone takes, at most", type: "number", min: 0, max: 24, step: 1, value: Math.round(c.max_exit_blocks / BLOCKS_PER_DAY), unit: "days", readonly: locked,
        hint: "If a host disappears you take your coins out without its help. This is the longest you accept that taking." }),
      exitHint,
      profiles,
      locked
        ? h("p", { class: "hint" }, "Locked while you are in the lobby “" + data.locked_by_lobby.name + "”. ", ui.link("Open that lobby", "#/lobby/" + data.locked_by_lobby.id), " to leave it.")
        : h("div", { class: "actions" }, ui.button("Save my conditions", null, { kind: "primary", type: "submit", id: "save-conditions" })));
    paintExit();
    return el;
  }

  function refusalExample(lobbies) {
    var refused = lobbies.filter(function (l) { return !l.check.ok; })[0];
    if (!refused) {
      return ui.card("An example of a refusal",
        h("p", null, "Every lobby listed right now is within your conditions, so there is no live example. This is what a refusal looks like:"),
        h("div", { class: "verdict bad" }, h("p", null, h("b", null, "A lobby called “Example”"), " is refused."),
          h("ul", null, h("li", null, "Your ceiling for the fee on each payment is 0.1%. This lobby charges 0.25%."))));
    }
    return ui.card("An example of a refusal",
      h("p", null, "With the conditions saved now, the app refuses this lobby from the current list:"),
      h("div", { class: "verdict bad" },
        h("p", null, h("b", null, "“" + refused.name + "”"), " is refused. The app will not join it and would not sign its factory."),
        gz.lobbyParts.failureList(refused.check)),
      h("div", { class: "actions" }, ui.link("See that lobby", "#/lobby/" + refused.id, "btn")));
  }

  function render() {
    return Promise.all([api.getConditions(), api.listLobbies()]).then(function (got) {
      var data = got[0], lobbies = got[1];
      var within = lobbies.filter(function (l) { return l.check.ok; }).length;
      return h("div", null,
        h("h1", null, "My conditions"),
        h("p", { class: "lead" }, "Conditions are your own limits for any factory you join. You set them here once, before joining a lobby. A lobby is the waiting room where a factory forms."),
        data.locked_by_lobby ? ui.notice("warn", "Your conditions are locked in.",
          "You joined the lobby “" + data.locked_by_lobby.name + "” with these conditions. Nobody can change them while you are in it, including you. To change them, leave the lobby first.") : null,
        ui.notice("danger", "The app will refuse to sign anything outside these conditions.",
          h("div", null,
            h("p", null, "They are checked twice: when a lobby is shown to you, and again against the real factory at the moment of signing. Whatever was said or changed in a lobby, the app signs only if the factory in front of it meets every condition."),
            h("p", null, "On top of your conditions the app applies one rule you cannot switch off: it signs only if, afterwards, you could still leave alone, in time, with at least what you are owed."))),
        form(data),
        h("p", { class: "hint", role: "status" }, within + " of " + lobbies.length + " listed lobbies are within the conditions saved now."),
        refusalExample(lobbies));
    });
  }

  gz.screens.conditions = { title: "My conditions", topics: ["conditions", "status"], render: render };
})();
