/* Screen: First run. Create or restore a wallet, then choose member, host or both. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, api = window.gzApi;

  var step = "choose";     // choose, phrase, restore, roles
  var phrase = null;
  var restored = null;

  function goTo(next) { step = next; gz.app.go("first-run"); }

  function choose() {
    return h("div", { class: "two" },
      ui.card("Create a new wallet",
        h("p", null, "The app makes a new set of keys on this machine and shows you a recovery phrase to write down."),
        h("div", { class: "actions" }, ui.button("Create a wallet", function (e) {
          ui.run(e.currentTarget, function () { return api.createWallet().then(function (r) { phrase = r.recovery_phrase; goTo("phrase"); }); });
        }, { kind: "primary" }))),
      ui.card("Restore a wallet",
        h("p", null, "You have a recovery phrase, and perhaps a backup file, from a wallet you used before."),
        h("div", { class: "actions" }, ui.button("Restore a wallet", function () { goTo("restore"); }))));
  }

  function showPhrase() {
    var words = h("ol", { class: "phrase" }, phrase.map(function (word) { return h("li", null, word); }));
    var agree = ui.checkbox({ id: "phrase-written", label: "I have written these words down, in order, on paper." });
    var next = ui.button("Continue", function () { goTo("roles"); }, { kind: "primary", disabled: true });
    agree.querySelector("input").addEventListener("change", function (e) { next.disabled = !e.target.checked; });
    return ui.card("Write down your recovery phrase",
      ui.notice("warn", "These are placeholder words.", "The prototype shows the word “example” twelve times. The real app shows twelve different words here, once."),
      words,
      h("p", null, "Anyone who has these words can take your on-chain coins. Keep them on paper, somewhere private. Do not photograph them or store them on a computer."),
      h("p", null, "The phrase restores your on-chain coins. It cannot rebuild a Lightning channel inside a factory: that needs the app's encrypted backup, which the app keeps for you and which you can export in Settings."),
      agree,
      h("div", { class: "actions" }, ui.button("Back", function () { goTo("choose"); }), next));
  }

  function restore() {
    return ui.card("Restore a wallet",
      ui.field({ id: "restore-phrase", label: "Recovery phrase", type: "textarea", rows: 3, value: "",
        hint: "Twelve or twenty-four words, separated by spaces. In the prototype any twelve words are accepted; do not type a real phrase here." }),
      ui.field({ id: "restore-file", label: "Encrypted backup file (optional)", type: "file",
        hint: "Needed to restore a channel in a factory. Without it only on-chain coins come back. The prototype reads the file's name and nothing else." }),
      ui.notice("info", "A restored copy never publishes.",
        "A backup can be older than your channel's latest state, and publishing an old state can cost you coins. A restored wallet therefore asks the host for the latest state and waits for the host to close the channel."),
      h("div", { class: "actions" }, ui.button("Back", function () { goTo("choose"); }),
        ui.button("Restore", function (e) {
          var file = document.getElementById("restore-file").files[0];
          ui.run(e.currentTarget, function () {
            return api.restoreWallet({ recovery_phrase: ui.value("restore-phrase"), backup_file_name: file ? file.name : null })
              .then(function (r) { restored = r; goTo("roles"); });
          });
        }, { kind: "primary" }),
        ui.button("Fill in placeholder words (prototype only)", function () {
          var input = document.getElementById("restore-phrase");
          input.value = new Array(13).join("example ").trim();
          input.setAttribute("data-dirty", "1");
        }, { kind: "ghost" })));
  }

  function roles() {
    return ui.card("How will you use Gazpacho?",
      restored ? ui.notice("ok", "Wallet restored.", restored.channels_restored
        ? "On-chain coins and channel state were restored. The channel will not publish anything by itself."
        : "On-chain coins were restored. No backup file was given, so no channel was restored.") : null,
      h("p", null, "A factory is one on-chain output shared by a host and many members. It gives each member a Lightning channel without each of them needing their own on-chain transaction. You can change this later in Settings."),
      ui.checkbox({ id: "first-member", label: "As a member", checked: true,
        hint: "Join a factory someone else hosts. You need no coins to start: the host funds the factory, and you are paid in over Lightning." }),
      ui.checkbox({ id: "first-host", label: "As a host",
        hint: "Fund and run factories for others and earn fees. Needs on-chain coins, a machine that stays on, and a Lightning node to link to." }),
      h("div", { class: "actions" }, ui.button("Finish", function (e) {
        ui.run(e.currentTarget, function () {
          return api.finishSetup({ roles: { member: ui.value("first-member"), host: ui.value("first-host") } }).then(function () {
            step = "choose"; phrase = null; restored = null;
            gz.app.go("home");
          });
        }, "Your wallet is ready.");
      }, { kind: "primary" })));
  }

  function render(params, status) {
    if (status.wallet_exists) {
      step = "choose";
      return Promise.resolve(h("div", null, h("h1", null, "First run"),
        ui.notice("info", "This wallet is already set up.", "First run appears only when no wallet exists. The demo controls can show it again.", [ui.link("Go to Home", "#/home", "btn primary")])));
    }
    if (step === "phrase" && !phrase) step = "choose";
    var body = step === "phrase" ? showPhrase() : step === "restore" ? restore() : step === "roles" ? roles() : choose();
    var number = { choose: 1, phrase: 2, restore: 2, roles: 3 }[step];
    return Promise.resolve(h("div", null,
      h("h1", null, "Welcome to Gazpacho"),
      h("p", { class: "lead" }, "A Bitcoin Lightning wallet for channel factories. This release works on " + ui.NETWORK_WORDS[status.network] + ", a test network, with test coins that have no value."),
      h("p", { class: "hint", role: "status" }, "Step " + number + " of 3"),
      body));
  }

  gz.screens.firstRun = { title: "First run", topics: [], render: render };
})();
