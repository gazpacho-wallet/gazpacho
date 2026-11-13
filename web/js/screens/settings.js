/* Screen: Settings. Chain view, host's Lightning node, backup, reminders, network. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var nodeTest = null;      // the last result of "Test the link"
  var lastExport = null;    // the last result of "Export"

  var SERVER_STATE = {
    ok: ["Answering", "green"], behind: ["Behind", "gold"], offline: ["Not answering", "tomato"], disagrees: ["Disagrees with the others", "tomato"]
  };

  var OPERATIONS = {
    pay: "Pay an invoice, with a spending limit and a deadline",
    hold: "Accept an incoming payment and hold it open",
    settle: "Settle a held payment",
    cancel: "Cancel a held payment"
  };

  var REMINDER_WORDS = {
    in_app: ["Countdowns inside the app", "Always on."],
    nostr: ["A Nostr message", "Planned for a later release."],
    email: ["Email", "Planned for a later release."],
    phone: ["Phone notifications", "Planned with the mobile app."]
  };

  function save(buttonEl, patch, doneText) {
    return ui.run(buttonEl, function () { return api.saveSettings(patch).then(function () { gz.app.go("settings"); }); }, doneText);
  }

  function chainSection(chain) {
    var servers = h("ul", { class: "rows" });
    chain.servers.forEach(function (s) {
      var words = SERVER_STATE[s.state];
      servers.appendChild(h("li", null,
        h("div", { class: "row-main" }, h("span", null, h("b", null, s.name), " ", h("span", { class: "hint" }, s.protocol === "http" ? "block-explorer interface" : "Electrum protocol")),
          ui.pill(words[0], words[1])),
        h("p", { class: "hint" }, h("code", null, s.address), " · run by " + s.operator + " · " +
          (s.state === "disagrees" ? "reports a different block at height " + u.number(s.height) : "block " + u.number(s.height)) + " · checked " + u.ago(s.checked_at))));
    });
    var summary = chain.state === "disagree"
      ? ui.notice("danger", "The servers disagree about the latest block.",
        "One server reports a different block from the others. The app cannot tell which is right, so it treats new transactions as not confirmed and will not publish anything until they agree. This usually clears by itself within a few blocks. If it does not, switch to your own server or node.")
      : chain.mode === "public" && chain.independent_operators < 2
        ? ui.notice("warn", "Only one operator is answering on this network.", "The app cannot compare answers, so a server could hide a transaction from it.")
        : chain.mode === "public" ? ui.notice("ok", null, chain.independent_operators + " independent operators agree on the latest block.") : null;

    function choice(id, label, hint) {
      return ui.checkbox({ id: "chain-" + id, name: "chain-mode", radio: true, value: id, label: label, hint: hint, checked: chain.mode === id });
    }
    return h("form", { class: "card", novalidate: true, onsubmit: function (e) {
      e.preventDefault();
      var mode = ui.value("chain-own_server") ? "own_server" : ui.value("chain-own_node") ? "own_node" : "public";
      save(document.getElementById("save-chain"), { chain: { mode: mode,
        own_server: { address: ui.value("own-server-address") },
        own_node: { address: ui.value("own-node-address"), user: ui.value("own-node-user") } } }, "Chain view saved.");
    } },
      h("h2", null, "Chain view"),
      h("p", null, "How the app reads the Bitcoin chain. It checks block headers itself, so a server cannot invent a confirmation, but a server can hide a transaction. That is why answers are compared."),
      h("fieldset", null, h("legend", null, "Where to read the chain from"),
        choice("public", "Public servers", "The default. Each answer that matters is asked of servers run by different operators. They learn which scripts you watch and your network address."),
        h("div", { class: "nested" }, summary, servers,
          h("div", { class: "actions" }, ui.button("Check again", function (e) {
            ui.run(e.currentTarget, function () { return api.checkChainServers(); }, "Servers checked.");
          }, { kind: "small" }))),
        choice("own_server", "Your own server", "An Electrum-style server you run. Nobody else learns what you watch."),
        h("div", { class: "nested" }, ui.field({ id: "own-server-address", label: "Server address", value: chain.own_server.address, hint: "For example host:port" })),
        choice("own_node", "Your own Bitcoin node", "The strongest choice, and the one recommended for hosts."),
        h("div", { class: "nested" },
          ui.field({ id: "own-node-address", label: "Node address", value: chain.own_node.address, hint: "For example 127.0.0.1:38332" }),
          ui.field({ id: "own-node-user", label: "Node user name", value: chain.own_node.user,
            hint: "The password is not asked for in the prototype." }))),
      h("div", { class: "actions" }, ui.button("Save chain view", null, { kind: "primary", type: "submit", id: "save-chain" })));
  }

  function hostNodeSection(node) {
    var result = nodeTest ? ui.notice(nodeTest.linked ? "ok" : "danger", nodeTest.linked ? "The node can do all four." : "The node cannot do everything needed.",
      h("ul", null, nodeTest.operations.map(function (op) { return h("li", null, OPERATIONS[op.id] + ": " + (op.ok ? "works" : "not available")); }))) : null;
    return h("form", { class: "card", novalidate: true, onsubmit: function (e) {
      e.preventDefault();
      nodeTest = null;
      save(document.getElementById("save-node"), { host_node: { kind: ui.value("node-kind"), address: ui.value("node-address"), access_file: ui.value("node-access") } }, "Node details saved. Test the link next.");
    } },
      h("h2", null, "Host's Lightning node"),
      h("p", null, "A host links its factory to the rest of Lightning through a regular Lightning node. Gazpacho needs four things from it: to pay an invoice, to accept an incoming payment and hold it open, to settle a held payment, and to cancel one."),
      h("p", null, node.linked ? ui.pill("Linked", "green") : ui.pill("Not linked", "gold")),
      ui.field({ id: "node-kind", label: "Node software", value: node.kind,
        choices: [["lnd", "LND (supported first)"], ["cln", "Core Lightning (needs a hold plugin installed in the node)"]] }),
      ui.field({ id: "node-address", label: "Node address", value: node.address, hint: "For example 127.0.0.1:10009" }),
      ui.field({ id: "node-access", label: "Path to the node's access file", value: node.access_file,
        hint: "A path on this machine. The file's contents never enter the browser." }),
      h("div", { class: "actions" },
        ui.button("Save node details", null, { kind: "primary", type: "submit", id: "save-node" }),
        ui.button("Test the link", function (e) {
          ui.run(e.currentTarget, function () { return api.testHostNode().then(function (r) { nodeTest = r; gz.app.redraw(); }); });
        })),
      result);
  }

  function backupSection(backup) {
    return ui.card("Backup",
      h("p", null, "Your recovery phrase restores your on-chain coins only. Your channel cannot be rebuilt from the phrase: it needs the app's saved state. That state is kept encrypted, and the encrypted file is the backup."),
      ui.facts([
        ["Last exported by you", backup.last_export_at ? u.dateTime(backup.last_export_at) : "Never"],
        ["Copy held by your host", backup.host_copy_at ? "Updated " + u.ago(backup.host_copy_at) : "None yet", "The host stores the encrypted file for you and cannot read it."]
      ]),
      h("div", { class: "actions" }, ui.button("Export the encrypted state", function (e) {
        ui.run(e.currentTarget, function () { return api.exportBackup().then(function (r) { lastExport = r; gz.app.redraw(); }); });
      }, { kind: "primary" })),
      lastExport ? ui.notice("ok", "Exported.", "The real app saves a file named " + lastExport.file_name + " (" + u.number(lastExport.bytes) + " bytes). In the prototype no file is written.") : null,
      ui.notice("info", "A restored copy never publishes.",
        "A backup can be older than your channel's latest state, and publishing an old state can cost you coins. So a wallet restored from a backup never publishes its own copy. It asks the host to prove the latest state and waits for the host to close the channel."));
  }

  function remindersSection(reminders) {
    return h("form", { class: "card", novalidate: true, onsubmit: function (e) {
      e.preventDefault();
      save(document.getElementById("save-reminders"), { reminders: { warn_days_before: Number(ui.value("warn-days")) } }, "Reminder saved.");
    } },
      h("h2", null, "Reminders"),
      h("p", null, "The app works out every date by which it needs you. This release shows them as countdowns on the Home screen and nowhere else, so it cannot reach you while it is closed."),
      h("ul", null, reminders.channels.map(function (c) {
        var words = REMINDER_WORDS[c.id];
        return h("li", null, h("b", null, words[0]), ": " + (c.available ? "on. " : "not in this release. ") + words[1]);
      })),
      ui.field({ id: "warn-days", label: "Mark a date as urgent this long before it", type: "number", min: 1, max: 14, value: reminders.warn_days_before, unit: "days" }),
      h("div", { class: "actions" }, ui.button("Save reminder", null, { kind: "primary", type: "submit", id: "save-reminders" })));
  }

  function networkSection(network) {
    var reasons = {
      one_operator: "Only one public server operator has been found for it so far, so answers cannot be compared.",
      switched_off_in_release: "Not available in this release. The software has not yet had the outside review that real money needs."
    };
    return ui.card("Network",
      h("p", null, "Which Bitcoin network this wallet uses. Each network has its own separate coins and factories."),
      h("ul", { class: "rows" }, network.choices.map(function (c) {
        var isCurrent = c.id === network.current;
        var action = isCurrent ? ui.pill("In use", "green")
          : !c.available ? ui.pill("Unavailable", "grey")
          : ui.button("Switch to " + ui.NETWORK_WORDS[c.id], function (e) {
            var target = e.currentTarget;
            ui.confirm({ title: "Switch to " + ui.NETWORK_WORDS[c.id] + "?", confirmLabel: "Switch network",
              body: h("p", null, "The wallet shows a different set of coins on each network. Nothing is moved or lost. You must not be in a lobby or factory when you switch.") })
              .then(function (yes) { if (yes) save(target, { network: c.id }, "Now on " + ui.NETWORK_WORDS[c.id] + "."); });
          }, { kind: "small" });
        return h("li", null, h("div", { class: "row-main" }, h("b", null, ui.NETWORK_WORDS[c.id]), action),
          h("p", { class: "hint" }, c.id === "signet" ? "A test network with a steady block every ten minutes. Test coins only." : "", c.reason ? reasons[c.reason] : ""));
      })));
  }

  function rolesSection(roles) {
    return ui.card("What this wallet does",
      ui.checkbox({ id: "role-member", label: "Member: join factories", checked: roles.member }),
      ui.checkbox({ id: "role-host", label: "Host: fund and run factories", checked: roles.host, hint: "Shows the hosting screens and the Lightning node link." }),
      h("div", { class: "actions" }, ui.button("Save", function (e) {
        ui.run(e.currentTarget, function () {
          return api.setRoles({ member: ui.value("role-member"), host: ui.value("role-host") }).then(function () { gz.app.go("settings"); });
        }, "Saved.");
      }, { kind: "primary" })));
  }

  function render() {
    return api.getSettings().then(function (s) {
      return h("div", null,
        h("h1", null, "Settings"),
        chainSection(s.chain),
        s.roles.host ? hostNodeSection(s.host_node) : null,
        backupSection(s.backup),
        remindersSection(s.reminders),
        networkSection(s.network),
        rolesSection(s.roles));
    });
  }

  gz.screens.settings = { title: "Settings", topics: ["settings", "chain"], render: render };
})();
