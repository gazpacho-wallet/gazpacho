/* Screen: Home. What you have and what needs your attention. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  /* What each item in status.attention says and where it leads. */
  var ATTENTION = {
    chain_disagree: function () {
      return { text: "The chain servers disagree about the latest block. Until they agree, the app treats new transactions as not confirmed and will not publish anything.", href: "#/settings", action: "See the servers" };
    },
    host_gone: function (p) {
      return { text: "The host, " + p.host + ", has not answered since " + u.ago(p.last_seen_at) + ". Payments are paused. Your coins are still yours: you can wait, or leave the factory alone.", href: "#/factory", action: "See your choices" };
    },
    sign_rotation: function (p) {
      return { text: "Your factory is winding down. Move to the host's next factory within " + u.blocks(p.blocks_left) + ".", href: "#/factory", action: "Move to the next factory" };
    },
    exit_running: function () {
      return { text: "You are leaving your factory alone. The app is publishing your transactions and waiting between them.", href: "#/factory", action: "See progress" };
    },
    exit_done: function (p) {
      return { text: "You have left your factory. " + u.sats(p.amount_sat) + " are now in your on-chain wallet.", href: "#/wallet", action: "See the wallet" };
    },
    reserve_low: function (p) {
      return { text: "Your on-chain wallet holds less than the recommended reserve of " + u.sats(p.recommended_sat) + ". The reserve lets the app raise the fee if you have to leave alone while the chain is busy.", href: "#/wallet", action: "See the wallet" };
    },
    lobby_not_ready: function (p) {
      return { text: "You are in the lobby “" + p.name + "” but marked not ready, because its terms are outside your conditions.", href: "#/lobby/" + p.lobby_id, action: "See why" };
    },
    lobby_signing: function (p) {
      return { text: "The lobby “" + p.name + "” is starting. Keep the app open until signing has finished.", href: "#/lobby/" + p.lobby_id, action: "Watch it" };
    },
    lobby_funding: function (p) {
      return { text: "Everyone in “" + p.name + "” has signed. Waiting for the host's funding transaction to confirm.", href: "#/lobby/" + p.lobby_id, action: "Watch it" };
    },
    host_can_start: function (p) {
      return { text: "Your lobby “" + p.name + "” has reached its minimum and can be started now.", href: "#/host", action: "Open the host dashboard" };
    },
    host_node_missing: function () {
      return { text: "Host mode is on but no Lightning node is linked. Without one, members of your factory cannot pay or be paid outside it.", href: "#/settings", action: "Link a node" };
    }
  };

  var LEVEL_KIND = { urgent: "danger", warn: "warn", info: "info" };

  var DATE_WORDS = {
    open_app: {
      title: "Open the app by",
      atZero: function () {
        return "At zero: the app may be too late to answer if an old state of your channel is published, and you could lose coins. Every time the app runs and checks the chain, this date moves forward again.";
      }
    },
    sign_rotation: {
      title: "Sign the rotation by",
      atZero: function (item) {
        return "A rotation moves you into the host's next factory before this one ends. At zero: if you have not moved, the app leaves this factory alone for you, which takes longer and uses the chain.";
      }
    },
    expiry: {
      title: "Factory expires on",
      atZero: function (item) {
        return "At zero: the factory's protections end. The app does not wait for that. It starts leaving alone at block " +
          u.number(item.auto_exit_height) + ", " + u.blocks(item.auto_exit_in_blocks) + " from now, because leaving takes " + u.blocks(item.exit_blocks) + ".";
      }
    }
  };

  function attentionList(status) {
    if (!status.attention.length) {
      return ui.notice("ok", "Nothing needs you right now.", "The app keeps watching while it is open.");
    }
    var list = h("ul", { class: "plain-list" });
    status.attention.forEach(function (item) {
      var words = (ATTENTION[item.code] || function () { return { text: item.code, href: "#/home", action: "Open" }; })(item.params);
      list.appendChild(h("li", null, ui.notice(LEVEL_KIND[item.level], null, words.text, [ui.link(words.action, words.href, "btn small")])));
    });
    return list;
  }

  function dateCard(item, prominent) {
    var words = DATE_WORDS[item.id];
    var body;
    if (item.state === "not_yet") {
      body = [h("p", { class: "date-main" }, "Not yet needed"),
        h("p", null, "The rotation opens at block " + u.number(item.opens_height) + ", in " + u.blocks(item.opens_in_blocks) +
          ". The last moment to sign is block " + u.number(item.due_height) + ", around " + u.dateOfBlock(item.blocks_left) + ".")];
    } else {
      body = [h("p", { class: "date-main" }, u.blocksAsTime(item.blocks_left).replace("about ", "About ")),
        h("p", null, u.number(item.blocks_left) + " blocks from now, at block " + u.number(item.due_height) + ", around " + u.dateOfBlock(item.blocks_left) + ".")];
    }
    var kind = item.state === "urgent" ? "danger" : item.state === "soon" ? "warn" : "plain";
    return h("section", { class: "card date " + kind + (prominent ? " prominent" : "") },
      h("h3", null, words.title, prominent ? ui.pill("Most urgent", kind === "plain" ? "blue" : kind === "danger" ? "tomato" : "gold") : null),
      body, h("p", { class: "hint" }, words.atZero(item)));
  }

  function datesSection(schedule) {
    if (!schedule.items.length) {
      return ui.card("Dates to keep",
        h("p", null, "There are no dates to keep at the moment. Dates appear here once you are in a factory: when to open the app by, when to move to the next factory, and when the factory ends."));
    }
    var items = schedule.items.slice().sort(function (a, b) {
      return (a.id === schedule.most_urgent ? -1 : 0) - (b.id === schedule.most_urgent ? -1 : 0);
    });
    return h("section", null, h("h2", null, "Dates to keep"),
      h("p", { class: "hint" }, "Dates are counted in blocks. A block takes about ten minutes, so the times are approximate."),
      h("div", { class: "dates" }, items.map(function (item) { return dateCard(item, item.id === schedule.most_urgent); })));
  }

  function membershipCard(status, factory, lobby) {
    if (factory) {
      var stateWords = { active: ["Live", "green"], winding_down: ["Winding down", "gold"], host_gone: ["Host not answering", "tomato"],
        exiting: ["You are leaving", "gold"], closed: ["You have left", "grey"] }[factory.state];
      return ui.card("Your factory",
        h("p", null, h("b", null, factory.name), " ", ui.pill(stateWords[0], stateWords[1])),
        h("p", null, "Hosted by " + factory.host.name + ", with " + factory.members + " members. " +
          "A factory is one on-chain output shared by a host and many members; your Lightning channel lives inside it."),
        h("div", { class: "actions" }, ui.link("Open the factory", "#/factory", "btn"), ui.link("Pay or receive", "#/pay", "btn")));
    }
    if (lobby) {
      return ui.card("Your lobby",
        h("p", null, h("b", null, lobby.name), " ", ui.pill(ui.STAGE_WORDS[lobby.stage], lobby.you.ready ? "green" : "gold")),
        h("p", null, ui.startRuleSentence(lobby)),
        h("div", { class: "actions" }, ui.link("Open the lobby", "#/lobby/" + lobby.id, "btn")));
    }
    return ui.empty("You are not in a factory",
      "To use Lightning here you join a factory: one on-chain output shared by a host and many members, which gives each member a channel. Factories form in lobbies. Joining costs nothing up front; the host funds the factory.",
      [ui.link("Look at the lobbies", "#/lobbies", "btn primary"), ui.link("Set my conditions first", "#/conditions", "btn")]);
  }

  function hostCard(status) {
    if (!status.roles.host) return null;
    var text = status.host.factory_id ? "You are hosting a live factory."
      : status.host.lobby_id ? "You have a lobby open." : "You are not hosting anything at the moment.";
    return ui.card("Hosting", h("p", null, text),
      h("div", { class: "actions" }, ui.link("Open the host screen", "#/host", "btn")));
  }

  function render(params, status) {
    var factoryId = status.member.factory_id, lobbyId = status.member.lobby_id;
    return Promise.all([
      api.getWallet(), api.getSchedule(),
      factoryId ? api.getFactory(factoryId) : null,
      lobbyId ? api.getLobby(lobbyId) : null
    ]).then(function (got) {
      var wallet = got[0], schedule = got[1], factory = got[2], lobby = got[3];
      var channel = factory && factory.channel;
      return h("div", null,
        h("h1", null, "Home"),
        h("p", { class: "lead" }, "This wallet is on " + ui.NETWORK_WORDS[status.network] +
          ", a test network. The coins shown here are test coins and have no value."),
        h("section", { "aria-label": "Needs you" }, h("h2", null, "Needs you"), attentionList(status)),
        h("section", null, h("h2", null, "What you have"),
          h("div", { class: "stats" },
            ui.stat("In your factory channel", channel ? ui.amount(channel.balance_sat) : "No channel yet",
              "Coins you can spend over Lightning right now. They sit inside the factory, and you can always take them out without anyone's help.",
              channel ? "Can receive up to " + u.sats(channel.receivable_sat) + " more" : null),
            ui.stat("On chain", ui.amount(wallet.confirmed_sat),
              "Ordinary on-chain coins in this wallet, outside any factory. A small reserve here lets the app raise fees if you ever have to leave a factory alone.",
              wallet.unconfirmed_sat ? u.sats(wallet.unconfirmed_sat) + " more not yet confirmed" : null))),
        datesSection(schedule),
        membershipCard(status, factory, lobby),
        hostCard(status));
    });
  }

  gz.screens.home = { title: "Home", topics: ["status", "schedule", "factory", "lobby", "wallet", "payments"], render: render };
})();
