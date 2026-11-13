/* Screen: Factory. The factory you are in, its tree, and leaving alone. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var STATE_PILL = {
    active: ["Live", "green"], winding_down: ["Winding down", "gold"], host_gone: ["Host not answering", "tomato"],
    exiting: ["You are leaving", "gold"], closed: ["You have left", "grey"]
  };

  var STEP_STATE = {
    pending: ["Not started", "grey"], waiting: ["Waiting", "gold"], published: ["Published, not confirmed", "blue"], confirmed: ["Confirmed", "green"]
  };

  function noFactory(status) {
    var actions = status.member.lobby_id
      ? [ui.link("Open your lobby", "#/lobby/" + status.member.lobby_id, "btn primary")]
      : [ui.link("Look at the lobbies", "#/lobbies", "btn primary")];
    return h("div", null, h("h1", null, "Factory"),
      ui.empty("You are not in a factory",
        status.member.lobby_id ? "You are waiting in a lobby. When it starts and its funding confirms, your factory appears here."
          : "A factory is one on-chain output shared by a host and many members, which gives each member a Lightning channel. Factories form in lobbies.", actions),
      status.host.factory_id ? ui.notice("info", null, "The factory you are hosting is on the host screen.", [ui.link("Open the host screen", "#/host", "btn")]) : null);
  }

  /* ----- leaving alone ----- */

  function leaveDialog(f) {
    return h("div", null,
      h("p", null, "Leaving alone takes your coins out of the factory without the host's help. The app publishes your branch of the tree on the chain, one transaction after another."),
      ui.facts([
        ["What you receive", u.sats(f.channel.balance_sat), "Your channel balance, paid to your on-chain wallet."],
        ["How long it takes", u.blocks(f.exit.blocks), "Plus about one block for each of the " + f.exit.transactions + " transactions to confirm. Until it finishes you cannot spend these coins."],
        ["What it costs", "About " + u.sats(f.exit.fee_sat) + " in chain fees", "Paid from the host's side of the factory, not from your balance. If the chain is busy the app uses your on-chain reserve to raise the fee."],
        ["What you lose", "Your channel", "Lightning payments stop at once. Payments still on their way fail and return to their senders."]
      ]),
      h("p", null, "This cannot be undone once the first transaction is published. If the host is answering, asking it to close with you is faster and cheaper; that is not in the prototype."));
  }

  function leaveSection(f) {
    return ui.card("Leave alone",
      h("p", null, "You can always take your coins out without the host's help. It is slower and uses the chain, so it is meant for when the host has disappeared or you no longer trust it."),
      h("div", { class: "actions" }, ui.button("Leave this factory alone", function (e) {
        var target = e.currentTarget;
        ui.confirm({ title: "Leave “" + f.name + "” alone?", confirmLabel: "Publish and leave", danger: true,
          mustTick: "I understand this closes my channel and cannot be undone.", body: leaveDialog(f) }).then(function (yes) {
          if (yes) ui.run(target, function () { return api.startExit(f.id); }, "Leaving has started. The first transaction is published.");
        });
      }, { kind: "danger" }), ui.notInPrototype("Ask the host to close with me")));
  }

  function stepTitle(step, total) {
    if (step.kind === "channel") return "Close your channel and move the coins to your on-chain wallet";
    if (step.kind === "leaf") return "Publish your leaf, which holds your channel";
    return "Publish level " + step.level + " of your branch";
  }

  function exitProgress(f) {
    var p = f.exit_progress;
    var list = h("ol", { class: "steps" });
    p.steps.forEach(function (step) {
      var words = STEP_STATE[step.state];
      var detail = null;
      if (step.state === "waiting") {
        detail = h("p", null, "Waiting " + u.blocks(step.wait_blocks_left) + " of a " + u.number(step.wait_blocks) + "-block waiting period. At zero: the app publishes this transaction by itself.");
      } else if (step.state === "pending" && step.wait_blocks) {
        detail = h("p", { class: "hint" }, "Has a waiting period of " + u.blocks(step.wait_blocks) + " after the step before it confirms.");
      } else if (step.txid) {
        detail = h("p", { class: "hint" }, "Transaction ", h("code", { title: step.txid }, u.shortId(step.txid)),
          step.state === "confirmed" ? ", " + u.plural(step.confirmations, "confirmation") : ", waiting for its first confirmation");
      }
      list.appendChild(h("li", { class: "step " + step.state }, h("p", null, h("b", null, stepTitle(step)), " ", ui.pill(words[0], words[1])), detail));
    });
    var done = p.steps.filter(function (st) { return st.state === "confirmed"; }).length;
    return h("div", null,
      p.done
        ? ui.notice("ok", "You have left the factory.", u.sats(p.amount_sat) + " are in your on-chain wallet, under your control alone.",
          [ui.link("Open the wallet", "#/wallet", "btn primary"), ui.link("Look at the lobbies", "#/lobbies", "btn")])
        : ui.notice("warn", "You are leaving this factory alone.",
          h("div", null,
            h("p", null, "About " + u.blocks(p.blocks_left) + " to go. At the end, " + u.sats(p.amount_sat) + " arrive in your on-chain wallet."),
            h("p", null, "The app does each step by itself, but only while it is running. If you close it, it carries on when you open it again; open it at least once a day until this is done."))),
      ui.card("Progress", ui.progress(done, p.steps.length, "Steps confirmed"),
        h("p", null, done + " of " + p.steps.length + " transactions confirmed. Started at block " + u.number(p.started_height) + "."), list),
      p.done ? null : h("p", { class: "hint" }, "In the prototype, the demo controls can mine blocks to move this along."));
  }

  /* ----- the live factory ----- */

  function stateNotice(f) {
    if (f.rotation) {
      return ui.notice("warn", "Moving to the next factory. Keep the app open.",
        f.rotation.step === "signing" ? "Step 1 of 2: signing your place in the next factory. The app checks it against your conditions first."
          : "Step 2 of 2: moving your balance across over Lightning.");
    }
    if (f.state === "winding_down") {
      var left = Math.max(0, f.auto_exit_height - f.height_now);
      var next = f.next_factory;
      return ui.notice("danger", "This factory is winding down. Move to the next one.",
        h("div", null,
          h("p", null, "A factory has a fixed lifetime. Before it ends, the host opens a new one and members move across; this is called a rotation. You have " + u.blocks(left) + " left to move."),
          h("p", null, "At zero: if you have not moved, the app leaves this factory alone for you. You keep your coins, but they come out on chain and that takes " + u.blocks(f.exit.blocks) + "."),
          next ? ui.facts([
            ["Next factory", next.name],
            ["Members", String(next.members)],
            ["Channel size", u.sats(next.channel_size_sat)],
            ["Joining fee", u.sats(next.join_fee_sat)],
            ["Your conditions", next.within_conditions ? "Met" : "Not met: the app will not move you"]
          ]) : h("p", null, "The host has not offered a next factory yet.")),
        next ? [ui.button("Move to the next factory", function (e) {
          var target = e.currentTarget;
          ui.confirm({ title: "Move to “" + next.name + "”?", confirmLabel: "Sign and move",
            body: h("div", null,
              h("p", null, "The app signs your place in the next factory, then pays your balance of " + u.sats(f.channel.balance_sat) + " across over Lightning. It takes a few seconds and uses no chain fee of yours."),
              h("p", null, "The app refuses if the next factory is outside your conditions.")) }).then(function (yes) {
            if (yes) ui.run(target, function () { return api.moveToNextFactory(f.id); });
          });
        }, { kind: "primary" })] : null);
    }
    if (f.state === "host_gone") {
      return ui.notice("danger", "The host has not answered since " + u.ago(f.host.last_seen_at) + ".",
        h("div", null,
          h("p", null, "Payments in and out are paused, because every payment passes through the host. Your coins are not at risk from this: your signed way out does not need the host."),
          h("p", null, "You can wait for the host to come back, or leave alone now (below). If you do nothing, the app leaves alone for you at block " +
            u.number(f.auto_exit_height) + ", " + u.blocks(Math.max(0, f.auto_exit_height - f.height_now)) + " from now.")));
    }
    return null;
  }

  function liveFactory(f) {
    var c = f.channel;
    var toExpiry = Math.max(0, f.expiry_height - f.height_now);
    return h("div", null,
      stateNotice(f),
      h("section", null, h("h2", null, "Your place in it"),
        h("div", { class: "stats" },
          ui.stat("Your channel balance", ui.amount(c.balance_sat),
            "What you can spend over Lightning now. It is yours: every state of the channel leaves you able to take this out alone."),
          ui.stat("You can still receive", ui.amount(c.receivable_sat),
            "Room left in your channel for incoming payments. Channel size " + u.sats(c.capacity_sat) + ", less your balance."),
          ui.stat("Host's spare liquidity on your leaf", ui.amount(c.spare_liquidity_sat),
            "Funds the host keeps beside your channel. They are the host's, not yours. The host can sell some of them to you as room to receive more."),
          ui.stat("Leaving alone would take", u.number(f.exit.blocks) + " blocks",
            "If you publish your branch yourself, this is the total waiting: " + f.exit.timed_levels + " waiting periods of 432 blocks on your path. A block takes about ten minutes.",
            u.blocksAsTime(f.exit.blocks)),
          ui.stat("Factory ends", u.dateOfBlock(toExpiry),
            "The factory expires at block " + u.number(f.expiry_height) + ". Before then you move to the host's next factory, or the app leaves alone for you at block " + u.number(f.auto_exit_height) + ".",
            u.number(toExpiry) + " blocks, " + u.blocksAsTime(toExpiry)),
          ui.stat("Members", String(f.members),
            "How many members share this factory's single on-chain output with the host. Every one of them, and the host, must sign to change it."))),
      ui.card("The tree, with your path",
        h("p", null, "The shared output is divided by transactions that everyone signed before the host paid in. Your path, in red, is the set you would publish to leave alone."),
        h("div", { class: "tree-wrap" }, gz.tree.diagram(f)),
        h("details", null, h("summary", null, "The same path in words"), gz.tree.inWords(f))),
      ui.card("Funding",
        ui.facts([
          ["Funded by", f.host.name, "The host paid for the whole factory. Members started at zero."],
          ["Funding transaction", h("code", { title: f.funding.txid }, u.shortId(f.funding.txid)), u.plural(f.funding.confirmations, "confirmation") + "."],
          ["Created at block", u.number(f.created_height)],
          ["Host last answered", f.host.online ? "Just now" : u.ago(f.host.last_seen_at)]
        ])),
      leaveSection(f));
  }

  function render(params, status) {
    if (!status.member.factory_id) return Promise.resolve(noFactory(status));
    return api.getFactory(status.member.factory_id).then(function (f) {
      f.height_now = status.chain.height;
      var pill = STATE_PILL[f.state];
      return h("div", null,
        h("h1", null, f.name),
        h("p", { class: "pills" }, ui.pill(pill[0], pill[1]), ui.pill("Hosted by " + f.host.name, "grey")),
        f.state === "exiting" || f.state === "closed" ? exitProgress(f) : liveFactory(f));
    });
  }

  gz.screens.factory = { title: "Factory", topics: ["factory", "status"], render: render };
})();
