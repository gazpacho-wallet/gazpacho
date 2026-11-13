/* Screens: the list of lobbies, and one lobby in detail.
   Also exports gz.lobbyParts, reused by the conditions and host screens. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var filter = { onlyMatching: false, profile: "all" };
  var invitationDraft = "";
  var invitationOpen = false;

  function profileNames(ids) {
    return ids.map(function (id) { return ui.PROFILE_WORDS[id].name; }).join(", ");
  }

  /* One failed condition, in a sentence. */
  function failureText(f) {
    switch (f.condition) {
      case "min_members": return "You asked for at least " + f.yours + " members. This lobby starts with " + f.offered + " at most.";
      case "min_channel_sat": return "You asked for a channel of at least " + u.sats(f.yours) + ". This lobby offers " + u.sats(f.offered) + ".";
      case "max_join_fee_sat": return "Your ceiling for the joining fee is " + u.sats(f.yours) + ". This lobby charges " + u.sats(f.offered) + ".";
      case "max_payment_fee_ppm": return "Your ceiling for the fee on each payment is " + u.ppm(f.yours) + ". This lobby charges " + u.ppm(f.offered) + ".";
      case "max_liquidity_fee_ppm": return "Your ceiling for the fee on extra receiving room is " + u.ppm(f.yours) + ". This lobby charges " + u.ppm(f.offered) + ".";
      case "profiles": return "You accept the profiles " + profileNames(f.yours) + ". This lobby uses " + ui.PROFILE_WORDS[f.offered].name + ".";
      case "max_exit_blocks": return "You want leaving alone to take no more than " + u.blocks(f.yours) + ". Here it takes " + u.blocks(f.offered) + ".";
      default: return "A condition called “" + f.condition + "” is not met.";
    }
  }

  function failureList(check) {
    return h("ul", null, check.failures.map(function (f) { return h("li", null, failureText(f)); }));
  }

  function pills(lobby) {
    return h("p", { class: "pills" },
      ui.pill(ui.PROFILE_WORDS[lobby.profile].name + " profile", "blue"),
      ui.pill(lobby.listed ? "Listed" : "Unlisted", "grey"),
      ui.pill(lobby.access === "open" ? "Open to anyone" : "By invitation", lobby.access === "open" ? "grey" : "gold"),
      lobby.stage !== "open" ? ui.pill(ui.STAGE_WORDS[lobby.stage], "green") : null);
  }

  /* The terms in full. Used on the lobby screen and in the host's preview. */
  function termsFacts(lobby) {
    var t = lobby.terms, rule = lobby.start_rule;
    return ui.facts([
      ["Target", rule.target + " members", "The lobby starts at once when this many are ready."],
      ["Minimum", rule.minimum + " members", "At the deadline it starts only if at least this many are ready."],
      ["Deadline", u.dateTime(rule.deadline_at), rule.on_shortfall === "carry_over" ? "Below the minimum, people waiting are carried over to the host's next lobby." : "Below the minimum, the lobby is cancelled."],
      ["Channel size", u.sats(t.channel_size_sat), "The size of the Lightning channel each member gets. The host pays for all of it. You start with a balance of zero and can receive up to this amount."],
      ["Host's spare liquidity", u.sats(t.spare_liquidity_sat) + " per member", "Extra funds the host keeps beside your channel and can sell to you as room to receive more."],
      ["Joining fee", u.sats(t.join_fee_sat), "Charged once, taken from the first payment you receive."],
      ["Fee on each payment", u.ppm(t.payment_fee_ppm) + " of the amount", "What the host charges to pass a payment on. " + u.number(t.payment_fee_ppm) + " parts per million."],
      ["Fee for extra receiving room", u.ppm(t.liquidity_fee_ppm) + " of the amount added", "What the host charges when you buy some of its spare liquidity."],
      ["Lifetime", u.blocks(t.lifetime_blocks), "How long the factory exists. You move to the host's next factory, or leave, before it ends."],
      ["Leaving alone takes", u.blocks(t.exit_blocks), "If the host disappears you can take your coins out without anyone's help. This is how long that takes: " + t.timed_levels + " waiting " + (t.timed_levels === 1 ? "period" : "periods") + " of 432 blocks."],
      ["Profile", ui.PROFILE_WORDS[lobby.profile].name, ui.PROFILE_WORDS[lobby.profile].about],
      ["Terms version", String(t.version), "The host signs its terms. If it changes them the version goes up and the app checks them against your conditions again."]
    ]);
  }

  /* A lobby as it appears in the list. */
  function lobbyCard(lobby, options) {
    options = options || {};
    var t = lobby.terms;
    var verdict = options.preview ? null : lobby.check.ok
      ? h("p", { class: "verdict ok" }, "Within your conditions.")
      : h("div", { class: "verdict bad" }, h("p", null, "Outside your conditions. The app will not join or sign:"), failureList(lobby.check));
    return h("article", { class: "card lobby-card" },
      h("h2", null, options.preview ? lobby.name : h("a", { href: "#/lobby/" + lobby.id }, lobby.name)),
      h("p", { class: "hint" }, "Hosted by " + lobby.host.name + (lobby.host.factories_funded ? ", which has funded " + lobby.host.factories_funded + " factories before" : ", a new host")),
      pills(lobby),
      h("p", null, ui.startRuleSentence(lobby)),
      h("p", null, "Deadline ", ui.countdown(lobby.start_rule.deadline_at, ui.shortfallSentence(lobby))),
      ui.facts([
        ["Channel size", u.sats(t.channel_size_sat)],
        ["Fees", u.sats(t.join_fee_sat) + " to join, " + u.ppm(t.payment_fee_ppm) + " per payment"],
        ["Lifetime", u.blocksAsTime(t.lifetime_blocks)],
        ["Leaving alone takes", u.blocksAsTime(t.exit_blocks)]
      ]),
      verdict,
      options.preview ? null : h("div", { class: "actions" }, ui.link("See this lobby", "#/lobby/" + lobby.id, "btn")));
  }

  /* ----- the list ----- */

  function invitationBox() {
    return h("details", { class: "card", open: invitationOpen, ontoggle: function (e) { invitationOpen = e.currentTarget.open; } },
      h("summary", null, "Join with an invitation link"),
      h("p", null, "Unlisted lobbies and lobbies by invitation are reached with a link from the host. Hosts usually show it as a QR code; scanning is not in the prototype, so paste the link."),
      ui.field({ id: "invitation-link", label: "Invitation link", value: invitationDraft, hint: "It starts with gazpacho:" }),
      h("div", { class: "actions" },
        ui.button("Open the invitation", function (e) {
          invitationDraft = ui.value("invitation-link");
          ui.run(e.currentTarget, function () {
            return api.openInvitation(invitationDraft).then(function (r) { gz.app.go("lobby/" + r.lobby_id); });
          });
        }, { kind: "primary" }),
        ui.button("Fill in an example link (prototype only)", function () {
          var input = document.getElementById("invitation-link");
          input.value = "gazpacho:invite/example-example-example";
          input.setAttribute("data-dirty", "1");
        }, { kind: "ghost" })));
  }

  function renderList(params, status) {
    return api.listLobbies().then(function (lobbies) {
      var shown = lobbies.filter(function (l) {
        return (!filter.onlyMatching || l.check.ok) && (filter.profile === "all" || l.profile === filter.profile);
      });
      var hidden = lobbies.length - shown.length;
      var matching = ui.checkbox({ id: "filter-matching", label: "Only lobbies within my conditions", checked: filter.onlyMatching });
      matching.querySelector("input").addEventListener("change", function (e) { filter.onlyMatching = e.target.checked; gz.app.redraw(); });
      var profile = ui.field({ id: "filter-profile", label: "Profile", value: filter.profile,
        choices: [["all", "Any profile"]].concat(Object.keys(ui.PROFILE_WORDS).map(function (id) { return [id, ui.PROFILE_WORDS[id].name]; })) });
      profile.querySelector("select").addEventListener("change", function (e) { filter.profile = e.target.value; gz.app.redraw(); });

      var list;
      if (!lobbies.length) {
        list = ui.empty("No lobbies are listed right now", "Hosts open new lobbies regularly, often once a day. This list updates by itself. If a host gave you an invitation link, use it above.");
      } else if (!shown.length) {
        list = ui.empty("No lobby matches this filter", hidden + " listed " + (hidden === 1 ? "lobby is" : "lobbies are") + " hidden by it.",
          [ui.button("Show all lobbies", function () { filter.onlyMatching = false; filter.profile = "all"; gz.app.go("lobbies"); }, { kind: "primary" }),
            ui.link("Change my conditions", "#/conditions", "btn")]);
      } else {
        list = h("div", { class: "card-list" }, shown.map(function (l) { return lobbyCard(l); }));
      }

      return h("div", null,
        h("h1", null, "Lobbies"),
        h("p", { class: "lead" }, "A lobby is the waiting room where members gather before a factory is created. A factory is one on-chain output shared by a host and many members, which gives each member a Lightning channel. Joining puts none of your money in: the host funds the factory, and only after everyone has signed."),
        status.member.factory_id && !status.member.lobby_id
          ? ui.notice("info", "You are already in a factory.", "You can look at lobbies, but the prototype handles one factory at a time, so joining is switched off until you have left it.") : null,
        h("section", { class: "card filters", "aria-label": "Filter the list" }, matching, profile,
          h("p", { class: "hint" }, "Every lobby is checked against ", ui.link("your conditions", "#/conditions"), " whether or not you filter.")),
        invitationBox(),
        h("p", { class: "hint", role: "status" }, shown.length + " of " + lobbies.length + " listed lobbies shown."),
        list);
    });
  }

  /* ----- one lobby ----- */

  function readyState(lobby) {
    var you = lobby.you;
    if (lobby.outcome === "started_without_you") {
      return ui.notice("warn", "This lobby started without you.", "When it started, your conditions were not met, so the app did not sign. Nothing was at risk.");
    }
    if (lobby.stage === "cancelled") {
      return ui.notice("warn", "This lobby was cancelled.", "The deadline passed with fewer than " + lobby.start_rule.minimum + " members ready. Nothing was at risk.");
    }
    if (lobby.stage === "active") {
      return ui.notice("ok", "The factory is live.", "The funding transaction is confirmed and your channel is open.",
        [ui.link("Go to the factory", "#/factory", "btn primary")]);
    }
    if (!you.joined) {
      if (lobby.stage !== "open") return ui.notice("info", "This lobby has started.", "It is no longer taking members.");
      return lobby.check.ok
        ? ui.notice("info", "You have not joined.", "This lobby is within your conditions.")
        : ui.notice("danger", "The app will not join this lobby.", h("div", null, h("p", null, "Its terms are outside your conditions:"), failureList(lobby.check)),
          [ui.link("Review my conditions", "#/conditions", "btn")]);
    }
    if (lobby.stage === "open") {
      if (!you.ready) {
        var reasons = lobby.check.ok
          ? h("p", null, "Someone on your block list is in this lobby. The app will not sign a factory that includes them.")
          : h("div", null, h("p", null, "The terms are outside the conditions you locked in:"), failureList(lobby.check));
        return ui.notice("danger", "You are in, but not ready. The app will not sign.",
          h("div", null, reasons, h("p", null, "The app becomes ready again by itself if this changes. You do not need to do anything, and nothing is at risk.")));
      }
      if (!you.counted) {
        return ui.notice("warn", "You are in and ready, but not counted yet.",
          "You asked for at least " + lobby.check.counted_from + " members and " + lobby.counts.ready + " are ready. You are counted once " + lobby.check.counted_from + " or more are here.");
      }
      return ui.notice("ok", "You are in and ready.",
        "Leave the app running. When the lobby starts, the app signs by itself, within your conditions, in a few seconds. Nothing is at risk while you wait: members put in no money.");
    }
    if (lobby.stage === "ready_check") {
      return ui.notice("warn", "Starting. Keep the app open.", "The host is checking who is present before signing begins.");
    }
    if (lobby.stage === "signing") {
      var sg = lobby.signing;
      return ui.notice("warn", "Signing now. Keep the app open.", h("div", null,
        h("p", null, sg.step === "nonces" ? "Step 1 of 2: everyone exchanges one-time signing numbers." : "Step 2 of 2: everyone exchanges signatures. The app checks each one."),
        ui.progress(sg.signed, sg.of, "Signing progress"),
        h("p", null, sg.signed + " of " + sg.of + " received. Attempt " + sg.attempt + " of " + sg.max_attempts + "."),
        h("p", { class: "hint" }, "If anyone drops out during signing, the round starts again without them. Signing secrets are never saved, so closing the app now would make everyone start over.")));
    }
    var fd = lobby.funding;
    return ui.notice("info", "Everyone has signed. Waiting for the funding transaction to confirm.", h("div", null,
      h("p", null, "The host funds last: it published the funding transaction only after the whole tree was signed."),
      ui.progress(fd.confirmations, fd.confirmations_needed, "Confirmations"),
      h("p", null, fd.confirmations === 0 ? "Not confirmed yet. " : "", fd.confirmations + " of " + fd.confirmations_needed + " confirmations. Each takes about ten minutes."),
      h("p", { class: "hint" }, "Transaction ", h("code", { title: fd.txid }, u.shortId(fd.txid)))));
  }

  function people(lobby) {
    var head = lobby.counts.present + " present, " + lobby.counts.ready + " ready.";
    if (!lobby.members) {
      return ui.card("Who is here", h("p", null, head),
        h("p", { class: "hint" }, "The host has switched names off for this lobby, so members see only a head-count."));
    }
    var list = h("ul", { class: "people" });
    lobby.members.forEach(function (m) {
      var identity = m.identity ? h("span", { class: "hint" }, " " + m.identity.label + (m.identity.verified ? " (proven)" : " (unverified, typed by them)")) : null;
      var block = lobby.you.joined && !m.you ? ui.button(m.blocked ? "Unblock" : "Block", function (e) {
        ui.run(e.currentTarget, function () { return api.setBlocked(lobby.id, m.id, !m.blocked); });
      }, { kind: "small" }) : null;
      if (block) block.setAttribute("aria-label", (m.blocked ? "Unblock " : "Block ") + m.name);
      list.appendChild(h("li", { class: m.you ? "you" : "" },
        h("span", { class: "who" }, m.name, identity),
        ui.pill(m.blocked ? "Blocked by you" : m.ready ? "Ready" : "Not ready", m.blocked ? "tomato" : m.ready ? "green" : "gold"),
        block));
    });
    return ui.card("Who is here", h("p", null, head),
      h("p", { class: "hint" }, "Names are temporary and exist only for this lobby. Blocking someone means your app will not sign a factory that includes them; it does not remove them for anyone else."),
      list);
  }

  function hostSwitches(lobby) {
    var s = lobby.switches;
    return ui.card("What the host allows here",
      ui.facts([
        ["Names", s.names ? "On" : "Off", s.names ? "Members can see each other's temporary names." : "Members see only a head-count."],
        ["Chat", s.chat ? "On" : "Off", "Chat itself is not in the prototype."],
        ["Requests to change the rules", s.rule_requests ? "On" : "Off", s.rule_requests ? "Members may ask the host to change a term. The host decides." : "The terms are as offered."]
      ]),
      s.rule_requests && lobby.you.joined ? h("div", { class: "actions" }, ui.notInPrototype("Ask for a rule change")) : null);
  }

  function joinDialogBody(lobby, conditions) {
    return h("div", null,
      h("p", null, "Joining puts none of your money in. It reserves a seat and locks in your conditions for this lobby:"),
      ui.facts([
        ["At least", conditions.min_members + " members"],
        ["Channel of at least", u.sats(conditions.min_channel_sat)],
        ["Joining fee at most", u.sats(conditions.max_join_fee_sat)],
        ["Fee per payment at most", u.ppm(conditions.max_payment_fee_ppm)],
        ["Leaving alone takes at most", u.blocks(conditions.max_exit_blocks)]
      ]),
      h("p", null, "The host of a factory can see every payment its members make through it."),
      h("p", null, "When the lobby starts, the app signs by itself if the real factory is within these conditions, and refuses if it is not. You can leave the lobby at any time before signing finishes."));
  }

  function actions(lobby, status) {
    if (lobby.you.joined) {
      if (lobby.stage === "funding" || lobby.stage === "active") return null;
      return h("div", { class: "actions" }, ui.button("Leave this lobby", function (e) {
        var signing = lobby.stage === "signing";
        ui.confirm({ title: "Leave this lobby?", confirmLabel: "Leave the lobby", danger: signing,
          body: h("p", null, signing ? "Signing is under way. If you leave now the round starts again for everyone else without you. You lose nothing."
            : "You give up your seat. You lose nothing, and you can join again while the lobby is open.") }).then(function (yes) {
          if (yes) ui.run(e.currentTarget, function () { return api.leaveLobby(lobby.id); }, "You have left the lobby.");
        });
      }));
    }
    if (lobby.stage !== "open") return null;
    var blockedBy = status.member.lobby_id ? "You are already in another lobby. Leave it first."
      : status.member.factory_id ? "You are already in a factory. The prototype handles one factory at a time."
      : !lobby.check.ok ? "The terms are outside your conditions."
      : lobby.access !== "open" && lobby.listed ? "This lobby needs an invitation link from its host." : null;
    var why = blockedBy ? h("p", { class: "hint", id: "join-why" }, "You cannot join: " + blockedBy) : null;
    return h("div", null, h("div", { class: "actions" }, ui.button("Join this lobby", function (e) {
      var target = e.currentTarget;
      api.getConditions().then(function (c) {
        return ui.confirm({ title: "Join “" + lobby.name + "”?", confirmLabel: "Join and lock my conditions", body: joinDialogBody(lobby, c.conditions) })
          .then(function (yes) {
            if (yes) ui.run(target, function () { return api.joinLobby(lobby.id, c.conditions); }, "You have joined. The app will sign for you when the lobby starts.");
          });
      }).catch(function (error) { ui.toast("That did not work. " + error.message); });
    }, { kind: "primary", disabled: !!blockedBy, describedBy: why ? "join-why" : null })), why);
  }

  function renderLobby(params, status) {
    return api.getLobby(params[0]).then(function (lobby) {
      var change = lobby.terms_change;
      return h("div", null,
        h("p", null, ui.link("Back to all lobbies", "#/lobbies")),
        h("h1", null, lobby.name),
        h("p", { class: "hint" }, "Hosted by " + lobby.host.name + (lobby.host.factories_funded ? ". This host has funded " + lobby.host.factories_funded + " factories before, by its own published record." : ". This host has no published record yet.")),
        pills(lobby),
        h("section", { "aria-label": "Your state in this lobby" }, readyState(lobby)),
        change ? ui.notice("warn", "The host changed the terms " + u.ago(change.at) + " (version " + change.version + ").",
          h("ul", null, change.changes.map(function (c) {
            return h("li", null, c.field === "payment_fee_ppm" ? "Fee on each payment: from " + u.ppm(c.from) + " to " + u.ppm(c.to) + "." : c.field + ": from " + c.from + " to " + c.to + ".");
          }))) : null,
        ui.card("When it starts",
          h("p", { class: "rule" }, ui.startRuleSentence(lobby)),
          ui.progress(lobby.counts.ready, lobby.start_rule.target, "Members ready, out of the target"),
          lobby.stage === "open" ? h("p", null, "Deadline ", ui.countdown(lobby.start_rule.deadline_at, ui.shortfallSentence(lobby))) : null,
          h("p", { class: "hint" }, "Only members whose app is connected and ready are counted.")),
        actions(lobby, status),
        ui.card("The terms in full", termsFacts(lobby)),
        people(lobby),
        hostSwitches(lobby));
    }, function (error) {
      if (error.code !== "not_found") throw error;
      return h("div", null, h("h1", null, "This lobby is gone"),
        ui.notice("info", null, "It has started, was cancelled, or its listing expired.", [ui.link("Back to all lobbies", "#/lobbies", "btn")]));
    });
  }

  gz.lobbyParts = { failureText: failureText, failureList: failureList, lobbyCard: lobbyCard, termsFacts: termsFacts, profileNames: profileNames };
  gz.screens.lobbies = { title: "Lobbies", topics: ["lobby", "conditions"], render: renderList };
  gz.screens.lobby = { title: "Lobby", topics: ["lobby", "status", "conditions"], render: renderLobby };
})();
