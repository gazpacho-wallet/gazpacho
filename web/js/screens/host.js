/* Screen: Host a factory. Create a lobby, then run it and the factory it becomes. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  /* The terms being written. Kept here so a live redraw never loses them. */
  var draft = {
    name: "", profile: "standard", target: 50, minimum: 30, deadline_minutes: 180, on_shortfall: "cancel",
    channel_size_sat: 500000, spare_liquidity_sat: 250000, join_fee_sat: 1000, payment_fee_pct: 0.05, liquidity_fee_pct: 0.3,
    lifetime_days: 33, timed_levels: 2, listed: true, access: "open", names: true, chat: false, rule_requests: false
  };
  var previewTimer = null;

  var PROBLEMS = {
    minimum_too_small: "The minimum must be at least 2 members.",
    target_below_minimum: "The target cannot be below the minimum.",
    target_too_large: "The largest factory this release supports is 512 members.",
    channel_too_small: "A channel must be at least 20,000 sats.",
    deadline_missing: "Choose a deadline.",
    name_missing: "Give the lobby a name.",
    lifetime_too_short: "The lifetime is too short for this tree: members need time to use the factory, to move on, and to leave alone if they must."
  };

  var RISKS = [
    ["You fund last, after everyone has signed.", "Until the whole tree is signed and checked, nothing of yours is committed. A lobby that fails costs you only time."],
    ["You pay for the whole factory.", "Members put in nothing. Your coins are locked in the factory for its lifetime and earn only the fees in your terms."],
    ["If you do not wind the factory down in time you lose your liquidity in it.", "When a factory expires, what is left in it goes to the members, not to you. Winding down on time is your job."],
    ["This program must keep running.", "Members cannot pay or be paid while you are away, and after a while their apps leave alone. Running your own Bitcoin node is recommended for a host."],
    ["Your terms are signed and kept by members.", "A member can show anyone what you offered."]
  ];

  function apiTerms() {
    var t = {};
    for (var key in draft) t[key] = draft[key];
    t.payment_fee_ppm = Math.round(Number(draft.payment_fee_pct) * 10000);
    t.liquidity_fee_ppm = Math.round(Number(draft.liquidity_fee_pct) * 10000);
    delete t.payment_fee_pct;
    delete t.liquidity_fee_pct;
    return t;
  }

  /* How the draft would look to a member, in the same shape the API gives a lobby. */
  function draftAsLobby(preview) {
    return {
      id: "preview", name: draft.name || "(no name yet)", host: { name: "You", factories_funded: 0 }, profile: draft.profile,
      listed: draft.listed, access: draft.access, stage: "open", terms: preview.terms,
      start_rule: { target: Number(draft.target), minimum: Number(draft.minimum),
        deadline_at: Math.floor(Date.now() / 1000) + Number(draft.deadline_minutes) * 60, on_shortfall: draft.on_shortfall },
      counts: { present: 0, ready: 0 }, check: { ok: true, failures: [] }
    };
  }

  function turnOnHostMode() {
    return h("div", null,
      h("h1", null, "Host a factory"),
      h("p", { class: "lead" }, "A host funds a factory, co-signs everything in it and links it to the rest of Lightning. Members get channels; the host earns the fees in its terms."),
      ui.card("What hosting asks of you", h("ul", null, RISKS.map(function (r) { return h("li", null, h("b", null, r[0]), " " + r[1]); }))),
      ui.notice("info", "Host mode is off.", "Turning it on only shows the hosting screens. It does not commit any coins.",
        [ui.button("Turn on host mode", function (e) {
          ui.run(e.currentTarget, function () { return api.setRoles({ member: true, host: true }); }, "Host mode is on.");
        }, { kind: "primary" })]));
  }

  /* ----- creating a lobby ----- */

  function paintPreview(box, preview) {
    var problems = preview.problems.map(function (p) { return h("li", null, PROBLEMS[p.code] || p.code); });
    var covers = preview.wallet_covers_target ? "ok" : preview.wallet_covers_minimum ? "warn" : "danger";
    var coverText = preview.wallet_covers_target ? "Your on-chain wallet covers a full lobby."
      : preview.wallet_covers_minimum ? "Your on-chain wallet covers the minimum but not a full lobby. If more members are ready than you can fund, the factory cannot be funded."
      : "Your on-chain wallet does not cover even the minimum. You can open the lobby, but you must add coins before it starts.";
    box.replaceChildren.apply(box, [
      h("h2", null, "How members will see it"),
      gz.lobbyParts.lobbyCard(draftAsLobby(preview), { preview: true }),
      h("h2", null, "What you must fund"),
      ui.facts([
        ["At the target of " + draft.target, u.sats(preview.funding_at_target_sat), "Each member's channel plus your spare liquidity beside it."],
        ["At the minimum of " + draft.minimum, u.sats(preview.funding_at_minimum_sat)],
        ["Chain fee, roughly", u.sats(preview.chain_fee_estimate_sat), "For the funding transaction. Members leaving alone later are also paid for from your side."],
        ["Your on-chain wallet has", u.sats(preview.wallet_sat)],
        ["Members can use it for", u.blocks(preview.usable_blocks), "After that the factory winds down."],
        ["You must wind it down by", u.blocks(preview.wind_down_by_blocks) + " after it starts", "After that, members' apps start leaving alone."]
      ]),
      ui.notice(covers, null, coverText),
      preview.host_node_linked ? null : ui.notice("warn", "No Lightning node is linked.", "Members of this factory could pay each other, but not anyone outside it.", [ui.link("Link a node in Settings", "#/settings", "btn small")]),
      problems.length ? ui.notice("danger", "Fix these before opening the lobby:", h("ul", null, problems)) : null
    ].filter(Boolean));
    var open = document.getElementById("open-lobby");
    if (open) open.disabled = problems.length > 0;
  }

  function refreshPreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(function () {
      var box = document.getElementById("host-preview");
      if (!box) return;
      api.previewTerms(apiTerms()).then(function (preview) {
        if (document.getElementById("host-preview") === box) paintPreview(box, preview);
      }, function (error) {
        box.replaceChildren(ui.notice("danger", "The preview could not be worked out.", error.message));
      });
    }, 250);
  }

  function readDraft() {
    Object.keys(draft).forEach(function (key) {
      var el = document.getElementById("host-" + key);
      if (el) draft[key] = el.type === "checkbox" ? el.checked : el.value;
    });
    draft.access = ui.value("host-access-invitation") ? "invitation" : "open";
  }

  function createForm() {
    function onInput(e) {
      readDraft();
      if (e.target.id === "host-profile" && draft.profile === "circle") {
        draft.listed = false; draft.access = "invitation";
        document.getElementById("host-listed").checked = false;
        document.getElementById("host-access-invitation").checked = true;
      }
      refreshPreview();
    }
    var profileChoices = Object.keys(ui.PROFILE_WORDS).map(function (id) { return [id, ui.PROFILE_WORDS[id].name + ": " + ui.PROFILE_WORDS[id].about]; });
    var form = h("form", { class: "card", novalidate: true, oninput: onInput, onchange: onInput,
      onsubmit: function (e) {
        e.preventDefault();
        readDraft();
        var target = document.getElementById("open-lobby");
        api.previewTerms(apiTerms()).then(function (preview) {
          return ui.confirm({ title: "Open this lobby?", confirmLabel: "Open the lobby",
            body: h("div", null,
              h("p", null, "Members can join as soon as it opens. Opening commits no coins."),
              h("p", null, "If it starts, you will fund up to " + u.sats(preview.funding_at_target_sat) + ", after everyone has signed. Those coins stay in the factory for " + u.blocksAsTime(preview.terms.lifetime_blocks).replace("about ", "") + "."),
              h("p", null, "If you do not wind the factory down in time you lose your liquidity in it.")) });
        }).then(function (yes) {
          if (yes) ui.run(target, function () { return api.createLobby(apiTerms()).then(function () { gz.app.go("host"); }); }, "Your lobby is open.");
        }).catch(function (error) { ui.toast("That did not work. " + error.message); });
      } },
      h("h2", null, "The terms"),
      ui.field({ id: "host-name", label: "Lobby name", value: draft.name, hint: "Members see this in the list." }),
      ui.field({ id: "host-profile", label: "Profile", value: draft.profile, choices: profileChoices, hint: "A named set of rules. Members choose which profiles they accept." }),
      h("fieldset", null, h("legend", null, "Start rule"),
        h("p", { class: "hint" }, "The lobby starts at once when the target is reached. At the deadline it starts if the minimum is met."),
        ui.field({ id: "host-target", label: "Target", type: "number", min: 2, max: 512, value: draft.target, unit: "members" }),
        ui.field({ id: "host-minimum", label: "Minimum", type: "number", min: 2, max: 512, value: draft.minimum, unit: "members",
          hint: "Protects you from funding a factory too small to be worth it." }),
        ui.field({ id: "host-deadline_minutes", label: "Deadline", value: draft.deadline_minutes,
          choices: [[2, "In 2 minutes (for trying the prototype)"], [60, "In 1 hour"], [180, "In 3 hours"], [720, "In 12 hours"], [1440, "In 24 hours"]] }),
        ui.field({ id: "host-on_shortfall", label: "If the deadline arrives below the minimum", value: draft.on_shortfall,
          choices: [["cancel", "Cancel the lobby"], ["carry_over", "Carry the people waiting over to my next lobby"]] })),
      h("fieldset", null, h("legend", null, "What each member gets"),
        ui.field({ id: "host-channel_size_sat", label: "Channel size", type: "number", min: 20000, step: 10000, value: draft.channel_size_sat, unit: "sats",
          hint: "You fund all of it. The member starts at zero and can receive up to this amount." }),
        ui.field({ id: "host-spare_liquidity_sat", label: "Your spare liquidity beside each channel", type: "number", min: 0, step: 10000, value: draft.spare_liquidity_sat, unit: "sats",
          hint: "Stays yours. You can sell it to the member later as room to receive more." })),
      h("fieldset", null, h("legend", null, "Fees you charge"),
        ui.field({ id: "host-join_fee_sat", label: "Joining fee", type: "number", min: 0, step: 100, value: draft.join_fee_sat, unit: "sats", hint: "Once per member, taken from the first payment they receive." }),
        ui.field({ id: "host-payment_fee_pct", label: "Fee on each payment", type: "number", min: 0, step: 0.01, value: draft.payment_fee_pct, unit: "%" }),
        ui.field({ id: "host-liquidity_fee_pct", label: "Fee for extra receiving room", type: "number", min: 0, step: 0.01, value: draft.liquidity_fee_pct, unit: "%" })),
      h("fieldset", null, h("legend", null, "Lifetime and tree"),
        ui.field({ id: "host-lifetime_days", label: "Lifetime", type: "number", min: 7, max: 90, value: draft.lifetime_days, unit: "days",
          hint: "From funding to expiry. The usable part is shorter; see the summary." }),
        ui.field({ id: "host-timed_levels", label: "Replaceable levels in the tree", value: draft.timed_levels,
          choices: [[1, "1 level: leaving alone takes about 3 days"], [2, "2 levels: about 6 days"], [3, "3 levels: about 9 days"]],
          hint: "Each replaceable level lets you move spare liquidity between more members later, and adds 432 blocks to the time a member needs to leave alone." })),
      h("fieldset", null, h("legend", null, "Who can find it and who can join"),
        ui.checkbox({ id: "host-listed", label: "Listed", checked: draft.listed, hint: "Publish the terms on Nostr so anyone can find the lobby. The listing never says who joined." }),
        ui.checkbox({ id: "host-access-open", name: "host-access", radio: true, value: "open", label: "Open to anyone", checked: draft.access === "open" }),
        ui.checkbox({ id: "host-access-invitation", name: "host-access", radio: true, value: "invitation", label: "By invitation", checked: draft.access === "invitation",
          hint: "A seat needs an invitation link from you, shown as a QR code." })),
      h("fieldset", null, h("legend", null, "What members can do in the lobby"),
        ui.checkbox({ id: "host-names", label: "Names", checked: draft.names, hint: "Members see each other's temporary names. Off: they see only a head-count." }),
        ui.checkbox({ id: "host-chat", label: "Chat", checked: draft.chat, hint: "Chat itself is not in the prototype." }),
        ui.checkbox({ id: "host-rule_requests", label: "Requests to change the rules", checked: draft.rule_requests, hint: "Members may ask you to change a term. You decide." })),
      h("div", { class: "actions" }, ui.button("Open this lobby", null, { kind: "primary", type: "submit", id: "open-lobby" })));
    return form;
  }

  function createScreen() {
    refreshPreview();
    return h("div", null,
      h("h1", null, "Host a factory"),
      h("p", { class: "lead" }, "Open a lobby with your terms. Members gather in it; when your start rule is met, everyone signs and you fund the factory."),
      h("div", { class: "two wide-left" },
        createForm(),
        h("div", null,
          h("section", { class: "card", id: "host-preview", "aria-label": "Preview and funding summary" }, h("p", { class: "loading" }, "Working out the preview…")),
          ui.card("What you risk", h("ul", null, RISKS.map(function (r) { return h("li", null, h("b", null, r[0]), " " + r[1]); }))))));
  }

  /* ----- running a lobby ----- */

  function lobbyStage(lobby) {
    var hv = lobby.host_view;
    if (lobby.stage === "open") {
      return hv.can_start_now
        ? ui.notice("ok", "The minimum is met. You can start now, or wait for more.", ui.startRuleSentence(lobby))
        : ui.notice("info", "Gathering.", ui.startRuleSentence(lobby));
    }
    if (lobby.stage === "ready_check") return ui.notice("warn", "Starting. Checking who is present.", "Keep this program running.");
    if (lobby.stage === "signing") {
      var sg = lobby.signing;
      return ui.notice("warn", "Signing. Nothing of yours is committed yet.", h("div", null,
        h("p", null, sg.step === "nonces" ? "Step 1 of 2: exchanging one-time signing numbers." : "Step 2 of 2: collecting and checking signatures."),
        ui.progress(sg.signed, sg.of, "Signing progress"),
        h("p", null, sg.signed + " of " + sg.of + " received. Attempt " + sg.attempt + " of " + sg.max_attempts + ". You fund only after the whole tree is signed.")));
    }
    if (lobby.stage === "funding") {
      var fd = lobby.funding;
      return ui.notice("info", "You have funded the factory. Waiting for confirmation.", h("div", null,
        h("p", null, u.sats(fd.amount_sat) + " left your on-chain wallet in the funding transaction."),
        ui.progress(fd.confirmations, fd.confirmations_needed, "Confirmations"),
        h("p", null, fd.confirmations === 0 ? "Not confirmed yet. " : "", fd.confirmations + " of " + fd.confirmations_needed + " confirmations."),
        h("p", { class: "hint" }, "Transaction ", h("code", { title: fd.txid }, u.shortId(fd.txid)))));
    }
    return ui.notice("warn", "This lobby has ended.", "Stage: " + ui.STAGE_WORDS[lobby.stage] + ".");
  }

  function memberTable(lobby) {
    if (!lobby.members.length) return h("p", null, "Nobody has joined yet. This list fills as members connect.");
    var list = h("ul", { class: "people" });
    lobby.members.forEach(function (m) {
      var remove = lobby.stage === "open" ? ui.button("Remove", function (e) {
        var target = e.currentTarget;
        ui.confirm({ title: "Remove " + m.name + "?", confirmLabel: "Remove from the lobby", danger: true,
          body: h("p", null, "They lose their seat in this lobby. They lose no money, and nothing stops them joining again unless the lobby is by invitation.") })
          .then(function (yes) { if (yes) ui.run(target, function () { return api.removeMember(lobby.id, m.id); }, m.name + " was removed."); });
      }, { kind: "small" }) : null;
      if (remove) remove.setAttribute("aria-label", "Remove " + m.name);
      list.appendChild(h("li", null,
        h("span", { class: "who" }, m.name, m.identity ? h("span", { class: "hint" }, " " + m.identity.label + (m.identity.verified ? " (proven)" : " (unverified)")) : null),
        ui.pill(m.ready ? "Ready" : "Not ready", m.ready ? "green" : "gold"), remove));
    });
    return list;
  }

  function lobbyDashboard(lobby) {
    var hv = lobby.host_view;
    var gathering = lobby.stage === "open";
    var covered = hv.wallet_sat >= hv.funding_now_sat;
    return h("div", null,
      h("h1", null, "Your lobby: " + lobby.name),
      h("p", { class: "pills" }, ui.pill(ui.STAGE_WORDS[lobby.stage], "blue"), ui.pill(lobby.listed ? "Listed" : "Unlisted", "grey"),
        ui.pill(lobby.access === "open" ? "Open to anyone" : "By invitation", "grey")),
      lobbyStage(lobby),
      h("div", { class: "stats" },
        ui.stat("Present", String(lobby.counts.present), "Members connected to your lobby, ready or not."),
        ui.stat("Ready", lobby.counts.ready + " of " + lobby.start_rule.target, "Members whose app is connected and whose conditions your terms meet. Only these count towards starting.",
          "Minimum " + lobby.start_rule.minimum),
        ui.stat("To fund if it started now", ui.amount(hv.funding_now_sat), "Each ready member's channel plus your spare liquidity beside it. You fund last, after everyone has signed.",
          covered ? "Your wallet covers it" : "Your wallet has only " + u.sats(hv.wallet_sat))),
      gathering ? ui.card("Start",
        h("p", null, "Deadline ", ui.countdown(lobby.start_rule.deadline_at, ui.shortfallSentence(lobby))),
        ui.progress(lobby.counts.ready, lobby.start_rule.target, "Members ready, out of the target"),
        h("div", { class: "actions" },
          ui.button("Start now with " + lobby.counts.ready, function (e) {
            var target = e.currentTarget;
            ui.confirm({ title: "Start now?", confirmLabel: "Start signing",
              body: h("div", null,
                h("p", null, "Signing begins with the " + lobby.counts.ready + " members who are ready. Members who are not ready are left out."),
                h("p", null, "When everyone has signed, " + u.sats(hv.funding_now_sat) + " leave your on-chain wallet to fund the factory.")) })
              .then(function (yes) { if (yes) ui.run(target, function () { return api.startLobbyNow(lobby.id); }); });
          }, { kind: "primary", disabled: !hv.can_start_now, describedBy: "start-why" }),
          ui.button("Cancel this lobby", function (e) {
            var target = e.currentTarget;
            ui.confirm({ title: "Cancel this lobby?", confirmLabel: "Cancel the lobby", cancelLabel: "Keep it open", danger: true,
              body: h("p", null, "Everyone waiting is sent away. Nobody loses money, you included.") })
              .then(function (yes) { if (yes) ui.run(target, function () { return api.cancelLobby(lobby.id); }, "The lobby was cancelled."); });
          })),
        h("p", { class: "hint", id: "start-why" }, hv.can_start_now ? "Allowed because the minimum of " + lobby.start_rule.minimum + " is met."
          : "Starting early is allowed once " + lobby.start_rule.minimum + " members are ready.")) : null,
      lobby.access === "invitation" || !lobby.listed ? ui.card("Invitation",
        h("p", null, "Give this link to the people you want. Anyone holding it can " + (lobby.access === "invitation" ? "take a seat." : "find the lobby.")),
        ui.field({ id: "invite-link", label: "Invitation link", value: "gazpacho:invite/example-example-example", readonly: true }),
        h("div", { class: "actions" }, ui.copyButton("gazpacho:invite/example-example-example", "Invitation link")),
        ui.qrPlaceholder("the invitation link")) : null,
      ui.card("Members", h("p", { class: "hint" }, "You alone decide who is in your lobby. There is no voting. Removing someone costs them only their seat."), memberTable(lobby)),
      ui.card("The terms you published", gz.lobbyParts.termsFacts(lobby),
        h("div", { class: "actions" }, ui.notInPrototype("Change the terms"))));
  }

  /* ----- running a factory ----- */

  function factoryDashboard(f, status) {
    var hv = f.host_view;
    var left = Math.max(0, hv.wind_down_by_height - status.chain.height);
    return h("div", null,
      h("h1", null, "Your factory: " + f.name),
      h("p", { class: "pills" }, ui.pill("Live", "green"), ui.pill(f.members + " members", "grey")),
      ui.notice(left < 3 * 144 ? "danger" : "info", "Wind this factory down by block " + u.number(hv.wind_down_by_height) + ".",
        h("div", null,
          h("p", null, "That is " + u.blocks(left) + " from now, around " + u.dateOfBlock(left) + ". Winding down means opening your next factory and moving members into it."),
          h("p", null, "At zero: members' apps start leaving alone, and at expiry what is left in the factory goes to the members. If you do not wind the factory down in time you lose your liquidity in it."))),
      h("div", { class: "stats" },
        ui.stat("You funded", ui.amount(hv.funded_sat), "The whole factory: every member's channel and your spare liquidity. It returns to you, less what members hold, when the factory is wound down."),
        ui.stat("Spare liquidity", ui.amount(hv.spare_total_sat), "Yours, spread across the leaves. You can sell it to members as room to receive more."),
        ui.stat("Members connected", hv.members_online + " of " + f.members, "Members whose app is connected to you now. Members must be reachable when the factory rotates.")),
      ui.card("Funding",
        ui.facts([
          ["Funding transaction", h("code", { title: f.funding.txid }, u.shortId(f.funding.txid)), u.plural(f.funding.confirmations, "confirmation") + "."],
          ["Created at block", u.number(f.created_height)],
          ["Expires at block", u.number(f.expiry_height)],
          ["Leaving alone takes a member", u.blocks(f.exit.blocks)]
        ])),
      ui.card("Running it",
        h("div", { class: "actions" }, ui.notInPrototype("Open the next lobby and start winding down"), ui.notInPrototype("Sell spare liquidity to a member"), ui.notInPrototype("See members")),
        h("p", { class: "hint" }, "A host sees every payment its members make through the factory. The real screens will need to treat that with care.")));
  }

  function render(params, status) {
    var screen = gz.screens.host;
    screen.topics = ["lobby", "status"];
    if (!status.roles.host) return Promise.resolve(turnOnHostMode());
    if (status.host.lobby_id) return api.getLobby(status.host.lobby_id).then(lobbyDashboard);
    if (status.host.factory_id) return api.getFactory(status.host.factory_id).then(function (f) { return factoryDashboard(f, status); });
    /* Nothing on the form is live, so it is not redrawn while someone is typing in it. */
    screen.topics = [];
    return Promise.resolve(createScreen());
  }

  gz.screens.host = { title: "Host a factory", topics: ["lobby", "status"], render: render };
})();
