/* A pretend Gazpacho program, for the prototype only.

   It defines window.gzApi, the one object the screens are allowed to use.
   The real interface replaces this file with a client that makes the same
   calls to the local program (see ../API.md). Nothing here is real: no keys,
   no network, no coins.

   It also defines window.gzMockDemo, used only by the demo controls panel. */
(function () {
  "use strict";

  var LATENCY_MS = 120;        // every call answers after this long
  var SLOW_MS = 1800;          // with "slow answers" switched on
  var BLOCK_EVERY_S = 30;      // the pretend chain is much faster than the real ten minutes
  var DAY = 144;               // blocks
  var TIMED_LEVEL_BLOCKS = 432;
  var EXIT_MARGIN_BLOCKS = 144;
  var ROTATION_WINDOW_BLOCKS = 432;
  var AWAY_BLOCKS = 2016;      // about two weeks to answer an old state
  var RESERVE_SAT = 20000;
  var CONFIRMATIONS_NEEDED = 2;

  var world;                   // the whole pretend state
  var listeners = [];
  var demo = { state: "first-run", failing: false, slow: false, paused: false };
  var idCounter = 1;

  function now() { return Math.floor(Date.now() / 1000); }

  /* Copies a value for the caller, leaving out private fields (names starting with "_"). */
  function publicCopy(value) {
    return JSON.parse(JSON.stringify(value, function (key, v) {
      return key.charAt(0) === "_" ? undefined : v;
    }));
  }

  function apiError(code, message) {
    var e = new Error(message);
    e.code = code;
    return e;
  }

  function reply(work) {
    return new Promise(function (resolve, reject) {
      setTimeout(function () {
        if (demo.failing) {
          reject(apiError("unreachable", "The Gazpacho program on this machine is not answering."));
          return;
        }
        try { resolve(publicCopy(work())); } catch (e) { reject(e); }
      }, demo.slow ? SLOW_MS : LATENCY_MS);
    });
  }

  function emit(topic) {
    listeners.slice().forEach(function (callback) {
      try { callback({ topic: topic, at: now() }); } catch (e) { console.error(e); }
    });
  }

  function fakeTxid() {
    var x = (idCounter++ * 2654435761) % 4294967296;
    var out = "";
    while (out.length < 64) {
      x = (x * 1664525 + 1013904223) % 4294967296;
      out += ("0000000" + x.toString(16)).slice(-8);
    }
    return out;
  }

  /* ---------- the pretend world ---------- */

  var NAME_WORDS = ["Tomato", "Pepper", "Cucumber", "Garlic", "Onion", "Olive", "Basil", "Celery", "Parsley", "Lemon"];

  function standardTerms(overrides) {
    var terms = {
      version: 1,
      channel_size_sat: 500000,
      spare_liquidity_sat: 250000,
      join_fee_sat: 1000,
      payment_fee_ppm: 500,
      liquidity_fee_ppm: 3000,
      lifetime_blocks: 33 * DAY,
      timed_levels: 2,
      exit_blocks: 2 * TIMED_LEVEL_BLOCKS,
      newcomer_seats_pct: 100
    };
    for (var key in overrides || {}) terms[key] = overrides[key];
    terms.exit_blocks = terms.timed_levels * TIMED_LEVEL_BLOCKS;
    return terms;
  }

  function makeLobby(spec) {
    var lobby = {
      id: spec.id,
      name: spec.name,
      role: spec.role || "member",
      host: { name: spec.host, factories_funded: spec.funded || 0 },
      profile: spec.profile,
      listed: spec.listed !== false,
      access: spec.access || "open",
      stage: "open",
      terms: standardTerms(spec.terms),
      terms_change: null,
      start_rule: {
        target: spec.target,
        minimum: spec.minimum,
        deadline_at: now() + spec.deadline_in,
        on_shortfall: spec.on_shortfall || "cancel"
      },
      switches: { names: spec.names !== false, chat: !!spec.chat, rule_requests: !!spec.rule_requests },
      members: [],
      signing: null,
      funding: null,
      outcome: null,
      factory_id: null,
      _join_every: spec.join_every || 0,
      _next_join_at: now() + (spec.join_every || 0),
      _name_counter: 10
    };
    for (var i = 0; i < spec.present; i++) addMember(lobby, true);
    return lobby;
  }

  function addMember(lobby, ready) {
    var n = lobby._name_counter++;
    var member = {
      id: "seat-" + n,
      name: NAME_WORDS[(n * 7) % NAME_WORDS.length] + "-" + ((n * 37) % 90 + 10),
      ready: !!ready,
      you: false,
      blocked: false,
      identity: null,
      _ready_at: now() + 2
    };
    if (n % 9 === 0) member.identity = { kind: "nostr", label: "npub1example…" + n, verified: true };
    if (n % 13 === 0) member.identity = { kind: "text", label: "from the meetup", verified: false };
    lobby.members.push(member);
    return member;
  }

  function baseWorld() {
    var t = now();
    var w = {
      network: "signet",
      wallet_exists: true,
      roles: { member: true, host: false },
      height: 330437,
      chain_state: "ok",
      servers_checked_at: t,
      conditions: {
        min_members: 20,
        min_channel_sat: 200000,
        max_join_fee_sat: 2000,
        max_payment_fee_ppm: 1000,
        max_liquidity_fee_ppm: 5000,
        profiles: ["safety", "standard", "starter"],
        max_exit_blocks: 1008
      },
      lobbies: {},
      member_lobby: null,
      member_factory: null,
      host_lobby: null,
      host_factory: null,
      factories: {},
      wallet: {
        confirmed_sat: 0,
        unconfirmed_sat: 0,
        address: "tb1qexampleexampleexampleexampleexample00",
        transactions: []
      },
      payments: [],
      invoices: [],
      settings: {
        chain: { mode: "public", own_server: { address: "" }, own_node: { address: "", user: "" } },
        host_node: { kind: "lnd", address: "", access_file: "", linked: false },
        backup: { last_export_at: null, host_copy_at: null },
        reminders: { warn_days_before: 3 }
      },
      last_opened_height: 330437,
      _last_block_at: t,
      _pending_phrase: false
    };
    [
      { id: "lobby-tomato", name: "Tomato Garden, daily factory", host: "Tomato Garden", funded: 12, profile: "standard",
        target: 50, minimum: 30, deadline_in: 2 * 3600, present: 37, join_every: 9, rule_requests: true },
      { id: "lobby-first", name: "First Steps", host: "Sprout Host", funded: 3, profile: "starter",
        target: 100, minimum: 40, deadline_in: 9 * 3600, present: 58, join_every: 14,
        terms: { channel_size_sat: 100000, spare_liquidity_sat: 50000, join_fee_sat: 0, payment_fee_ppm: 1000, timed_levels: 3 } },
      { id: "lobby-quiet", name: "Quiet Vault", host: "Stone Cellar", funded: 31, profile: "safety",
        target: 16, minimum: 8, deadline_in: 26 * 3600, present: 5, names: false,
        terms: { channel_size_sat: 1000000, spare_liquidity_sat: 500000, join_fee_sat: 2000, payment_fee_ppm: 2500, timed_levels: 1 } },
      { id: "lobby-river", name: "Riverside Hackers", host: "Riverside", funded: 1, profile: "standard", access: "invitation",
        target: 24, minimum: 12, deadline_in: 5 * 3600, present: 9, chat: true },
      { id: "lobby-circle", name: "Sunday table", host: "Ana (unverified name)", funded: 0, profile: "circle", listed: false, access: "invitation",
        target: 8, minimum: 4, deadline_in: 20 * 3600, present: 3, chat: true, rule_requests: true,
        terms: { channel_size_sat: 300000, spare_liquidity_sat: 100000, join_fee_sat: 0, payment_fee_ppm: 0, liquidity_fee_ppm: 0 } }
    ].forEach(function (spec) { w.lobbies[spec.id] = makeLobby(spec); });
    return w;
  }

  function fundWallet(w, amount) {
    w.wallet.confirmed_sat = amount;
    w.wallet.transactions = [
      { txid: fakeTxid(), kind: "received", amount_sat: amount, confirmations: 310, at: now() - 2 * 86400, note: "From a signet faucet" }
    ];
  }

  function seedPayments(w) {
    var t = now();
    w.payments = [
      { id: "pay-3", direction: "sent", amount_sat: 21000, fee_sat: 11, description: "Coffee beans", state: "done", at: t - 5400, reason: null },
      { id: "pay-2", direction: "sent", amount_sat: 300000, fee_sat: 0, description: "Too large on purpose", state: "failed", at: t - 40000, reason: "not_enough_balance" },
      { id: "pay-1", direction: "received", amount_sat: 203411, fee_sat: 0, description: "First payment in", state: "done", at: t - 86400, reason: null }
    ];
  }

  /* The shape of the tree for a given size. Invented for the prototype:
     the real table of shapes is an open design question. */
  function shapeFor(members, timedLevels) {
    var widths = members <= 8 ? [Math.ceil(members / 2), 2]
      : members <= 120 ? [Math.ceil(members / 8), 4, 2]
      : [Math.ceil(members / 120), 15, 4, 2];
    return widths.map(function (width, i) {
      var timed = i >= widths.length - timedLevels;
      return { kind: timed ? "timed" : "fixed", width: Math.max(2, width), delay_blocks: timed ? TIMED_LEVEL_BLOCKS : 0 };
    });
  }

  function makeFactory(spec) {
    var terms = spec.terms;
    var levels = shapeFor(spec.members, terms.timed_levels);
    var below = spec.members;
    var path = levels.map(function (level, i) {
      below = Math.max(1, Math.ceil(below / level.width));
      return { level: i + 1, kind: level.kind, width: level.width, index: (i * 2 + 1) % level.width,
        delay_blocks: level.delay_blocks, members_below: below };
    });
    var exitBlocks = terms.exit_blocks;
    var expiry = spec.created_height + terms.lifetime_blocks;
    var autoExit = expiry - exitBlocks - EXIT_MARGIN_BLOCKS;
    var factory = {
      id: spec.id,
      name: spec.name,
      role: spec.role || "member",
      state: "active",
      host: { name: spec.host, online: true, last_seen_at: now() },
      members: spec.members,
      terms: terms,
      created_height: spec.created_height,
      rotation_opens_height: autoExit - ROTATION_WINDOW_BLOCKS,
      auto_exit_height: autoExit,
      expiry_height: expiry,
      funding: { txid: spec.txid || fakeTxid(), confirmations: spec.confirmations || 6,
        amount_sat: spec.members * (terms.channel_size_sat + terms.spare_liquidity_sat) },
      channel: {
        capacity_sat: terms.channel_size_sat,
        balance_sat: spec.balance || 0,
        receivable_sat: terms.channel_size_sat - (spec.balance || 0),
        spare_liquidity_sat: terms.spare_liquidity_sat
      },
      tree: { levels: levels, path: path, members_per_leaf: 1 },
      exit: { blocks: exitBlocks, timed_levels: terms.timed_levels, fee_sat: 1200, fee_paid_from: "host_side",
        reserve_recommended_sat: RESERVE_SAT, transactions: levels.length + 1 },
      exit_progress: null,
      rotation: null,
      next_factory: null,
      host_view: null
    };
    if (factory.role === "host") {
      factory.channel = null;
      factory.host_view = {
        funded_sat: factory.funding.amount_sat,
        spare_total_sat: spec.members * terms.spare_liquidity_sat,
        members_online: spec.members - 3,
        wind_down_by_height: factory.auto_exit_height
      };
    }
    return factory;
  }

  function liveFactory(w, age, balance) {
    var f = makeFactory({ id: "factory-tomato-12", name: "Tomato Garden, factory 12", host: "Tomato Garden",
      members: 50, created_height: w.height - age, terms: standardTerms(), balance: balance, confirmations: age + 1 });
    w.factories[f.id] = f;
    w.member_factory = f.id;
    w.settings.backup.host_copy_at = now() - 900;
    fundWallet(w, 48000);
    seedPayments(w);
    return f;
  }

  function youJoin(lobby, w) {
    var you = addMember(lobby, true);
    you.you = true;
    you.name = "You (" + you.name + ")";
    you.identity = null;
    you._conditions = JSON.parse(JSON.stringify(w.conditions));
    w.member_lobby = lobby.id;
    return you;
  }

  var SEEDS = {
    "first-run": function (w) { w.wallet_exists = false; },
    "empty": function () {},
    "in-lobby": function (w) { youJoin(w.lobbies["lobby-tomato"], w); fundWallet(w, 48000); },
    "lobby-starting": function (w) {
      var lobby = w.lobbies["lobby-tomato"];
      while (lobby.members.length < 46) addMember(lobby, true);
      youJoin(lobby, w);
      lobby.start_rule.deadline_at = now() + 75;
      lobby._join_every = 5;
      lobby._next_join_at = now() + 5;
      fundWallet(w, 48000);
    },
    "factory-live": function (w) { liveFactory(w, 1000, 182400); },
    "winding-down": function (w) {
      var f = liveFactory(w, 3500, 182400);
      f.state = "winding_down";
      f.next_factory = { name: "Tomato Garden, factory 13", members: 48, channel_size_sat: 500000, join_fee_sat: 1000, within_conditions: true };
    },
    "host-gone": function (w) {
      var f = liveFactory(w, 1000, 182400);
      f.state = "host_gone";
      f.host.online = false;
      f.host.last_seen_at = now() - 26 * 3600;
    },
    "exiting": function (w) {
      var f = liveFactory(w, 1000, 182400);
      beginExit(w, f);
      var steps = f.exit_progress.steps;
      steps[0].state = "confirmed"; steps[0].txid = fakeTxid(); steps[0].confirmations = 132;
      steps[1].state = "waiting"; steps[1].wait_blocks_left = 300;
    },
    "conditions-not-met": function (w) {
      var lobby = w.lobbies["lobby-tomato"];
      youJoin(lobby, w);
      lobby.terms.version = 2;
      lobby.terms.payment_fee_ppm = 2500;
      lobby.terms_change = { version: 2, at: now() - 240, changes: [{ field: "payment_fee_ppm", from: 500, to: 2500 }] };
      lobby._join_every = 0;
      fundWallet(w, 48000);
    },
    "servers-disagree": function (w) {
      liveFactory(w, 1000, 182400);
      w.chain_state = "disagree";
      w.wallet.unconfirmed_sat = 15000;
      w.wallet.transactions.unshift({ txid: fakeTxid(), kind: "received", amount_sat: 15000, confirmations: 0, at: now() - 500, note: "" });
    },
    "hosting-lobby": function (w) {
      w.roles.host = true;
      fundWallet(w, 42000000);
      w.settings.host_node = { kind: "lnd", address: "127.0.0.1:10009", access_file: "/home/example/lnd/gazpacho.macaroon", linked: true };
      var lobby = makeLobby({ id: "lobby-mine", name: "My first lobby", host: "You", role: "host", profile: "standard",
        target: 40, minimum: 24, deadline_in: 90 * 60, present: 27, join_every: 6, rule_requests: true });
      lobby.members[3].ready = false; lobby.members[3]._ready_at = now() + 3600;
      lobby.members[11].ready = false; lobby.members[11]._ready_at = now() + 3600;
      w.lobbies[lobby.id] = lobby;
      w.host_lobby = lobby.id;
    },
    "hosting-factory": function (w) {
      w.roles.host = true;
      fundWallet(w, 4500000);
      w.settings.host_node = { kind: "lnd", address: "127.0.0.1:10009", access_file: "/home/example/lnd/gazpacho.macaroon", linked: true };
      var f = makeFactory({ id: "factory-mine-1", name: "My first lobby, factory 1", host: "You", role: "host",
        members: 40, created_height: w.height - 600, terms: standardTerms() });
      w.factories[f.id] = f;
      w.host_factory = f.id;
    }
  };

  function setDemoState(name) {
    if (!SEEDS[name]) name = "first-run";
    demo.state = name;
    world = baseWorld();
    SEEDS[name](world);
    emit("reset");
  }

  /* ---------- rules the real core would apply ---------- */

  function checkTerms(lobby, conditions) {
    var t = lobby.terms;
    var failures = [];
    function fail(condition, yours, offered) { failures.push({ condition: condition, yours: yours, offered: offered }); }
    if (lobby.start_rule.target < conditions.min_members) fail("min_members", conditions.min_members, lobby.start_rule.target);
    if (t.channel_size_sat < conditions.min_channel_sat) fail("min_channel_sat", conditions.min_channel_sat, t.channel_size_sat);
    if (t.join_fee_sat > conditions.max_join_fee_sat) fail("max_join_fee_sat", conditions.max_join_fee_sat, t.join_fee_sat);
    if (t.payment_fee_ppm > conditions.max_payment_fee_ppm) fail("max_payment_fee_ppm", conditions.max_payment_fee_ppm, t.payment_fee_ppm);
    if (t.liquidity_fee_ppm > conditions.max_liquidity_fee_ppm) fail("max_liquidity_fee_ppm", conditions.max_liquidity_fee_ppm, t.liquidity_fee_ppm);
    if (conditions.profiles.indexOf(lobby.profile) < 0) fail("profiles", conditions.profiles, lobby.profile);
    if (t.exit_blocks > conditions.max_exit_blocks) fail("max_exit_blocks", conditions.max_exit_blocks, t.exit_blocks);
    return {
      ok: failures.length === 0,
      failures: failures,
      counted_from: Math.max(conditions.min_members, lobby.start_rule.minimum)
    };
  }

  function yourSeat(lobby) {
    return lobby.members.filter(function (m) { return m.you; })[0] || null;
  }

  function readyCount(lobby) {
    return lobby.members.filter(function (m) { return m.ready; }).length;
  }

  function lobbyView(lobby, full) {
    var you = yourSeat(lobby);
    var check = checkTerms(lobby, you ? you._conditions : world.conditions);
    if (you) you.ready = check.ok && !lobby.members.some(function (m) { return m.blocked; });
    var ready = readyCount(lobby);
    var view = {
      id: lobby.id, name: lobby.name, role: lobby.role, host: lobby.host, profile: lobby.profile,
      listed: lobby.listed, access: lobby.access, stage: lobby.stage, terms: lobby.terms,
      terms_change: lobby.terms_change, start_rule: lobby.start_rule, switches: lobby.switches,
      counts: { present: lobby.members.length, ready: ready },
      check: check,
      you: {
        joined: !!you,
        ready: !!you && you.ready,
        counted: !!you && you.ready && ready >= check.counted_from,
        blocked_someone: lobby.members.some(function (m) { return m.blocked; })
      },
      signing: lobby.signing, funding: lobby.funding, outcome: lobby.outcome, factory_id: lobby.factory_id
    };
    if (full) {
      var showNames = lobby.switches.names || lobby.role === "host";
      view.members = showNames ? lobby.members : null;
      if (lobby.role === "host") {
        var perMember = lobby.terms.channel_size_sat + lobby.terms.spare_liquidity_sat;
        view.host_view = {
          can_start_now: lobby.stage === "open" && ready >= lobby.start_rule.minimum,
          funding_now_sat: ready * perMember,
          funding_at_target_sat: lobby.start_rule.target * perMember,
          wallet_sat: world.wallet.confirmed_sat
        };
      }
    }
    return view;
  }

  function schedule() {
    var f = world.factories[world.member_factory];
    var items = [];
    function item(id, dueHeight, extra) {
      var it = { id: id, due_height: dueHeight, blocks_left: Math.max(0, dueHeight - world.height), state: "ok" };
      for (var key in extra || {}) it[key] = extra[key];
      items.push(it);
      return it;
    }
    if (!f || f.state === "closed" || f.state === "exiting") {
      return { height: world.height, factory_id: f ? f.id : null, items: [], most_urgent: null };
    }
    item("open_app", world.last_opened_height + AWAY_BLOCKS);
    var rotation = item("sign_rotation", f.auto_exit_height, {
      opens_height: f.rotation_opens_height,
      opens_in_blocks: Math.max(0, f.rotation_opens_height - world.height),
      can_sign_now: f.state === "winding_down" && !!f.next_factory
    });
    item("expiry", f.expiry_height, { auto_exit_height: f.auto_exit_height,
      auto_exit_in_blocks: Math.max(0, f.auto_exit_height - world.height), exit_blocks: f.exit.blocks });
    if (rotation.opens_in_blocks > 0) rotation.state = "not_yet";
    items.forEach(function (it) {
      if (it.state === "not_yet") return;
      if (it.blocks_left <= 3 * DAY) it.state = "urgent";
      else if (it.blocks_left <= 7 * DAY) it.state = "soon";
    });
    var urgent = items.filter(function (it) { return it.state !== "not_yet"; })
      .sort(function (a, b) { return a.blocks_left - b.blocks_left; })[0];
    return { height: world.height, factory_id: f.id, items: items, most_urgent: urgent ? urgent.id : null };
  }

  function attention() {
    var list = [];
    function add(code, level, params) { list.push({ code: code, level: level, params: params || {} }); }
    if (world.chain_state === "disagree") add("chain_disagree", "urgent");
    var f = world.factories[world.member_factory];
    if (f) {
      if (f.state === "host_gone") add("host_gone", "urgent", { host: f.host.name, last_seen_at: f.host.last_seen_at });
      if (f.state === "winding_down") add("sign_rotation", "urgent", { blocks_left: Math.max(0, f.auto_exit_height - world.height) });
      if (f.state === "exiting") add("exit_running", "info");
      if (f.state === "closed") add("exit_done", "info", { amount_sat: f.exit_progress.amount_sat });
      if (f.state !== "closed" && world.wallet.confirmed_sat < RESERVE_SAT) add("reserve_low", "info", { recommended_sat: RESERVE_SAT });
    }
    var lobby = world.lobbies[world.member_lobby];
    if (lobby) {
      var view = lobbyView(lobby, false);
      if (!view.you.ready) add("lobby_not_ready", "warn", { lobby_id: lobby.id, name: lobby.name });
      else if (lobby.stage === "signing" || lobby.stage === "ready_check") add("lobby_signing", "warn", { lobby_id: lobby.id, name: lobby.name });
      else if (lobby.stage === "funding") add("lobby_funding", "info", { lobby_id: lobby.id, name: lobby.name });
    }
    var hosted = world.lobbies[world.host_lobby];
    if (hosted && hosted.stage === "open" && readyCount(hosted) >= hosted.start_rule.minimum) add("host_can_start", "info", { name: hosted.name });
    if (world.roles.host && !world.settings.host_node.linked) add("host_node_missing", "warn");
    return list;
  }

  /* ---------- time passing ---------- */

  function beginLobbyStart(lobby, reason) {
    var you = yourSeat(lobby);
    var view = lobbyView(lobby, false);
    lobby._you_in = !!you && view.you.counted;
    if (you && !lobby._you_in) {
      lobby.members.splice(lobby.members.indexOf(you), 1);
      lobby.outcome = "started_without_you";
      if (world.member_lobby === lobby.id) world.member_lobby = null;
    }
    lobby.members = lobby.members.filter(function (m) { return m.ready; });
    lobby.stage = "ready_check";
    lobby._started_by = reason;
    lobby._stage_until = now() + 4;
  }

  function stepLobby(lobby, t) {
    var changed = false;
    if (lobby.stage === "open") {
      lobby.members.forEach(function (m) {
        if (!m.ready && !m.you && t >= m._ready_at) { m.ready = true; changed = true; }
      });
      if (lobby._join_every && t >= lobby._next_join_at && lobby.members.length < lobby.start_rule.target + 2) {
        addMember(lobby, false);
        lobby._next_join_at = t + lobby._join_every;
        changed = true;
      }
      var ready = lobbyView(lobby, false).counts.ready;
      if (ready >= lobby.start_rule.target) { beginLobbyStart(lobby, "target"); changed = true; }
      else if (t >= lobby.start_rule.deadline_at) {
        if (ready >= lobby.start_rule.minimum) beginLobbyStart(lobby, "deadline");
        else { lobby.stage = "cancelled"; lobby.outcome = "too_few"; releaseLobby(lobby); }
        changed = true;
      }
    } else if (lobby.stage === "ready_check" && t >= lobby._stage_until) {
      lobby.stage = "signing";
      lobby.signing = { attempt: 1, max_attempts: 3, step: "nonces", signed: 0, of: lobby.members.length + 1 };
      changed = true;
    } else if (lobby.stage === "signing") {
      var sg = lobby.signing;
      sg.signed = Math.min(sg.of, sg.signed + Math.ceil(sg.of / 4));
      if (sg.signed >= sg.of) {
        if (sg.step === "nonces") { sg.step = "signatures"; sg.signed = 0; }
        else {
          sg.step = "done";
          lobby.stage = "funding";
          var amount = lobby.members.length * (lobby.terms.channel_size_sat + lobby.terms.spare_liquidity_sat);
          lobby.funding = { txid: fakeTxid(), confirmations: 0, confirmations_needed: CONFIRMATIONS_NEEDED, amount_sat: amount };
          if (lobby.role === "host") {
            world.wallet.confirmed_sat = Math.max(0, world.wallet.confirmed_sat - amount);
            world.wallet.transactions.unshift({ txid: lobby.funding.txid, kind: "factory_funding", amount_sat: -amount,
              confirmations: 0, at: t, note: lobby.name });
            emit("wallet");
          }
        }
      }
      changed = true;
    }
    if (changed) {
      emit("lobby");
      if (lobby.id === world.member_lobby || lobby.id === world.host_lobby || lobby.factory_id) emit("status");
    }
  }

  function releaseLobby(lobby) {
    if (world.member_lobby === lobby.id) world.member_lobby = null;
    if (world.host_lobby === lobby.id && lobby.stage === "cancelled") world.host_lobby = null;
  }

  function lobbyConfirmed(lobby) {
    lobby.stage = "active";
    if (lobby.role !== "host" && !lobby._you_in) { delete world.lobbies[lobby.id]; return; }
    var f = makeFactory({ id: "factory-" + lobby.id.replace("lobby-", "") + "-1", name: lobby.name + ", factory 1",
      host: lobby.host.name, role: lobby.role, members: lobby.members.length, created_height: world.height - CONFIRMATIONS_NEEDED,
      terms: lobby.terms, txid: lobby.funding.txid, confirmations: lobby.funding.confirmations });
    world.factories[f.id] = f;
    lobby.factory_id = f.id;
    if (lobby.role === "host") { world.host_factory = f.id; world.host_lobby = null; }
    else { world.member_factory = f.id; world.member_lobby = null; world.settings.backup.host_copy_at = now(); }
  }

  function beginExit(w, f) {
    var steps = [];
    f.tree.path.forEach(function (node) {
      steps.push({ id: "level-" + node.level, kind: "tree", level: node.level, wait_blocks: node.delay_blocks,
        wait_blocks_left: node.delay_blocks, state: "pending", txid: null, confirmations: 0 });
    });
    steps[steps.length - 1].kind = "leaf";
    steps.push({ id: "channel", kind: "channel", level: null, wait_blocks: 0, wait_blocks_left: 0, state: "pending", txid: null, confirmations: 0 });
    steps[0].state = "published";
    steps[0].txid = fakeTxid();
    f.state = "exiting";
    f.exit_progress = { started_height: w.height, amount_sat: f.channel.balance_sat, fee_sat: f.exit.fee_sat,
      steps: steps, blocks_left: f.exit.blocks + steps.length, done: false };
  }

  function stepExit(f) {
    var p = f.exit_progress;
    var step = p.steps.filter(function (st) { return st.state !== "confirmed"; })[0];
    if (!step) return;
    if (step.state === "pending") step.state = step.wait_blocks_left > 0 ? "waiting" : "published";
    else if (step.state === "waiting") { step.wait_blocks_left--; if (step.wait_blocks_left <= 0) step.state = "published"; }
    else if (step.state === "published") { step.state = "confirmed"; step.confirmations = 1; }
    if (step.state === "published" && !step.txid) step.txid = fakeTxid();
    p.steps.forEach(function (st) { if (st.state === "confirmed" && st !== step) st.confirmations++; });
    p.blocks_left = p.steps.reduce(function (sum, st) {
      return sum + (st.state === "confirmed" ? 0 : st.wait_blocks_left + 1);
    }, 0);
    if (p.steps.every(function (st) { return st.state === "confirmed"; })) {
      p.done = true;
      p.blocks_left = 0;
      f.state = "closed";
      world.wallet.confirmed_sat += p.amount_sat;
      world.wallet.transactions.unshift({ txid: p.steps[p.steps.length - 1].txid, kind: "factory_exit", amount_sat: p.amount_sat,
        confirmations: 1, at: now(), note: f.name });
      f.channel.balance_sat = 0;
      f.channel.receivable_sat = 0;
    }
  }

  function mine(count) {
    if (world.chain_state === "disagree") { world._last_block_at = now(); return; }
    for (var i = 0; i < count; i++) {
      world.height++;
      world.wallet.transactions.forEach(function (tx) { tx.confirmations++; });
      for (var id in world.lobbies) {
        var lobby = world.lobbies[id];
        if (lobby.stage === "funding") {
          lobby.funding.confirmations++;
          if (lobby.funding.confirmations >= lobby.funding.confirmations_needed) lobbyConfirmed(lobby);
        }
      }
      for (var fid in world.factories) {
        var f = world.factories[fid];
        f.funding.confirmations++;
        if (f.state === "exiting") stepExit(f);
        if (f.state === "active" && f.role === "member" && world.height >= f.rotation_opens_height) {
          f.state = "winding_down";
          f.next_factory = { name: f.host.name + ", next factory", members: f.members, channel_size_sat: f.terms.channel_size_sat,
            join_fee_sat: f.terms.join_fee_sat, within_conditions: true };
        }
        if ((f.state === "winding_down" || f.state === "host_gone" || f.state === "active") && f.role === "member" &&
            world.height >= f.auto_exit_height) beginExit(world, f);
      }
    }
    if (world.member_factory) world.last_opened_height = world.height;
    world._last_block_at = now();
    world.servers_checked_at = now();
    ["chain", "status", "lobby", "factory", "wallet", "schedule"].forEach(emit);
  }

  function stepPayments(t) {
    var f = world.factories[world.member_factory];
    world.payments.forEach(function (p) {
      if (p.state !== "pending" || t < p._settle_at) return;
      p.state = "done";
      emit("payments"); emit("factory");
    });
    world.invoices.forEach(function (inv) {
      if (inv.state !== "waiting" || t < inv._paid_at || !f || !f.channel) return;
      inv.state = "paid";
      f.channel.balance_sat += inv.amount_sat;
      f.channel.receivable_sat -= inv.amount_sat;
      world.payments.unshift({ id: "pay-" + idCounter++, direction: "received", amount_sat: inv.amount_sat, fee_sat: 0,
        description: inv.description, state: "done", at: t, reason: null });
      emit("payments"); emit("factory");
    });
  }

  function stepRotation(t) {
    var f = world.factories[world.member_factory];
    if (!f || !f.rotation || t < f.rotation._next_at) return;
    var r = f.rotation;
    r._next_at = t + 2;
    if (r.step === "signing") r.step = "moving";
    else if (r.step === "moving") {
      var next = makeFactory({ id: f.id + "-next", name: f.next_factory.name, host: f.host.name, members: f.next_factory.members,
        created_height: world.height, terms: f.terms, balance: f.channel.balance_sat });
      world.factories[next.id] = next;
      delete world.factories[f.id];
      world.member_factory = next.id;
      emit("status"); emit("schedule");
    }
    emit("factory");
  }

  function tick() {
    if (!world || demo.failing || demo.paused) return;
    if (demo._was_paused) { world._last_block_at = now(); demo._was_paused = false; }
    var t = now();
    if (t - world._last_block_at >= BLOCK_EVERY_S) mine(1);
    for (var id in world.lobbies) stepLobby(world.lobbies[id], t);
    stepPayments(t);
    stepRotation(t);
  }

  /* ---------- the calls ---------- */

  function need(value, code, message) { if (!value) throw apiError(code, message); return value; }
  function lobbyOr404(id) { return need(world.lobbies[id], "not_found", "That lobby is no longer there."); }
  function factoryOr404(id) { return need(world.factories[id], "not_found", "That factory is not known to this wallet."); }

  function decode(text) {
    text = String(text || "").trim().toLowerCase();
    var f = world.factories[world.member_factory];
    var result = { valid: false, can_pay: false, reason: null, amount_sat: 0, description: "", payee: "",
      fee_max_sat: 0, deadline_blocks: 0, expires_at: 0, balance_sat: f && f.channel ? f.channel.balance_sat : 0 };
    if (!text) { result.reason = "empty"; return result; }
    if (text.indexOf("lnbc") === 0) { result.reason = "wrong_network"; return result; }
    if (text.indexOf("lntbs") !== 0 || text.length < 20) { result.reason = "not_an_invoice"; return result; }
    var match = /^lntbs(\d+)sat1/.exec(text);
    result.valid = true;
    result.amount_sat = match ? parseInt(match[1], 10) : 1000 + (text.length * 137) % 9000;
    result.description = text.indexOf("large") > 0 ? "A payment larger than the balance" : "Example purchase";
    result.payee = "02example…node";
    result.expires_at = now() + 3600;
    if (!f || !f.channel || f.state === "closed" || f.state === "exiting") { result.reason = "no_channel"; return result; }
    result.fee_max_sat = Math.ceil(result.amount_sat * f.terms.payment_fee_ppm / 1000000) + 1;
    result.deadline_blocks = f.exit.blocks + EXIT_MARGIN_BLOCKS;
    if (f.state === "host_gone") { result.reason = "host_offline"; return result; }
    if (result.amount_sat + result.fee_max_sat > f.channel.balance_sat) { result.reason = "not_enough_balance"; return result; }
    if (f.auto_exit_height - world.height < result.deadline_blocks) { result.reason = "too_close_to_end"; return result; }
    result.can_pay = true;
    return result;
  }

  function previewTerms(terms) {
    var t = standardTerms(terms);
    var perMember = t.channel_size_sat + t.spare_liquidity_sat;
    var target = Number(terms.target) || 0;
    var minimum = Number(terms.minimum) || 0;
    var problems = [];
    if (minimum < 2) problems.push({ field: "minimum", code: "minimum_too_small" });
    if (target < minimum) problems.push({ field: "target", code: "target_below_minimum" });
    if (target > 512) problems.push({ field: "target", code: "target_too_large" });
    if (t.channel_size_sat < 20000) problems.push({ field: "channel_size_sat", code: "channel_too_small" });
    if (!(Number(terms.deadline_minutes) >= 1)) problems.push({ field: "deadline_minutes", code: "deadline_missing" });
    if (!String(terms.name || "").trim()) problems.push({ field: "name", code: "name_missing" });
    if (t.lifetime_blocks < t.exit_blocks + EXIT_MARGIN_BLOCKS + ROTATION_WINDOW_BLOCKS + DAY) problems.push({ field: "lifetime_days", code: "lifetime_too_short" });
    var atTarget = target * perMember;
    return {
      terms: t,
      exit_blocks: t.exit_blocks,
      usable_blocks: Math.max(0, t.lifetime_blocks - t.exit_blocks - EXIT_MARGIN_BLOCKS - ROTATION_WINDOW_BLOCKS),
      wind_down_by_blocks: Math.max(0, t.lifetime_blocks - t.exit_blocks - EXIT_MARGIN_BLOCKS),
      funding_at_target_sat: atTarget,
      funding_at_minimum_sat: minimum * perMember,
      chain_fee_estimate_sat: 400 + target * 12,
      wallet_sat: world.wallet.confirmed_sat,
      wallet_covers_target: world.wallet.confirmed_sat >= atTarget,
      wallet_covers_minimum: world.wallet.confirmed_sat >= minimum * perMember,
      host_node_linked: world.settings.host_node.linked,
      problems: problems
    };
  }

  function termsFromForm(terms) {
    return {
      channel_size_sat: Number(terms.channel_size_sat), spare_liquidity_sat: Number(terms.spare_liquidity_sat),
      join_fee_sat: Number(terms.join_fee_sat), payment_fee_ppm: Number(terms.payment_fee_ppm),
      liquidity_fee_ppm: Number(terms.liquidity_fee_ppm), lifetime_blocks: Number(terms.lifetime_days) * DAY,
      timed_levels: Number(terms.timed_levels), target: terms.target, minimum: terms.minimum,
      deadline_minutes: terms.deadline_minutes, name: terms.name
    };
  }

  function serverList() {
    var disagree = world.chain_state === "disagree";
    if (world.network === "testnet4") {
      return [{ id: "mempool-http", name: "mempool.space", operator: "mempool.space", protocol: "http",
        address: "https://mempool.space/testnet4/api", state: "ok", height: world.height, checked_at: world.servers_checked_at }];
    }
    return [
      { id: "mempool-http", name: "mempool.space", operator: "mempool.space", protocol: "http",
        address: "https://mempool.space/signet/api", state: "ok", height: world.height, checked_at: world.servers_checked_at },
      { id: "blockstream-http", name: "blockstream.info", operator: "Blockstream", protocol: "http",
        address: "https://blockstream.info/signet/api", state: disagree ? "disagrees" : "ok",
        height: world.height, checked_at: world.servers_checked_at },
      { id: "mempool-electrum", name: "mempool.space (Electrum)", operator: "mempool.space", protocol: "electrum",
        address: "mempool.space:60602", state: "ok", height: world.height, checked_at: world.servers_checked_at }
    ];
  }

  function settingsView() {
    var view = JSON.parse(JSON.stringify(world.settings));
    view.chain.state = world.chain_state;
    view.chain.servers = serverList();
    view.chain.independent_operators = world.network === "testnet4" ? 1 : 2;
    view.network = {
      current: world.network,
      choices: [
        { id: "signet", available: true, reason: null },
        { id: "testnet4", available: true, reason: "one_operator" },
        { id: "mainnet", available: false, reason: "switched_off_in_release" }
      ]
    };
    view.reminders.channels = [
      { id: "in_app", available: true, on: true },
      { id: "nostr", available: false, on: false },
      { id: "email", available: false, on: false },
      { id: "phone", available: false, on: false }
    ];
    view.roles = world.roles;
    return view;
  }

  var api = {
    getStatus: function () {
      return reply(function () {
        return {
          prototype: true,
          version: "prototype",
          network: world.network,
          test_coins: true,
          wallet_exists: world.wallet_exists,
          roles: world.roles,
          chain: { state: world.chain_state, height: world.height, seconds_per_block_here: BLOCK_EVERY_S },
          member: { lobby_id: world.member_lobby, factory_id: world.member_factory },
          host: { lobby_id: world.host_lobby, factory_id: world.host_factory },
          attention: world.wallet_exists ? attention() : []
        };
      });
    },

    subscribe: function (callback) {
      listeners.push(callback);
      return function unsubscribe() {
        listeners = listeners.filter(function (l) { return l !== callback; });
      };
    },

    /* First run */
    createWallet: function () {
      return reply(function () {
        world._pending_phrase = true;
        var words = [];
        for (var i = 0; i < 12; i++) words.push("example");
        return { recovery_phrase: words };
      });
    },
    restoreWallet: function (input) {
      return reply(function () {
        var words = String(input.recovery_phrase || "").trim().split(/\s+/);
        if (words.length !== 12 && words.length !== 24) throw apiError("bad_phrase", "A recovery phrase has 12 or 24 words. This one has " + (words[0] ? words.length : 0) + ".");
        world._pending_phrase = true;
        return { on_chain_restored: true, channels_restored: !!input.backup_file_name };
      });
    },
    finishSetup: function (input) {
      return reply(function () {
        need(world._pending_phrase, "no_wallet", "Create or restore a wallet first.");
        need(input.roles && (input.roles.member || input.roles.host), "no_role", "Choose member, host, or both.");
        world.wallet_exists = true;
        world.roles = { member: !!input.roles.member, host: !!input.roles.host };
        demo.state = "empty";
        emit("status");
        return { ok: true };
      });
    },
    setRoles: function (roles) {
      return reply(function () {
        need(roles.member || roles.host, "no_role", "Choose member, host, or both.");
        world.roles = { member: !!roles.member, host: !!roles.host };
        emit("status"); emit("settings");
        return world.roles;
      });
    },

    /* Conditions */
    getConditions: function () {
      return reply(function () {
        var lobby = world.lobbies[world.member_lobby];
        return { conditions: world.conditions, locked_by_lobby: lobby ? { id: lobby.id, name: lobby.name } : null,
          limits: { min_members: [2, 512], max_exit_blocks: [0, 8 * TIMED_LEVEL_BLOCKS] },
          profiles: ["safety", "standard", "starter", "circle"] };
      });
    },
    saveConditions: function (conditions) {
      return reply(function () {
        need(!world.member_lobby, "locked", "Your conditions are locked while you are in a lobby. Leave the lobby to change them.");
        need(conditions.profiles && conditions.profiles.length, "no_profile", "Accept at least one profile, or no lobby can match.");
        ["min_members", "min_channel_sat", "max_join_fee_sat", "max_payment_fee_ppm", "max_liquidity_fee_ppm", "max_exit_blocks"].forEach(function (key) {
          var n = Number(conditions[key]);
          need(isFinite(n) && n >= 0, "bad_value", "Every condition needs a number that is zero or more.");
          world.conditions[key] = Math.round(n);
        });
        world.conditions.profiles = conditions.profiles.slice();
        emit("conditions"); emit("lobby");
        return world.conditions;
      });
    },

    /* Lobbies */
    listLobbies: function () {
      return reply(function () {
        return Object.keys(world.lobbies).map(function (id) { return world.lobbies[id]; })
          .filter(function (l) { return l.role !== "host" && (l.listed || yourSeat(l)); })
          .map(function (l) { return lobbyView(l, false); });
      });
    },
    getLobby: function (id) {
      return reply(function () { return lobbyView(lobbyOr404(id), true); });
    },
    openInvitation: function (link) {
      return reply(function () {
        need(/^gazpacho:/.test(String(link).trim()), "bad_invitation", "That is not a Gazpacho invitation link. They start with gazpacho:");
        var lobby = world.lobbies["lobby-circle"];
        lobby._invited = true;
        return { lobby_id: lobby.id };
      });
    },
    joinLobby: function (id, conditions) {
      return reply(function () {
        var lobby = lobbyOr404(id);
        need(lobby.stage === "open", "not_open", "This lobby is no longer taking members.");
        need(!world.member_lobby, "already_in_lobby", "You are already in a lobby. Leave it before joining another.");
        var f = world.factories[world.member_factory];
        need(!f || f.state === "closed", "already_in_factory", "You are already in a factory. The prototype handles one factory at a time.");
        need(lobby.access === "open" || lobby._invited, "needs_invitation", "This lobby needs an invitation from its host.");
        var check = checkTerms(lobby, conditions || world.conditions);
        need(check.ok, "conditions_not_met", "This lobby's terms are outside your conditions, so the app will not join it.");
        if (f) { delete world.factories[f.id]; world.member_factory = null; }
        youJoin(lobby, world);
        emit("lobby"); emit("status"); emit("conditions");
        return lobbyView(lobby, true);
      });
    },
    leaveLobby: function (id) {
      return reply(function () {
        var lobby = lobbyOr404(id);
        var you = need(yourSeat(lobby), "not_joined", "You are not in this lobby.");
        need(lobby.stage === "open" || lobby.stage === "ready_check" || lobby.stage === "signing", "too_late", "The factory is already signed. Use the factory screen to leave.");
        lobby.members.splice(lobby.members.indexOf(you), 1);
        lobby.members.forEach(function (m) { m.blocked = false; });
        if (lobby.stage === "signing") { lobby.signing.attempt++; lobby.signing.step = "nonces"; lobby.signing.signed = 0; lobby.signing.of--; }
        world.member_lobby = null;
        emit("lobby"); emit("status"); emit("conditions");
        return { ok: true };
      });
    },
    setBlocked: function (lobbyId, memberId, blocked) {
      return reply(function () {
        var lobby = lobbyOr404(lobbyId);
        var member = need(lobby.members.filter(function (m) { return m.id === memberId; })[0], "not_found", "That person has left the lobby.");
        member.blocked = !!blocked;
        emit("lobby"); emit("status");
        return { ok: true };
      });
    },

    /* Factory */
    getFactory: function (id) {
      return reply(function () { return factoryOr404(id); });
    },
    getSchedule: function () {
      return reply(schedule);
    },
    startExit: function (factoryId) {
      return reply(function () {
        var f = factoryOr404(factoryId);
        need(f.role === "member", "host_factory", "A host does not leave its own factory this way.");
        need(f.state !== "exiting" && f.state !== "closed", "already_exiting", "Leaving is already under way.");
        need(world.chain_state !== "disagree", "chain_disagree", "The chain servers disagree, so the app cannot safely publish now. Check Settings, then try again.");
        beginExit(world, f);
        ["factory", "status", "schedule"].forEach(emit);
        return f.exit_progress;
      });
    },
    moveToNextFactory: function (factoryId) {
      return reply(function () {
        var f = factoryOr404(factoryId);
        need(f.state === "winding_down" && f.next_factory, "not_winding_down", "There is no next factory to move to yet.");
        f.rotation = { step: "signing", _next_at: now() + 2 };
        emit("factory");
        return { ok: true };
      });
    },

    /* Pay and receive */
    decodeInvoice: function (text) {
      return reply(function () { return decode(text); });
    },
    payInvoice: function (text) {
      return reply(function () {
        var d = decode(text);
        need(d.can_pay, d.reason || "cannot_pay", "This invoice cannot be paid now.");
        var f = world.factories[world.member_factory];
        var fee = Math.max(0, d.fee_max_sat - 1);
        f.channel.balance_sat -= d.amount_sat + fee;
        f.channel.receivable_sat += d.amount_sat + fee;
        var payment = { id: "pay-" + idCounter++, direction: "sent", amount_sat: d.amount_sat, fee_sat: fee,
          description: d.description, state: "pending", at: now(), reason: null, _settle_at: now() + 3 };
        world.payments.unshift(payment);
        emit("payments"); emit("factory");
        return payment;
      });
    },
    createInvoice: function (input) {
      return reply(function () {
        var f = world.factories[world.member_factory];
        need(f && f.channel && f.state !== "closed" && f.state !== "exiting", "no_channel", "You need a channel in a factory before you can be paid over Lightning.");
        need(f.state !== "host_gone", "host_offline", "The host is not answering, so payments cannot arrive at the moment.");
        var amount = Math.round(Number(input.amount_sat));
        need(amount > 0, "bad_amount", "Enter an amount above zero.");
        need(amount <= f.channel.receivable_sat, "above_receivable", "That is more than this channel can receive.");
        var invoice = { id: "inv-" + idCounter++, amount_sat: amount, description: String(input.description || ""),
          invoice: "lntbs" + amount + "sat1" + new Array(9).join("example"), state: "waiting",
          created_at: now(), expires_at: now() + 3600, _paid_at: now() + 7 };
        world.invoices.unshift(invoice);
        return invoice;
      });
    },
    getInvoice: function (id) {
      return reply(function () {
        return need(world.invoices.filter(function (inv) { return inv.id === id; })[0], "not_found", "That invoice is not known.");
      });
    },
    listPayments: function () {
      return reply(function () {
        var f = world.factories[world.member_factory];
        var usable = !!(f && f.channel && f.state !== "closed" && f.state !== "exiting");
        return {
          channel: usable ? { balance_sat: f.channel.balance_sat, receivable_sat: f.channel.receivable_sat,
            host_online: f.host.online, factory_id: f.id } : null,
          payments: world.payments
        };
      });
    },

    /* Hosting */
    previewTerms: function (terms) {
      return reply(function () { return previewTerms(termsFromForm(terms)); });
    },
    createLobby: function (terms) {
      return reply(function () {
        need(world.roles.host, "not_host", "Turn on host mode first.");
        need(!world.host_lobby, "already_hosting", "You already have a lobby open.");
        var preview = previewTerms(termsFromForm(terms));
        need(!preview.problems.length, "bad_terms", "Some of the terms need fixing before the lobby can open.");
        var lobby = makeLobby({ id: "lobby-mine", name: String(terms.name).trim(), host: "You", role: "host", profile: terms.profile,
          listed: !!terms.listed, access: terms.access, target: Number(terms.target), minimum: Number(terms.minimum),
          deadline_in: Number(terms.deadline_minutes) * 60, on_shortfall: terms.on_shortfall, present: 0, join_every: 4,
          names: !!terms.names, chat: !!terms.chat, rule_requests: !!terms.rule_requests });
        lobby.terms = preview.terms;
        world.lobbies[lobby.id] = lobby;
        world.host_lobby = lobby.id;
        emit("lobby"); emit("status");
        return lobbyView(lobby, true);
      });
    },
    removeMember: function (lobbyId, memberId) {
      return reply(function () {
        var lobby = lobbyOr404(lobbyId);
        need(lobby.role === "host", "not_host", "Only the host can remove someone.");
        need(lobby.stage === "open", "not_open", "Members can be removed only while the lobby is gathering.");
        lobby.members = lobby.members.filter(function (m) { return m.id !== memberId; });
        emit("lobby");
        return { ok: true };
      });
    },
    startLobbyNow: function (lobbyId) {
      return reply(function () {
        var lobby = lobbyOr404(lobbyId);
        need(lobby.role === "host", "not_host", "Only the host can start a lobby.");
        need(lobby.stage === "open" && readyCount(lobby) >= lobby.start_rule.minimum, "below_minimum", "The lobby is below its minimum, so it cannot start.");
        beginLobbyStart(lobby, "host");
        emit("lobby"); emit("status");
        return { ok: true };
      });
    },
    cancelLobby: function (lobbyId) {
      return reply(function () {
        var lobby = lobbyOr404(lobbyId);
        need(lobby.role === "host", "not_host", "Only the host can cancel a lobby.");
        need(lobby.stage !== "funding" && lobby.stage !== "active", "too_late", "The factory is already funded.");
        delete world.lobbies[lobby.id];
        world.host_lobby = null;
        emit("lobby"); emit("status");
        return { ok: true };
      });
    },

    /* On-chain wallet */
    getWallet: function () {
      return reply(function () {
        return {
          confirmed_sat: world.wallet.confirmed_sat,
          unconfirmed_sat: world.wallet.unconfirmed_sat,
          reserve_recommended_sat: RESERVE_SAT,
          address: world.wallet.address,
          chain_state: world.chain_state,
          transactions: world.wallet.transactions
        };
      });
    },
    newAddress: function () {
      return reply(function () {
        var n = String(idCounter++);
        world.wallet.address = "tb1qexampleexampleexampleexampleexample" + ("00" + n).slice(-2);
        emit("wallet");
        return { address: world.wallet.address };
      });
    },

    /* Settings */
    getSettings: function () {
      return reply(settingsView);
    },
    saveSettings: function (patch) {
      return reply(function () {
        var st = world.settings;
        if (patch.chain) {
          var mode = patch.chain.mode || st.chain.mode;
          if (mode === "own_server") need(String((patch.chain.own_server || st.chain.own_server).address).trim(), "address_missing", "Enter your server's address.");
          if (mode === "own_node") need(String((patch.chain.own_node || st.chain.own_node).address).trim(), "address_missing", "Enter your node's address.");
          st.chain.mode = mode;
          if (patch.chain.own_server) st.chain.own_server = { address: String(patch.chain.own_server.address).trim() };
          if (patch.chain.own_node) st.chain.own_node = { address: String(patch.chain.own_node.address).trim(), user: String(patch.chain.own_node.user || "") };
        }
        if (patch.host_node) {
          st.host_node = { kind: patch.host_node.kind, address: String(patch.host_node.address || "").trim(),
            access_file: String(patch.host_node.access_file || "").trim(), linked: false };
        }
        if (patch.reminders) {
          var days = Number(patch.reminders.warn_days_before);
          need(days >= 1 && days <= 14, "bad_value", "Choose between 1 and 14 days.");
          st.reminders.warn_days_before = Math.round(days);
        }
        if (patch.network) {
          need(patch.network !== "mainnet", "network_unavailable", "Mainnet is switched off in this release.");
          need(!world.member_factory && !world.member_lobby && !world.host_lobby && !world.host_factory, "network_busy",
            "Leave your lobby or factory before changing network.");
          world.network = patch.network;
          world.height = patch.network === "testnet4" ? 160702 : 330437;
          world.last_opened_height = world.height;
        }
        emit("settings"); emit("status"); emit("chain");
        return settingsView();
      });
    },
    checkChainServers: function () {
      return reply(function () {
        world.servers_checked_at = now();
        emit("settings");
        return { state: world.chain_state, servers: serverList() };
      });
    },
    testHostNode: function () {
      return reply(function () {
        var node = world.settings.host_node;
        need(node.address, "address_missing", "Enter the node's address first.");
        var ok = node.kind === "lnd";
        node.linked = ok;
        emit("status"); emit("settings");
        return { linked: ok, operations: [
          { id: "pay", ok: true }, { id: "hold", ok: ok }, { id: "settle", ok: ok }, { id: "cancel", ok: ok }
        ] };
      });
    },
    exportBackup: function () {
      return reply(function () {
        world.settings.backup.last_export_at = now();
        emit("settings");
        return { file_name: "gazpacho-backup-example.gzb", bytes: 48213, exported_at: world.settings.backup.last_export_at };
      });
    }
  };

  /* ---------- prototype-only controls ---------- */

  var demoStates = [
    { id: "first-run", label: "First run (no wallet yet)" },
    { id: "empty", label: "Empty wallet" },
    { id: "in-lobby", label: "In a lobby" },
    { id: "lobby-starting", label: "Lobby about to start" },
    { id: "conditions-not-met", label: "Conditions not met" },
    { id: "factory-live", label: "Factory live" },
    { id: "winding-down", label: "Factory winding down" },
    { id: "host-gone", label: "Host has disappeared" },
    { id: "exiting", label: "Exit in progress" },
    { id: "servers-disagree", label: "Chain servers disagree" },
    { id: "hosting-lobby", label: "Hosting: lobby open" },
    { id: "hosting-factory", label: "Hosting: factory live" }
  ];

  window.gzMockDemo = {
    states: demoStates,
    current: function () {
      return { state: demo.state, failing: demo.failing, slow: demo.slow, paused: demo.paused, block_every_s: BLOCK_EVERY_S };
    },
    setState: setDemoState,
    mine: function (count) { mine(count); },
    setFailing: function (on) { demo.failing = !!on; emit("reset"); },
    setSlow: function (on) { demo.slow = !!on; },
    setPaused: function (on) { demo.paused = !!on; demo._was_paused = true; }
  };

  window.gzApi = api;

  /* The starting state can be chosen in the address: index.html?state=factory-live */
  var wanted = /[?&]state=([a-z-]+)/.exec(window.location.search);
  var remembered = null;
  try { remembered = window.sessionStorage.getItem("gz-demo-state"); } catch (e) { /* storage may be unavailable */ }
  setDemoState(wanted ? wanted[1] : remembered || "first-run");
  setInterval(tick, 1000);
})();
