// SPDX-License-Identifier: MIT
/* The interface holds the wording; the program returns codes and numbers
   (spec/local-api.md 1). A code without wording here is shown as
   "unknown state", never as success (6). */
(function () {
  "use strict";
  var gz = window.gz, u = gz.util;

  /* 14.3, interface rules 3 to 5: what each signing setting does, in the words the person reads */
  var LOCKED_SEAT = "Not taking part until you mark ready again: your app told the host this seat is locked.";
  var signing = {
    at_join: "Gazpacho asks for your passphrase when you mark ready in a lobby. Only then does it make that lobby's signing key, and only for the terms you readied for; it forgets the key when that check ends. While Gazpacho is unlocked it still holds your wallet's seed, so this stops signing you did not mean, not someone who controls this computer.",
    auto: "Gazpacho signs in every lobby you are ready in, by itself, whenever it is unlocked."
  };
  var signingNames = { at_join: "Ask for my passphrase when I mark ready", auto: "Sign by itself in every lobby I am ready in", when_unlocked: "Sign while signing is unlocked" };
  var SIGNING_SAVED = "Saved. This takes effect the next time Gazpacho starts; until then it keeps signing as it does now.";

  var errors = {
    unreachable: "Gazpacho is not answering. Check that the program is still running on this computer.",
    not_signed_in: "You are signed out. Type your passphrase to go on.",
    wallet_locked: "The wallet is locked. Type your passphrase to unlock it.",
    wrong_passphrase: "That passphrase is not right. Nothing was done.",
    passphrase_not_checked: "Gazpacho could not check the passphrase just now. It was not counted as wrong. Try again.",
    passphrases_differ: "The two passphrases are not the same. Type them again.",
    no_wallet: "There is no wallet here yet.",
    wallet_exists: "A wallet already exists here.",
    wallet_restoring: "This wallet is still being restored. Wait until it has current data.",
    bad_code: "That code did not work. It may be mistyped, already used or more than 10 minutes old.",
    code_expired: "That code is more than 10 minutes old. Ask the program for a new one.",
    too_many_attempts: "Too many wrong codes. Every unused code was cancelled. Ask the program for a new one.",
    token_used: "This start link was already used.",
    fresh_sign_in_needed: "Gazpacho needs your passphrase again for this.",
    confirm_mismatch: "What this page showed you no longer matches what Gazpacho would do. Nothing was done. Look again and repeat it.",
    request_id_reused: "The page repeated an old request by mistake. Nothing was done. Try again.",
    changed_elsewhere: "This was changed in another window. Nothing was saved. The page shows the newer values now.",
    paused: "Gazpacho is paused: it joins and signs nothing new. Resume first.",
    signing_now: "Gazpacho is signing right now. Try again in a few seconds.",
    chain_in_doubt: "Gazpacho cannot trust its view of the chain right now, so it will not do this. See Connections.",
    node_busy: "Gazpacho is still saving your last request. Nothing is lost. Try again: the same request is never done twice.",
    view_pending: "It was done; Gazpacho is still catching up on showing it. Try again: the same request is answered, never done twice.",
    coins_unknown: "Gazpacho cannot tell right now whether the wallet's coins cover this. Try again in a moment.",
    request_in_progress: "That request is still being answered. Try again in a moment: it is never done twice.",
    node_stopped: "Gazpacho's node stopped and is starting again from its saved files. Try again in a moment.",
    internal: "Something went wrong inside Gazpacho. Nothing was done.",
    bad_value: "One of the values is outside what Gazpacho accepts.",
    unknown_field: "This page and the program do not match. Reload the page.",
    missing_field: "This page and the program do not match. Reload the page.",
    bad_json: "This page and the program do not match. Reload the page.",
    not_found: "Gazpacho no longer knows this item. It may have ended, or the program was restarted.",
    not_in_this_release: "This is not in this release.",
    too_many_streams: "Too many windows are following this app.",
    other_user: "This computer account may not use Gazpacho's page.",
    not_setup_call: "Finish setting up the wallet first.",
    not_files_behind_call: "Choose what to do with these files first.",
    not_files_behind: "These files are not older than the wallet's last saved state any more.",
    hosting_lobby_open: "You are hosting a lobby that is still open. Cancel it before you lock: a locked wallet cannot answer its members.",
    bad_words: "These are not 24 valid words.",
    below_floor: "Gazpacho does not accept fewer confirmations than its own floor.",
    not_open: "This lobby is not open any more.",
    conditions_not_met: "This lobby does not fit your conditions. Nothing was joined.",
    fits_only_now: "This lobby fits only at the host's current values, and the host may move them. Nothing was joined.",
    terms_changed: "The host changed a value since you looked. Read the terms again, then join.",
    already_in_lobby: "This build of Gazpacho allows one joined lobby at a time, and you are in one.",
    needs_invitation: "This lobby needs an invitation.",
    host_unreachable: "The host is not answering. Nothing was joined.",
    lobby_full: "Every seat in this lobby is taken.",
    host_avoided: "This host is on your list of hosts to avoid.",
    not_joined: "You are not in this lobby.",
    too_late: "Too late: signing has begun. Signatures already sent cannot be called back.",
    bad_host_address: "That is not a host address. It is the host's key, then @, then its address and port.",
    wrong_network: "That host is on another network.",
    draft_changed: "The terms changed since the preview. Look at the preview again.",
    funds_short: "This wallet does not hold enough coins to fund the lobby at its target.",
    already_hosting: "This build of Gazpacho allows one hosted lobby at a time, and you are hosting one.",
    below_minimum: "Fewer members are ready than the lobby's minimum, so it cannot start yet.",
    frozen: "The ready check has run. Nothing about the seats can change now.",
    not_host: "This lobby is not one you host.",
    weak_passphrase: "This passphrase is not strong enough."
  };

  function errorText(e) {
    var p = e && e.params ? e.params : {}, code = e && e.code ? e.code : "internal";
    if (code === "rate_limited") {
      return typeof p.retry_after_s === "number"
        ? "Too many tries. Wait " + waitText(p.retry_after_s) + " and try again."
        : "Too many tries. Wait a moment and try again.";
    }
    if (code === "weak_passphrase") {
      if (p.reason === "too_short") return "This passphrase is too short (" + u.number(p.length) + " of " + u.number(p.minimum) + " characters).";
      if (p.reason === "too_long") return "This passphrase is too long.";
      if (p.reason === "too_common") return "This passphrase is too common. Choose another.";
      if (p.reason === "names_the_wallet") return "This passphrase names the wallet. Choose another.";
      if (p.reason === "uses_the_words") return "This passphrase uses your 24 words. Choose another.";
    }
    if (code === "bad_words") {
      if (typeof p.position === "number") return "Word " + p.position + " is not in the word list. Check the spelling on your paper.";
      return "These 24 words do not belong together. One of them is wrong or out of order. Check them against your paper.";
    }
    if (code === "conditions_not_met" && Array.isArray(p.failures) && p.failures.length) {
      return "This lobby does not fit your conditions. " + failuresText(p.failures) + " Nothing was joined.";
    }
    if (code === "below_minimum" && typeof p.ready === "number") {
      return u.number(p.ready) + " ready; the lobby needs " + u.number(p.minimum) + " to start.";
    }
    if (code === "node_stopped" && p.reason === "stopping") return "Gazpacho is shutting down.";
    if (code === "already_in_lobby" || errors[code]) return errors[code];
    return "Gazpacho answered with something this page does not know (" + code + "). Nothing is assumed to have worked.";
  }

  function waitText(s) {
    if (s < 90) return u.plural(Math.max(1, Math.ceil(s)), "second");
    return u.plural(Math.ceil(s / 60), "minute");
  }

  var conditionNames = {
    profiles: "Lobby types I accept",
    min_members: "Fewest members",
    min_channel_sat: "Smallest channel",
    max_joining_fee_sat: "Joining fee, at most",
    max_fee_base_msat: "Payment fee, fixed part, at most",
    max_fee_ppm: "Payment fee, share, at most",
    min_life_blocks: "Factory life, at least",
    max_life_blocks: "Factory life, at most",
    max_exit_blocks: "Leaving alone takes, at most",
    min_confirmations: "Confirmations before live",
    payment_sizes_sat: "Payment sizes",
    compare_with: "Compare with",
    ready_hint: "Fewest members I sign with"
  };
  var conditionUnits = {
    min_members: "members", min_channel_sat: "sats", max_joining_fee_sat: "sats", max_fee_base_msat: "msat",
    max_fee_ppm: "per million", min_life_blocks: "blocks", max_life_blocks: "blocks", max_exit_blocks: "blocks",
    min_confirmations: "blocks"
  };

  /* A refusal always carries both numbers (8). */
  function failuresText(failures) {
    return failures.map(function (f) {
      /* a condition may be a list (profiles) or a range (payment_sizes_sat): ui.value shows each kind */
      var name = conditionNames[f.condition] || f.condition, v = gz.ui.value;
      return name + ": your limit is " + v(f.yours) + ", the lobby offers " + v(f.offered) + ".";
    }).join(" ");
  }

  var fitTerms = {
    profile: "Lobby type", members: "Members", channel_sat: "Channel size", joining_fee_sat: "Joining fee",
    fee: "Payment fee", life_blocks: "Factory life", exit_blocks: "Leaving alone takes", confirmations: "Confirmations",
    payment_sizes: "Payment sizes", host_record: "Host's record", host_avoided: "Host avoided",
    people_blocked: "People blocked", move_fee: "Move fee", seat_cost: "Seat cost", receiving_room_fee: "Receiving room fee"
  };
  var fitResults = { fits: "Fits", fits_now_only: "Fits only now", fails: "Does not fit", not_compared: "Not compared" };
  var fitClass = { fits: "Fits your conditions", fits_only_now: "Fits only now", does_not_fit: "Does not fit your conditions" };

  /* refused_at_check: which check refused (14.1) */
  var refusedWhich = {
    conditions: "", safety_check: "A fixed safety check failed.",
    fingerprint_differs: "The lobby is not the one you joined: its fingerprint differs.",
    values_differ_from_frozen: "The host's final values differ from the ones frozen at the ready check."
  };
  var stages = {
    open: "Open", ready_check: "Ready check", signing: "Signing", funding: "Waiting for funding", active: "Live",
    cancelled: "Cancelled", failed: "Failed", unknown: "Unknown"
  };
  var seats = {
    none: "Not joined", joining: "Joining…", joined_not_ready: "Joined, not ready", ready: "Ready",
    chosen: "Chosen", not_chosen: "Not chosen", left: "Left", removed: "Removed by the host", refused_by_host: "Refused by the host",
    /* the host's side (15.3) */
    locked: "Locked: out of the count until it marks ready again", refused: "Refused at its own check"
  };
  var rounds = {
    checking: "Checking the proposal", nonces_sent: "First round sent", signed: "Signatures sent", complete: "Complete",
    awaiting_funding: "Waiting for funding", live: "Live", aborted: "Stopped before any signature",
    unfinished: "Did not finish", abandoned: "Abandoned", dead: "Can never be funded"
  };
  var hostRounds = {
    collecting_nonces: "Collecting the first round", collecting_signatures: "Collecting signatures",
    tier_result: "Checking a level", complete: "Every signature is in", collecting_acks: "Collecting confirmations",
    funding: "Funding", funded: "Funded", failed: "Failed"
  };
  var checks = {
    fingerprint_same: "The lobby is the one you joined (same fingerprint)",
    frozen_values_inside_limits: "The host's final values are inside your limits",
    tree_inside_conditions: "The tree offered is inside your conditions",
    safety_checks: "The fixed safety checks pass"
  };
  var funding = {
    not_broadcast: "not published yet", broadcast: "published, not in a block yet", seen: "seen by the chain servers",
    confirming: "confirming", buried: "buried", reorganised_away: "removed by a reorganisation",
    input_spent_elsewhere: "can never confirm: an input was spent elsewhere"
  };
  var factoryStates = {
    awaiting_funding: "Waiting for funding. Not live yet", live: "Live", funding_reorganised: "Funding un-confirmed: signing stopped",
    abandoned: "Start abandoned", dead: "Can never be funded", ended: "Ended"
  };
  var chain = {
    agree: "servers agree", lagging: "servers agree; one is behind", catching_up: "still loading",
    one_source: "only one server answers", disagree: "servers disagree", unreachable: "no server answers",
    offline_by_choice: "offline, by your choice"
  };
  var watching = {
    this_app: "this app, while it runs",
    watcher_locked: "this app, locked: it watches, but cannot finish leaving a factory without your passphrase",
    nobody_locked: "nobody is watching while Gazpacho is locked",
    nobody_restoring: "nobody is watching the factories this wallet may have been in",
    nobody_offline: "nobody is watching",
    nobody_chain_in_doubt: "nobody can watch while the chain view is in doubt",
    nothing_to_watch: "nothing to watch: you are in no factory"
  };
  var dateKinds = {
    lobby_starts_by: "Lobby starts by", ready_check_answer_by: "Answer the ready check by", signing_ends_by: "Signing ends by",
    funding_deadline: "Funding needed by", unfinished_deadline: "Settled by", factory_ends: "Factory ends",
    host_fund_by: "You must fund by", host_online_for_try: "Be online by", open_app_by: "Open the app by"
  };
  var atZero = {
    lobby_applies_start_rule: "At zero it starts if enough are ready, or is cancelled",
    lobby_cancelled: "At zero the lobby is cancelled",
    round_abandoned: "At zero the start is abandoned: you owe nothing and are owed nothing",
    factory_end_rule_applies: "At zero the factory's end rule applies",
    lobby_cancelled_by_host_absence: "At zero the lobby is cancelled if the host is absent",
    next_date_takes_over: "At zero the next date takes over"
  };
  var provenance = {
    term_start_plus_life: "The start plus the life written in the host's signed terms",
    ack_height_plus_deadline: "The block at which the round was confirmed, plus the funding deadline",
    signing_budget_from_sent: "The time your signatures were sent, plus the signing budget in the terms"
  };
  var attention = {
    chain_disagree: "The chain servers disagree. Gazpacho signs nothing and treats nothing as newly confirmed until they agree.",
    chain_one_source: "Only one chain server answers. With one source Gazpacho cannot compare, so it signs nothing.",
    chain_unreachable: "No chain server answers. Gazpacho signs nothing and cannot see new blocks.",
    chain_catching_up: "The chain servers are still loading. Gazpacho signs nothing until two of them agree.",
    signing_unfinished: "Signing did not finish. Your app sent its signatures and no result came back. Keep the app running until it is settled.",
    node_stopped: "Gazpacho's node stopped and is starting again from its saved files.",
    host_not_answering: "A host is not answering. Nothing is signed without it.",
    words_not_checked: "Your 24 words have not been checked yet.",
    restored_factories_unknown: "This wallet was restored from its words. Factories it was in are not known and not watched.",
    storage_nearly_full: "Gazpacho's storage is nearly full.",
    terms_changed: "A host moved a value in a lobby you are in.",
    refused_to_sign: "The app refused to sign for a lobby. Nothing was signed. Nothing moved.",
    unlock_to_take_part: "A seat of yours is locked: it does not take part until you mark ready again with your passphrase.",
    host_can_start: "Enough members are ready in a lobby you host: you can start it now.",
    host_funds_short: "A lobby you host needs more coins than this wallet has free.",
    member_refused: "A member of a lobby you host refused its values. Open the lobby to see which.",
    lobby_left_out: "A lobby you are in is waiting: this start could not get its keys. Nothing is signed or sent for it until it can."
  };
  var tiers = { at_risk: "At risk", act_now: "Act now", important: "Important", recommended: "Recommended", heads_up: "Heads-up", record: "Record" };
  var activityKinds = {
    wallet_created: "Wallet made", words_checked: "Words checked", lobby_found: "Lobby found", joined: "Joined a lobby",
    readied: "Ready", unreadied: "Not ready", left: "Left a lobby", removed_by_host: "Removed by the host",
    refused: "Did not sign", aborted_before_signatures: "Stopped before any signature", not_chosen: "Not chosen",
    lobby_cancelled: "Lobby cancelled", signed: "Signed", signing_unfinished: "Signing did not finish",
    creation_abandoned: "Start abandoned", creation_dead: "Start can never be funded", factory_live: "Factory live",
    funding_reorganised: "Funding un-confirmed", host_fault_evidence: "Evidence of a host fault", paused: "Paused",
    resumed: "Resumed", lobby_opened: "Lobby opened", values_moved: "Values moved", ready_check_run: "Ready check run",
    funded: "Funding published", host_recovered: "Coins recovered", received_coins: "Coins received", sent_coins: "Coins sent"
  };
  var who = { you: "you", the_app: "the app, by itself", the_host: "the host", the_sender: "the sender", the_chain: "the chain", all_members: "all members" };
  var rules = {
    my_conditions: "your conditions", joining_was_consent: "joining was your consent", fixed_safety_check: "a fixed safety check",
    confirmations_required: "the confirmations required", factory_terms: "the factory's terms", start_rule: "the lobby's start rule", pause: "Pause"
  };
  var problems = {
    name_missing: "Give the lobby a name.", deadline_missing: "Set when the lobby closes.", deadline_past: "The closing time is in the past.",
    minimum_too_small: "The minimum is too small.", target_below_minimum: "The target is below the minimum.",
    target_too_large: "The target is too large.", channel_too_small: "The channel size is too small.",
    life_too_short: "The factory life is too short.", budget_below_step: "The signing budget is shorter than one step.",
    range_inverted: "A range has its lowest value above its highest.", now_outside_range: "A current value is outside its range.",
    shape_invalid: "The tree shape does not work for some member count.", profile_not_in_slice: "This build accepts the Standard type only.",
    on_shortfall_not_in_slice: "This build accepts only \"cancel\" when too few are ready.", reserved_term_set: "A term reserved for a later release is set."
  };
  var cannotOpen = {
    problems: "The terms have problems (listed above).", funds_short: "This wallet does not hold enough free coins to fund the lobby at its target.",
    no_wallet: "There is no wallet yet.", chain_in_doubt: "Gazpacho cannot trust its view of the chain right now.",
    already_hosting: "This build allows one hosted lobby at a time, and you are hosting one.", host_node_missing: "Hosting needs a Lightning node, which is not set up."
  };
  var headlines = {
    files_behind: "These files are older than this wallet's last saved state. Unlock to choose: start them as a restore, with new keys, or stay locked so you can put the newer files back.",
    nothing_needs_you: {
      watcher_locked: "Locked. Gazpacho is still watching. Nothing needs you now.",
      nobody_locked: "Locked. Nothing needs you now. Nothing is watched while Gazpacho is locked.",
      nothing_to_watch: "Locked. Nothing needs watching."
    },
    nobody_watching_locked: "Gazpacho is locked, and nobody watches your factories while it is locked. Unlock to watch them.",
    nobody_watching_at_risk: "Locked. Nothing is watched. Unlock, or a factory balance is at risk.",
    unlock_before: "Locked. Gazpacho is still watching. Unlock soon: leaving a factory alone needs your passphrase for its last step.",
    past_unlock_by: "Unlock at once. It may already be too late to leave a factory in time.",
    deadline_passed_while_locked: "Unlock. A factory's deadline passed while Gazpacho was locked; it will check what happened.",
    waiting_for_unlock: "Unlock now. Only the last step of leaving a factory is left, and it needs your passphrase.",
    publishing_tree_steps: "Locked and leaving a factory alone. The last step needs your passphrase. Unlock soon.",
    tree_step_late: "Unlock now. Leaving a factory is behind and needs a higher fee, which Gazpacho can only pay once unlocked.",
    penalty_file_short: "Unlock now. Some of Gazpacho's answers to your host's old states are missing from this computer.",
    old_state_answered: "Locked. The host published an old state and Gazpacho answered it. Unlock to see.",
    host_closed: "The host closed this channel. Your balance waits for you; unlock to collect it.",
    second_stage_after_breach: "Unlock now. The host published an old state; answering it fully needs your passphrase.",
    payment_secret_released: "Unlock now, or a payment you received may be lost."
  };

  function lookup(table, code) {
    return Object.prototype.hasOwnProperty.call(table, code) ? table[code] : null;
  }
  function known(table, code) {
    var t = lookup(table, code);
    return t === null ? "unknown state (" + String(code) + ")" : t;
  }

  function headline(status) {
    var w = status && status.watching ? status.watching : {}, code = w.headline ? w.headline.code : null, t;
    if (status && status.wallet === "files_behind") return headlines.files_behind;
    t = lookup(headlines, code);
    if (t === null) return "Locked. Gazpacho reports a state this page does not know (" + String(code) + "). Unlock to see.";
    if (typeof t === "string") return t;
    return lookup(t, w.state) || t.nobody_locked;
  }

  function dateText(d) {
    var t;
    if (!d) return "none";
    t = known(dateKinds, d.kind) + ": block " + u.number(d.due_height);
    if (typeof d.blocks_left === "number") {
      t += d.blocks_left >= 0 ? " (in " + u.plural(d.blocks_left, "block") + ", " + u.blocksAsTime(d.blocks_left) + ")" : " (passed)";
    }
    return t;
  }

  /* The strip's sentence for doing.code (11.2). Returns { strong, rest }. */
  function doing(status) {
    var d = status.doing || {}, p = d.params || {}, c = d.code;
    switch (c) {
    case "no_wallet": return { strong: "", rest: "No wallet yet. Make one or bring one back to begin." };
    case "restoring": return { strong: "Restoring.", rest: "Waiting for current data. Balances are not confirmed yet, and nothing can be joined or hosted." };
    case "node_stopped": return { strong: "Gazpacho's node stopped.", rest: "It is starting again from its saved files. Nothing can be done until it is back." };
    case "signing": return { strong: "Signing. Keep the app open.", rest: "A few seconds. Pause now would take effect when signing ends." };
    case "signing_unfinished": return { strong: "Signing did not finish.", rest: "The app sent its signatures and no result came back. Not live. It keeps watching until this is settled." };
    case "chain_in_doubt": return { strong: "At risk: the chain view is in doubt.", rest: "Signing stopped. Gazpacho treats nothing as newly confirmed." };
    case "awaiting_funding":
      return { strong: "Signed. Waiting for the host's funding:", rest: (typeof p.confirmations === "number" ? u.number(p.confirmations) + " of " + u.number(p.needed) + " confirmations. " : "") + "Not live yet." };
    case "paused": return { strong: "Paused.", rest: "The app signs nothing new and joins nothing until you resume. Dates still apply and watching goes on." };
    case "ready_check": return { strong: "Ready check.", rest: "The lobby's start rule was met. Keep the app open: signing follows by itself." };
    case "in_lobby_not_ready":
      if ((p.reasons || []).indexOf("not_unlocked") >= 0) return { strong: "In a lobby, locked.", rest: LOCKED_SEAT };
      return { strong: "In a lobby, not ready.", rest: "You are not counted until you say you are ready." };
    case "in_lobby_not_counted": return { strong: "In a lobby, not counted yet.", rest: "Fewer members are ready than you asked for. If that stays so, the lobby starts without you or is cancelled." };
    case "in_lobby_waiting":
      return { strong: "In a lobby:", rest: (typeof p.ready === "number" ? u.number(p.ready) + " of " + u.number(p.target) + " ready. Starts at " + u.number(p.target) + ", or at its deadline with " + u.number(p.minimum) + " or more; otherwise cancelled. " : "") + "Then the app signs by itself." };
    case "creation_dead": return { strong: "The start can never be funded.", rest: "The tree you signed can never be used. Nothing was owed." };
    case "creation_abandoned":
      return { strong: "Start abandoned.", rest: "Signatures went out, but the factory was not funded in time. You owe nothing and are owed nothing." + (p.still_watched ? " Gazpacho still watches in case the funding appears." : "") };
    case "refused":
      return { strong: "Did not sign.", rest: (Array.isArray(p.failures) ? failuresText(p.failures) + " " : "") + "Nothing was signed. Nothing moved." };
    case "refused_by_host": return { strong: "The host refused your seat.", rest: "Nothing was signed. Nothing moved." };
    case "lobby_cancelled": return { strong: "Lobby cancelled.", rest: "Not your doing. Nothing was signed. Nothing moved." };
    case "not_chosen": return { strong: "Not chosen.", rest: "The lobby started without you. Not your doing. Nothing was signed. Nothing moved." };
    case "idle_in_factory": return { strong: "In a live factory.", rest: "Nothing to do." };
    case "idle_no_factory": return { strong: "", rest: "Not in a factory. You cannot pay or receive until you are in a live one." };
    default: return { strong: "Unknown state (" + String(c) + ").", rest: "This page does not know what the app is doing. See Activity." };
    }
  }

  gz.words = {
    errorText: errorText, waitText: waitText, failuresText: failuresText, known: known, lookup: lookup,
    conditionNames: conditionNames, conditionUnits: conditionUnits, fitTerms: fitTerms, fitResults: fitResults,
    fitClass: fitClass, refusedWhich: refusedWhich, stages: stages, seats: seats, rounds: rounds, hostRounds: hostRounds, checks: checks,
    funding: funding, factoryStates: factoryStates, chain: chain, watching: watching, dateKinds: dateKinds,
    atZero: atZero, provenance: provenance, attention: attention, tiers: tiers, activityKinds: activityKinds,
    who: who, rules: rules, problems: problems, cannotOpen: cannotOpen, headline: headline, dateText: dateText,
    doing: doing, signing: signing, signingNames: signingNames, SIGNING_SAVED: SIGNING_SAVED, LOCKED_SEAT: LOCKED_SEAT
  };
})();
