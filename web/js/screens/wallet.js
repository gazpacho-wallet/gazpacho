/* Screen: Wallet (on chain). Ordinary coins outside any factory. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var KIND_WORDS = {
    received: "Received", sent: "Sent", factory_funding: "Funded a factory", factory_exit: "Returned from a factory"
  };

  function transactions(wallet) {
    if (!wallet.transactions.length) {
      return ui.card("Recent transactions",
        h("p", null, "No transactions yet. To try the app you need signet test coins, which signet faucets give away. Send them to the address above."));
    }
    var list = h("ul", { class: "rows" });
    wallet.transactions.forEach(function (tx) {
      var unsure = wallet.chain_state !== "ok" && tx.confirmations < 6;
      var state = tx.confirmations === 0 ? ui.pill("Not confirmed", "gold")
        : unsure ? ui.pill("Treated as not confirmed", "tomato")
        : ui.pill(u.plural(tx.confirmations, "confirmation"), "green");
      list.appendChild(h("li", null,
        h("div", { class: "row-main" },
          h("span", null, h("b", null, (KIND_WORDS[tx.kind] || tx.kind) + " "), ui.amount(Math.abs(tx.amount_sat))), state),
        h("p", { class: "hint" }, (tx.note ? tx.note + " · " : "") + u.dateTime(tx.at) + " · ", h("code", { title: tx.txid }, u.shortId(tx.txid)))));
    });
    return ui.card("Recent transactions", list);
  }

  function render(params, status) {
    return api.getWallet().then(function (wallet) {
      var belowReserve = wallet.confirmed_sat < wallet.reserve_recommended_sat;
      return h("div", null,
        h("h1", null, "Wallet (on chain)"),
        h("p", { class: "lead" }, "Ordinary on-chain coins held by this wallet, outside any factory. These are " + ui.NETWORK_WORDS[status.network] + " test coins with no value."),
        wallet.chain_state === "disagree" ? ui.notice("danger", "The chain servers disagree about the latest block.",
          "Until they agree, the app treats recent transactions as not confirmed, so the balance below may be behind.", [ui.link("See the servers", "#/settings", "btn small")]) : null,
        h("div", { class: "stats" },
          ui.stat("Confirmed", ui.amount(wallet.confirmed_sat), "Coins in transactions that are in a block, checked against the block headers the app verifies itself."),
          ui.stat("Not yet confirmed", ui.amount(wallet.unconfirmed_sat), "Coins on their way in transactions that are not in a block yet. They cannot be relied on until they confirm.")),
        ui.notice(belowReserve ? "warn" : "info", "Why keep a small reserve here",
          h("div", null,
            h("p", null, "If you ever have to leave a factory alone, the fees for that are already provided from the host's side. When the chain is busy those fees can be too low, and the app then adds to them from this wallet so your transactions confirm in time."),
            h("p", null, "A reserve of about " + u.sats(wallet.reserve_recommended_sat) + " is recommended, not required. " +
              (belowReserve ? "You hold less than that now." : "You hold more than that now.")))),
        ui.card("Receive",
          ui.field({ id: "receive-address", label: "Your address", value: wallet.address, readonly: true,
            hint: "A placeholder, not a real address. The real app shows a fresh address here." }),
          h("div", { class: "actions" }, ui.copyButton(wallet.address, "Address"),
            ui.button("New address", function (e) { ui.run(e.currentTarget, function () { return api.newAddress(); }, "A new address is shown."); }, { kind: "small" })),
          ui.qrPlaceholder("this address")),
        ui.card("Send", h("p", null, "Sending on-chain coins to another address."), h("div", { class: "actions" }, ui.notInPrototype("Send on chain"))),
        transactions(wallet));
    });
  }

  gz.screens.wallet = { title: "Wallet (on chain)", topics: ["wallet", "chain"], render: render };
})();
