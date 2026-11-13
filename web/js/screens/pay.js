/* Screen: Pay and receive, over Lightning, through your factory channel. */
(function () {
  "use strict";
  var gz = window.gz, h = gz.util.h, ui = gz.ui, u = gz.util, api = window.gzApi;

  var checked = null;      // { text, result } for the invoice being reviewed
  var invoiceId = null;    // the invoice being shown on the receive side

  var REFUSALS = {
    empty: function () { return "Paste an invoice first."; },
    not_an_invoice: function () { return "This is not a Lightning invoice the app can read. Signet invoices start with lntbs."; },
    wrong_network: function () { return "This invoice is for mainnet. This wallet is on a test network and cannot pay it."; },
    no_channel: function () { return "You have no usable channel. Join a factory first."; },
    host_offline: function () { return "The host is not answering, and every payment passes through the host. Try again when it is back."; },
    not_enough_balance: function (d) { return "The amount plus the largest possible fee is more than your balance of " + u.sats(d.balance_sat) + "."; },
    too_close_to_end: function () { return "Your factory is too close to its end for a payment to be safe. Move to the next factory first."; }
  };

  function review(d) {
    if (!d.valid) return ui.notice("danger", "This cannot be paid.", REFUSALS[d.reason](d));
    var rows = ui.facts([
      ["Amount", u.sats(d.amount_sat)],
      ["For", d.description || "No description given"],
      ["Fee", "At most " + u.sats(d.fee_max_sat), "Charged by the host for passing the payment on."],
      ["Deadline", u.blocks(d.deadline_blocks), "Payments normally finish in seconds. If this one gets stuck, it is cancelled at this deadline and the amount returns to you. The deadline is long because it must outlast the time leaving your factory alone would take."],
      ["Balance afterwards", "At least " + u.sats(Math.max(0, d.balance_sat - d.amount_sat - d.fee_max_sat))]
    ]);
    if (!d.can_pay) return h("div", null, rows, ui.notice("danger", "The app will not send this payment.", REFUSALS[d.reason](d)));
    return h("div", null, rows,
      h("div", { class: "actions" },
        ui.button("Pay " + u.sats(d.amount_sat), function (e) {
          ui.run(e.currentTarget, function () {
            return api.payInvoice(checked.text).then(function () { checked = null; gz.app.go("pay"); });
          }, "Payment sent. It appears in the history below.");
        }, { kind: "primary" }),
        ui.button("Do not pay", function () { checked = null; gz.app.go("pay"); })));
  }

  function sendCard() {
    function check(e) {
      var text = ui.value("invoice-text");
      ui.run(e.currentTarget, function () {
        return api.decodeInvoice(text).then(function (result) { checked = { text: text, result: result }; gz.app.redraw(); });
      });
    }
    function example(text) {
      return function () {
        var input = document.getElementById("invoice-text");
        input.value = text;
        input.setAttribute("data-dirty", "1");
        input.focus();
      };
    }
    return ui.card("Send",
      ui.field({ id: "invoice-text", label: "Lightning invoice", type: "textarea", value: checked ? checked.text : "",
        hint: "Paste the invoice from whoever you are paying. Nothing is sent until you have seen the amount, fee and deadline." }),
      h("div", { class: "actions" }, ui.button("Check this invoice", check, { kind: checked ? "" : "primary" })),
      h("div", { class: "actions" },
        ui.button("Fill in an example (prototype only)", example("lntbs2500sat1exampleexampleexampleexampleexample"), { kind: "ghost" }),
        ui.button("Fill in one that is too large (prototype only)", example("lntbs900000sat1largeexampleexampleexampleexample"), { kind: "ghost" })),
      checked ? h("section", { class: "review", "aria-label": "Check before paying" }, h("h3", null, "Check before paying"), review(checked.result)) : null);
  }

  function receiveCard(channel, invoice) {
    var shown = null;
    if (invoice) {
      shown = h("section", { class: "review", "aria-label": "Your invoice" },
        h("h3", null, "Invoice for " + u.sats(invoice.amount_sat)),
        invoice.state === "paid"
          ? ui.notice("ok", "Paid.", u.sats(invoice.amount_sat) + " arrived in your channel.")
          : ui.notice("info", "Waiting to be paid.", h("p", null, "This invoice expires ", ui.countdown(invoice.expires_at, "At zero: it can no longer be paid and you would make a new one."),
            " In the prototype it is paid by itself after a few seconds.")),
        ui.field({ id: "invoice-out", label: "Invoice as text", type: "textarea", value: invoice.invoice, readonly: true, rows: 4 }),
        h("div", { class: "actions" }, ui.copyButton(invoice.invoice, "Invoice"),
          ui.button("Make another", function () { invoiceId = null; gz.app.go("pay"); }, { kind: "small" })),
        ui.qrPlaceholder("this invoice"));
    }
    return ui.card("Receive",
      h("p", { class: "hint" }, "You can receive up to " + u.sats(channel.receivable_sat) + " more in this channel."),
      ui.field({ id: "receive-amount", label: "Amount", type: "number", min: 1, step: 1, unit: "sats", value: "" }),
      ui.field({ id: "receive-description", label: "Description (optional)", value: "", hint: "The payer sees this." }),
      h("div", { class: "actions" },
        ui.button("Create invoice", function (e) {
          ui.run(e.currentTarget, function () {
            return api.createInvoice({ amount_sat: Number(ui.value("receive-amount")), description: ui.value("receive-description") })
              .then(function (inv) { invoiceId = inv.id; gz.app.go("pay"); });
          });
        }, { kind: "primary" }),
        ui.notInPrototype("Buy more receiving room from the host")),
      shown);
  }

  function history(payments) {
    if (!payments.length) {
      return ui.card("Payment history", h("p", null, "No payments yet. Payments you send and receive over Lightning are listed here, newest first."));
    }
    var stateWords = { done: ["Done", "green"], pending: ["On its way", "gold"], failed: ["Failed", "tomato"] };
    var list = h("ul", { class: "rows" });
    payments.forEach(function (p) {
      var failed = p.state === "failed" ? " Not sent: " + (REFUSALS[p.reason] ? "the amount was more than the balance at the time." : "no reason recorded.") : "";
      list.appendChild(h("li", null,
        h("div", { class: "row-main" },
          h("span", null, h("b", null, p.direction === "sent" ? "Sent " : "Received "), ui.amount(p.amount_sat)),
          ui.pill(stateWords[p.state][0], stateWords[p.state][1])),
        h("p", { class: "hint" }, (p.description || "No description") + " · " + u.dateTime(p.at) +
          (p.direction === "sent" && p.state !== "failed" ? " · fee " + u.sats(p.fee_sat) : "") + failed)));
    });
    return ui.card("Payment history", list);
  }

  function render(params, status) {
    return Promise.all([api.listPayments(), invoiceId ? api.getInvoice(invoiceId).catch(function () { return null; }) : null]).then(function (got) {
      var data = got[0], invoice = got[1];
      var channel = data.channel;
      var top;
      if (!channel) {
        checked = null;
        top = ui.empty("You have no channel to pay from",
          "Lightning payments here go through a channel inside a factory. Join a lobby, and when its factory is live you can pay and be paid.",
          [ui.link("Look at the lobbies", "#/lobbies", "btn primary")]);
      } else {
        top = h("div", null,
          !channel.host_online ? ui.notice("danger", "Payments are paused.", "The host is not answering, and every payment passes through the host. Your balance is unaffected.",
            [ui.link("See your choices", "#/factory", "btn small")]) : null,
          h("div", { class: "stats" },
            ui.stat("You can send", ui.amount(channel.balance_sat), "Your channel balance. A little of it is kept back for the fee."),
            ui.stat("You can receive", ui.amount(channel.receivable_sat), "Room left in your channel. To receive more than this you would buy receiving room from the host.")),
          h("div", { class: "two" }, sendCard(), receiveCard(channel, invoice)));
      }
      return h("div", null,
        h("h1", null, "Pay and receive"),
        h("p", { class: "lead" }, "Lightning payments, through the channel in your factory. The host passes each payment on and charges the fee in its terms."),
        top, history(data.payments));
    });
  }

  gz.screens.pay = { title: "Pay and receive", topics: ["payments", "factory"], render: render };
})();
