/* Gazpacho screens: the factory tree as a picture.
   Draws the member's own path in full and folds the other branches away,
   so the same picture works for 8 members and for 512. */
(function () {
  "use strict";
  var gz = window.gz;
  var h = gz.util.h;
  var SVG = "http://www.w3.org/2000/svg";

  var WIDTH = 320;
  var BOX_W = 56, BOX_H = 30, GAP = 8, ROW = 76, MAX_BOXES = 5;

  function s(tag, attrs, text) {
    var el = document.createElementNS(SVG, tag);
    for (var key in attrs) el.setAttribute(key, attrs[key]);
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function levelCaption(node) {
    var kind = node.kind === "timed"
      ? "replaceable, wait " + gz.util.number(node.delay_blocks) + " blocks"
      : "fixed, no wait";
    return "Level " + node.level + ": " + node.width + " branches (" + kind + ")";
  }

  function diagram(factory) {
    var path = factory.tree.path;
    var height = 50 + path.length * ROW + 78;
    var svg = s("svg", { viewBox: "0 0 " + WIDTH + " " + height, class: "tree", role: "img",
      "aria-label": "The factory tree. Your path runs from the shared output through " + path.length +
        " levels to your leaf. The steps are listed in words below." });

    var rootW = 150;
    svg.appendChild(s("rect", { x: (WIDTH - rootW) / 2, y: 8, width: rootW, height: BOX_H, rx: 7, class: "node on-path" }));
    svg.appendChild(s("text", { x: WIDTH / 2, y: 28, class: "node-text", "text-anchor": "middle" }, "Shared output, on chain"));

    var parentX = WIDTH / 2, parentY = 8 + BOX_H;
    path.forEach(function (node, i) {
      var y = 50 + i * ROW + 22;
      var shown = Math.min(node.width, MAX_BOXES);
      var folded = node.width > MAX_BOXES ? node.width - (MAX_BOXES - 1) : 0;
      var slot = folded ? Math.min(node.index, MAX_BOXES - 2) : node.index;
      var total = shown * BOX_W + (shown - 1) * GAP;
      var x0 = (WIDTH - total) / 2;
      svg.appendChild(s("text", { x: 4, y: y - 8, class: "caption" }, levelCaption(node)));
      var nextX = parentX;
      for (var b = 0; b < shown; b++) {
        var x = x0 + b * (BOX_W + GAP);
        var mine = b === slot;
        var isFold = folded && b === shown - 1;
        svg.insertBefore(s("line", { x1: parentX, y1: parentY, x2: x + BOX_W / 2, y2: y, class: mine ? "edge on-path" : "edge" }), svg.firstChild);
        svg.appendChild(s("rect", { x: x, y: y, width: BOX_W, height: BOX_H, rx: 7,
          class: "node" + (mine ? " on-path" : "") + (isFold ? " folded" : "") }));
        svg.appendChild(s("text", { x: x + BOX_W / 2, y: y + 19, class: "node-text" + (mine ? "" : " quiet"), "text-anchor": "middle" },
          mine ? (i === path.length - 1 ? "Your leaf" : "Yours") : isFold ? "+" + folded + " more" : ""));
        if (mine) nextX = x + BOX_W / 2;
      }
      parentX = nextX;
      parentY = y + BOX_H;
    });

    var leafY = parentY + 30;
    var leafW = 250, leafX = (WIDTH - leafW) / 2;
    svg.insertBefore(s("line", { x1: parentX, y1: parentY, x2: WIDTH / 2, y2: leafY, class: "edge on-path dashed" }), svg.firstChild);
    svg.appendChild(s("text", { x: 4, y: leafY - 8, class: "caption" }, "Inside your leaf"));
    svg.appendChild(s("rect", { x: leafX, y: leafY, width: leafW / 2 - 3, height: 38, rx: 7, class: "node channel" }));
    svg.appendChild(s("text", { x: leafX + leafW / 4, y: leafY + 16, class: "node-text", "text-anchor": "middle" }, "Your channel"));
    svg.appendChild(s("text", { x: leafX + leafW / 4, y: leafY + 30, class: "node-text quiet", "text-anchor": "middle" },
      gz.util.number(factory.channel.capacity_sat)));
    svg.appendChild(s("rect", { x: leafX + leafW / 2 + 3, y: leafY, width: leafW / 2 - 3, height: 38, rx: 7, class: "node spare" }));
    svg.appendChild(s("text", { x: leafX + leafW * 3 / 4, y: leafY + 16, class: "node-text", "text-anchor": "middle" }, "Host's spare"));
    svg.appendChild(s("text", { x: leafX + leafW * 3 / 4, y: leafY + 30, class: "node-text quiet", "text-anchor": "middle" },
      gz.util.number(factory.channel.spare_liquidity_sat)));
    return svg;
  }

  /* The same path in words, for people who cannot see the picture. */
  function inWords(factory) {
    var list = h("ol", { class: "tree-words" });
    list.appendChild(h("li", null, h("b", null, "The shared output."), " One output on the chain holds the whole factory. Spending it needs the signature of the host and all " +
      factory.members + " members."));
    factory.tree.path.forEach(function (node, i) {
      var last = i === factory.tree.path.length - 1;
      var wait = node.kind === "timed"
        ? "This level can be replaced by agreement, so publishing it has a waiting period of " + gz.util.blocks(node.delay_blocks) + "."
        : "This level is fixed, so publishing it has no waiting period.";
      list.appendChild(h("li", null, h("b", null, "Level " + node.level + ". "),
        "A transaction, signed in advance, splits its parent into " + node.width + " branches. Yours is one of them and " +
        (last ? "is your leaf. " : "holds " + gz.util.plural(node.members_below, "member") + ". ") + wait));
    });
    list.appendChild(h("li", null, h("b", null, "Your leaf."), " It holds your Lightning channel and some of the host's spare liquidity, which the host can sell to you as room to receive more."));
    return list;
  }

  gz.tree = { diagram: diagram, inWords: inWords };
})();
