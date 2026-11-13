/* Gazpacho screens: small helpers with no knowledge of the wallet.
   Everything hangs off one global, window.gz. */
(function () {
  "use strict";
  var gz = window.gz = window.gz || {};
  gz.screens = {};

  var MINUTES_PER_BLOCK = 10;

  /* Build a DOM element. Text is always inserted as text, never as HTML,
     because names and descriptions come from other people. */
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var key;
    for (key in attrs || {}) {
      var value = attrs[key];
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.className = value;
      else if (key === "text") el.textContent = value;
      else if (key.slice(0, 2) === "on") el.addEventListener(key.slice(2), value);
      else if (value === true) el.setAttribute(key, "");
      else el.setAttribute(key, value);
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(el, c); }); return; }
    el.appendChild(child.nodeType ? child : document.createTextNode(String(child)));
  }

  function number(n) {
    var s = String(Math.abs(Math.round(n)));
    var out = "";
    while (s.length > 3) { out = "," + s.slice(-3) + out; s = s.slice(0, -3); }
    return (n < 0 ? "-" : "") + s + out;
  }

  function sats(n) { return number(n) + " sats"; }

  /* Parts per million shown as a percentage: 1,000 becomes "0.1%". */
  function ppm(n) {
    var pct = n / 10000;
    return String(Math.round(pct * 1000) / 1000) + "%";
  }

  function plural(n, word) { return number(n) + " " + word + (n === 1 ? "" : "s"); }

  /* A length of time in words, to the two largest units. */
  function duration(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    var d = Math.floor(seconds / 86400);
    var hr = Math.floor((seconds % 86400) / 3600);
    var min = Math.floor((seconds % 3600) / 60);
    var sec = seconds % 60;
    if (d > 0) return d + " d " + hr + " h";
    if (hr > 0) return hr + " h " + min + " min";
    if (min > 0) return min + " min " + sec + " s";
    return sec + " s";
  }

  /* Blocks as an approximate human time. A block takes about ten minutes. */
  function blocksAsTime(blocks) {
    var minutes = Math.max(0, blocks) * MINUTES_PER_BLOCK;
    if (minutes < 60) return "about " + plural(minutes, "minute");
    if (minutes < 60 * 36) return "about " + plural(Math.round(minutes / 60), "hour");
    return "about " + plural(Math.round(minutes / 1440), "day");
  }

  function blocks(n) { return plural(n, "block") + " (" + blocksAsTime(n) + ")"; }

  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function two(n) { return (n < 10 ? "0" : "") + n; }

  function dateTime(unix) {
    var d = new Date(unix * 1000);
    return d.getDate() + " " + MONTHS[d.getMonth()] + " " + d.getFullYear() + ", " + two(d.getHours()) + ":" + two(d.getMinutes());
  }

  /* The approximate calendar date of a future block. */
  function dateOfBlock(blocksLeft) {
    var d = new Date(Date.now() + blocksLeft * MINUTES_PER_BLOCK * 60000);
    return d.getDate() + " " + MONTHS[d.getMonth()] + " " + d.getFullYear();
  }

  function ago(unix) {
    var seconds = Math.floor(Date.now() / 1000) - unix;
    if (seconds < 60) return "just now";
    return duration(seconds).replace(/ \d+ s$/, "") + " ago";
  }

  function shortId(id) {
    return id && id.length > 20 ? id.slice(0, 8) + "…" + id.slice(-8) : id;
  }

  gz.util = {
    h: h, number: number, sats: sats, ppm: ppm, plural: plural, duration: duration,
    blocksAsTime: blocksAsTime, blocks: blocks, dateTime: dateTime, dateOfBlock: dateOfBlock,
    ago: ago, shortId: shortId
  };
})();
