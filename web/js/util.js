// SPDX-License-Identifier: MIT
/* Gazpacho's interface: small helpers with no knowledge of the wallet.
   Everything hangs off one global, window.gz. Text is always inserted as
   text: there is no HTML sink anywhere in these files (spec/local-api.md 5.4). */
(function () {
  "use strict";
  var gz = window.gz = {};
  gz.screens = {};

  /* "1 lobby", "2 lobbies": n and the right form of a word with an irregular plural. */
  function count(n, one, many) { return number(n) + " " + (n === 1 ? one : many); }

  /* Build an element. attrs: class, text, on<event> handlers, or attributes.
     Children are nodes, strings, arrays, or null. */
  function h(tag, attrs) {
    var el = document.createElement(tag);
    var key, value, i;
    for (key in attrs || {}) {
      value = attrs[key];
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") el.className = value;
      else if (key === "text") el.textContent = value;
      else if (key.slice(0, 2) === "on") el.addEventListener(key.slice(2), value);
      else if (value === true) el.setAttribute(key, "");
      else el.setAttribute(key, String(value));
    }
    for (i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }

  function add(el, child) {
    if (child === null || child === undefined || child === false) return el;
    if (Array.isArray(child)) { child.forEach(function (c) { add(el, c); }); return el; }
    el.appendChild(child.nodeType ? child : document.createTextNode(String(child)));
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function number(n) {
    if (typeof n !== "number" || !isFinite(n)) return "?";
    var s = String(Math.abs(Math.round(n))), out = "";
    while (s.length > 3) { out = "," + s.slice(-3) + out; s = s.slice(0, -3); }
    return (n < 0 ? "-" : "") + s + out;
  }

  function sats(n) { return number(n) + " sats"; }
  function plural(n, word) { return number(n) + " " + word + (n === 1 ? "" : "s"); }

  /* Parts per million as a percentage: 1,000 is "0.1%". */
  function ppm(n) { return String(Math.round(n / 10) / 1000) + "%"; }

  /* Blocks as an approximate time. A block takes about ten minutes. */
  function blocksAsTime(blocks) {
    var minutes = Math.max(0, blocks) * 10;
    if (minutes < 60) return "about " + plural(minutes, "minute");
    if (minutes < 60 * 36) return "about " + plural(Math.round(minutes / 60), "hour");
    return "about " + plural(Math.round(minutes / 1440), "day");
  }

  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function two(n) { return (n < 10 ? "0" : "") + n; }

  function dateTime(unix) {
    if (typeof unix !== "number") return "?";
    var d = new Date(unix * 1000);
    return d.getDate() + " " + MONTHS[d.getMonth()] + " " + d.getFullYear() + ", " + two(d.getHours()) + ":" + two(d.getMinutes());
  }

  /* Text written by someone else ({ text, by }, 5.6): shown as text inside an
     isolating element, never as a link, and never in the app's own voice. */
  function quoted(t) {
    var text = t && typeof t.text === "string" ? t.text : "";
    return h("bdi", { class: "other", "data-by": t && t.by ? String(t.by) : "unknown" }, text);
  }

  function shortHex(s) {
    return typeof s === "string" && s.length > 20 ? s.slice(0, 8) + "…" + s.slice(-8) : String(s);
  }

  /* 128 random bits, base64url: a request id (7.4). */
  function requestId() {
    var b = new Uint8Array(16), s = "", i;
    crypto.getRandomValues(b);
    for (i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /* A uniform integer below n from the browser's random source (no modulo bias). */
  function randomBelow(n) {
    var limit = Math.floor(0x100000000 / n) * n, b = new Uint32Array(1);
    do { crypto.getRandomValues(b); } while (b[0] >= limit);
    return b[0] % n;
  }

  /* Overwrite and empty an array that held secret strings (12.7). JavaScript
     cannot erase a string; this drops every reference this page holds. */
  function wipe(list) {
    var i;
    if (!list) return;
    for (i = 0; i < list.length; i++) list[i] = "";
    list.length = 0;
  }

  gz.util = {
    h: h, count: count, add: add, clear: clear, number: number, sats: sats, plural: plural, ppm: ppm,
    blocksAsTime: blocksAsTime, dateTime: dateTime, quoted: quoted, shortHex: shortHex,
    requestId: requestId, randomBelow: randomBelow, wipe: wipe
  };
})();
