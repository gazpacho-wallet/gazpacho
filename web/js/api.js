// SPDX-License-Identifier: MIT
/* The one place that talks to the program (spec/local-api.md).
   - Every request is a same-origin fetch() in its default mode, with a relative
     address: nothing here names a host, so nothing can leave the local API.
   - The session token lives in sessionStorage and in this closure, and travels
     only in the X-Gazpacho-Session header: never a cookie, a URL, localStorage
     or the page (4.4).
   - The event stream is read with fetch(), not EventSource (10.1).
   - A request refreshes the idle timer (X-Gazpacho-User) only when the person
     touched the page in the last two seconds, and never when it was made
     because an event arrived (4.7). */
(function () {
  "use strict";
  var gz = window.gz;
  var KEY = "gz-session";
  var token = null;
  var lastInput = 0;
  var listeners = [];
  var channel = null;
  var pendingAsk = null;
  var tabId = gz.util.requestId();
  var stream = { state: "stopped", ctrl: null, lastId: null, delay: 2000, timer: null, heard: 0 };
  var api = { version: null, session: null };

  function ApiError(status, body) {
    this.status = status;
    this.code = body && typeof body.code === "string" ? body.code : (status ? "http_" + status : "unreachable");
    this.params = body && body.params && typeof body.params === "object" ? body.params : {};
    this.field = body && typeof body.field === "string" ? body.field : null;
  }

  ["pointerdown", "keydown"].forEach(function (name) {
    document.addEventListener(name, function () { lastInput = Date.now(); }, true);
  });

  function setToken(t) {
    token = t || null;
    try {
      if (token) sessionStorage.setItem(KEY, token);
      else sessionStorage.removeItem(KEY);
    } catch (e) { /* storage refused: the token stays in memory for this page only */ }
  }

  function say(message) {
    if (channel) { try { channel.postMessage(message); } catch (e) { /* closed */ } }
  }

  /* The session ended here (sign-out, idle, lock, a session event, a 401). */
  function signedOut(reason, quiet) {
    var had = !!token;
    setToken(null);
    stopEvents();
    if (had && !quiet) say({ type: "signed_out" });
    if (had && gz.app) gz.app.signedOut(reason);
  }

  function call(method, path, body, opts) {
    opts = opts || {};
    var headers = {};
    var sent = token;
    if (body !== undefined && body !== null) headers["Content-Type"] = "application/json";
    if (sent && !opts.noSession) headers["X-Gazpacho-Session"] = sent;
    if (!opts.background && Date.now() - lastInput < 2000) headers["X-Gazpacho-User"] = "1";
    return fetch("/api/v1" + path, {
      method: method,
      headers: headers,
      body: body === undefined || body === null ? undefined : JSON.stringify(body),
      cache: "no-store"
    }).then(function (res) {
      if (res.status === 204) return null;
      return res.json().catch(function () { return null; }).then(function (j) {
        var e;
        if (res.ok) return j;
        e = new ApiError(res.status, j);
        if (!opts.keepSession && sent && sent === token) {
          if (e.code === "not_signed_in") signedOut("signed_out");
          else if (e.code === "wallet_locked") signedOut("locked");
        }
        throw e;
      });
    }, function () {
      throw new ApiError(0, null);
    });
  }

  /* A call that may need a fresh sign-in (4.8, kind B): when the program asks
     for one, the passphrase is asked for and the same request is sent again. */
  function act(method, path, body, opts) {
    return call(method, path, body, opts).catch(function (e) {
      if (e.code !== "fresh_sign_in_needed") throw e;
      return gz.ui.askPassphrase({
        title: "Type your passphrase again",
        why: (opts && opts.why) || "This changes what Gazpacho does for you, so it asks for your passphrase again.",
        run: function (pass) { return call("POST", "/session/fresh", { passphrase: pass }); }
      }).then(function () { return call(method, path, body, opts); });
    });
  }

  /* ---- session ---- */
  function load() {
    try { token = sessionStorage.getItem(KEY) || null; } catch (e) { token = null; }
  }

  function refreshSession() {
    return call("GET", "/session", null, { background: true, keepSession: true }).catch(function (e) {
      if (e.code !== "not_signed_in") throw e;
      setToken(null);
      return call("GET", "/session", null, { background: true });
    }).then(function (s) {
      if (!s.signed_in && token) setToken(null);
      api.session = s;
      return s;
    });
  }

  function boot() {
    load();
    openChannel();
    return call("GET", "/version", null, { noSession: true, background: true }).then(function (v) {
      api.version = v;
      return refreshSession();
    });
  }

  function adopt(session) {
    setToken(session);
    return refreshSession();
  }

  function signIn(passphrase) {
    return call("POST", "/session", { passphrase: passphrase.normalize("NFC") }, { noSession: true }).then(function (r) {
      setToken(r.session);
      api.session = r;
      return r;
    });
  }

  function start(body) {
    return call("POST", "/session/start", body, { noSession: true }).then(function (r) {
      setToken(r.session);
      return refreshSession();
    });
  }

  function signOut() {
    return call("DELETE", "/session", null, { keepSession: true }).catch(function () { return null; }).then(function () {
      signedOut("you");
    });
  }

  /* ---- other tabs (4.4): hand-over of a normal session, and "signed out" ---- */
  function openChannel() {
    if (channel || !("BroadcastChannel" in window)) return;
    channel = new BroadcastChannel("gazpacho-session-" + location.port);
    channel.onmessage = function (e) {
      var m = e.data;
      if (!m || typeof m.type !== "string") return;
      if (m.type === "ask") {
        if (token && api.session && api.session.signed_in && api.session.kind === "normal" && api.session.handover &&
            typeof m.nonce === "string") {
          say({ type: "offer", nonce: m.nonce, session: token });
        }
      } else if (m.type === "offer") {
        if (pendingAsk && m.nonce === pendingAsk.nonce && typeof m.session === "string") pendingAsk.done(m.session);
      } else if (m.type === "signed_out") {
        signedOut("signed_out", true);
      } else if (m.type === "event") {
        if (stream.state === "too_many" && typeof m.topic === "string") deliver({ topic: m.topic, id: m.id || null, seq: m.seq });
      } else if (m.type === "leader_gone") {
        if (stream.state === "too_many") startEvents();
      }
    };
    window.addEventListener("pagehide", function () {
      if (stream.state === "open") say({ type: "leader_gone", tab: tabId });
    });
  }

  /* Ask the other tabs for a session; null after 500 ms without an offer. */
  function askOtherTabs() {
    var b = new Uint8Array(16), nonce = "", i;
    if (!channel) return Promise.resolve(null);
    crypto.getRandomValues(b);
    for (i = 0; i < b.length; i++) nonce += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return new Promise(function (resolve) {
      var timer = setTimeout(function () { pendingAsk = null; resolve(null); }, 500);
      pendingAsk = { nonce: nonce, done: function (session) { clearTimeout(timer); pendingAsk = null; resolve(session); } };
      say({ type: "ask", nonce: nonce });
    });
  }

  /* ---- the event stream (10) ---- */
  function setStream(state) {
    stream.state = state;
    listeners.forEach(function (fn) { fn({ topic: "stream_state", state: state }); });
  }

  function deliver(ev) {
    if (ev.topic === "session") { signedOut("ended"); return; }
    listeners.forEach(function (fn) { fn(ev); });
  }

  function block(text) {
    var id = null, name = "message", data = "", lines = text.split("\n"), i, line, ev;
    stream.heard = Date.now();
    for (i = 0; i < lines.length; i++) {
      line = lines[i];
      if (line.slice(0, 3) === "id:") id = line.slice(3).trim();
      else if (line.slice(0, 6) === "event:") name = line.slice(6).trim();
      else if (line.slice(0, 5) === "data:") data += line.slice(5).trim();
    }
    if (name !== "change" || !data) return;
    try { ev = JSON.parse(data); } catch (e) { return; }
    if (!ev || typeof ev.topic !== "string") return;
    if (id) stream.lastId = id;
    say({ type: "event", topic: ev.topic, id: ev.id || null, seq: ev.seq });
    deliver({ topic: ev.topic, id: ev.id || null, seq: ev.seq });
  }

  function retry() {
    if (!token) { setStream("stopped"); return; }
    setStream("reconnecting");
    clearTimeout(stream.timer);
    stream.timer = setTimeout(startEvents, stream.delay);
    stream.delay = Math.min(stream.delay * 2, 60000);
  }

  function startEvents() {
    var ctrl, headers;
    if (!token || stream.ctrl) return;
    ctrl = new AbortController();
    stream.ctrl = ctrl;
    headers = { "X-Gazpacho-Session": token };
    if (stream.lastId) headers["Last-Event-ID"] = stream.lastId;
    fetch("/api/v1/events", { headers: headers, signal: ctrl.signal, cache: "no-store" }).then(function (res) {
      var reader, decoder, buf = "";
      if (res.status !== 200) {
        stream.ctrl = null;
        if (res.status === 429) { setStream("too_many"); return null; }       /* never retried by itself (10.3) */
        if (res.status === 401) { signedOut("signed_out"); return null; }
        if (res.status === 423) { signedOut("locked"); return null; }
        if (res.status >= 400 && res.status < 500) { setStream("stopped"); return null; }
        retry();
        return null;
      }
      stream.delay = 2000;
      stream.heard = Date.now();
      setStream("open");
      say({ type: "leader", tab: tabId });
      reader = res.body.getReader();
      decoder = new TextDecoder();
      function pump() {
        return reader.read().then(function (r) {
          var i;
          if (r.done) {
            if (stream.ctrl === ctrl) { stream.ctrl = null; retry(); }
            return null;
          }
          buf = (buf + decoder.decode(r.value, { stream: true })).replace(/\r\n/g, "\n");
          while ((i = buf.indexOf("\n\n")) >= 0) {
            block(buf.slice(0, i));
            buf = buf.slice(i + 2);
          }
          return pump();
        });
      }
      return pump();
    }).catch(function () {
      if (stream.ctrl === ctrl) { stream.ctrl = null; retry(); }
    });
  }

  function stopEvents() {
    var ctrl = stream.ctrl;
    clearTimeout(stream.timer);
    stream.ctrl = null;
    stream.lastId = null;
    stream.delay = 2000;
    if (ctrl) ctrl.abort();
    if (stream.state !== "stopped") setStream("stopped");
  }

  /* A stream that has gone quiet (no event and no keep-alive for 40 s) is opened again. */
  setInterval(function () {
    var ctrl = stream.ctrl;
    if (stream.state === "open" && ctrl && Date.now() - stream.heard > 40000) {
      stream.ctrl = null;
      ctrl.abort();
      retry();
    }
  }, 10000);

  api.ApiError = ApiError;
  api.boot = boot;
  api.call = call;
  api.act = act;
  api.get = function (path, opts) { return call("GET", path, null, opts); };
  api.refreshSession = refreshSession;
  api.adopt = adopt;
  api.signIn = signIn;
  api.start = start;
  api.signOut = signOut;
  api.askOtherTabs = askOtherTabs;
  api.hasToken = function () { return !!token; };
  api.onEvent = function (fn) { listeners.push(fn); };
  api.startEvents = startEvents;
  api.stopEvents = stopEvents;
  api.streamState = function () { return stream.state; };
  api.dropSession = function (reason) { signedOut(reason); };
  gz.api = api;
})();
