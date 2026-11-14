#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End to end: Python's http.client against gz-api-fake (spec/local-api.md
draft 4). Runs the Slice 1 interface flow as the interface would make it:
first run from the redirect file, create, the words check, finishing setup,
status, finding a host, a lobby with a replayed join, the event stream, a
hosted lobby, signing out and in, locking; and checks the walls of section
5 and the headers of 5.4 on every answer.

    python3 -I tests/api/e2e_fake.py BUILD/gz-api-fake

Standard library only. Exits 1 on the first failure."""
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

PASS = "an end to end test passphrase"
FAILS = []


def check(cond, what):
    if not cond:
        FAILS.append(what)
        print("FAIL", what)


class Client:
    def __init__(self, port):
        self.port = port
        self.session = None
        self.origin = "http://127.0.0.1:%d" % port

    def call(self, method, path, body=None, extra=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or "127.0.0.1:%d" % self.port, "Sec-Fetch-Site": "same-origin",
             "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
        if method not in ("GET", "HEAD") or extra and extra.get("Origin"):
            h["Origin"] = self.origin
        if self.session:
            h["X-Gazpacho-Session"] = self.session
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(extra or {})
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        if data is not None:
            c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        raw = r.read()
        headers = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        walls(method, path, r.status, headers)
        try:
            obj = json.loads(raw) if raw else None
        except ValueError:
            obj = raw
        return r.status, obj, headers


def walls(method, path, status, h):
    """5.4: every answer, errors included."""
    tag = "%s %s %d" % (method, path, status)
    check(h.get("cross-origin-resource-policy") == "same-origin", tag + ": CORP")
    check(h.get("x-content-type-options") == "nosniff", tag + ": nosniff")
    check(h.get("referrer-policy") == "same-origin", tag + ": Referrer-Policy")
    check("content-security-policy" in h, tag + ": CSP")
    check(h.get("cache-control") == "no-store", tag + ": no-store")
    check(not any(k.startswith("access-control-") for k in h), tag + ": no CORS")
    check("set-cookie" not in h, tag + ": no cookie")


def main():
    exe = os.path.abspath(sys.argv[1])
    tmp = tempfile.mkdtemp(prefix="gze2e-")
    data = os.path.join(tmp, "data")
    os.mkdir(data, 0o700)
    env = dict(os.environ, XDG_RUNTIME_DIR=tmp)
    proc = subprocess.Popen([exe, "--data-dir", data, "--port", "0", "--no-ipv6", "--quiet"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
    try:
        first = proc.stdout.readline()
        m = re.search(r"listening http://127\.0\.0\.1:(\d+)/", first)
        check(m is not None, "gz-api-fake prints its address first")
        if not m:
            return 1
        port = int(m.group(1))
        run(port, data, tmp, proc)
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
    check(proc.returncode == 0, "gz-api-fake stops cleanly on SIGTERM")
    check(not os.path.exists(os.path.join(data, "first-run.html")), "redirect file gone at stop (4.3)")
    check(not os.path.exists(os.path.join(data, "interface.sock")), "socket gone at stop")
    toks = [p for p in os.listdir(tmp) if p.startswith("gazpacho-")]
    check(all(not os.path.exists(os.path.join(tmp, p, "socket.token")) for p in toks),
          "socket token deleted at stop (storage 12.2)")
    shutil.rmtree(tmp, ignore_errors=True)
    if FAILS:
        print("RESULT: FAIL (%d)" % len(FAILS))
        return 1
    print("RESULT: PASS")
    return 0


def run(port, data, tmp, proc):
    c = Client(port)
    # the walls first
    s, b, _ = c.call("GET", "/api/v1/version", host="rebind.attacker.example:%d" % port)
    check(s == 421, "rebinding Host refused")
    s, b, _ = c.call("POST", "/api/v1/session", {"passphrase": "x" * 20}, {"Origin": "http://127.0.0.1:8080"})
    check(s == 403 and b["code"] == "forbidden_origin", "other-port Origin refused")
    s, b, h = c.call("GET", "/", extra={"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
                                         "Sec-Fetch-Dest": "document"})
    check(s == 200 and "frame-ancestors 'none'" in h.get("content-security-policy", ""), "the page and its CSP")
    check(h.get("x-frame-options") == "DENY", "X-Frame-Options")
    s, b, _ = c.call("GET", "/api/v1/version")
    check(s == 200 and b["api"] == "1.0" and b["network"] == "signet" and len(b["run_id"]) == 8, "version (6)")

    # first run: the token is in the redirect file only (4.3)
    path = os.path.join(data, "first-run.html")
    st = os.stat(path)
    check(st.st_mode & 0o777 == 0o600, "redirect file 0600")
    page = open(path).read()
    tok = re.search(r"#start=([A-Za-z0-9_-]{43})\"", page).group(1)
    check(("#start=" + tok) in page and "<script" not in page, "redirect file holds the fragment, no script")
    s, b, _ = c.call("GET", "/api/v1/session")
    check(s == 200 and b["wallet"] == "none" and b["signed_in"] is False, "session: no wallet")
    s, b, _ = c.call("POST", "/api/v1/session/start", {"start_token": tok})
    check(s == 200 and b["kind"] == "setup", "start token gives a setup session")
    c.session = b["session"]
    check(not os.path.exists(path), "redirect file deleted at first presentation")
    s, b, _ = c.call("POST", "/api/v1/session/start", {"start_token": tok})
    check(s == 409 and b["code"] == "token_used", "second presentation: token_used")
    s, b, _ = c.call("GET", "/api/v1/wallet/setup")
    check(s == 200 and b["state"] == "none" and b["words"] == 24, "setup state")
    s, b, _ = c.call("GET", "/api/v1/conditions")
    check(s == 403 and b["code"] == "not_setup_call", "setup session: first-run calls only")
    s, b, h = c.call("POST", "/api/v1/wallet/create",
                     {"confirm": "create_wallet", "passphrase": PASS, "confirm_passphrase": PASS})
    check(s == 200 and len(b["words"]) == 24 and b["shown_until"] == "this_answer", "create gives the words once")
    words = b["words"]

    # the words check (12.3)
    s, b, _ = c.call("POST", "/api/v1/wallet/phrase/check-start", {})
    check(s == 200 and len(b["positions"]) == 3, "check-start: positions only")
    s, b, _ = c.call("POST", "/api/v1/wallet/phrase/check",
                     {"check_id": b["check_id"], "passphrase": PASS, "words": [words[p - 1] for p in b["positions"]]})
    check(s == 200 and b["ok"] is True, "words check ok")
    s, b, _ = c.call("POST", "/api/v1/wallet/finish-setup", {"preset": "everyday", "find": "browse"})
    check(s == 200 and b["state"] == "ready", "finish-setup")

    # status (11)
    s, b, _ = c.call("GET", "/api/v1/status")
    check(s == 200 and b["wallet"] == "ready" and b["network"]["id"] == "signet", "status: ready")
    for k in ("version", "pause", "lock", "interface", "doing", "connection", "watching", "next_date",
              "auto_join", "hosting", "money", "attention", "while_closed"):
        check(k in b, "status has " + k)
    check(b["money"]["chain_view"] == "trusted" and b["doing"]["code"] == "awaiting_funding", "status tables")
    check(b["interface"]["peer_check"] == "same_user_only", "the same-user check runs on Linux")

    # finding the host (21) and lobbies (14)
    key = "02c7e1b2a4d6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"
    s, b, _ = c.call("POST", "/api/v1/discovery/query", {"host": key + "@tomato.example:9735"})
    check(s == 202 and b["state"] == "asking", "discovery query answers at once")
    s, b, _ = c.call("GET", "/api/v1/discovery/queries/" + b["query_id"])
    check(s == 200 and "lob_7k2q" in b["lobbies"], "query answered")
    s, b, _ = c.call("GET", "/api/v1/lobbies?show=all&limit=50")
    check(s == 200 and len(b["items"]) == 2 and b["next_cursor"] is None, "lobby list")
    s, lob, _ = c.call("GET", "/api/v1/lobbies/lob_7k2q")
    check(s == 200 and lob["fit"]["class"] == "fits", "lobby object")
    alias = lob["terms"]["host"]["alias"]
    check(alias["by"] == "host" and alias["checked"] is False and "‮" not in alias["text"]
          and "​" not in alias["text"], "host text: format characters dropped (5.6)")
    s, b, _ = c.call("GET", "/api/v1/lobbies/lob_b19d")
    check(b["fit"]["class"] == "does_not_fit", "the other lobby does not fit")

    # the event stream (10), read with a plain GET as fetch() would
    events = []

    def reader():
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/v1/events", headers={"X-Gazpacho-Session": c.session,
                                                      "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty"})
        r = conn.getresponse()
        events.append(("status", r.status, r.getheader("Content-Type")))
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                chunk = r.read1(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            events.append(("data", chunk.decode()))
            if b'"topic":"session"' in chunk:
                break
        conn.close()

    t = threading.Thread(target=reader)
    t.start()
    time.sleep(0.5)

    digest = lob["terms"]["current"]["digest"]
    join = {"request_id": "e2e_join_request_00001", "seen_current_digest": digest}
    s, b, _ = c.call("POST", "/api/v1/lobbies/lob_7k2q/join", join)
    check(s == 202 and b["you"]["seat"] == "joining", "join: 202 joining")
    s, b, _ = c.call("POST", "/api/v1/lobbies/lob_7k2q/join", join)
    check(s == 202 and b.get("replayed") is True, "join replayed by request_id (7.4)")
    s, b, _ = c.call("POST", "/api/v1/lobbies/lob_7k2q/join", dict(join, ready=True))
    check(s == 409 and b["code"] == "request_id_reused", "same id, other body: request_id_reused")
    s, b, _ = c.call("PUT", "/api/v1/lobbies/lob_7k2q/ready",
                     {"request_id": "e2e_ready_request_0001", "ready": True, "seen_current_digest": digest})
    check(s == 202 and b["you"]["seat"] == "ready", "ready")
    s, b, _ = c.call("POST", "/api/v1/lobbies/lob_b19d/join",
                     {"request_id": "e2e_join_request_00002", "seen_current_digest": "d" * 64})
    check(s == 409 and b["code"] in ("conditions_not_met", "already_in_lobby"), "one lobby at a time, or a refusal")

    # hosting (15): preview, open with the passphrase in the request and the echo
    draft = {"name": "End to end", "profile": "standard", "target": 50, "minimum": 30,
             "deadline_at": int(time.time()) + 86400, "on_shortfall": "cancel", "channel_sat": 500000,
             "joining_fee_sat": {"now": 1000, "min": 500, "max": 1500}}
    s, p, _ = c.call("POST", "/api/v1/host/preview", draft)
    check(s == 200 and p["can_open"] is True and p["funding_at_target_sat"] == 37500000, "host preview")
    s, b, _ = c.call("POST", "/api/v1/host/lobbies",
                     {"request_id": "e2e_open_request_00001", "draft": draft, "draft_digest": p["draft_digest"],
                      "confirm_funding_sat": p["funding_at_target_sat"], "passphrase": PASS})
    check(s == 201 and b["id"] == "lob_4c08" and b["funding"]["set_aside_sat"] == 37500000, "host lobby opened (kind A)")
    s, b, _ = c.call("POST", "/api/v1/host/lobbies/lob_4c08/cancel", {"request_id": "e2e_cancel_request_001"})
    check(s == 202 and b["stage"] == "cancelled", "host lobby cancelled")

    for path in ("/api/v1/factories", "/api/v1/factories/fac_2d91", "/api/v1/factories/fac_2d91/dates",
                 "/api/v1/wallet", "/api/v1/activity", "/api/v1/activity/act_1182", "/api/v1/backup",
                 "/api/v1/settings/connections", "/api/v1/conditions", "/api/v1/host/lobbies"):
        s, b, _ = c.call("GET", path)
        check(s == 200 and isinstance(b, dict), "GET " + path)
    s, b, _ = c.call("POST", "/api/v1/wallet/address", {})
    check(s == 200 and b["address"].startswith("tb1p"), "new address")
    s, b, _ = c.call("POST", "/api/v1/receiving-room/quote", {})
    check(s == 501 and b["params"]["release"] == "1.1.0", "reserved call 501")

    # sign out: the stream ends with a session event; the wallet stays unlocked
    s, b, h = c.call("DELETE", "/api/v1/session")
    check(s == 204 and "clear-site-data" in h, "sign out: 204 and Clear-Site-Data")
    t.join(10)
    text = "".join(e[1] for e in events if e[0] == "data")
    check(events and events[0][1] == 200 and events[0][2] == "text/event-stream", "stream opened")
    check('"topic":"lobby","id":"lob_7k2q"' in text, "a lobby event arrived")
    check('"topic":"session"' in text, "the session event closed the stream")
    check(digest not in text and tok not in text, "events carry no content and no secret")
    c.session = None
    s, b, _ = c.call("GET", "/api/v1/session")
    check(b["wallet"] == "unlocked" and b["signed_in"] is False, "signed out, still unlocked (4.7)")
    s, b, _ = c.call("POST", "/api/v1/session", {"passphrase": PASS})
    check(s == 200 and b["kind"] == "normal" and len(b["session"]) == 43, "sign in again")
    c.session = b["session"]

    # lock: something to watch, so the fresh sign-in and confirm_locked (4.7)
    s, b, _ = c.call("POST", "/api/v1/wallet/lock", {"confirm": "lock_wallet", "confirm_locked": "nobody_watching"})
    check(s == 202 and b["wallet"] == "locked", "lock")
    s, b, _ = c.call("GET", "/api/v1/lobbies")
    check(s == 423 and b["code"] == "wallet_locked", "locked: 423")
    c.session = None
    s, b, _ = c.call("GET", "/api/v1/status")
    check(s == 200 and b["wallet"] == "locked" and b["watching"]["state"] == "nobody_locked"
          and b["watching"]["reason"] == "no_bundle" and b["watching"]["headline"]["code"] == "nothing_needs_you",
          "the Slice 1 locked status (23.2 item 41)")
    blob = json.dumps(b)
    check("lob_" not in blob and "fac_" not in blob and "_sat" not in blob and key not in blob,
          "the locked status holds no ids, amounts or keys")


if __name__ == "__main__":
    sys.exit(main())
