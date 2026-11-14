// SPDX-License-Identifier: MIT
// Browser behaviour of spec/local-api.md (23.2 and 23.6) against gz-api-fake.
// TEST ONLY: the fake backend is not a wallet. Set GZ_API_FAKE to the built
// gz-api-fake. A second server on another loopback port plays the "other
// local web application" of 5.7 (review F1).
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const FAKE = process.env.GZ_API_FAKE;
const PASS = 'fake test passphrase, not a wallet'; // the fake's fixture (fake_backend.h)

function startFake(locked, freshAttempts) {
  const dir = mkdtempSync(join(tmpdir(), 'gzpw-'));
  const args = ['--data-dir', join(dir, 'd'), '--port', '0', '--no-ipv6', '--quiet'];
  if (locked) args.push('--locked');
  // TEST ONLY: a clean attempts file, so the sign-in path really runs (review F4)
  if (freshAttempts) args.push('--fresh-attempts');
  const proc = spawn(FAKE, args, { env: { ...process.env, XDG_RUNTIME_DIR: dir } });
  return new Promise((resolve, reject) => {
    let out = '';
    proc.stdout.on('data', (b) => {
      out += b;
      const m = out.match(/listening http:\/\/127\.0\.0\.1:(\d+)\//);
      if (m) resolve({ proc, dir, port: Number(m[1]) });
    });
    proc.on('exit', (c) => reject(new Error('gz-api-fake exited ' + c)));
  });
}

function stopFake(f) {
  f.proc.kill('SIGTERM');
  rmSync(f.dir, { recursive: true, force: true });
}

// The other loopback application: serves plain pages and records what it receives.
function startOther() {
  const seen = [];
  const srv = createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers });
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><title>other</title><p>other local app</p>');
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ srv, seen, port: srv.address().port })));
}

test.describe('the walls of section 5 in a real browser', () => {
  let fake;
  let other;
  test.beforeAll(async () => {
    test.skip(!FAKE, 'GZ_API_FAKE is not set');
    fake = await startFake(true, true);
    other = await startOther();
  });
  test.afterAll(async () => {
    if (fake) stopFake(fake);
    if (other) other.srv.close();
  });

  test('T1: sessionStorage is per origin, port included', async ({ browser }) => {
    const ctx = await browser.newContext();
    const a = await ctx.newPage();
    await a.goto(`http://127.0.0.1:${fake.port}/`);
    await a.evaluate(() => sessionStorage.setItem('k', 'gazpacho'));
    const b = await ctx.newPage();
    await b.goto(`http://localhost:${fake.port}/`);
    expect(await b.evaluate(() => sessionStorage.getItem('k'))).toBeNull();
    const c = await ctx.newPage();
    await c.goto(`http://127.0.0.1:${other.port}/`);
    expect(await c.evaluate(() => sessionStorage.getItem('k'))).toBeNull();
    await ctx.close();
  });

  test('T2: a BroadcastChannel does not cross ports', async ({ browser }) => {
    const ctx = await browser.newContext();
    const a = await ctx.newPage();
    await a.goto(`http://127.0.0.1:${fake.port}/`);
    await a.evaluate(() => {
      window.got = [];
      new BroadcastChannel('gazpacho-session-' + location.port).onmessage = (e) => window.got.push(e.data);
    });
    const c = await ctx.newPage();
    await c.goto(`http://127.0.0.1:${other.port}/`);
    await c.evaluate((p) => new BroadcastChannel('gazpacho-session-' + p).postMessage({ type: 'ask', nonce: '00' }), fake.port);
    await a.waitForTimeout(500);
    expect(await a.evaluate(() => window.got.length)).toBe(0);
    await ctx.close();
  });

  test('items 3, 4, 12: another port cannot call the API, even with the header', async ({ page }) => {
    await page.goto(`http://127.0.0.1:${other.port}/`);
    const r = await page.evaluate(async (p) => {
      const out = {};
      try {
        await fetch(`http://127.0.0.1:${p}/api/v1/lobbies`, { headers: { 'X-Gazpacho-Session': 'x'.repeat(43) } });
        out.withHeader = 'answered';
      } catch (e) {
        out.withHeader = 'failed';
      }
      try {
        const res = await fetch(`http://127.0.0.1:${p}/api/v1/session`, {
          method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' },
          body: '{"passphrase":"guess guess guess"}',
        });
        out.noCors = res.type;
      } catch (e) {
        out.noCors = 'failed';
      }
      try {
        await fetch(`http://127.0.0.1:${p}/api/v1/version`);
        out.read = 'readable';
      } catch (e) {
        out.read = 'failed';
      }
      return out;
    }, fake.port);
    expect(r.withHeader).toBe('failed'); // the preflight answers 405 without CORS
    // The program refuses it (403/415), and Cross-Origin-Resource-Policy:
    // same-origin (5.4) makes the browser turn even that answer into a
    // network error: the page sees nothing, not even an opaque response.
    expect(r.noCors).toBe('failed');
    expect(r.read).toBe('failed'); // same-origin policy
  });

  test('items 11, 14: no image and no frame from another origin', async ({ page }) => {
    await page.goto(`http://127.0.0.1:${other.port}/`);
    const img = await page.evaluate((p) => new Promise((ok) => {
      const i = new Image();
      i.onload = () => ok('loaded');
      i.onerror = () => ok('blocked');
      i.src = `http://127.0.0.1:${p}/api/v1/version`;
    }), fake.port);
    expect(img).toBe('blocked');
    await page.evaluate((p) => {
      const f = document.createElement('iframe');
      f.src = `http://127.0.0.1:${p}/`;
      document.body.appendChild(f);
    }, fake.port);
    await page.waitForTimeout(1000);
    const frame = page.frames().find((f) => f !== page.mainFrame());
    let readable = true;
    try {
      const t = await frame.evaluate(() => (document.body ? document.body.innerText : ''));
      readable = t.includes('Gazpacho');
    } catch (e) {
      readable = false;
    }
    expect(readable).toBe(false); // frame-ancestors 'none' and X-Frame-Options: DENY
  });

  test('item 12: EventSource cannot send the session header', async ({ page }) => {
    await page.goto(`http://127.0.0.1:${fake.port}/`);
    const r = await page.evaluate(() => new Promise((ok) => {
      const es = new EventSource('/api/v1/events');
      es.onerror = () => { ok(es.readyState); es.close(); };
      es.onopen = () => { ok('open'); es.close(); };
    }));
    expect(r).not.toBe('open');
  });

  test('item 36, T4: the page signs in with fetch(), its Origin passes; Clear-Site-Data recorded', async ({ page }, info) => {
    await page.goto(`http://127.0.0.1:${fake.port}/`);
    const r = await page.evaluate(async (pass) => {
      sessionStorage.setItem('gz', 'held');
      const s = await fetch('/api/v1/session', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase: pass }),
      });
      const out = { signIn: s.status };
      if (s.status === 200) {
        const tok = (await s.json()).session;
        const l = await fetch('/api/v1/lobbies', { headers: { 'X-Gazpacho-Session': tok } });
        out.lobbies = l.status;
        const d = await fetch('/api/v1/session', { method: 'DELETE', headers: { 'X-Gazpacho-Session': tok } });
        out.signOut = d.status;
      }
      out.storageAfter = sessionStorage.getItem('gz');
      return out;
    }, PASS);
    // --fresh-attempts: a clean attempts file, so the browser really signs in (review F4).
    expect(r.signIn).toBe(200);
    expect(r.lobbies).toBe(200);
    expect(r.signOut).toBe(204);
    info.annotations.push({ type: 'T4: Clear-Site-Data emptied sessionStorage', description: String(r.storageAfter === null) });
  });
});

test.describe('a missing attempts file (storage 12.3)', () => {
  let fake;
  test.beforeAll(async () => {
    test.skip(!FAKE, 'GZ_API_FAKE is not set');
    fake = await startFake(true, false);
  });
  test.afterAll(async () => {
    if (fake) stopFake(fake);
  });

  test('the strictest state: sign-in refused for 15 minutes, before any derivation', async ({ page }) => {
    await page.goto(`http://127.0.0.1:${fake.port}/`);
    const r = await page.evaluate(async (pass) => {
      const s = await fetch('/api/v1/session', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase: pass }),
      });
      const j = await s.json();
      return { status: s.status, code: j.code, retry: j.params.retry_after_s };
    }, PASS);
    expect(r.status).toBe(429);
    expect(r.code).toBe('rate_limited');
    expect(r.retry).toBeGreaterThan(800);
  });
});

test.describe('first run from the redirect file (T5, item 37)', () => {
  let fake;
  test.beforeAll(async () => {
    test.skip(!FAKE, 'GZ_API_FAKE is not set');
    fake = await startFake(false);
  });
  test.afterAll(async () => {
    if (fake) stopFake(fake);
  });

  test('the file: navigation is served while no wallet exists, and the token works once', async ({ page }) => {
    const file = join(fake.dir, 'd', 'first-run.html');
    const tok = readFileSync(file, 'utf8').match(/#start=([A-Za-z0-9_-]{43})/)[1];
    await page.goto('file://' + file);
    await page.waitForURL(/127\.0\.0\.1/);
    expect(page.url()).toContain(`127.0.0.1:${fake.port}/#start=`);
    const r = await page.evaluate(async (t) => {
      const post = (body) => fetch('/api/v1/session/start', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      const a = await post({ start_token: t });
      const b = await post({ start_token: t });
      return [a.status, b.status, (await b.json()).code];
    }, tok);
    expect(r).toEqual([200, 409, 'token_used']);
  });
});
