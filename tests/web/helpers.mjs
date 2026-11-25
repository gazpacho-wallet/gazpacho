// SPDX-License-Identifier: MIT
// Helpers for the interface's tests (stream S10). TEST ONLY: everything here
// drives gz-api-fake, the fake backend, which is not a wallet. Set GZ_API_FAKE
// to the built gz-api-fake.
import { test as base, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const FAKE = process.env.GZ_API_FAKE;
export const PASS = 'fake test passphrase, not a wallet'; // the fake's fixture (fake_backend.h)
export const HOST_KEY = '02c7e1b2a4d6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192';
export const WORDS = Array.from({ length: 24 }, (_, i) => (i === 23 ? 'art' : 'abandon')); // the fake's test phrase

// Start gz-api-fake with the story on. opts.locked: a wallet exists (PASS);
// otherwise first run. opts.args: more flags. cmd(line) sends one line of the
// story's script and waits for the fake's "ok".
export function startFake(opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'gzweb-'));
  const args = ['--data-dir', join(dir, 'd'), '--port', '0', '--no-ipv6', '--quiet', '--story', ...(opts.args || [])];
  if (opts.locked) args.push('--locked', '--fresh-attempts');
  const proc = spawn(FAKE, args, { env: { ...process.env, XDG_RUNTIME_DIR: dir }, stdio: ['pipe', 'pipe', 'inherit'] });
  let out = '';
  const waiters = [];
  proc.stdout.on('data', (b) => {
    out += b;
    for (const w of [...waiters]) w();
  });
  const until = (re, ms = 10000) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('gz-api-fake: no ' + re + ' in: ' + out)), ms);
    const check = () => {
      const m = out.match(re);
      if (!m) return;
      clearTimeout(timer);
      waiters.splice(waiters.indexOf(check), 1);
      resolve(m);
    };
    waiters.push(check);
    check();
  });
  return until(/listening http:\/\/127\.0\.0\.1:(\d+)\//).then((m) => {
    const port = Number(m[1]);
    const fake = {
      proc, dir, port,
      url: `http://127.0.0.1:${port}/`,
      origin: `http://127.0.0.1:${port}`,
      redirectFile: join(dir, 'd', 'first-run.html'),
      async cmd(line) {
        const before = out.length;
        proc.stdin.write(line + '\n');
        await until(new RegExp('(?:^|\\n)(ok|unknown) ' + line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\n'));
        if (out.slice(before).includes('unknown ' + line)) throw new Error('gz-api-fake does not know: ' + line);
      },
      stop() {
        proc.kill('SIGTERM');
        rmSync(dir, { recursive: true, force: true });
      },
    };
    return fake;
  });
}

// A TCP forwarder that plays an SSH tunnel (spec/local-api.md 3.3): the browser
// talks to its port, the fake is told that port as --tunnel-port. drop() cuts
// every connection, as a tunnel that fails does; pause(true) refuses new ones.
export function startTunnel() {
  const sockets = new Set();
  let target = 0;
  let paused = false;
  const srv = createServer((c) => {
    if (paused || !target) { c.destroy(); return; }
    const up = connect(target, '127.0.0.1');
    sockets.add(c);
    sockets.add(up);
    c.pipe(up);
    up.pipe(c);
    const end = () => { c.destroy(); up.destroy(); sockets.delete(c); sockets.delete(up); };
    c.on('error', end); up.on('error', end); c.on('close', end); up.on('close', end);
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({
    port: srv.address().port,
    setTarget(p) { target = p; },
    drop() { for (const s of [...sockets]) s.destroy(); },
    pause(v) { paused = v; },
    stop() { for (const s of [...sockets]) s.destroy(); srv.close(); },
  })));
}

// Every test's page is watched: each request must go to the local API's own
// origin (or be the first-run redirect file), no address may carry a fragment,
// a secret-looking query or a 64-hex segment (5.5, 23.3 item 3), and the page
// must raise no script error and no content-security-policy report.
export const test = base.extend({
  page: async ({ page }, use, info) => {
    const requests = [];
    const problems = [];
    page.on('request', (r) => requests.push(r.url()));
    page.on('pageerror', (e) => problems.push('page error: ' + e.message));
    page.on('console', (m) => {
      if (/Content Security Policy|Trusted ?Type/i.test(m.text())) problems.push('console: ' + m.text());
    });
    page.gzRequests = requests;
    page.gzProblems = problems;
    await use(page);
    if (info.status !== 'passed') return;
    const allowed = info.annotations.filter((a) => a.type === 'origin').map((a) => a.description);
    for (const u of requests) {
      if (u.startsWith('file://') && u.endsWith('/first-run.html')) continue;
      const url = new URL(u);
      expect(allowed, 'a request left the local API: ' + u).toContain(url.origin);
      expect(url.hash, 'a fragment in a request address: ' + u).toBe('');
      expect(u, 'a 64-hex segment in an address').not.toMatch(/[0-9a-f]{64}/);
      expect(url.search, 'a secret-looking query').not.toMatch(/token|code|phrase|words|seed|key|password|session|backup/i);
    }
    expect(problems).toEqual([]);
  },
});

// Tell the page fixture which origin this test's fake has.
export function allow(info, fake, extra) {
  info.annotations.push({ type: 'origin', description: fake.origin });
  if (extra) info.annotations.push({ type: 'origin', description: extra });
}

export async function signIn(page, fake, pass = PASS, base) {
  await page.goto(base || fake.url);
  await page.getByLabel('Password', { exact: true }).fill(pass);
  await page.getByRole('button', { name: /^(Unlock|Sign in)$/ }).click();
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
  await expect(page.locator('#doing')).not.toBeEmpty();
}

// The strip's "Status details" are folded on a phone; this opens them when the button shows.
export async function openChips(page) {
  const more = page.locator('#more');
  if (await more.isVisible() && (await more.getAttribute('aria-expanded')) !== 'true') await more.click();
}

export { expect };
