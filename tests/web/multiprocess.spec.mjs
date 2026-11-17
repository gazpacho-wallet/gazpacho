// SPDX-License-Identifier: MIT
// Real gazpacho processes driven through their own interfaces (P6): a host
// and two members on signet with no chain, each with its own data folder and
// its own local API, the members connected to the host. One lobby is opened
// by the host, joined and readied by both members with their passphrases, up
// to the ready check, where P4.3's signing takes over. On the way, one
// member's own conditions stop fitting while Open: it refuses, and the host
// sees the refusal (15.3, seat state refused), not a member that left.
//
// TEST ONLY: gazpacho-test, whose passphrase layer is the stand-in. It needs
// GZ_PROGRAM (the built gazpacho-test) and waits for P6a, the core's view
// objects (composite-node.md 10): until then the program answers the lobby
// calls 501 with params.needs, so it is marked fixme unless GZ_P6A is set.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

const EXE = process.env.GZ_PROGRAM;
test.skip(!EXE, 'GZ_PROGRAM is not set');
test.fixme(!process.env.GZ_P6A, 'waits for P6a: the core emits no lobby view objects yet');
test.setTimeout(240000);

const PASS = { host: 'host passphrase, test only, long enough', m1: 'member one passphrase, test only', m2: 'member two passphrase, test only' };

function freePort() {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// One gazpacho process: its data folder (with a fixed test seed, as
// tests/program/api_program.py writes it), its interface port, its output.
async function program(name, role, extra) {
  const dir = mkdtempSync(join(tmpdir(), 'gzmp-' + name + '-'));
  const data = join(dir, 'd');
  mkdirSync(data, { mode: 0o700 });
  const seed = createHash('sha256').update('gazpacho multiprocess test seed ' + name).digest('hex');
  writeFileSync(join(data, 'wallet-seed.standin'), seed + '\n', { mode: 0o600, flag: 'wx' });
  const port = await freePort();
  const args = ['--data-dir', data, '--role', role, '--name', name, '--no-chain', '--interface-port', String(port), ...extra];
  const proc = spawn(EXE, args, { env: { ...process.env, XDG_RUNTIME_DIR: dir }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  proc.stdout.on('data', (b) => { out += b; });
  proc.stderr.on('data', (b) => { out += b; });
  const until = async (re, ms = 20000) => {
    const end = Date.now() + ms;
    for (;;) {
      const m = out.match(re);
      if (m) return m;
      if (Date.now() > end) throw new Error(name + ': no ' + re + ' in:\n' + out);
      await new Promise((r) => setTimeout(r, 100));
    }
  };
  await until(new RegExp('interface listening http://127\\.0\\.0\\.1:' + port + '/'));
  return {
    name, dir, data, port, url: `http://127.0.0.1:${port}/`, origin: `http://127.0.0.1:${port}`, until,
    output: () => out,
    stop() { proc.kill('SIGTERM'); },
    clean() { rmSync(dir, { recursive: true, force: true }); },
  };
}

// First run through the program's own API, as the interface does it: the
// start token from the redirect file, create, finish setup.
async function setUp(request, p, pass) {
  const h = { Origin: p.origin, 'Content-Type': 'application/json', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty' };
  const page = readFileSync(join(p.data, 'first-run.html'), 'utf8');
  const tok = page.match(/#start=([A-Za-z0-9_-]{43})/)[1];
  const s = await request.post(p.url + 'api/v1/session/start', { headers: h, data: { start_token: tok } });
  expect(s.status()).toBe(200);
  const session = (await s.json()).session;
  const hs = { ...h, 'X-Gazpacho-Session': session };
  const c = await request.post(p.url + 'api/v1/wallet/create', { headers: hs, data: { confirm: 'create_wallet', passphrase: pass, confirm_passphrase: pass } });
  expect(c.status()).toBe(200);
  const f = await request.post(p.url + 'api/v1/wallet/finish-setup', { headers: hs, data: { preset: 'everyday', find: 'browse' } });
  expect(f.status()).toBe(200);
}

async function signIn(page, p, pass) {
  await page.goto(p.url);
  await page.getByLabel('Wallet passphrase').fill(pass);
  await page.getByRole('button', { name: /^(Unlock|Sign in)$/ }).click();
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
}

test('a host and two members: one lobby opened, joined and readied up to the ready check; a refusal seen by the host', async ({ browser, request }) => {
  const procs = [];
  try {
    const listen = await freePort();
    const host = await program('host', 'host', ['--listen', '127.0.0.1:' + listen]);
    procs.push(host);
    const key = (await host.until(/host key=([0-9a-f]{66})/))[1];
    const connect = ['--connect', `${key}@127.0.0.1:${listen}`];
    const m1 = await program('m1', 'member', connect);
    const m2 = await program('m2', 'member', connect);
    procs.push(m1, m2);
    await setUp(request, host, PASS.host);
    await setUp(request, m1, PASS.m1);
    await setUp(request, m2, PASS.m2);

    // the host opens a lobby of two, with the passphrase
    const hp = await (await browser.newContext()).newPage();
    await signIn(hp, host, PASS.host);
    await hp.goto(host.url + '#/host/new');
    await hp.getByLabel('Lobby name').fill('Three seats');
    await hp.getByLabel(/^Target/).fill('3');
    await hp.getByLabel(/^Minimum/).fill('2');
    await expect(hp.locator('#open-lobby')).toBeEnabled();
    await hp.waitForTimeout(1100);
    await hp.locator('#open-lobby').click();
    await hp.locator('dialog').getByLabel('Wallet passphrase').fill(PASS.host);
    await hp.locator('dialog').getByRole('button', { name: 'Sign and open' }).click();
    await expect(hp.locator('#host-lobby')).toHaveAttribute('data-stage', 'open');

    // member 1: finds the host's lobby, joins it ready, with its passphrase
    const p1 = await (await browser.newContext()).newPage();
    await signIn(p1, m1, PASS.m1);
    await p1.goto(m1.url + '#/lobbies');
    await p1.getByLabel('Add a host by its address').fill(`${key}@127.0.0.1:${listen}`);
    await p1.getByRole('button', { name: 'Ask this host' }).click();
    await expect(p1.locator('#query-note')).toContainText('The host answered.');
    await p1.locator('#lobbies-fit li a').first().click();
    await p1.waitForTimeout(1100);
    await p1.locator('#review').getByLabel('Wallet passphrase').fill(PASS.m1);
    await p1.locator('#join').click();
    await expect(p1.locator('#lobby')).toHaveAttribute('data-seat', 'ready', { timeout: 20000 });
    await expect(hp.locator('#host-counts')).toContainText('1 ready of 3', { timeout: 20000 });

    // member 2 joins ready too: 2 of 3, the minimum
    const p2 = await (await browser.newContext()).newPage();
    await signIn(p2, m2, PASS.m2);
    const join2 = async () => {
      await p2.goto(m2.url + '#/lobbies');
      await p2.getByLabel('Add a host by its address').fill(`${key}@127.0.0.1:${listen}`);
      await p2.getByRole('button', { name: 'Ask this host' }).click();
      await expect(p2.locator('#query-note')).toContainText('The host answered.');
      await p2.locator('#lobbies-fit li a').first().click();
      await p2.waitForTimeout(1100);
      await p2.locator('#review').getByLabel('Wallet passphrase').fill(PASS.m2);
      await p2.locator('#join').click();
      await expect(p2.locator('#lobby')).toHaveAttribute('data-seat', 'ready', { timeout: 20000 });
    };
    await join2();
    await expect(hp.locator('#host-counts')).toContainText('2 ready of 3', { timeout: 20000 });

    // its conditions tighten below the lobby's terms while Open: its own check
    // refuses (leave reason 1), and the host sees a refusal, not a member that left
    await p2.goto(m2.url + '#/conditions');
    await p2.getByLabel('Fewest members').fill('4');
    await p2.locator('#save-conditions').click();
    await expect(hp.locator('#seats tr[data-seat-state="refused"]')).toHaveCount(1, { timeout: 20000 });
    await expect(hp.locator('#seats tr[data-seat-state="left"]')).toHaveCount(0);

    // it loosens again (a fresh sign-in) and joins ready: the refusal is shown only until then (review M3.2)
    await p2.getByLabel('Fewest members').fill('2');
    await p2.locator('#save-conditions').click();
    const fresh = p2.locator('dialog');
    await fresh.getByLabel('Wallet passphrase').fill(PASS.m2);
    await fresh.getByRole('button', { name: 'Continue' }).click();
    await join2();
    await expect(hp.locator('#seats tr[data-seat-state="refused"]')).toHaveCount(0, { timeout: 20000 });
    await expect(hp.locator('#host-counts')).toContainText('2 ready of 3');

    // the host starts at the minimum: the ready check. P4.3's signing takes over from here.
    await hp.locator('#start').click();
    const again = hp.locator('dialog');
    if (await again.isVisible()) {
      await again.getByLabel('Wallet passphrase').fill(PASS.host);
      await again.getByRole('button').first().click();
    }
    await expect(hp.locator('#host-lobby')).toHaveAttribute('data-stage', /ready_check|signing/, { timeout: 30000 });
    await expect(p1.locator('#lobby')).toHaveAttribute('data-stage', /ready_check|signing/, { timeout: 30000 });
    await expect(p2.locator('#lobby')).toHaveAttribute('data-stage', /ready_check|signing/, { timeout: 30000 });
    for (const p of procs) expect(p.output()).not.toContain(PASS.host);
  } finally {
    for (const p of procs) p.stop();
    await new Promise((r) => setTimeout(r, 500));
    for (const p of procs) p.clean();
  }
});
