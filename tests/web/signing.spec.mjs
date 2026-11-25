// SPDX-License-Identifier: MIT
// Draft 5 of the local API in the interface (spec/local-api.md 14.3, 14.4,
// 14.6, 15.3, 4.3): the passphrase with a ready under at_join, a seat locked
// by a restart and "Mark ready in all", the signing setting that takes effect
// at the next start, Slice 1 accountability, the host's locked seats, and a
// junk start token. TEST ONLY: against gz-api-fake's story.
import { test, expect, startFake, allow, signIn, FAKE, PASS } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');

let fake;
test.afterEach(() => fake && fake.stop());
async function start(info, args) {
  fake = await startFake({ locked: true, args });
  allow(info, fake);
}

// 14.3 interface rule 5, and section 22's rows
const AT_JOIN = 'Gazpacho asks for your passphrase when you mark ready in a lobby.';
const SEED_LINE = "While Gazpacho is unlocked it still holds your wallet's seed";
const LOCKED = 'Not taking part until you mark ready again: your app told the host this seat is locked.';
const SAVED = 'Saved. This takes effect the next time Gazpacho starts; until then it keeps signing as it does now.';

async function joinReady(page) {
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
  await page.locator('#join').click();
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Join', exact: true }).click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
}

async function nowhere(page) {
  const all = await page.evaluate(() => document.documentElement.outerHTML + '\n' +
    Array.from(document.querySelectorAll('input')).map((i) => i.value).join('\n'));
  expect(all, 'the passphrase is kept nowhere on the page').not.toContain(PASS);
}

test('at_join: the passphrase comes with every ready, in a dialog emptied at once, and the words say what it protects', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  const bodies = [];
  page.on('request', (r) => { if (/\/lobbies\/lob_7k2q\/(join|ready)$/.test(r.url())) bodies.push(JSON.parse(r.postData())); });
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#review')).toContainText(AT_JOIN);
  await expect(page.locator('#review')).toContainText(SEED_LINE);
  await expect(page.locator('#review input[type="password"]')).toHaveCount(0); // never on the redrawn screen (review M2)
  // nothing is sent without it
  await page.locator('#join').click();
  const dlg = page.locator('dialog');
  await expect(dlg).toContainText(SEED_LINE);
  await dlg.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(dlg).toContainText('Type your passphrase first.');
  expect(bodies).toHaveLength(0);
  // a wrong one: refused in the dialog, the field emptied, nothing joined
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill('not the passphrase at all');
  await dlg.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(dlg.locator('[data-code="wrong_passphrase"]')).toBeVisible();
  await expect(dlg.getByLabel('Wallet passphrase')).toHaveValue('');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'none');
  // live events redraw the lobby screen under the dialog: what is typed stays, with the focus (review M2)
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill('half typed');
  await page.locator('#lobby').evaluate((e) => e.setAttribute('data-old', '1'));
  await fake.cmd('chain lagging');
  await expect(page.locator('#lobby[data-old]')).toHaveCount(0); // drawn again
  await expect(dlg.getByLabel('Wallet passphrase')).toHaveValue('half typed');
  await expect(dlg.getByLabel('Wallet passphrase')).toBeFocused();
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Join', exact: true }).click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await expect(page.locator('dialog')).toHaveCount(0);
  expect(bodies.map((b) => typeof b.passphrase)).toEqual(['string', 'string']);
  // not ready: no passphrase; ready again: asked for in a dialog, with the same words
  await page.locator('#ready-toggle').click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
  expect('passphrase' in bodies[2]).toBe(false);
  await expect(page.locator('#gate-words')).toContainText(AT_JOIN);
  await page.locator('#ready-toggle').click();
  await expect(dlg).toContainText(SEED_LINE);
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  expect(typeof bodies[3].passphrase).toBe('string');
  await nowhere(page);
});

test('after a restart a Ready seat is locked: said plainly, out of the count, and readied again in all with one passphrase', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await joinReady(page);
  await expect(page.locator('#counts')).toContainText('30 ready of 50');
  await fake.cmd('restart');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
  await expect(page.locator('#seat-line')).toContainText(LOCKED);
  await expect(page.locator('#counts')).toContainText('29 ready of 50');
  await expect(page.locator('#ready-toggle')).toHaveText('Mark ready');
  await expect(page.locator('#doing')).toContainText('In a lobby, locked.');
  await expect(page.locator('#doing')).not.toContainText('signs by itself');
  await page.goto(fake.url + '#/');
  await expect(page.locator('#todo li[data-code="unlock_to_take_part"]')).toContainText('does not take part until you mark ready again');
  // "Mark ready in all": one call, one passphrase check
  const posts = [];
  page.on('request', (r) => { if (r.url().endsWith('/api/v1/lobbies/ready')) posts.push(JSON.parse(r.postData())); });
  await page.goto(fake.url + '#/lobbies');
  await expect(page.locator('#locked-seats')).toContainText(LOCKED);
  await page.locator('#ready-all').click();
  const dlg = page.locator('dialog');
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill('not the passphrase at all');
  await dlg.getByRole('button', { name: 'Mark ready' }).click();
  await expect(dlg.locator('[data-code="wrong_passphrase"]')).toBeVisible();
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#toasts')).toContainText('Ready again in 1 lobby.');
  await expect(page.locator('#locked-seats')).toHaveCount(0);
  expect(posts).toHaveLength(2);
  expect(posts[1].lobbies.map((l) => l.lobby_id)).toEqual(['lob_7k2q']);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await expect(page.locator('#seat-line')).not.toContainText(LOCKED);
  await nowhere(page);
});

test('a locked seat is readied from its lobby with the passphrase', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await joinReady(page);
  await fake.cmd('restart');
  await expect(page.locator('#ready-toggle')).toHaveText('Mark ready');
  await expect(page.locator('#seat-line')).toContainText(LOCKED);
  await expect(page.locator('#doing')).toContainText(LOCKED);
  await page.locator('#ready-toggle').click();
  const dlg = page.locator('dialog');
  await expect(dlg.getByRole('heading')).toHaveText('Mark ready again');
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await expect(page.locator('#doing')).toContainText('In a lobby:');
});

test('the signing setting: auto only behind a fresh sign-in, saved for the next start, both values shown until then', async ({ page }, info) => {
  await start(info, ['--fresh-ms', '500']);
  await signIn(page, fake);
  await page.goto(fake.url + '#/settings');
  const box = page.locator('#signing-box');
  await expect(box.locator('#signing-now')).toHaveText('In force now: Ask for my passphrase when I mark ready.');
  await expect(box).toContainText(SEED_LINE);
  await expect(box.locator('#signing-pending')).toHaveCount(0);
  await page.waitForTimeout(1100); // the sign-in is no longer fresh, and one attempt a second
  await box.getByLabel('Sign by itself in every lobby I am ready in').check();
  await box.locator('#signing-save').click();
  const dlg = page.locator('dialog');
  await expect(dlg).toContainText('Type your passphrase again');
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Continue' }).click();
  await expect(page.locator('#signing-msg')).toContainText(SAVED);
  await expect(page.locator('#signing-now')).toHaveText('In force now: Ask for my passphrase when I mark ready.');
  await expect(page.locator('#signing-pending')).toHaveText('From the next start: Sign by itself in every lobby I am ready in.');
  // until the next start, joining still asks for the passphrase
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#join-gate-words')).toContainText(AT_JOIN); // joining ready asks for it
  await fake.cmd('restart');
  await page.goto(fake.url + '#/settings');
  await expect(page.locator('#signing-now')).toHaveText('In force now: Sign by itself in every lobby I am ready in.');
  await expect(page.locator('#signing-pending')).toHaveCount(0);
  await expect(page.locator('#signing-box')).toContainText('Gazpacho signs in every lobby you are ready in, by itself, whenever it is unlocked.');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#join-gate-words')).toHaveCount(0);
  await expect(page.locator('#review')).toContainText('the app signs by itself');
  await page.locator('#join').click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
});

test('accountability in Slice 1: what this app saw of its own seat, no count, and a removal as what the host said', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/lobby/lob_7k2q'); // shown joined or not
  const acc = page.locator('#accountability');
  await expect(acc).toContainText('Your app sees only what happened to your own seat.');
  await expect(acc.locator('[data-count]')).toHaveCount(0);
  await expect(acc).not.toContainText(/\d|nobody/i);
  await joinReady(page);
  await fake.cmd('member-removed');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'removed');
  await expect(acc.locator('.removal')).toContainText('The host said:');
  await expect(acc.locator('.removal')).toContainText('did not answer for an hour');
  await expect(acc).not.toContainText(/signed that|removed by the host: \d/i);
  await expect(acc.locator('[data-count]')).toHaveCount(0);
});

test("the host sees a member's locked seat as locked, out of the count", async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/host/new');
  await page.getByLabel('Lobby name').fill('Locked seats');
  await expect(page.locator('#open-lobby')).toBeEnabled();
  await page.waitForTimeout(1100);
  await page.locator('#open-lobby').click();
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Sign and open' }).click();
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'open');
  await fake.cmd('host-seats 3');
  await expect(page.locator('#seats tbody tr')).toHaveCount(3);
  await fake.cmd('host-locked 1');
  const locked = page.locator('#seats tr[data-seat-state="locked"]');
  await expect(locked).toHaveCount(1);
  await expect(locked).toContainText('Locked: out of the count until it marks ready again');
  await expect(page.locator('#host-counts')).toContainText('2 ready');
  await expect(page.locator('#seats tr[data-seat-state="refused"], #seats tr[data-seat-state="left"]')).toHaveCount(0);
});

test('a junk start token with a wallet: the plain unlock screen, never the hijack warning', async ({ page }, info) => {
  await start(info);
  await page.goto(fake.url + '#start=' + 'A'.repeat(43));
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Unlock Gazpacho');
  await expect(page.getByRole('heading', { name: 'Do not use this wallet' })).toHaveCount(0);
});

// ---- review of PR 51 ----

test('M1/W03: "Mark ready in all" readies every locked seat, each with the digest drawn beside its terms', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await joinReady(page);
  await fake.cmd('join-second');
  await fake.cmd('restart');
  const posts = [];
  page.on('request', (r) => { if (r.url().endsWith('/api/v1/lobbies/ready')) posts.push(JSON.parse(r.postData())); });
  await page.goto(fake.url + '#/lobbies');
  const drawn = {};
  for (const id of ['lob_7k2q', 'lob_b19d']) {
    await expect(page.locator(`#locked-list li[data-lobby="${id}"]`)).toContainText('Joining fee');
    drawn[id] = await page.evaluate(async (lid) => (await (await fetch('/api/v1/lobbies/' + lid,
      { headers: { 'X-Gazpacho-Session': sessionStorage.getItem('gz-session') } })).json()).terms.current.digest, id);
  }
  await page.locator('#ready-all').click();
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#toasts')).toContainText('Ready again in 2 lobbies.');
  expect(posts).toHaveLength(1);
  expect(posts[0].lobbies).toEqual([{ lobby_id: 'lob_7k2q', seen_current_digest: drawn.lob_7k2q }, { lobby_id: 'lob_b19d', seen_current_digest: drawn.lob_b19d }]);
  for (const id of ['lob_7k2q', 'lob_b19d']) {
    await page.goto(fake.url + '#/lobby/' + id);
    await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  }
});

test('M1: a locked lobby whose terms moved is left out of "Mark ready in all", with the change, never readied under the new values', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await joinReady(page);
  await fake.cmd('join-second');
  await fake.cmd('restart');
  await fake.cmd('host-moves-fee'); // while locked, the host moves lob_7k2q's fee inside its range
  const posts = [];
  page.on('request', (r) => { if (r.url().endsWith('/api/v1/lobbies/ready')) posts.push(JSON.parse(r.postData())); });
  await page.goto(fake.url + '#/lobbies');
  const moved = page.locator('#locked-list li[data-lobby="lob_7k2q"]');
  await expect(moved).toHaveAttribute('data-moved', 'yes');
  await expect(moved).toContainText('the terms changed since you readied');
  await expect(moved).toContainText('Joining fee from 1,000 to 1,400');
  await page.locator('#ready-all').click();
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#toasts')).toContainText('Ready again in 1 lobby.');
  expect(posts.map((p) => p.lobbies.map((l) => l.lobby_id))).toEqual([['lob_b19d']]);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
});

test('M1: terms that move after the page was drawn are refused for that lobby, and the page says to review them', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await joinReady(page);
  await fake.cmd('restart');
  await page.goto(fake.url + '#/lobbies');
  await page.locator('#ready-all').click(); // the dialog is open over the page drawn before the move
  await fake.cmd('host-moves-fee');
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#ready-all-left li[data-lobby="lob_7k2q"]')).toContainText('the terms changed since this page was drawn');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
});

test('M1: a retry of "Mark ready in all" after node busy is the same request, done once', async ({ page }, info) => {
  await start(info, ['--held-ms', '1500']);
  await signIn(page, fake);
  await joinReady(page);
  await fake.cmd('restart');
  const ids = [];
  page.on('request', (r) => { if (r.url().endsWith('/api/v1/lobbies/ready')) ids.push(JSON.parse(r.postData()).request_id); });
  await page.goto(fake.url + '#/lobbies');
  await fake.cmd('hold forever');
  await page.locator('#ready-all').click();
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#ready-all-msg [data-code="node_busy"]')).toBeVisible();
  await fake.cmd('release');
  await fake.cmd('hold off');
  await page.locator('#ready-all').click();
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
  await expect(page.locator('#toasts')).toContainText('Ready again in 1 lobby.');
  expect(ids).toHaveLength(2);
  expect(ids[1]).toBe(ids[0]);
});

test('W07: counts the host did not sign are never shown; signed ones are the host\'s statement', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  const acc = page.locator('#accountability');
  await fake.cmd('host-counts-unsigned');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(acc).toContainText('Your app sees only what happened to your own seat.');
  await expect(acc.locator('[data-count]')).toHaveCount(0);
  await expect(acc).not.toContainText(/\d/);
  await fake.cmd('host-counts-signed');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(acc.locator('[data-count="removed_by_host"]')).toHaveText('The host signed that it removed 1 seat.');
  await expect(acc).not.toContainText('Your app sees only what happened to your own seat.');
});
