// SPDX-License-Identifier: MIT
// Three tabs on one session (spec/local-api.md 4.4, 10.3). The cap is two
// streams per session, so the third tab follows the events the others relay
// over the BroadcastChannel. It takes the stream over when a streaming tab
// closes (leader_gone, a 429 meanwhile tried again with a growing delay) or
// when nothing has been relayed for 30 s (a tab that died without pagehide).
//
// A tab that dies is played by closing it without its unload handlers
// (Playwright's default close): no pagehide runs, and its connections end, as
// with a renderer crash. A CDP Page.crash was used first; whether the browser
// then closes the dead tab's stream at once is not something this test can
// rely on (it passed on the build server and failed in CI), so it is not used.
// TEST ONLY.
import { test, expect, startFake, signIn, FAKE, PASS } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');
test.setTimeout(150000);

let fake;
test.afterEach(() => fake && fake.stop());

// Under at_join (14.3), the default, joining ready carries the passphrase.
async function joinIn(page) {
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
  await page.locator('#join').click();
  await page.locator('dialog').getByLabel('Password', { exact: true }).fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Join', exact: true }).click();
}

async function threeTabs(context) {
  const a = await context.newPage();
  await signIn(a, fake);
  await expect(a.locator('#live-chip')).toHaveAttribute('data-state', 'open');
  const b = await context.newPage();
  await b.goto(fake.url);
  await expect(b.locator('body')).toHaveAttribute('data-chrome', 'app'); // handed over, no passphrase
  await expect(b.locator('#live-chip')).toHaveAttribute('data-state', 'open');
  const c = await context.newPage();
  await c.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(c.locator('body')).toHaveAttribute('data-chrome', 'app');
  await expect(c.locator('#live-chip')).toHaveAttribute('data-state', 'too_many');
  await expect(c.locator('#live-chip')).toContainText('updates through another window');
  return [a, b, c];
}

test('the third tab follows relayed events, and takes over when a streaming tab closes', async ({ context }) => {
  fake = await startFake({ locked: true });
  const [a, b, c] = await threeTabs(context);
  await joinIn(a);
  await expect(c.locator('#lobby')).toHaveAttribute('data-seat', 'ready'); // relayed, then read with its own token
  await b.close({ runBeforeUnload: true }); // the person closes it: pagehide, leader_gone
  await expect(c.locator('#live-chip')).toHaveAttribute('data-state', 'open', { timeout: 30000 });
  await fake.cmd('step');
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
  await expect(a.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
});

test('streaming tabs that die without pagehide during the signing moment: the third takes over after 30 s of silence and shows it', async ({ context }) => {
  fake = await startFake({ locked: true });
  const [a, b, c] = await threeTabs(context);
  const streams = [];
  c.on('response', (r) => { if (r.url().endsWith('/api/v1/events')) streams.push(r.status()); });
  await joinIn(a);
  await expect(c.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await fake.cmd('step'); // the ready check, relayed
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
  // both streaming tabs die without pagehide: nothing tells the third, and it hears nothing more
  await c.evaluate((port) => {
    window.heard = [];
    new BroadcastChannel('gazpacho-session-' + port).onmessage = (e) => window.heard.push(e.data.type);
  }, String(fake.port));
  await a.close();
  await b.close();
  expect(a.isClosed() && b.isClosed()).toBe(true);
  await fake.cmd('step'); // signing: nobody relays it now
  await fake.cmd('step');
  await expect(c.locator('#live-chip'), 'the stream answers seen by the third tab: ' + JSON.stringify(streams))
    .toHaveAttribute('data-state', 'open', { timeout: 60000 });
  expect(await c.evaluate(() => window.heard)).not.toContain('leader_gone'); // it took over on silence, not on a message
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'signing');
  await expect(c.locator('#doing')).toContainText('Signing. Keep the app open.');
  // and it now follows live itself
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'funding');
});

test('a tab whose take-over keeps getting 429 with nothing relayed says it is not following, and reads the status every 5 s', async ({ context }) => {
  fake = await startFake({ locked: true });
  const [a, b, c] = await threeTabs(context);
  await joinIn(a);
  await expect(c.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  // both streaming tabs are frozen without pagehide: they keep the session's two
  // streams but relay nothing (review M5, 10.3)
  for (const p of [a, b]) await p.evaluate(() => { BroadcastChannel.prototype.postMessage = function () {}; });
  await expect(c.locator('#live-chip')).toHaveAttribute('data-state', 'not_following', { timeout: 60000 });
  await expect(c.locator('#live-chip')).toContainText('Not following the app: what you see may be old');
  await expect(c.locator('#live-chip')).not.toContainText('following the app;');
  // nothing is relayed, yet the status is read: a change reaches this tab within seconds
  await fake.cmd('chain disagree');
  await expect(c.locator('#alerts .alertbar[data-code="chain_disagree"]')).toBeVisible({ timeout: 12000 });
});
