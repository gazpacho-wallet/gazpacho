// SPDX-License-Identifier: MIT
// Three tabs on one session (spec/local-api.md 4.4, 10.3). The cap is two
// streams per session, so the third tab follows the events the others relay
// over the BroadcastChannel. It takes the stream over when a streaming tab
// closes (leader_gone, a 429 meanwhile tried again with a growing delay) or
// when nothing has been relayed for 30 s (a tab that died without pagehide).
// TEST ONLY.
import { test, expect, startFake, signIn, FAKE } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');
test.setTimeout(150000);

let fake;
test.afterEach(() => fake && fake.stop());

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
  await a.goto(fake.url + '#/lobby/lob_7k2q');
  await a.locator('#join').click();
  await expect(c.locator('#lobby')).toHaveAttribute('data-seat', 'ready'); // relayed, then read with its own token
  await b.close({ runBeforeUnload: true }); // the person closes it: pagehide, leader_gone
  await expect(c.locator('#live-chip')).toHaveAttribute('data-state', 'open', { timeout: 30000 });
  await fake.cmd('step');
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
  await expect(a.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
});

test('streaming tabs that crash during the signing moment: the third takes over after 30 s of silence and shows it', async ({ context }) => {
  fake = await startFake({ locked: true });
  const [a, b, c] = await threeTabs(context);
  await a.goto(fake.url + '#/lobby/lob_7k2q');
  await a.locator('#join').click();
  await expect(c.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await fake.cmd('step'); // the ready check, relayed
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
  // both streaming tabs die without pagehide (a renderer crash)
  for (const p of [a, b]) {
    const s = await context.newCDPSession(p);
    s.send('Page.crash').catch(() => {});
  }
  await fake.cmd('step'); // signing: nobody relays it now
  await fake.cmd('step');
  await expect(c.locator('#live-chip')).toHaveAttribute('data-state', 'open', { timeout: 75000 });
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'signing');
  await expect(c.locator('#doing')).toContainText('Signing. Keep the app open.');
  // and it now follows live itself
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(c.locator('#lobby')).toHaveAttribute('data-stage', 'funding');
});
