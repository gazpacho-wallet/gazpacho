// SPDX-License-Identifier: MIT
// The Slice 1 flows through the interface, against the fake backend's story:
// conditions, finding and joining a lobby, the waiting view, the signing
// moment and its refusals, the live factory, hosting, and the error states
// (node busy, the chain view in doubt, the stream dropping). TEST ONLY.
import { test, expect, startFake, startTunnel, allow, signIn, openChips, FAKE, PASS, HOST_KEY } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');

let fake;
test.afterEach(() => fake && fake.stop());
async function start(info, args) {
  fake = await startFake({ locked: true, args });
  allow(info, fake);
}

// Under at_join (14.3), the default, joining ready carries the passphrase.
async function joinClick(page) {
  await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
  await page.locator('#review').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('#join').click(); // the same button the person presses
}

// "I am ready" asks for the passphrase in a dialog (14.3 interface rule 2).
async function readyAgain(page) {
  await page.locator('#ready-toggle').click();
  await page.waitForTimeout(1100);
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Mark ready' }).click();
}

async function join(page) {
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await joinClick(page);
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
}

test('find a host by its address, read the terms and the fit, join, wait, sign, funding, live', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  let alerts = 0;
  page.on('dialog', (d) => { alerts++; d.dismiss(); });

  // Lobbies: a wrong address, then the host's
  await page.goto(fake.url + '#/lobbies');
  await page.getByLabel('Add a host by its address').fill('not a host');
  await page.getByRole('button', { name: 'Ask this host' }).click();
  await expect(page.locator('[data-code="bad_host_address"]')).toBeVisible();
  await page.getByLabel('Add a host by its address').fill(HOST_KEY + '@tomato.example:9735');
  await page.getByRole('button', { name: 'Ask this host' }).click();
  await expect(page.locator('#query-note')).toContainText('The host answered. 2 lobbies found.');
  // fits first; the other with both numbers; text written by a host is shown as text
  await expect(page.locator('#lobbies-fit li')).toHaveCount(1);
  await expect(page.locator('#lobbies-fit')).toContainText('Tomato Garden, daily factory');
  const rest = page.locator('#lobbies-rest li');
  await expect(rest).toHaveCount(1);
  await expect(rest).toContainText('Basil Corner <script>alert(1)</script>');
  await expect(rest).toContainText('Does not fit your conditions.');
  await expect(rest).toContainText('Joining fee: the lobby offers 3,000 to 5,000 (now 4,000); your limit is 2,000.');
  expect(alerts).toBe(0);
  expect(await page.locator('main script, main a[href^="javascript"]').count()).toBe(0);

  // a lobby that does not fit: Join is off, with the reason
  await rest.getByRole('link').first().click();
  await expect(page.locator('#join')).toBeDisabled();
  await expect(page.locator('#review')).toContainText('Join is off: this lobby does not fit your conditions.');
  await expect(page.locator('#review')).toContainText('your limit is 2,000');

  // the one that fits: sealed terms in the host's voice, the fit check, consent, join
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('.sealed')).toContainText('Set and signed by host');
  await expect(page.locator('.sealed')).toContainText('signature checked by this app');
  await expect(page.locator('.sealed')).toContainText('<b>no</b> markup is ever rendered');
  await expect(page.locator('.sealed input, .sealed button')).toHaveCount(0);
  await expect(page.locator('table.fit caption')).toContainText('Fits your conditions');
  await expect(page.locator('#review')).toContainText('Joining is your consent.');
  await joinClick(page);
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await expect(page.locator('#seat-line')).toContainText('You are counted.');
  await expect(page.locator('#counts')).toContainText('30 ready of 50');
  await expect(page.locator('#doing')).toContainText('In a lobby: 30 of 50 ready.');
  await expect(page.locator('#waiting .dates')).toContainText('At zero it starts if enough are ready, or is cancelled');

  // not ready, ready again
  await page.locator('#ready-toggle').click();
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
  await expect(page.locator('#doing')).toContainText('In a lobby, not ready.');
  await readyAgain(page);
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');

  // the start, live, with no click: ready check, the signing moment, funding, live
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-stage', 'ready_check');
  await expect(page.locator('#doing')).toContainText('Ready check.');
  await expect(page.locator('#leave')).toHaveCount(0);
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-stage', 'signing');
  await expect(page.locator('#doing')).toContainText('Signing. Keep the app open.');
  await expect(page.locator('#checks li')).toHaveCount(4);
  await expect(page.locator('#checks li[data-ok="no"]')).toHaveCount(0);
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#round-state')).toContainText('Signatures sent. 11 of 17 signatures.');
  // conditions cannot change during the seconds of signing
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-stage', 'funding');
  await expect(page.locator('#doing')).toContainText("Signed. Waiting for the host's funding: 0 of 3 confirmations. Not live yet.");
  await expect(page.locator('#funding')).toContainText('0 of 3');
  await expect(page.locator('#funding')).toContainText('Not live until it has them all.');

  // the factory: not live while the funding confirms
  await page.locator('#funding').getByRole('link', { name: 'Open the factory' }).click();
  await expect(page.locator('#factory')).toHaveAttribute('data-state', 'awaiting_funding');
  await expect(page.locator('#factory')).toContainText('Not live yet.');
  await expect(page.locator('#factory-dates')).toContainText('Funding needed by');
  await fake.cmd('step');
  await expect(page.locator('#factory-funding')).toContainText('1 of 3');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#factory')).toHaveAttribute('data-state', 'live');
  await expect(page.locator('#factory')).toContainText('The funding is buried and this app holds the whole signed tree.');
  await expect(page.locator('#factory-dates')).toContainText('Factory ends');
  await expect(page.locator('#factory-dates')).toContainText('Where this date comes from');
  await expect(page.locator('#factory')).toContainText('Nothing of yours is inside');
  await expect(page.locator('#doing')).toContainText('In a live factory.');
  await openChips(page);
  await expect(page.locator('#chips')).toContainText('Watching: this app, while it runs');

  // Home and Activity tell the same story; the saved copy of the terms never changes
  await page.goto(fake.url + '#/');
  await expect(page.locator('main')).toContainText('Tomato Garden, factory 12');
  await page.goto(fake.url + '#/activity');
  await expect(page.locator('#activity li[data-kind="factory_live"]')).toHaveCount(1);
  await page.locator('#activity li[data-kind="joined"]').getByRole('link', { name: 'The saved copy' }).click();
  await expect(page.locator('main')).toContainText('A saved copy.');
  await expect(page.locator('.sealed')).toContainText('The terms, as they were');
});

test('the signing moment: the app refuses at its own check, with both numbers, and says nothing was signed', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await join(page);
  await fake.cmd('member-refuse');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'left');
  const notice = page.locator('#lobby .notice.bad').first();
  await expect(notice).toContainText('Did not sign.');
  await expect(notice).toContainText('Fewest members: your limit is 20, the lobby offers 18.');
  await expect(notice).toContainText('Nothing was signed. Nothing moved.');
  await expect(page.locator('#checks li[data-check="tree_inside_conditions"]')).toHaveAttribute('data-ok', 'no');
  await expect(page.locator('#doing')).toContainText('Did not sign.');
  await expect(page.locator('#doing')).toContainText('your limit is 20, the lobby offers 18');
  // the record, with its saved copy
  await page.goto(fake.url + '#/');
  await page.locator('#todo li[data-code="refused_to_sign"]').getByRole('link', { name: 'See the record' }).click();
  await expect(page.locator('main')).toContainText('Did not sign');
  await expect(page.locator('main')).toContainText('Nothing was signed. Nothing moved.');
  await expect(page.locator('main')).toContainText('The fit check, as it was');
});

test('signing that did not finish is never called "nothing was signed"', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await join(page);
  await fake.cmd('step');
  await fake.cmd('step');
  await fake.cmd('step');
  await fake.cmd('step');
  await fake.cmd('member-unfinished');
  await expect(page.locator('#alerts .alertbar[data-code="signing_unfinished"]')).toContainText('At risk: Signing did not finish.');
  await expect(page.locator('#lobby')).toContainText('It treats both outcomes as possible and keeps watching until this is settled. Not live.');
  await expect(page.locator('#doing')).toContainText('Signing did not finish.');
  await expect(page.locator('body')).not.toContainText(/nothing was signed/i);
  await expect(page.locator('#lobby .dates')).toContainText('At zero the start is abandoned');
  // pressing Pause now cannot call signatures back; leaving is too late
  await expect(page.locator('#leave')).toHaveCount(0);
});

test('conditions: the live fit line, tightening leaves a lobby, loosening asks for the passphrase; several lobbies at once', async ({ page }, info) => {
  await start(info, ['--fresh-ms', '500']);
  await signIn(page, fake);
  await join(page);
  await page.goto(fake.url + '#/conditions');
  await expect(page.locator('#fitline')).toContainText('1 of 2 lobbies the app knows fit these conditions.');
  await expect(page.locator('#fitline')).toContainText('The limit that excludes most: Joining fee, at most (yours: 2,000)');
  const fee = page.getByLabel('Joining fee, at most');
  // tighten: the app would leave the lobby it is in, and says so before saving
  await fee.fill('1000');
  await expect(page.locator('#cond-warn')).toContainText('Saving this makes the app leave a lobby you joined');
  await expect(page.locator('#fitline')).toContainText('0 of 2 lobbies');
  await page.locator('#save-conditions').click();
  await expect(page.locator('#toasts')).toContainText('Saved. The app left 1 lobby that no longer fit.');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'left');
  // loosen: the program says what loosens; saving needs the person, freshly
  await page.goto(fake.url + '#/conditions');
  await page.getByLabel('Joining fee, at most').fill('5000');
  await expect(page.locator('#cond-warn')).toContainText('This loosens: joining fee, at most.');
  await expect(page.locator('#fitline')).toContainText('2 of 2 lobbies');
  await page.waitForTimeout(600);
  await page.locator('#save-conditions').click();
  const dlg = page.locator('dialog');
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Continue' }).click();
  await expect(dlg).toHaveCount(0);
  await expect(page.getByLabel('Joining fee, at most')).toHaveValue('5000');
  await expect(page.locator('#fitline')).toContainText('2 of 2 lobbies');
  // a value the program does not accept
  await page.getByLabel('Confirmations before live').fill('1');
  await page.locator('#save-conditions').click();
  await expect(page.locator('#cond-msg')).toContainText('fewer confirmations than its own floor');

  // both lobbies fit now: join both
  await page.goto(fake.url + '#/lobby/lob_b19d');
  await joinClick(page);
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await join(page);
  await page.goto(fake.url + '#/');
  await expect(page.locator('main')).toContainText('Tomato Garden, daily factory');
  await expect(page.locator('main')).toContainText('Basil Corner');
  await expect(page.locator('main .pill', { hasText: 'Ready' })).toHaveCount(2);

  // Pause leaves the lobbies that had not started, and says so
  await page.locator('#pause').click();
  await expect(page.locator('#toasts')).toContainText('Paused. Gazpacho left');
  await expect(page.locator('#doing')).toContainText('Paused.');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await joinClick(page);
  await expect(page.locator('#review [data-code="paused"]')).toBeVisible();
});

test('host a lobby: terms with a live preview, open with the passphrase, seats, a member seen to refuse, start, funding by itself, live', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/host');
  await expect(page.locator('main')).toContainText('Every wallet can host.');
  await page.locator('#write-terms').click();
  // the preview is the program's: problems, funding, what members will see
  await expect(page.locator('#preview [data-problem="name_missing"]')).toBeVisible();
  await expect(page.locator('#open-lobby')).toBeDisabled();
  await page.getByLabel('Lobby name').fill('Lemon Yard, first lobby');
  await page.getByLabel(/^Target/).fill('2');
  await expect(page.locator('#preview [data-problem="target_below_minimum"]')).toBeVisible();
  await page.getByLabel(/^Target/).fill('4');
  await expect(page.locator('#preview')).toContainText('These terms can be opened.');
  await expect(page.locator('#preview')).toContainText('3,000,000 sats');
  await expect(page.locator('#preview .sealed')).toContainText('preview, not signed yet');
  await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
  await page.locator('#open-lobby').click();
  const dlg = page.locator('dialog');
  await expect(dlg).toContainText('Opening sets aside 3,000,000 sats');
  await expect(dlg).toContainText('publishes the funding by itself');
  await dlg.getByLabel('Wallet passphrase').fill('not the passphrase at all');
  await dlg.getByRole('button', { name: 'Sign and open' }).click();
  await expect(dlg.locator('[data-code="wrong_passphrase"]')).toBeVisible();
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Sign and open' }).click();

  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'open');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Lemon Yard, first lobby');
  await expect(page.locator('#host-counts')).toContainText('0 ready of 4');
  await expect(page.locator('#start')).toBeDisabled();
  await expect(page.locator('#start-off')).toContainText('fewer than the minimum are ready');
  await openChips(page);
  await expect(page.locator('#chips')).toContainText('Hosting: 1 lobby open, 0 factories');

  // locking is refused while a hosted lobby is open
  await page.goto(fake.url + '#/settings');
  await page.locator('#lock').click();
  await page.locator('dialog').getByRole('button', { name: 'Lock', exact: true }).click();
  await expect(page.locator('#lock-msg [data-code="hosting_lobby_open"]')).toBeVisible();

  // members arrive; one is removed before the start
  await page.goto(fake.url + '#/host/lobby/lob_4c08');
  await fake.cmd('host-seats 3');
  await expect(page.locator('#host-counts')).toContainText('3 ready of 4');
  await expect(page.locator('#seats tbody tr')).toHaveCount(3);
  await page.locator('#seats button[data-remove]').last().click();
  await page.locator('dialog').getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.locator('#host-counts')).toContainText('2 ready of 4');
  await fake.cmd('host-seats 3');
  await expect(page.locator('#start')).toBeEnabled();
  await page.goto(fake.url + '#/');
  await expect(page.locator('#todo li[data-code="host_can_start"]')).toBeVisible();
  await page.locator('#todo li[data-code="host_can_start"]').getByRole('link').click();

  // an early start; a member whose own check fails is seen to leave, and the lobby is Open again
  await page.locator('#start').click();
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'ready_check');
  await expect(page.locator('#cancel')).toHaveCount(0);
  await fake.cmd('host-leave');
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'open');
  await expect(page.locator('#seats tr[data-seat-state="left"]')).toHaveCount(1);
  await expect(page.locator('main')).toContainText('A member left at its own check.');
  await expect(page.locator('main')).toContainText('Nothing was signed with it');

  // the target is reached: the start, the signing and the funding follow by themselves
  await fake.cmd('host-seats 4');
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'ready_check');
  await fake.cmd('step');
  await expect(page.locator('#host-round')).toContainText('Collecting the first round.');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#host-round')).toContainText('Every signature is in.');
  await fake.cmd('step');
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'funding');
  await expect(page.locator('#host-funding')).toContainText('Published by the app itself.');
  await page.locator('#host-funding').getByRole('link', { name: 'Open the factory' }).click();
  await expect(page.locator('#factory')).toHaveAttribute('data-state', 'awaiting_funding');
  await expect(page.locator('#factory')).toContainText('You host');
  await fake.cmd('step');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#factory')).toHaveAttribute('data-state', 'live');
  await page.goto(fake.url + '#/');
  await expect(page.locator('main')).toContainText(/In factories you host\s*3,000,000/);
});

test('a hosted lobby can be cancelled before signing; the coins set aside are free again', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/host/new');
  await page.getByLabel('Lobby name').fill('Short-lived');
  await expect(page.locator('#open-lobby')).toBeEnabled();
  await page.waitForTimeout(1100);
  await page.locator('#open-lobby').click();
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Sign and open' }).click();
  await expect(page.locator('#host-funding')).toContainText('3,000,000 sats');
  await page.locator('#cancel').click();
  await page.locator('dialog').getByRole('button', { name: 'Cancel the lobby' }).click();
  await expect(page.locator('#host-lobby')).toHaveAttribute('data-stage', 'cancelled');
  await page.goto(fake.url + '#/');
  await expect(page.locator('#money-free')).toContainText('42,000,000');
});

test('node busy: the page says so, and the retry is the same request, done once', async ({ page }, info) => {
  await start(info, ['--held-ms', '1500']);
  await signIn(page, fake);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await fake.cmd('hold forever'); // the save is never confirmed: the server answers 503 node_busy
  await joinClick(page);
  await expect(page.locator('#review [data-code="node_busy"]')).toContainText('still saving your last request');
  const first = page.gzRequests.length;
  await fake.cmd('release');
  await page.locator('#join').click(); // the same request id, no passphrase: a replay may omit it (7.4)
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  expect(page.gzRequests.length).toBeGreaterThan(first);
});

test('the chain view in doubt: at risk on every screen, figures marked old, joining refused', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await fake.cmd('chain disagree');
  await expect(page.locator('#alerts .alertbar[data-code="chain_disagree"]')).toContainText('The chain servers disagree.');
  await expect(page.locator('#doing')).toContainText('At risk: the chain view is in doubt.');
  await expect(page.locator('main')).toContainText('These figures may be old.');
  await expect(page.locator('body')).not.toContainText(/has not moved/i);
  await openChips(page);
  await expect(page.locator('#chips')).toContainText('Chain: servers disagree');
  await expect(page.locator('#chips')).toContainText('Watching: nothing to watch');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#alerts .alertbar[data-code="chain_disagree"]')).toBeVisible();
  await joinClick(page);
  await expect(page.locator('#review [data-code="chain_in_doubt"]')).toBeVisible();
  await fake.cmd('chain one_source');
  await expect(page.locator('#alerts .alertbar[data-code="chain_one_source"]')).toContainText('Only one chain server answers.');
  await fake.cmd('chain agree');
  await expect(page.locator('#alerts .alertbar')).toHaveCount(0);
});

test('the event stream drops and resumes: the page says it is behind, then catches up', async ({ page }, info) => {
  const tunnel = await startTunnel();
  try {
    await start(info, ['--tunnel-port', String(tunnel.port)]);
    tunnel.setTarget(fake.port);
    const base = `http://127.0.0.1:${tunnel.port}`;
    allow(info, fake, base);
    await signIn(page, fake, PASS, base + '/');
    await openChips(page);
    await expect(page.locator('#live-chip')).toHaveAttribute('data-state', 'open');
    // the tunnel fails: every connection is cut, and something changes meanwhile
    tunnel.pause(true);
    tunnel.drop();
    await expect(page.locator('#live-chip')).toHaveAttribute('data-state', 'reconnecting');
    await expect(page.locator('#live-chip')).toContainText('what you see may be old');
    await fake.cmd('chain disagree');
    await expect(page.locator('#alerts .alertbar[data-code="chain_disagree"]')).toHaveCount(0);
    tunnel.pause(false);
    // it comes back by itself, and the missed change arrives
    await expect(page.locator('#live-chip')).toHaveAttribute('data-state', 'open', { timeout: 20000 });
    await expect(page.locator('#alerts .alertbar[data-code="chain_disagree"]')).toBeVisible();
    // and it still follows live
    await fake.cmd('chain agree');
    await expect(page.locator('#alerts .alertbar')).toHaveCount(0);
  } finally {
    tunnel.stop();
  }
});

test('the program stops answering: plain words, and a way to try again', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  fake.proc.kill('SIGKILL');
  await page.goto(fake.url + '#/lobbies');
  await expect(page.locator('main')).toContainText('Gazpacho is not answering.');
  await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
});

// ---- review of PR 45: each of these failed before its fix -----------------------------

const LIST_WANT = 'Lobby types I accept: your limit is safety, standard, the lobby offers starter. ' +
  'Payment sizes: your limit is 100 to 200,000, the lobby offers 1,000 to 500,000.';

test('M1: a refusal on a list and a range shows both values: at join, at the check, in the strip and the record', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await fake.cmd('join-refuse-list');
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await joinClick(page);
  await expect(page.locator('#join-msg [data-code="conditions_not_met"]')).toContainText(LIST_WANT);
  await joinClick(page);
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await fake.cmd('member-refuse-list');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'left');
  await expect(page.locator('#lobby .notice.bad').first()).toContainText(LIST_WANT);
  await expect(page.locator('#doing')).toContainText(LIST_WANT);
  await page.goto(fake.url + '#/activity');
  await expect(page.locator('#activity li[data-kind="refused"]').first()).toContainText(LIST_WANT);
  await page.goto(fake.url + '#/activity/act_2001');
  await expect(page.locator('main')).toContainText(LIST_WANT);
});

test('L5: a refusal at a fixed safety check says which check', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await join(page);
  await fake.cmd('member-refuse-safety');
  await fake.cmd('step');
  await fake.cmd('step');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'left');
  await expect(page.locator('#lobby .notice.bad').first()).toContainText('A fixed safety check failed.');
  await expect(page.locator('#lobby .notice.bad').first()).toContainText('Nothing was signed. Nothing moved.');
  await expect(page.locator('#checks li[data-check="safety_checks"]')).toHaveAttribute('data-ok', 'no');
});

test('L4b: a request kept after node busy is never sent again with a different body', async ({ page }, info) => {
  await start(info, ['--held-ms', '1500']);
  await signIn(page, fake);
  await join(page);
  await fake.cmd('hold forever');
  await page.locator('#ready-toggle').click(); // "I am not ready"
  await expect(page.locator('#seat-msg [data-code="node_busy"]')).toBeVisible();
  await fake.cmd('release');
  await fake.cmd('hold off');
  await fake.cmd('chain lagging'); // an event: the screen is drawn again, now "not ready"
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'joined_not_ready');
  await readyAgain(page); // "I am ready": a request of its own
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  await expect(page.locator('[data-code="request_id_reused"]')).toHaveCount(0);
});

test('L6: a held call waits for its save under the default limits (held_ms is 30 s, not 0)', async ({ page }, info) => {
  await start(info); // no --held-ms: the server's own default
  await signIn(page, fake);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await fake.cmd('hold on');
  await joinClick(page);
  await page.waitForTimeout(4000);
  await expect(page.locator('#join-msg [data-code]')).toHaveCount(0);
  await expect(page.locator('#join')).toBeDisabled();
  await fake.cmd('hold off');
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
});

test('L2b: a new receiving address stays on screen when the screen is drawn again', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/settings');
  await page.getByRole('button', { name: 'Show a new address' }).click();
  const addr = await page.locator('#address pre').innerText();
  expect(addr).toMatch(/^tb1p/);
  await page.locator('#onchain').evaluate((e) => e.setAttribute('data-old', '1'));
  await fake.cmd('chain lagging');
  await expect(page.locator('#onchain[data-old]')).toHaveCount(0); // drawn again
  await expect(page.locator('#address pre')).toHaveText(addr);
});

test('L2: the 24 words shown from Settings stay through a dropped and resumed stream', async ({ page }, info) => {
  const tunnel = await startTunnel();
  try {
    await start(info, ['--tunnel-port', String(tunnel.port)]);
    tunnel.setTarget(fake.port);
    const base = `http://127.0.0.1:${tunnel.port}`;
    allow(info, fake, base);
    await signIn(page, fake, PASS, base + '/');
    await page.goto(base + '/#/settings/words');
    await page.getByRole('button', { name: 'Show the 24 words' }).click();
    await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
    await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
    await page.locator('dialog').getByRole('button', { name: 'Show the words' }).click();
    await page.getByRole('button', { name: 'Show the words' }).click();
    await expect(page.locator('ol.words li')).toHaveCount(24);
    tunnel.pause(true);
    tunnel.drop();
    await expect(page.locator('#live-chip')).toHaveAttribute('data-state', 'reconnecting');
    tunnel.pause(false);
    await expect(page.locator('#live-chip')).toHaveAttribute('data-state', 'open', { timeout: 20000 });
    await page.waitForTimeout(800); // the reset that follows a reconnect
    await expect(page.locator('ol.words li')).toHaveCount(24);
  } finally {
    tunnel.stop();
  }
});

test('M17: the retry after node busy carries the same request id, and acts once', async ({ page }, info) => {
  await start(info, ['--held-ms', '1500']);
  await signIn(page, fake);
  const ids = [];
  page.on('request', (r) => { if (r.url().endsWith('/join')) ids.push(JSON.parse(r.postData()).request_id); });
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await fake.cmd('hold forever');
  await joinClick(page);
  await expect(page.locator('#join-msg [data-code="node_busy"]')).toBeVisible();
  await fake.cmd('release');
  await fake.cmd('hold off');
  await page.locator('#join').click(); // the same request id, no passphrase: a replay may omit it (7.4)
  await expect(page.locator('#lobby')).toHaveAttribute('data-seat', 'ready');
  expect(ids).toHaveLength(2);
  expect(ids[1]).toBe(ids[0]);
});
