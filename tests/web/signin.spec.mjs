// SPDX-License-Identifier: MIT
// Sign-in, sign-out, lock, idle, fresh sign-in, other tabs (spec/local-api.md 4). TEST ONLY.
import { test, expect, startFake, allow, signIn, FAKE, PASS } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');

let fake;
test.afterEach(() => fake && fake.stop());
async function start(info, args) {
  fake = await startFake({ locked: true, args });
  allow(info, fake);
}

async function passphraseNowhere(page) {
  const held = await page.evaluate(() => ({
    html: document.documentElement.outerHTML,
    values: Array.from(document.querySelectorAll('input')).map((i) => i.value).join('\n'),
    session: JSON.stringify(Object.entries(sessionStorage)),
    local: JSON.stringify(Object.entries(localStorage)),
    history: JSON.stringify(history.state),
  }));
  for (const [where, text] of Object.entries(held)) expect(text, 'the passphrase in ' + where).not.toContain(PASS);
}

test('a wrong passphrase, then the delay, then the right one', async ({ page }, info) => {
  await start(info);
  await page.goto(fake.url);
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await expect(page.locator('#locked-headline')).toContainText('Locked.');
  const field = page.getByLabel('Wallet passphrase');
  await expect(field).toHaveAttribute('type', 'password');
  await expect(field).toHaveAttribute('autocomplete', 'current-password');
  const go = page.getByRole('button', { name: 'Unlock' });

  await field.fill('this is not the passphrase');
  await go.click();
  await expect(page.locator('[data-code="wrong_passphrase"]')).toHaveText('That passphrase is not right. Nothing was done.');
  await expect(field).toHaveValue(''); // emptied as soon as it was sent
  // Six wrong in a row: from the fifth on the delay doubles (4.3), so the next
  // try, made at once, is certainly inside it, however slow this machine is.
  for (let wrong = 1; wrong < 6;) {
    await expect(go).toBeEnabled({ timeout: 20000 });
    await field.fill('this is not the passphrase');
    await go.click();
    const note = page.locator('[data-code="wrong_passphrase"], [data-code="rate_limited"]');
    await expect(note).toBeVisible();
    if ((await note.getAttribute('data-code')) === 'wrong_passphrase') wrong++;
  }
  // at once again, even with the right passphrase: refused before any check, the wait said, the button held
  await field.fill(PASS);
  await go.click();
  await expect(page.locator('[data-code="rate_limited"]')).toContainText(/Too many tries\. Wait \d+ (seconds?|minutes?)/);
  await expect(go).toBeDisabled();
  await expect(page.getByText(/You can try again in/)).toBeVisible();
  await expect(go).toBeEnabled({ timeout: 30000 });
  await field.fill(PASS);
  await go.click();
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
  await expect(page.locator('#doing')).toContainText('Not in a factory');
  await passphraseNowhere(page);
  // sign-in by the keyboard alone works too (checked in quality.spec.mjs)
});

test('sign out: the wallet stays unlocked; lock: it does not', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/settings');
  await page.locator('#sign-out').click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.locator('#locked-headline')).toHaveText('The wallet is still unlocked and keeps working. This browser is signed out.');
  expect(await page.evaluate(() => sessionStorage.getItem('gz-session'))).toBeNull();
  await page.waitForTimeout(1100);
  await page.getByLabel('Wallet passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');

  await page.locator('#lock').click();
  await expect(page.locator('dialog')).toContainText('joins nothing, signs nothing and answers no host');
  await page.locator('dialog').getByRole('button', { name: 'Lock', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await expect(page.getByText('The wallet was locked.')).toBeVisible();
  await expect(page.locator('#locked-headline')).toContainText('Locked.');
  // no screen of this build promises that a locked wallet leaves in time
  await expect(page.locator('main')).not.toContainText(/leave in time|will leave/i);
});

test('lock during a call: the page ends on the unlock screen, not on a broken one', async ({ page, request }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.goto(fake.url + '#/lobby/lob_7k2q');
  await expect(page.locator('#join')).toBeEnabled();
  await fake.cmd('hold on'); // the join's save is not confirmed: the call stays open
  await page.waitForTimeout(1100); // one passphrase attempt a second (4.3)
  await page.locator('#join').click();
  await page.locator('dialog').getByLabel('Wallet passphrase').fill(PASS);
  await page.locator('dialog').getByRole('button', { name: 'Join', exact: true }).click();
  await expect(page.locator('#join')).toBeDisabled();
  // meanwhile the wallet is locked from another session
  await page.waitForTimeout(1100);
  const headers = { Origin: fake.origin, 'Content-Type': 'application/json' };
  const s = await request.post(fake.url + 'api/v1/session', { headers, data: { passphrase: PASS } });
  expect(s.status()).toBe(200);
  const token = (await s.json()).session;
  const l = await request.post(fake.url + 'api/v1/wallet/lock', { headers: { ...headers, 'X-Gazpacho-Session': token }, data: { confirm: 'lock_wallet' } });
  expect(l.status()).toBe(202);
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await fake.cmd('hold off');
  await expect(page.locator('dialog')).toHaveCount(0); // the join's passphrase dialog went with the session
  await expect(page.getByLabel('Wallet passphrase')).toBeVisible();
  await page.waitForTimeout(1100);
  await page.getByLabel('Wallet passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
});

test('idle: the browser is signed out with events flowing, and the wallet keeps working', async ({ page }, info) => {
  await start(info, ['--idle-ms', '3000']);
  await signIn(page, fake);
  // events keep arriving and the page keeps refreshing, without input: that must not keep the session awake
  for (let i = 0; i < 4; i++) {
    await fake.cmd(i % 2 ? 'chain agree' : 'chain lagging');
    await page.waitForTimeout(700);
  }
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('#locked-headline')).toContainText('still unlocked and keeps working');
});

test('a fresh sign-in is asked for when the program wants one, and the action then goes through', async ({ page }, info) => {
  await start(info, ['--fresh-ms', '500']);
  await signIn(page, fake);
  await page.locator('#pause').click();
  await expect(page.locator('#doing')).toContainText('Paused.');
  await expect(page.locator('#pause')).toHaveText('Resume');
  await page.waitForTimeout(1200);
  await page.locator('#pause').click(); // resume needs the person, freshly (4.8)
  const dlg = page.locator('dialog');
  await expect(dlg).toContainText('Type your passphrase again');
  await dlg.getByLabel('Wallet passphrase').fill('wrong wrong wrong wrong');
  await dlg.getByRole('button', { name: 'Continue' }).click();
  await expect(dlg.locator('[data-code="wrong_passphrase"]')).toBeVisible();
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Continue' }).click();
  await expect(dlg).toHaveCount(0);
  await expect(page.locator('#pause')).toHaveText('Pause');
  await expect(page.locator('#doing')).not.toContainText('Paused.');
  await passphraseNowhere(page);
});

test('files older than the wallet: stay locked, or start them as a restore with the passphrase', async ({ page }, info) => {
  await start(info);
  await fake.cmd('files-behind'); // the next unlock finds the files behind (4.7)
  await page.goto(fake.url);
  await page.getByLabel('Wallet passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('heading', { name: 'These files are older than this wallet' })).toBeVisible();
  await expect(page.locator('main')).toContainText('Gazpacho has not started the wallet.');
  await expect(page.locator('main')).not.toContainText(/your wallet is fine/i);
  // stay locked: nothing changes, and the unlock screen says why it is locked
  await page.getByRole('button', { name: 'Stay locked' }).click();
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await expect(page.locator('#locked-headline')).toContainText("These files are older than this wallet's last saved state.");
  await page.waitForTimeout(1100);
  await page.getByLabel('Wallet passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Unlock' }).click();
  // start as a restore: the passphrase in the request, after a warning that it cannot be undone
  await page.getByRole('button', { name: 'Start these files as a restore' }).click();
  const dlg = page.locator('dialog');
  await expect(dlg).toContainText('This cannot be undone.');
  await page.waitForTimeout(1100);
  await dlg.getByLabel('Wallet passphrase').fill(PASS);
  await dlg.getByRole('button', { name: 'Start as a restore' }).click();
  await expect(page.locator('#restoring')).toContainText('Your balance is not confirmed yet.');
  await expect(page.locator('#doing')).toContainText('Restoring.');
});

test('a second tab takes the session from the first; signing out in one signs out both', async ({ page, context }, info) => {
  await start(info);
  await signIn(page, fake);
  const second = await context.newPage();
  await second.goto(fake.url);
  await expect(second.locator('body')).toHaveAttribute('data-chrome', 'app'); // no passphrase typed
  await expect(second.locator('#doing')).toContainText('Not in a factory');
  await second.goto(fake.url + '#/settings');
  await second.locator('#sign-out').click();
  await expect(second.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
});

// Owner, 2026-11-25: the secret is a password, as in Sparrow, Electrum, Ledger
// Live and Trezor Suite. "Passphrase" means the BIP39 seed extension in
// Bitcoin, and the sign-in screen must not read as asking for the seed.
test('the sign-in screen is minimal: one field named Password, no seed wording, the empty-field error', async ({ page }, info) => {
  await start(info);
  await page.goto(fake.url);
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await expect(page.locator('#locked-headline')).toContainText('Locked.');
  const text = await page.locator('body').innerText();
  expect(text).not.toMatch(/passphrase/i);
  expect(text).not.toMatch(/seed/i);
  expect(text).not.toMatch(/24 words/i);
  const inputs = page.locator('input');
  await expect(inputs).toHaveCount(1);
  await expect(inputs).toHaveAttribute('type', 'password');
  await expect(inputs).toHaveAccessibleName('Password');
  await expect(page.getByRole('link', { name: 'Forgot your password?' })).toBeVisible();
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText('Enter your password.', { exact: true })).toBeVisible();
  expect(await page.locator('body').innerText()).not.toMatch(/passphrase|seed|24 words/i);
});

test('"Forgot your password?" leads to restoring from the 24 words, and the restore it names is there at first run', async ({ page }, info) => {
  await start(info);
  await page.goto(fake.url);
  await page.getByLabel('Password', { exact: true }).fill('typed, then left');
  await page.getByRole('link', { name: 'Forgot your password?' }).click();
  await expect(page.getByRole('heading', { name: 'Forgot your password?' })).toBeVisible();
  const forgot = page.locator('#forgot-page');
  await expect(forgot).toContainText('Your 24 words restore the wallet on this computer, with a new password.');
  await expect(forgot).toContainText('choose Restore from 24 words');
  await expect(forgot).toContainText('not your place in a factory');
  await expect(page.locator('input')).toHaveCount(0); // no field for the words, or anything else, here (5.7)
  expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toContain('typed, then left');
  await page.getByRole('button', { name: 'Back' }).click();
  await expect(page.getByRole('heading', { name: 'Unlock Gazpacho' })).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');

  // the way it names: a data folder with no wallet opens on first run, with "Restore from 24 words"
  const fresh = await startFake();
  allow(info, fresh);
  try {
    await page.goto('file://' + fresh.redirectFile);
    await expect(page.getByRole('heading', { name: 'Welcome to Gazpacho' })).toBeVisible();
    await page.getByRole('button', { name: 'Restore from 24 words' }).click();
    await expect(page.locator('input[data-word]')).toHaveCount(24);
    await expect(page.getByText(/Gazpacho asks for your 24 words only when you restore a wallet/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Next: choose a password' })).toBeVisible();
  } finally {
    fresh.stop();
  }
});
