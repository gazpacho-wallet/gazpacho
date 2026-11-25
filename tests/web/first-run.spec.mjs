// SPDX-License-Identifier: MIT
// First run through the interface: create or restore a wallet, the 24 words,
// the backup check, the passphrase (spec/local-api.md 4.3, 12). TEST ONLY.
import { readFileSync } from 'node:fs';
import { test, expect, startFake, allow, FAKE, WORDS } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');

let fake;
test.beforeEach(async ({}, info) => {
  fake = await startFake();
  allow(info, fake);
});
test.afterEach(() => fake && fake.stop());

// Open the program's redirect file, as the program does at first run.
async function openFromProgram(page) {
  await page.goto('file://' + fake.redirectFile);
  await expect(page.getByRole('heading', { name: 'Welcome to Gazpacho' })).toBeVisible();
}

async function secretsNowhere(page, secrets) {
  const held = await page.evaluate(() => ({
    html: document.documentElement.outerHTML,
    values: Array.from(document.querySelectorAll('input, textarea')).map((i) => i.value).join('\n'),
    session: JSON.stringify(Object.entries(sessionStorage)),
    local: JSON.stringify(Object.entries(localStorage)),
    history: JSON.stringify(history.state),
    title: document.title,
    url: location.href,
  }));
  for (const s of secrets) {
    for (const [where, text] of Object.entries(held)) expect(text, `a secret in ${where}`).not.toContain(s);
  }
}

test('create a wallet: six generated words first, the 24 words, the check, a preset', async ({ page }) => {
  const token = readFileSync(fake.redirectFile, 'utf8').match(/#start=([A-Za-z0-9_-]{43})/)[1];
  await openFromProgram(page);
  // the start token is out of the address at once, and was never in a request address
  expect(page.url()).toBe(fake.url);
  expect(page.gzRequests.join('\n')).not.toContain(token);
  // nothing asks "member or host"
  await expect(page.locator('main')).not.toContainText(/member or host/i);
  await expect(page.getByText('Real bitcoin (mainnet) is switched off in this release.')).toBeVisible();

  await page.getByRole('button', { name: 'Make a new wallet' }).click();
  const six = (await page.locator('#sixwords').innerText()).trim();
  expect(six.split(' ')).toHaveLength(6);
  expect(six.length).toBeGreaterThanOrEqual(15);
  // typed wrongly: refused in the page
  await page.getByLabel(/Type the six words once/).fill('not the six words at all');
  await page.getByRole('button', { name: 'Make the wallet' }).click();
  await expect(page.getByText('That is not the six words shown.')).toBeVisible();
  await page.getByLabel(/Type the six words once/).fill(six);
  await page.getByRole('button', { name: 'Make the wallet' }).click();

  // the 24 words: not in the page until asked for, not selectable, no copy control
  const list = page.locator('ol.words');
  await expect(page.getByRole('button', { name: 'Show the words' })).toBeVisible();
  await expect(list.locator('li')).toHaveCount(0);
  await page.getByRole('button', { name: 'Show the words' }).click();
  await expect(list.locator('li')).toHaveCount(24);
  await expect(list.locator('li').nth(23)).toHaveText('art');
  expect(await list.evaluate((el) => getComputedStyle(el).userSelect)).toBe('none');
  await expect(page.getByRole('button', { name: /copy/i })).toHaveCount(0);
  await expect(page.getByText(/only when you restore a wallet, or right after showing them/).first()).toBeVisible();
  await secretsNowhere(page, [six]);

  // on to the check: the words leave the page
  await page.getByRole('button', { name: 'I wrote them down: check them' }).click();
  await expect(page.getByRole('button', { name: 'Check', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.outerHTML)).not.toMatch(/abandon|>art</);
  const fields = page.locator('input[data-word]');
  await expect(fields).toHaveCount(3);
  for (let i = 0; i < 3; i++) {
    const pos = Number(await fields.nth(i).getAttribute('data-word'));
    await expect(fields.nth(i)).toHaveAttribute('autocomplete', 'off');
    await expect(fields.nth(i)).toHaveAttribute('spellcheck', 'false');
    await expect(fields.nth(i)).toHaveAttribute('autocapitalize', 'off');
    await expect(fields.nth(i)).toHaveAttribute('autocorrect', 'off');
    await fields.nth(i).fill(WORDS[pos - 1]);
  }
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText('Your words are written down correctly.')).toBeVisible();

  await page.getByLabel('Everyday').check();
  await page.getByRole('button', { name: 'Use this preset' }).click();
  await expect(page.getByText(/dedicated to the developers/)).toBeVisible();
  await page.getByRole('button', { name: 'Go to Home' }).click();
  await expect(page.locator('#doing')).toContainText('Not in a factory');
  await expect(page.locator('#network')).toHaveText('Signet: test coins, no value');
  await expect(page.locator('#todo')).not.toContainText('24 words have not been checked');
  await secretsNowhere(page, [six, 'abandon']);
  // the session token is in sessionStorage only, and the page set no cookie
  const store = await page.evaluate(() => ({ s: Object.keys(sessionStorage), cookie: document.cookie }));
  expect(store.s).toEqual(['gz-session']);
  expect(store.cookie).toBe('');
});

test('a failed check never says which word was wrong, and signs the browser out', async ({ page }) => {
  await openFromProgram(page);
  await page.getByRole('button', { name: 'Make a new wallet' }).click();
  const six = (await page.locator('#sixwords').innerText()).trim();
  await page.getByLabel(/Type the six words once/).fill(six);
  await page.getByRole('button', { name: 'Make the wallet' }).click();
  await page.getByRole('button', { name: 'I wrote them down: check them' }).click();
  const fields = page.locator('input[data-word]');
  await expect(fields).toHaveCount(3);
  for (let i = 0; i < 3; i++) await fields.nth(i).fill('zebra');
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText(/The words did not match, so Gazpacho signed this browser out/)).toBeVisible();
  await expect(page.locator('main')).not.toContainText(/Word \d+ (is|was) wrong/);
  // signing in again leads back into setup, where the words can be shown again with the passphrase
  await page.waitForTimeout(1100);
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByText('setting it up was not finished')).toBeVisible();
  await page.getByRole('button', { name: 'Show the 24 words' }).click();
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.getByRole('button', { name: 'Show the words', exact: true }).click();
  await page.getByRole('button', { name: 'Show the words', exact: true }).click();
  await expect(page.locator('ol.words li')).toHaveCount(24);
});

test('the 24 words leave the page: hidden with the tab, shown again, gone after Done and after leaving', async ({ page }) => {
  await openFromProgram(page);
  await page.getByRole('button', { name: 'Make a new wallet' }).click();
  const six = (await page.locator('#sixwords').innerText()).trim();
  await page.getByLabel(/Type the six words once/).fill(six);
  await page.getByRole('button', { name: 'Make the wallet' }).click();
  await page.getByRole('button', { name: 'Show the words' }).click();
  await expect(page.locator('ol.words li')).toHaveCount(24);
  const inDom = () => page.evaluate(() => /abandon/.test(document.documentElement.outerHTML));
  expect(await inDom()).toBe(true);
  // the tab is hidden: the text nodes go
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(page.locator('ol.words li')).toHaveCount(0);
  expect(await inDom()).toBe(false);
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.getByRole('button', { name: 'Show again' }).click();
  await expect(page.locator('ol.words li')).toHaveCount(24);
  // Done: cleared for good
  await page.getByRole('button', { name: 'Done, check later' }).click();
  await expect(page.getByRole('button', { name: 'Use this preset' })).toBeVisible();
  expect(await inDom()).toBe(false);
  await page.getByRole('button', { name: 'Use this preset' }).click();
  await page.getByRole('button', { name: 'Go to Home' }).click();
  await expect(page.locator('#todo')).toContainText('24 words have not been checked');

  // from Settings: shown only with the passphrase typed for that request, gone on leaving the view
  await page.goto(fake.url + '#/settings/words');
  await page.getByRole('button', { name: 'Show the 24 words' }).click();
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.locator('dialog').getByRole('button', { name: 'Show the words' }).click();
  await page.getByRole('button', { name: 'Show the words' }).click();
  await expect(page.locator('ol.words li')).toHaveCount(24);
  await page.locator('nav.side a[data-nav="home"], nav.tabs a[data-nav="home"]').locator('visible=true').first().click();
  await expect(page.getByRole('heading', { name: 'Home' })).toBeVisible();
  expect(await inDom()).toBe(false);
  // and when the page is hidden for good
  await page.goto(fake.url + '#/settings/words');
  await page.getByRole('button', { name: 'Show the 24 words' }).click();
  await page.getByLabel('Password', { exact: true }).fill(six);
  await page.locator('dialog').getByRole('button', { name: 'Show the words' }).click();
  await page.getByRole('button', { name: 'Show the words' }).click();
  await expect(page.locator('ol.words li')).toHaveCount(24);
  await page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
  await expect(page.locator('ol.words li')).toHaveCount(0);
  expect(await inDom()).toBe(false);
});

test('restore from 24 words: a wrong word, a weak password, then the restored wallet', async ({ page }) => {
  await openFromProgram(page);
  await page.getByRole('button', { name: 'Restore from 24 words' }).click();
  const fields = page.locator('input[data-word]');
  await expect(fields).toHaveCount(24);
  // the page offers matching words from the 24-word list itself
  await fields.nth(0).fill('aban');
  await page.getByRole('button', { name: 'abandon', exact: true }).click();
  await expect(fields.nth(0)).toHaveValue('abandon');
  for (let i = 1; i < 24; i++) await fields.nth(i).fill(i === 23 ? 'about' : 'abandon');
  await page.getByRole('button', { name: 'Next: choose a password' }).click();
  await page.getByRole('button', { name: 'Choose my own' }).click();
  await page.getByLabel('Your own password').fill('a long enough passphrase');
  await page.getByLabel('The same password again').fill('a long enough passphrase');
  await page.getByRole('button', { name: 'Restore the wallet' }).click();
  await expect(page.getByText(/These 24 words do not belong together/)).toBeVisible();
  await page.getByRole('button', { name: 'Type the 24 words again' }).click();
  await expect(fields).toHaveCount(24);
  for (let i = 0; i < 24; i++) await fields.nth(i).fill(WORDS[i]);
  await page.getByRole('button', { name: 'Next: choose a password' }).click();
  await page.getByRole('button', { name: 'Choose my own' }).click();
  await page.getByLabel('Your own password').fill('too short');
  await expect(page.getByText('9 of 15 characters.')).toBeVisible();
  await page.getByLabel('The same password again').fill('too short');
  await page.getByRole('button', { name: 'Restore the wallet' }).click();
  await expect(page.getByText('This password is too short (9 of 15 characters).')).toBeVisible();
  await page.waitForTimeout(1100);
  await page.getByLabel('Your own password').fill('a long enough passphrase');
  await page.getByLabel('The same password again').fill('a long enough passphrase');
  await page.getByRole('button', { name: 'Restore the wallet' }).click();
  // restoring: never "your wallet is fine", and nothing is said to be watched
  await expect(page.locator('#restoring')).toContainText('Your balance is not confirmed yet.');
  await expect(page.locator('#restoring')).toContainText('Not known and not watched');
  await expect(page.locator('#doing')).toContainText('Restoring.');
  await fake.cmd('restore-done');
  await expect(page.getByRole('button', { name: 'Use this preset' })).toBeVisible();
  await page.getByRole('button', { name: 'Use this preset' }).click();
  await page.getByRole('button', { name: 'Go to Home' }).click();
  await expect(page.locator('#doing')).toContainText('Not in a factory');
  await secretsNowhere(page, ['a long enough passphrase', 'abandon']);
});

test('without the start link nothing can be made; a wrong code is refused', async ({ page }) => {
  await page.goto(fake.url);
  await expect(page.getByRole('heading', { name: 'Open Gazpacho from the program' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Make a new wallet' })).toHaveCount(0);
  await page.getByLabel('First-run code').fill('ABCDE-FGHJK');
  await page.getByRole('button', { name: 'Use this code' }).click();
  await expect(page.locator('[data-code="bad_code"]')).toBeVisible();
  // a fragment that is not a start token is never presented
  await page.goto(fake.url + '#start=junk');
  await expect(page.getByRole('heading', { name: 'Open Gazpacho from the program' })).toBeVisible();
  expect(page.url()).toBe(fake.url);
});

test('a start link used before: the hijack warning, in place of every other screen', async ({ page, browser }) => {
  const token = readFileSync(fake.redirectFile, 'utf8').match(/#start=([A-Za-z0-9_-]{43})/)[1];
  const other = await browser.newContext();
  const first = await other.newPage();
  await first.goto(fake.url + '#start=' + token);
  await expect(first.getByRole('heading', { name: 'Welcome to Gazpacho' })).toBeVisible();
  await page.goto(fake.url + '#start=' + token);
  await expect(page.getByRole('heading', { name: 'Do not use this wallet' })).toBeVisible();
  await expect(page.getByText(/Someone may have used this program's start link before you/)).toBeVisible();
  await expect(page.getByRole('button')).toHaveCount(1); // the theme switch only
  await other.close();
});

// Owner, 2026-11-25: the step says once, plainly, what the password is and is not.
test('the password step: called a password, said once to lock the files here and not to be part of the seed', async ({ page }) => {
  await openFromProgram(page);
  await expect(page.locator('ol.steps h2').nth(1)).toHaveText('Choose a password');
  await page.getByRole('button', { name: 'Make a new wallet' }).click();
  const step = page.locator('ol.steps li.cur');
  await expect(step.locator('h2')).toHaveText('Choose a password');
  await expect(step).toContainText('Gazpacho made a password for you: six words.');
  const about = 'Your password opens Gazpacho and locks its files on this computer. It is not part of your seed: your 24 words alone restore your wallet.';
  await expect(step.getByText(about, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Choose my own' }).click();
  await expect(step.getByText(about, { exact: true })).toBeVisible(); // the same once, whichever way is chosen
  await expect(step.getByText(about, { exact: true })).toHaveCount(1);
  expect(await page.locator('body').innerText()).not.toMatch(/passphrase/i);
});
