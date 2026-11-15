// SPDX-License-Identifier: MIT
// Browser security and quality of the interface itself: the headers its files
// are served with, no request to any other host, no HTML sinks at work, mainnet
// refused, unknown states never shown as success, keyboard, labels, phone
// width, light and dark. TEST ONLY.
import { createServer } from 'node:http';
import { test, expect, startFake, allow, signIn, FAKE, PASS } from './helpers.mjs';

test.skip(!FAKE, 'GZ_API_FAKE is not set');

let fake;
test.afterEach(() => fake && fake.stop());
async function start(info, args) {
  fake = await startFake({ locked: true, args });
  allow(info, fake);
}

test('the pages are served under the strict policy, and every file with its type', async ({ page, request }, info) => {
  await start(info);
  const res = await page.goto(fake.url);
  const hd = res.headers();
  const csp = hd['content-security-policy'];
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("script-src 'self'");
  expect(csp).toContain("style-src 'self'");
  expect(csp).toContain("connect-src 'self'");
  expect(csp).toContain("form-action 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("require-trusted-types-for 'script'");
  expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|data:|blob:|https?:/);
  expect(hd['cache-control']).toBe('no-store');
  expect(hd['x-content-type-options']).toBe('nosniff');
  expect(hd['cross-origin-resource-policy']).toBe('same-origin');
  expect(hd['set-cookie']).toBeUndefined();
  // the page's own markup: no inline script, style or handler
  const html = await res.text();
  expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
  expect(html).not.toMatch(/\son[a-z]+\s*=|\sstyle\s*=|<style/i);
  const files = [...html.matchAll(/(?:src|href)="(\/[^"]+)"/g)].map((m) => m[1]);
  expect(files.length).toBeGreaterThan(10);
  for (const f of files) {
    const r = await request.get(fake.origin + f, { headers: { 'Sec-Fetch-Site': 'same-origin' } });
    expect(r.status(), f).toBe(200);
    expect(r.headers()['content-type'], f).toBe(f.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8');
    expect(r.headers()['x-content-type-options']).toBe('nosniff');
    expect(r.headers()['content-security-policy']).toBe("default-src 'none'; frame-ancestors 'none'");
    expect(r.headers()['cache-control']).toBe('no-store');
  }
  // only exact paths are served; another site cannot load a script from here
  expect((await request.get(fake.origin + '/js/nothing.js')).status()).toBe(404);
  expect((await request.get(fake.origin + '/js/app.js?x=1')).status()).toBe(404);
  expect((await request.get(fake.origin + '/js/app.js', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status()).toBe(403);
  // the HTML sinks are shut in this browser: assigning markup throws instead of running
  const sink = await page.evaluate(() => {
    try { document.createElement('div').innerHTML = '<img src=x onerror=alert(1)>'; return 'assigned'; } catch (e) { return 'refused'; }
  });
  info.annotations.push({ type: 'Trusted Types refuse innerHTML', description: sink });
  expect(sink).toBe('refused');
  // recorded for the hand-off: under this policy a page cannot create its SharedWorker from a plain address
  const worker = await page.evaluate(() => {
    try { new SharedWorker('/js/util.js'); return 'created'; } catch (e) { return 'refused: ' + e.name; }
  });
  info.annotations.push({ type: 'SharedWorker under the page policy', description: worker });
  page.gzProblems.length = 0; // the two refusals above are this test's own doing
});

test('through every screen, no request goes to any host but the local API', async ({ page, context }, info) => {
  await start(info);
  // another server on loopback stands for "anything else": it must hear nothing
  const heard = [];
  const other = createServer((req, res) => { heard.push(req.url); res.end('x'); });
  await new Promise((ok) => other.listen(0, '127.0.0.1', ok));
  const seen = [];
  context.on('request', (r) => seen.push(r.url()));
  try {
    await signIn(page, fake);
    for (const route of ['#/', '#/lobbies', '#/lobby/lob_7k2q', '#/lobby/lob_b19d', '#/conditions', '#/activity', '#/activity/act_1182',
      '#/host', '#/host/new', '#/settings', '#/settings/words', '#/about']) {
      await page.goto(fake.url + route);
      await expect(page.locator('main h1')).toBeVisible();
      await expect(page.locator('main')).not.toContainText('Loading');
      await expect(page.locator('main .notice.bad[data-code]')).toHaveCount(0);
    }
    await page.locator('#theme').click();
    expect(seen.length).toBeGreaterThan(30);
    for (const u of seen) expect(new URL(u).origin, u).toBe(fake.origin);
    expect(heard).toEqual([]);
    // nothing but the session token and the theme is kept by the page
    const kept = await page.evaluate(() => ({ s: Object.keys(sessionStorage), l: Object.keys(localStorage), c: document.cookie }));
    expect(kept).toEqual({ s: ['gz-session'], l: ['gz-theme'], c: '' });
    expect(await page.evaluate(() => sessionStorage.getItem('gz-session'))).toMatch(/^[A-Za-z0-9_-]{43}$/);
  } finally {
    other.close();
  }
});

test('mainnet is refused: the interface opens no wallet on a network with real bitcoin', async ({ page }, info) => {
  await start(info);
  await page.route('**/api/v1/version', (r) => r.fulfill({ json: { api: '1.0', program: '0.1.0', network: 'mainnet', run_id: 'x' } }));
  await page.goto(fake.url);
  await expect(page.getByRole('heading', { name: 'Gazpacho does not run on mainnet' })).toBeVisible();
  await expect(page.getByLabel('Wallet passphrase')).toHaveCount(0);
});

test('a state this page does not know is shown as unknown, never as success', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  await page.route('**/api/v1/status', async (r) => {
    const res = await r.fetch();
    const j = await res.json();
    j.doing = { code: 'brand_new_state', lobby_id: null, params: {}, since_at: null };
    j.watching.state = 'some_new_watcher';
    await r.fulfill({ response: res, json: j });
  });
  await page.goto(fake.url + '#/settings');
  await page.goto(fake.url + '#/');
  await expect(page.locator('#doing')).toContainText('Unknown state (brand_new_state).');
  await expect(page.locator('#next')).toContainText('Unknown state (brand_new_state).');
  await expect(page.locator('#chips')).toContainText('unknown state (some_new_watcher)');
});

test('keyboard: skip link first, sign in without a mouse, focus is always visible', async ({ page }, info) => {
  await start(info);
  await page.goto(fake.url);
  await expect(page.getByLabel('Wallet passphrase')).toBeFocused();
  await page.keyboard.type(PASS);
  await page.keyboard.press('Enter');
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
  await expect(page.locator('main h1')).toBeFocused(); // a new screen puts focus on its heading
  // tab through the frame: every stop shows a focus ring
  expect(await page.evaluate(() => document.querySelector('a[href], button, input') === document.querySelector('a.skip'))).toBe(true);
  await page.locator('a.skip').focus();
  expect((await page.locator('a.skip').boundingBox()).x).toBeGreaterThanOrEqual(0); // it shows when it has focus
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeFocused();
  await page.locator('a.skip').focus();
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press('Tab');
    const ring = await page.evaluate(() => {
      const el = document.activeElement, cs = getComputedStyle(el);
      return { tag: el.tagName, style: cs.outlineStyle, width: parseFloat(cs.outlineWidth) };
    });
    expect(ring.style, 'focus ring on ' + ring.tag).not.toBe('none');
    expect(ring.width).toBeGreaterThanOrEqual(2);
  }
  // Pause and a dialog by keyboard: Escape closes it and nothing was done
  await page.goto(fake.url + '#/settings');
  await page.locator('#lock').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('dialog')).toHaveCount(0);
  await expect(page.locator('body')).toHaveAttribute('data-chrome', 'app');
});

test('every field has a label, every button a name, on every screen', async ({ page }, info) => {
  await start(info);
  await signIn(page, fake);
  for (const route of ['#/', '#/lobbies', '#/lobby/lob_7k2q', '#/conditions', '#/activity', '#/host', '#/host/new', '#/settings', '#/settings/words']) {
    await page.goto(fake.url + route);
    await expect(page.locator('main h1')).toBeVisible();
    const bad = await page.evaluate(() => {
      const out = [];
      for (const el of document.querySelectorAll('input, select, textarea')) {
        const named = (el.labels && el.labels.length) || el.getAttribute('aria-label') || el.getAttribute('aria-labelledby');
        if (!named) out.push('no label: ' + el.outerHTML.slice(0, 80));
      }
      for (const el of document.querySelectorAll('button, a[href]')) {
        if (!(el.textContent || '').trim() && !el.getAttribute('aria-label')) out.push('no name: ' + el.outerHTML.slice(0, 80));
      }
      if (document.querySelectorAll('main h1').length !== 1) out.push('not exactly one h1');
      if (!document.documentElement.lang) out.push('no lang');
      return out;
    });
    expect(bad, route).toEqual([]);
  }
});

test('phone width: nothing scrolls sideways, the tabs replace the side menu, the strip folds', async ({ page }, info) => {
  await start(info);
  await page.setViewportSize({ width: 360, height: 740 });
  await signIn(page, fake);
  for (const route of ['#/', '#/lobbies', '#/lobby/lob_7k2q', '#/conditions', '#/host/new', '#/settings', '#/activity/act_1182']) {
    await page.goto(fake.url + route);
    await expect(page.locator('main h1')).toBeVisible();
    await expect(page.locator('main')).not.toContainText('Loading');
    const wide = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(wide, route + ' scrolls sideways').toBeLessThanOrEqual(0);
  }
  await expect(page.locator('nav.tabs')).toBeVisible();
  await expect(page.locator('nav.side')).toBeHidden();
  await expect(page.locator('#chips')).toBeHidden();
  await page.locator('#more').click();
  await expect(page.locator('#chips')).toBeVisible();
  await page.locator('nav.tabs a[data-nav="host"]').click();
  await expect(page.getByRole('heading', { name: 'Hosting', exact: true })).toBeVisible();
  await expect(page.locator('nav.tabs a[data-nav="host"]')).toHaveAttribute('aria-current', 'page');
});

// WCAG contrast of the page's text colour on its background, from the computed colours.
async function contrast(page, selector) {
  return page.evaluate((sel) => {
    const lum = (c) => {
      const [r, g, b] = c.match(/[\d.]+/g).slice(0, 3).map((v) => {
        const x = Number(v) / 255;
        return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const el = document.querySelector(sel);
    let bg = null;
    for (let n = el; n && !bg; n = n.parentElement) {
      const c = getComputedStyle(n).backgroundColor;
      if (c && !/rgba\(0, 0, 0, 0\)|transparent/.test(c)) bg = c;
    }
    const a = lum(getComputedStyle(el).color), b = lum(bg || 'rgb(255,255,255)');
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  }, selector);
}

for (const scheme of ['light', 'dark']) {
  test(`${scheme} theme: text keeps its contrast`, async ({ browser }, info) => {
    await start(info);
    const context = await browser.newContext({ colorScheme: scheme });
    const page = await context.newPage();
    await signIn(page, fake);
    await expect(page.locator('#money-free')).toBeVisible(); // Home is drawn
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe(scheme === 'dark' ? 'rgb(23, 18, 15)' : 'rgb(251, 246, 238)');
    for (const sel of ['main h1', '#doing', '.lead, .mute', '.btn.primary', 'nav.side a', '.signet', '.money .k', 'main a']) {
      await page.locator(sel).first().waitFor();
      expect(await contrast(page, sel), sel + ' in ' + scheme).toBeGreaterThanOrEqual(4.5);
    }
    // the switch overrides the system's choice
    await page.locator('#theme').click();
    const flipped = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(flipped).toBe(scheme === 'dark' ? 'rgb(251, 246, 238)' : 'rgb(23, 18, 15)');
    await context.close();
  });
}
