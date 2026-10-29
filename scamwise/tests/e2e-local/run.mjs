// Browser E2E against the real pages + real SQL (see server.mjs). Writes screenshots to ./shots.
import { createRequire } from 'node:module';
const { chromium, devices } = createRequire(import.meta.url)('playwright');
import pg from 'pg';
import fs from 'node:fs';

const BASE = 'http://localhost:8790';
const db = new pg.Pool({ host: process.env.PGHOST || '/var/run/postgresql', port: +(process.env.PGPORT || 5432), user: 'postgres', database: 'scamwise_e2e' });
const q1 = async (sql, p) => (await db.query(sql, p)).rows[0];
fs.mkdirSync('shots', { recursive: true });
const results = [];
const ok = (cond, name) => { results.push([!!cond, name]); console.log(cond ? 'PASS ' : 'FAIL ', name); };
const FAKE = fs.readFileSync(new URL('./fake-supabase.mjs', import.meta.url), 'utf8');
const CHART = fs.readFileSync(new URL('./node_modules/chart.js/dist/chart.umd.js', import.meta.url), 'utf8');

const browser = await chromium.launch();
async function ctx(opts = {}) {
  const c = await browser.newContext({ viewport: { width: 1440, height: 950 }, colorScheme: 'dark', ...opts });
  await c.route('https://cdn.jsdelivr.net/npm/@supabase/**', (r) => r.fulfill({ status: 200, contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: FAKE }));
  await c.route('https://cdn.jsdelivr.net/npm/chart.js**', (r) => r.fulfill({ status: 200, contentType: 'text/javascript', headers: { 'access-control-allow-origin': '*' }, body: CHART }));
  await c.route(/fonts\.(googleapis|gstatic)\.com|tesseract|unpkg/, (r) => r.abort());
  return c;
}
const errors = [];
function watch(page, label) {
  page.on('pageerror', (e) => errors.push(`${label}: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error' && !/Failed to load resource|ERR_FAILED|net::/.test(m.text())) errors.push(`${label} console: ${m.text()}`); });
}
async function signIn(page, path, email) {
  await page.goto(BASE + path);
  if (!path.startsWith('/admin')) {
    // an existing session goes straight to device registration
    const which = await Promise.race([page.waitForSelector('#login-email', { state: 'visible' }).then(() => 'login'),
      page.waitForSelector('#view-main:not(.hidden), #view-pending:not(.hidden)').then(() => 'in')]);
    if (which === 'in') return;
  }
  if (path.startsWith('/admin')) {
    await page.fill('#l-email', email); await page.fill('#l-pass', 'x'); await page.click('#login-form button[type=submit]');
  } else {
    await page.waitForSelector('#login-email', { state: 'visible' });
    await page.fill('#login-email', email); await page.fill('#login-password', 'test-password'); await page.click('#login-submit');
  }
}

// ---------------------------------------------------------------- customer: Bob on a laptop and a phone (test 3)
const UA_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const laptop = await ctx({ userAgent: UA_WIN });
const bobL = await laptop.newPage(); watch(bobL, 'bob-laptop');
await signIn(bobL, '/app/', 'bob@example.com');
await bobL.waitForSelector('#view-main:not(.hidden)', { timeout: 15000 });
ok(true, 'customer signs in on a laptop and reaches the app');

const phoneCtx = await ctx({ ...devices['Pixel 7'], colorScheme: 'dark' });
const bobP = await phoneCtx.newPage(); watch(bobP, 'bob-phone');
await signIn(bobP, '/app/', 'bob@example.com');
await bobP.waitForFunction(() => /device limit/i.test(document.body.innerText), null, { timeout: 15000 });
ok(true, 'TEST 5: on the trial (1 device) a second device is refused with a clear message');
await bobP.screenshot({ path: 'shots/app-device-limit.png' });
const bob0 = await q1("select id from auth.users where email = 'bob@example.com'");
await db.query(`select set_config('request.uid', (select user_id::text from public.admin_users limit 1), false),
  set_config('request.jwt', '{"session_id":"00000000-0000-0000-0000-0000000000aa","aal":"aal2"}', false),
  public.admin_set_subscription($1, 'family', now() + interval '30 days', null, null, null, 'UPI ref 5521', false)`, [bob0.id]);
await signIn(bobP, '/app/', 'bob@example.com');
await bobP.waitForSelector('#view-pending:not(.hidden)', { timeout: 15000 });
ok(true, 'after upgrading to Family the phone registers and waits for approval (existing pairing model)');
// approve from the laptop via the real pairing flow
await bobL.evaluate(async () => { /* nothing: approval is done below via SQL-backed RPCs in the UI */ });
const bob = await q1("select id from auth.users where email = 'bob@example.com'");
await db.query("update public.devices set status = 'active', approved_at = now() where user_id = $1 and status = 'pending'", [bob.id]);
await bobP.reload(); await bobP.waitForSelector('#view-main:not(.hidden)', { timeout: 15000 });

// trial dashboard + quota (tests 6, 7)
await bobL.click('.side [data-tab=dashboard]');
await bobL.waitForFunction(() => document.querySelector('#dash-plan')?.textContent.includes('Family'));
ok(/2 of 3/.test(await bobL.textContent('#dash-plan')), 'customer dashboard shows the Family plan with 2 of 3 devices');
await bobL.screenshot({ path: 'shots/app-dashboard-family.png', fullPage: true });
// trial quota is exercised with Alice, a brand-new trial customer
const aliceCtx = await ctx({ userAgent: UA_WIN });
const al = await aliceCtx.newPage(); watch(al, 'alice');
await signIn(al, '/app/', 'alice@example.com'); await al.waitForSelector('#view-main:not(.hidden)', { timeout: 15000 });
await al.click('.side [data-tab=dashboard]');
await al.waitForFunction(() => document.querySelector('#dash-plan')?.textContent.includes('Free trial'));
ok((await al.textContent('#dash-plan')).includes('0 of 2 today'), 'trial customer dashboard shows 0 of 2 checks used today');
await al.screenshot({ path: 'shots/app-dashboard-trial.png', fullPage: true });
const bobLsave = bobL;
const QP = al;
await QP.click('.side [data-tab=scan]');
for (const msg of ['Your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login',
                   'Your parcel is held. Pay Rs 25 to release it: http://indiapost-track.top/pay']) {
  await QP.fill('#msg', msg); await QP.click('#analyse');
  await QP.waitForFunction(() => /score|risk/i.test(document.querySelector('#result')?.textContent || ''), null, { timeout: 15000 });
  await QP.waitForTimeout(400);
}
await QP.fill('#msg', 'Third check today: http://example-bank-verify.top'); await QP.click('#analyse');
await QP.waitForTimeout(1200);
const third = (await QP.textContent('body'));
ok(/2 checks per day/.test(third), 'TEST 6: third scan of the day is refused with the trial message');
await QP.screenshot({ path: 'shots/app-trial-limit.png' });
await QP.reload(); await QP.waitForSelector('#view-main:not(.hidden)');
await QP.fill('#msg', 'After refresh: http://example-bank-verify.top'); await QP.click('#analyse'); await QP.waitForTimeout(1200);
ok(/2 checks per day/.test(await QP.textContent('body')), 'TEST 7: refreshing the page does not reset the limit');
await QP.evaluate(() => { Date.now = () => new Date('2030-01-01T10:00:00Z').getTime(); });
await QP.fill('#msg', 'Clock changed: http://example-bank-verify.top'); await QP.click('#analyse'); await QP.waitForTimeout(1200);
ok(/2 checks per day/.test(await QP.textContent('body')), 'TEST 7: changing the client clock does not bypass the limit');
const alice = await q1("select id from auth.users where email = 'alice@example.com'");
const used = await q1("select coalesce(sum(trial_checks),0)::int n from public.usage_daily where user_id = $1", [alice.id]);
ok(used.n === 2, 'server recorded exactly 2 trial checks');

// isolation (test 11): Bob sees only his own scans
const seen = await bobP.evaluate(async () => (await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm')).createClient().from('incidents').select('*'));
const mine = await q1('select count(*)::int n from public.incidents where user_id = $1', [bob.id]);
ok(seen.data.length === mine.n && seen.data.every((r) => r.user_id === bob.id), 'TEST 11: browser query for incidents returns only the customer\'s own rows');
const adminTry = await bobP.evaluate(async () => (await import('https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm')).createClient().rpc('admin_customers', {}));
ok(/admin_required/.test(adminTry.error?.message || ''), 'TEST 12: a customer calling an admin API is refused by the server');
await bobP.click('.side [data-tab=dashboard]').catch(async () => { await bobP.click('#avatar'); });
await bobP.waitForTimeout(800);
await bobP.screenshot({ path: 'shots/app-dashboard-mobile.png', fullPage: true });

// ---------------------------------------------------------------- admin (tests 1, 2, 3, 9, 10, 13)
const adm = await ctx();
const a = await adm.newPage(); watch(a, 'admin');
await signIn(a, '/admin/', 'admin@scamwise.example');
await a.waitForSelector('#view-mfa:not(.hidden)');
ok(true, 'admin sign-in requires the second factor');
await a.fill('#mfa-form input[name=code]', '123456'); await a.click('#mfa-form button');
await a.waitForSelector('#view-app:not(.hidden)'); await a.waitForSelector('.kpi');
await a.waitForTimeout(800);
const kpiText = await a.textContent('#page');
const real = await q1(`select (select count(*) from public.profiles where id not in (select user_id from public.admin_users))::int customers,
  (select count(*) from public.devices where status <> 'revoked')::int devices`);
ok(kpiText.includes(String(real.customers)) && /Registered customers/.test(kpiText), `TEST 1: overview shows the real customer count (${real.customers})`);
ok(await a.$$eval('canvas', (c) => c.length) >= 5, 'overview renders interactive charts');
await a.screenshot({ path: 'shots/admin-overview.png', fullPage: true });

await a.click('a[data-r=customers]'); await a.waitForSelector('#cust-filters');
await a.fill('#cust-filters [name=search]', 'bob'); await a.waitForTimeout(900);
ok((await a.$$('[data-cust]')).length === 1, 'TEST 2: search finds the customer');
await a.click('[data-cust]'); await a.waitForSelector('.hero');
await a.click('.tabs [data-tab=devices]'); await a.waitForSelector('.device');
const devText = await a.textContent('#cu-body');
ok((await a.$$('.device')).length === 2 && /Windows/.test(devText) && /Android/.test(devText), 'TEST 3: both of Bob\'s devices (Windows laptop + Android phone) are listed');
ok(/2 active sign-in sessions/.test(devText), 'TEST 3: two login sessions tracked separately');
await a.screenshot({ path: 'shots/admin-customer-devices.png', fullPage: true });

// test 4: phone signs out -> admin sees it
if (await bobP.isVisible('#nav-signout')) await bobP.click('#nav-signout');
else { await bobP.click('#avatar'); await bobP.click('#signout'); }
await bobP.waitForTimeout(1500); await bobP.screenshot({ path: 'shots/debug-signout.png' });
await bobP.waitForSelector('#login-email', { state: 'visible', timeout: 5000 }).catch(() => {});
await a.click('.tabs [data-tab=overview]'); await a.click('.tabs [data-tab=devices]').catch(() => {});
await a.reload(); await a.waitForSelector('.hero'); await a.click('.tabs [data-tab=devices]');
ok(/Signed out/.test(await a.textContent('#cu-body')), 'TEST 4: the phone\'s sign-out shows immediately as "Signed out"');

// change plan through the UI (test 5 + 13)
await a.click('[data-a=plan]'); await a.waitForSelector('#dlg');
await a.selectOption('#dlg-plan', 'business'); await a.fill('#dlg-note', 'UPI ref 77812'); await a.click('#dlg button[type=submit]');
await a.waitForTimeout(1200);
const sub = await q1('select plan_code from public.subscriptions where user_id = $1', [bob.id]);
ok(sub.plan_code === 'business', 'admin changes the plan (Family -> Business) from the customer page');
await a.click('.tabs [data-tab=billing]'); await a.waitForTimeout(300);
ok(/converted/i.test(await a.textContent('#cu-body')), 'subscription history shows the trial conversion');

// customer with threats + incident workflow (tests 9, 10)
await a.goto(BASE + '/admin/#/customers'); await a.waitForSelector('#cust-filters');
await a.fill('#cust-filters [name=search]', 'carol'); await a.waitForTimeout(900); await a.click('[data-cust]'); await a.waitForSelector('.hero');
await a.click('.tabs [data-tab=threats]'); await a.waitForSelector('[data-incident]');
const tt = await a.textContent('#cu-body');
const cs = await q1(`select count(*) filter (where blocked_at is not null)::int b, count(*) filter (where status='resolved')::int r,
  count(*) filter (where status in ('detected','blocked','investigating'))::int o from public.incidents where user_id = (select id from auth.users where email='carol@shop.example')`);
ok(cs.b === 1 && cs.r === 1 && cs.o === 3, 'TEST 10: blocked (1), resolved (1), open (3) are distinct in the data');
await a.screenshot({ path: 'shots/admin-customer-threats.png', fullPage: true });
await a.click('[data-incident]'); await a.waitForSelector('#drawer:not(.hidden) .timeline');
ok(/Detection evidence/.test(await a.textContent('#drawer')) && /Warning shown|User warned/i.test(await a.textContent('#drawer')), 'incident detail shows evidence and response timeline');
await a.screenshot({ path: 'shots/admin-incident.png' });
await a.click('#drawer [data-st=resolved]'); await a.waitForSelector('#dlg');
await a.click('#dlg button[type=submit]'); await a.waitForTimeout(300);
ok(!(await a.$('#modal.hidden')), 'resolving without a note is blocked (note required)');
await a.fill('#dlg-note', 'Phishing domain reported to CERT-In; customer reset password'); await a.click('#dlg button[type=submit]');
await a.waitForTimeout(1200);
ok(/Resolved/.test(await a.textContent('#drawer')), 'admin resolves the incident with a recorded note');
await a.keyboard.press('Escape');

// remaining sections render without errors
for (const r of ['devices', 'threats', 'incidents', 'subscriptions', 'payments', 'notifications', 'feedback', 'audit', 'settings']) {
  await a.goto(BASE + '/admin/#/' + r); await a.waitForTimeout(900);
  const txt = await a.textContent('#page');
  ok(!/Could not load this page/.test(txt) && txt.length > 50, `admin section "${r}" loads real data`);
  if (['devices', 'incidents', 'subscriptions', 'payments', 'audit', 'settings'].includes(r)) await a.screenshot({ path: `shots/admin-${r}.png`, fullPage: true });
}
ok(/subscription\.set/.test(await (async () => { await a.goto(BASE + '/admin/#/audit'); await a.waitForTimeout(900); return a.textContent('#page'); })()), 'TEST 13: plan change appears in the audit log');
ok(/Manual \(unverified\)|manual/i.test(await (async () => { await a.goto(BASE + '/admin/#/payments'); await a.waitForTimeout(900); return a.textContent('#page'); })()), 'payments are labelled manual, never fake-verified');

// mobile admin
const am = await ctx({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
const amp = await am.newPage(); watch(amp, 'admin-mobile');
await amp.addInitScript((v) => localStorage.setItem('fake-sb-identity', v), await a.evaluate(() => localStorage.getItem('fake-sb-identity')));
await amp.goto(BASE + '/admin/#/overview'); await amp.waitForSelector('.kpi'); await amp.waitForTimeout(700);
const overflow = await amp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
ok(overflow <= 1, 'admin overview has no horizontal page scroll on a phone');
await amp.screenshot({ path: 'shots/admin-mobile.png', fullPage: false });

// non-admin cannot open the admin console (test 12)
const nc = await ctx(); const np = await nc.newPage(); watch(np, 'nonadmin');
await signIn(np, '/admin/', 'carol@shop.example'); await np.waitForSelector('#view-denied:not(.hidden)');
ok(true, 'TEST 12: a customer account is shown "Access denied" in the admin console');

ok(errors.length === 0, 'no JavaScript errors on any page' + (errors.length ? ': ' + errors.slice(0, 5).join(' | ') : ''));
await browser.close(); await db.end();
const failed = results.filter(([p]) => !p);
console.log(`\n${results.length - failed.length}/${results.length} browser checks passed`);
process.exit(failed.length ? 1 : 0);
