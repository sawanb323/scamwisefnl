// SCAMWISE admin console.
// Authorisation is enforced in Postgres: every admin_* function checks admin_users membership AND an
// MFA-verified (aal2) session, and every write is rate-limited and audit-logged server-side.
// This page only decides what to display. It never receives message text, passwords, OTPs or card data.
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm';
import { SUPABASE_URL, SUPABASE_KEY } from '../assets/config.js';

const sb = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: true, storageKey: 'scamwise-admin' } });
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const VIEWS = ['login', 'mfa', 'denied', 'app'];
const show = (v) => VIEWS.forEach((x) => $('#view-' + x).classList.toggle('hidden', x !== v));
const short = (id) => esc(String(id ?? '').split('-')[0]);
const when = (iso) => (iso ? new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }) : '—');
const day = (iso) => (iso ? new Date(iso).toLocaleDateString('en-IN', { dateStyle: 'medium' }) : '—');
const num = (n) => Number(n ?? 0).toLocaleString('en-IN');
const inr = (n) => '₹' + Number(n ?? 0).toLocaleString('en-IN', { maximumFractionDigits: 2 });
function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 0) { const f = -s; return f < 86400 ? `in ${Math.ceil(f / 3600)} h` : `in ${Math.ceil(f / 86400)} d`; }
  if (s < 60) return 'just now'; if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`; return `${Math.floor(s / 86400)} d ago`;
}
const LABEL = {
  trialing: 'Trial', active: 'Active', cancelled: 'Cancelled (until expiry)', expired: 'Expired', suspended: 'Suspended',
  no_threat: 'No threat', detected: 'Detected', blocked: 'Blocked', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive',
  connected: 'Connected', idle: 'Idle', signed_out: 'Signed out', session_ended: 'Session ended', unlinked: 'Unlinked', pending: 'Pending approval',
  user_warned: 'User warned', alert_sent: 'Alert sent', none: 'None', manual_recorded: 'Manual (unverified)', provider_verified: 'Provider verified',
};
const chip = (v, cls) => `<span class="chip ${esc(cls ?? v)}">${esc(LABEL[v] ?? String(v ?? '—').replace(/_/g, ' '))}</span>`;
const PLAN = { trial: 'Free trial', individual: 'Individual', family: 'Family', business: 'Business', enterprise: 'Enterprise & Banking' };
const plan = (p) => esc(PLAN[p] ?? p ?? '—');
const ERR = {
  admin_required: 'Your admin session has ended. Sign in again.', rate_limited: 'Too many admin actions in a minute. Wait and retry.',
  reason_required: 'A reason is required.', note_required: 'A written note is required for this status.',
  enterprise_device_limit_required: 'Enterprise plans need a contract device limit.', not_found: 'That record no longer exists.',
  reference_looks_like_card_number: 'Do not enter card numbers. Use the gateway / UTR / invoice reference.',
  bad_status: 'That status change is not allowed.', expiry_required: 'Choose an expiry date.',
};
const friendly = (e) => { const m = String(e?.message ?? e ?? ''); for (const [k, v] of Object.entries(ERR)) if (m.includes(k)) return v; return m || 'Something went wrong.'; };

// ------------------------------------------------------------------ toast / modal / drawer
let toastTimer;
function toast(msg, bad) {
  const t = $('#toast'); t.textContent = msg; t.classList.toggle('bad', !!bad); t.classList.remove('hidden');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 3800);
}
function closeOverlays() { ['#drawer', '#modal', '#scrim'].forEach((s) => $(s).classList.add('hidden')); }
$('#scrim').onclick = closeOverlays;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeOverlays(); });
function openDrawer(html) { const d = $('#drawer'); d.innerHTML = html; d.classList.remove('hidden'); $('#scrim').classList.remove('hidden'); d.scrollTop = 0; return d; }

// confirmation / form dialog: resolves with the form values, or null when cancelled
function dialog({ title, body = '', fields = [], confirm = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const m = $('#modal');
    m.innerHTML = `<h3>${esc(title)}</h3><div class="note">${body}</div><form id="dlg">${fields.map((f) => `
      <label class="f" for="dlg-${f.name}">${esc(f.label)}${f.required ? ' *' : ''}</label>
      ${f.type === 'select' ? `<select id="dlg-${f.name}" name="${f.name}">${f.options.map(([v, l]) => `<option value="${esc(v)}" ${v === f.value ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`
        : f.type === 'textarea' ? `<textarea id="dlg-${f.name}" name="${f.name}" rows="3" maxlength="${f.max ?? 300}" ${f.required ? 'required' : ''}>${esc(f.value ?? '')}</textarea>`
        : `<input id="dlg-${f.name}" name="${f.name}" type="${f.type ?? 'text'}" value="${esc(f.value ?? '')}" ${f.required ? 'required' : ''} ${f.min != null ? `min="${f.min}"` : ''} ${f.step ? `step="${f.step}"` : ''} maxlength="${f.max ?? 300}">`}
      ${f.hint ? `<div class="note">${esc(f.hint)}</div>` : ''}`).join('')}
      <div class="acts"><button type="button" class="btn ghost" id="dlg-cancel">Cancel</button><button type="submit" class="btn ${danger ? 'danger' : 'primary'}">${esc(confirm)}</button></div></form>`;
    m.classList.remove('hidden'); $('#scrim').classList.remove('hidden');
    const done = (v) => { m.classList.add('hidden'); if ($('#drawer').classList.contains('hidden')) $('#scrim').classList.add('hidden'); resolve(v); };
    $('#dlg-cancel').onclick = () => done(null);
    $('#dlg').onsubmit = (e) => { e.preventDefault(); done(Object.fromEntries(new FormData(e.target))); };
    (m.querySelector('input,select,textarea') || m.querySelector('[type=submit]')).focus();
  });
}

// ------------------------------------------------------------------ server calls
async function rpc(name, params) {
  const { data, error } = await sb.rpc(name, params);
  if (error) {
    if (/admin_required/.test(error.message)) { stopLive(); route(); }
    throw error;
  }
  return data;
}
async function act(fn, ok) {
  try { await fn(); if (ok) toast(ok); await render(); return true; }
  catch (e) { toast(friendly(e), true); return false; }
}

// ------------------------------------------------------------------ auth flow
async function route() {
  const { data: { session } } = await sb.auth.getSession();
  if (!session) { $('#logout').classList.add('hidden'); $('#menu').classList.add('hidden'); $('#who').textContent = ''; return show('login'); }
  $('#who').textContent = session.user.email ?? '';
  $('#logout').classList.remove('hidden');
  const { data: who, error } = await sb.rpc('admin_whoami');
  if (error) { $('#login-error').textContent = error.message; return show('login'); }
  if (!who.is_member) return show('denied');
  const { data: aal } = await sb.auth.mfa.getAuthenticatorAssuranceLevel();
  if (aal?.currentLevel !== 'aal2') return startMfa();
  if (!who.is_admin) {
    await sb.auth.refreshSession();
    const again = await sb.rpc('admin_whoami');
    if (!again.data?.is_admin) return show('denied');
  }
  show('app'); $('#menu').classList.remove('hidden');
  render();
}
let mfaFactorId = null;
async function startMfa() {
  show('mfa'); $('#mfa-error').textContent = '';
  const { data: f, error } = await sb.auth.mfa.listFactors();
  if (error) { $('#mfa-error').textContent = error.message; return; }
  const verified = (f.totp || []).filter((x) => x.status === 'verified');
  if (verified.length) { mfaFactorId = verified[0].id; $('#mfa-enroll').classList.add('hidden'); $('#mfa-title').textContent = 'Two-step verification'; return; }
  for (const x of (f.all || []).filter((x) => x.status !== 'verified')) await sb.auth.mfa.unenroll({ factorId: x.id });
  const { data: en, error: enErr } = await sb.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'SCAMWISE admin ' + new Date().toISOString().slice(0, 10) });
  if (enErr) { $('#mfa-error').textContent = enErr.message; return; }
  mfaFactorId = en.id;
  $('#mfa-title').textContent = 'Set up two-step verification';
  $('#mfa-qr').src = en.totp.qr_code; $('#mfa-secret').textContent = en.totp.secret;
  $('#mfa-enroll').classList.remove('hidden');
}
$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target); $('#login-error').textContent = '';
  const { error } = await sb.auth.signInWithPassword({ email: f.get('email'), password: f.get('password') });
  if (error) { $('#login-error').textContent = error.message.includes('Invalid') ? 'Incorrect email or password.' : error.message; return; }
  e.target.reset(); route();
});
$('#mfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const { error } = await sb.auth.mfa.challengeAndVerify({ factorId: mfaFactorId, code: new FormData(e.target).get('code') });
  if (error) { $('#mfa-error').textContent = 'That code is not valid. Check the time on your phone and try again.'; return; }
  e.target.reset(); route();
});
for (const id of ['#logout', '#denied-logout']) $(id).onclick = async () => { stopLive(); await sb.auth.signOut(); route(); };
sb.auth.onAuthStateChange((evt) => { if (evt === 'SIGNED_OUT') { stopLive(); show('login'); } });
$('#menu').onclick = () => $('#side').classList.toggle('open');

// ------------------------------------------------------------------ date range (IST buckets are computed server-side)
const R = { days: 30, from: null, to: null, bucket: 'day' };
function range() {
  if (R.from || R.to) {
    const from = R.from ? new Date(R.from + 'T00:00:00') : new Date(Date.now() - 30 * 864e5);
    const to = R.to ? new Date(R.to + 'T23:59:59') : new Date();
    return { from: from.toISOString(), to: to.toISOString(), label: `${day(from)} – ${day(to)}` };
  }
  return { from: new Date(Date.now() - R.days * 864e5).toISOString(), to: new Date().toISOString(), label: R.days === 1 ? 'last 24 hours' : `last ${R.days} days` };
}
function autoBucket() { const d = R.from || R.to ? 31 : R.days; return d <= 31 ? 'day' : d <= 120 ? 'week' : 'month'; }
$$('#range [data-p]').forEach((b) => (b.onclick = () => {
  R.days = +b.dataset.p; R.from = R.to = null; $('#r-from').value = $('#r-to').value = '';
  $$('#range [data-p]').forEach((x) => x.classList.toggle('on', x === b));
  R.bucket = autoBucket(); $('#bucket').value = R.bucket; render();
}));
['#r-from', '#r-to'].forEach((s) => ($(s).onchange = () => {
  R.from = $('#r-from').value || null; R.to = $('#r-to').value || null;
  $$('#range [data-p]').forEach((x) => x.classList.remove('on')); render();
}));
$('#bucket').onchange = () => { R.bucket = $('#bucket').value; render(); };

// ------------------------------------------------------------------ charts (Chart.js; degrades to a note if blocked)
const charts = [];
const C = { teal: '#14b8a6', teal2: '#2dd4bf', crit: '#ff4d6d', high: '#f97066', med: '#fdb022', low: '#47cd89', info: '#7cb6ff', mute: '#6f8399', grid: '#1d3247', ink: '#a9b8c8' };
function destroyCharts() { while (charts.length) charts.pop().destroy(); }
function chart(id, config) {
  const el = document.getElementById(id); if (!el) return;
  if (!window.Chart) { el.parentElement.innerHTML = '<p class="chart-fallback">Chart library unavailable (blocked or offline). Figures are in the tables.</p>'; return; }
  const Chart = window.Chart;
  Chart.defaults.color = C.ink; Chart.defaults.borderColor = C.grid; Chart.defaults.font.family = 'Inter, system-ui, sans-serif';
  config.options = Object.assign({ responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
    plugins: { legend: { labels: { boxWidth: 10, boxHeight: 10 } } } }, config.options || {});
  charts.push(new Chart(el, config));
}
const series = (rows, k) => rows.map((r) => Number(r[k] ?? 0));
const bucketLabel = (iso) => { const d = new Date(iso + 'T00:00:00'); return R.bucket === 'month' ? d.toLocaleDateString('en-IN', { month: 'short', year: '2-digit' }) : d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }); };

// ------------------------------------------------------------------ router
const ROUTES = {
  overview: ['Overview', 'Security operations and business health'], customers: ['Customers', 'Search, filter and open any customer'],
  customer: ['Customer', ''], devices: ['Devices & Sessions', 'Registered devices, sign-in sessions and live connection status'],
  threats: ['Threat Monitoring', 'Detection activity across all customers'], incidents: ['Incident Management', 'Triage, investigate and resolve'],
  subscriptions: ['Subscriptions & Plans', 'Plans, validity, renewals, cancellations and upgrade requests'],
  payments: ['Payments & Revenue', 'Recorded transactions and revenue by plan and period'],
  notifications: ['Notifications', 'Security notifications delivered to customer devices'], feedback: ['Feedback', 'Messages from the website contact form'],
  audit: ['Audit Logs', 'Every administrator and security-relevant action'], settings: ['Settings', 'Plans, trial policy, administrators and integrations'],
};
const RANGED = new Set(['overview', 'threats', 'incidents', 'payments']);
const state = { page: {} };
function parseHash() { const [, r = 'overview', id = ''] = location.hash.match(/^#\/([a-z]+)\/?([\w-]*)/) || []; return { r: ROUTES[r] ? r : 'overview', id }; }
window.addEventListener('hashchange', () => { closeOverlays(); $('#side').classList.remove('open'); render(true); });

let rendering = false;
async function render(scrollTop) {
  if (rendering) return; rendering = true;
  const { r, id } = parseHash();
  $$('#side a').forEach((a) => a.classList.toggle('on', a.dataset.r === (r === 'customer' ? 'customers' : r)));
  $('#title').textContent = ROUTES[r][0]; $('#subtitle').textContent = ROUTES[r][1];
  $('#range').classList.toggle('hidden', !RANGED.has(r)); $('#bucket').classList.toggle('hidden', !['overview', 'threats'].includes(r));
  try {
    const html = await PAGES[r](id);
    destroyCharts();
    if (typeof html === 'string') $('#page').innerHTML = html;
    if (PAGES[r].after) PAGES[r].after(id);
    $('#refreshed').textContent = 'Updated ' + new Date().toLocaleTimeString('en-IN') + (RANGED.has(r) ? ` · range: ${range().label}` : '') + ' · times shown in your local time; quota days use IST';
    if (scrollTop) window.scrollTo(0, 0);
    if (!timer) startLive();
    badges();
  } catch (e) {
    $('#page').innerHTML = `<div class="panel"><p class="err">Could not load this page: ${esc(friendly(e))}</p></div>`;
  } finally { rendering = false; }
}
let timer = null;
function stopLive() { clearInterval(timer); timer = null; }
function startLive() { stopLive(); if ($('#live').checked) timer = setInterval(() => { if ($('#modal').classList.contains('hidden') && $('#drawer').classList.contains('hidden') && !document.hidden) render(); }, 30000); }
$('#live').onchange = startLive;
$('#refresh').onclick = () => render();
async function badges() {
  try {
    const d = await rpc('admin_dashboard', {});
    const set = (s, n) => { const el = $(s); el.textContent = n; el.classList.toggle('hidden', !n); };
    set('#n-incidents', d.threats?.open ?? 0); set('#n-requests', d.open_plan_requests ?? 0);
  } catch { /* ignore */ }
}

// pagination + sorting helpers
function pager(key, total, limit) {
  const p = state.page[key] ?? 0, pages = Math.max(1, Math.ceil(total / limit));
  return `<div class="pager"><span>${num(total)} result${total === 1 ? '' : 's'} · page ${p + 1} of ${pages}</span>
    <button class="btn sm" data-pg="${key}" data-to="${p - 1}" ${p <= 0 ? 'disabled' : ''}>Previous</button>
    <button class="btn sm" data-pg="${key}" data-to="${p + 1}" ${p + 1 >= pages ? 'disabled' : ''}>Next</button></div>`;
}
document.addEventListener('click', (e) => {
  const b = e.target.closest('[data-pg]'); if (!b) return;
  state.page[b.dataset.pg] = Math.max(0, +b.dataset.to); render();
});
const PAGES = {};

// ================================================================== OVERVIEW
const kpi = (l, v, c, s) => `<div class="kpi" style="--c:${c ?? C.teal}"><div class="v">${v}</div><div class="l">${esc(l)}</div>${s ? `<div class="s">${s}</div>` : ''}</div>`;
let OV = null;
PAGES.overview = async () => {
  const rg = range();
  const [d, ts] = await Promise.all([rpc('admin_dashboard', { p_from: rg.from, p_to: rg.to }),
    rpc('admin_timeseries', { p_from: rg.from, p_to: rg.to, p_bucket: R.bucket })]);
  OV = { d, ts };
  const t = d.threats || {};
  return `
  <div class="kpis">
    ${kpi('Registered customers', num(d.customers_total), C.teal, `+${num(d.customers_new)} in range`)}
    ${kpi('Active customers', num(d.customers_active), C.low, `${num(d.customers_active_in_range)} scanned in range`)}
    ${kpi('On free trial', num(d.trialing), C.med)}
    ${kpi('Premium subscriptions', num(d.premium_active), C.low, `${num(d.conversions)} trial conversions in range`)}
    ${kpi('Expired subscriptions', num(d.expired), C.high, `${num(d.trial_expired)} expired trials · ${num(d.expiring_7d)} expiring ≤7 d`)}
    ${kpi('Registered devices', num(d.devices_registered), C.info, `${num(d.devices_pending)} pending approval`)}
    ${kpi('Connected now', num(d.devices_connected), C.low, `${num(d.sessions_active)} signed-in sessions`)}
    ${kpi('Links checked', num(t.urls_checked), C.teal, `${num(d.checks_in_range)} scans in range · ${num(d.checks_lifetime)} lifetime`)}
    ${kpi('Threats detected', num(t.threats_detected), C.high, `${num(t.severity?.critical)} critical · ${num(t.severity?.high)} high`)}
    ${kpi('Threats blocked', num(t.blocked), C.info, 'only real block events')}
    ${kpi('Resolved incidents', num(t.resolved), C.low, `${num(t.false_positive)} false positives`)}
    ${kpi('Under investigation', num(t.investigating), C.med, `${num(t.open)} open in total`)}
    ${kpi('Recurring revenue (MRR)', inr(d.mrr_inr), C.teal, 'from active plan prices')}
    ${kpi('Payments recorded', inr(Number(d.revenue?.paid_verified ?? 0) + Number(d.revenue?.paid_manual ?? 0)), C.teal,
         `${inr(d.revenue?.paid_verified)} provider-verified · ${num(d.revenue?.failed_count)} failed`)}
  </div>
  <div class="cols">
    <div class="panel"><div class="panel-head"><h3>Scans and threats</h3><span class="note r">${R.bucket} · IST</span></div><div class="chart tall"><canvas id="ch-activity"></canvas></div></div>
    <div class="panel"><div class="panel-head"><h3>Customers and revenue</h3></div><div class="chart tall"><canvas id="ch-business"></canvas></div></div>
  </div>
  <div class="cols c3">
    <div class="panel"><h3>Plan distribution</h3><div class="chart"><canvas id="ch-plans"></canvas></div></div>
    <div class="panel"><h3>Threat severity</h3><div class="chart"><canvas id="ch-sev"></canvas></div></div>
    <div class="panel"><h3>Incident status</h3><div class="chart"><canvas id="ch-status"></canvas></div></div>
  </div>
  <div class="panel" style="margin-top:14px"><div class="panel-head"><h3>Recent security incidents</h3><a class="r" href="#/incidents">All incidents →</a></div>
    ${incidentTable(d.recent_incidents, { compact: true })}</div>`;
};
PAGES.overview.after = () => {
  const { d, ts } = OV; const t = d.threats || {}; const labels = ts.map((r) => bucketLabel(r.bucket));
  chart('ch-activity', { type: 'line', data: { labels, datasets: [
    { label: 'Scans', data: series(ts, 'checks'), borderColor: C.teal, backgroundColor: 'rgba(20,184,166,.15)', fill: true, tension: .15, pointRadius: 2 },
    { label: 'Threats', data: series(ts, 'threats'), borderColor: C.high, tension: .15, pointRadius: 2 },
    { label: 'Critical', data: series(ts, 'critical'), borderColor: C.crit, borderDash: [4, 4], tension: .15, pointRadius: 2 },
    { label: 'Resolved', data: series(ts, 'resolved'), borderColor: C.low, tension: .15, pointRadius: 2 }] }, options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
  chart('ch-business', { data: { labels, datasets: [
    { type: 'bar', label: 'Revenue recorded (₹)', data: series(ts, 'revenue'), backgroundColor: 'rgba(20,184,166,.5)', yAxisID: 'y1' },
    { type: 'line', label: 'Active customers', data: series(ts, 'active_customers'), borderColor: C.info, tension: .15, pointRadius: 2 },
    { type: 'line', label: 'Sign-ups', data: series(ts, 'signups'), borderColor: C.med, tension: .15, pointRadius: 2 },
    { type: 'line', label: 'Conversions', data: series(ts, 'conversions'), borderColor: C.low, tension: .15, pointRadius: 2 }] },
    options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, y1: { beginAtZero: true, position: 'right', grid: { drawOnChartArea: false } } } } });
  const pd = d.plan_distribution || {};
  chart('ch-plans', { type: 'doughnut', data: { labels: Object.keys(pd).map((k) => PLAN[k] ?? k),
    datasets: [{ data: Object.values(pd), backgroundColor: [C.med, C.teal, C.info, C.low, C.crit], borderWidth: 0 }] }, options: { plugins: { legend: { position: 'bottom' } } } });
  const sv = t.severity || {};
  chart('ch-sev', { type: 'bar', data: { labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{ label: 'Incidents', data: [sv.critical, sv.high, sv.medium, sv.low], backgroundColor: [C.crit, C.high, C.med, C.low] }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
  chart('ch-status', { type: 'doughnut', data: { labels: ['Detected (open)', 'Blocked', 'Investigating', 'Resolved', 'False positive'],
    datasets: [{ data: [Math.max(0, (t.open ?? 0) - (t.investigating ?? 0) - (t.blocked ?? 0)), t.blocked, t.investigating, t.resolved, t.false_positive],
      backgroundColor: [C.high, C.info, C.med, C.low, C.mute], borderWidth: 0 }] }, options: { plugins: { legend: { position: 'bottom' } } } });
};

function incidentTable(rows, { compact } = {}) {
  if (!rows?.length) return '<p class="empty">No incidents in this view.</p>';
  return `<div class="table-wrap"><table><tr><th>Detected</th><th>Customer</th><th>Device</th><th>Verdict</th><th>Severity</th><th>Category</th><th>Response</th><th>Status</th>${compact ? '' : '<th>Domains</th>'}</tr>
    ${rows.map((i) => `<tr class="click" data-incident="${esc(i.id)}">
      <td>${esc(ago(i.created_at))}<div class="sub">${esc(when(i.created_at))}</div></td>
      <td>${esc(i.email ?? '—')}</td><td>${esc(i.device_name ?? '—')}</td>
      <td>${chip(i.verdict)}<div class="sub">score ${esc(i.score)}</div></td><td>${chip(i.severity)}</td>
      <td>${esc(String(i.category ?? '').replace(/_/g, ' '))}</td><td>${chip(i.blocked_at ? 'blocked' : i.response_status)}</td><td>${chip(i.status)}</td>
      ${compact ? '' : `<td class="mono sub">${esc((i.url_domains || []).join(', ') || '—')}</td>`}</tr>`).join('')}</table></div>`;
}
document.addEventListener('click', (e) => { const r = e.target.closest('[data-incident]'); if (r) openIncident(r.dataset.incident); });

// ================================================================== CUSTOMERS
const CF = { search: '', plan: '', status: '', from: '', to: '', threat: '', sort: 'joined', desc: true };
const SUB_STATUS = [['', 'Any status'], ['trialing', 'On trial'], ['active', 'Active (paid)'], ['cancelled', 'Cancelled (until expiry)'], ['expired', 'Expired'],
  ['suspended', 'Subscription suspended'], ['account_suspended', 'Account suspended'], ['expiring', 'Expiring in 7 days']];
const PLAN_OPTS = [['', 'All plans'], ...Object.entries(PLAN)];
const opts = (list, v) => list.map(([k, l]) => `<option value="${esc(k)}" ${k === v ? 'selected' : ''}>${esc(l)}</option>`).join('');
PAGES.customers = async () => {
  const lim = 25, off = (state.page.cust ?? 0) * lim;
  const res = await rpc('admin_customers', { p_search: CF.search || null, p_plan: CF.plan || null, p_status: CF.status || null,
    p_joined_from: CF.from ? new Date(CF.from + 'T00:00:00').toISOString() : null, p_joined_to: CF.to ? new Date(CF.to + 'T23:59:59').toISOString() : null,
    p_threat: CF.threat || null, p_sort: CF.sort, p_desc: CF.desc, p_limit: lim, p_offset: off });
  const th = (k, l) => `<th class="sort ${CF.sort === k ? 'on' : ''} ${CF.sort === k && !CF.desc ? 'asc' : ''}" data-sort="${k}">${l}</th>`;
  return `<div class="panel">
    <div class="filters" id="cust-filters">
      <input name="search" placeholder="Search name, email or ID" value="${esc(CF.search)}" aria-label="Search customers">
      <select name="plan" aria-label="Plan">${opts(PLAN_OPTS, CF.plan)}</select>
      <select name="status" aria-label="Status">${opts(SUB_STATUS, CF.status)}</select>
      <select name="threat" aria-label="Threat activity">${opts([['', 'Any threat activity'], ['with_threats', 'Has threats'], ['open', 'Has open incidents'], ['none', 'No threats']], CF.threat)}</select>
      <label class="note">Registered from<input type="date" name="from" value="${esc(CF.from)}"></label>
      <label class="note">Registered to<input type="date" name="to" value="${esc(CF.to)}"></label>
    </div>
    <div class="table-wrap"><table>
      <tr><th>ID</th>${th('name', 'Customer')}${th('plan', 'Plan')}<th>Status</th><th>Trial</th>${th('expires', 'Subscription expiry')}
        ${th('devices', 'Devices')}${th('last_active', 'Last active')}${th('checks', 'Links / scans')}${th('threats', 'Threats')}<th>Blocked / resolved</th></tr>
      ${res.rows.map((c) => `<tr class="click" data-cust="${esc(c.id)}">
        <td class="mono sub">${short(c.id)}</td>
        <td><b>${esc(c.name || '—')}</b><div class="sub">${esc(c.email)} ${c.email_verified ? '' : '· unverified'}</div></td>
        <td>${plan(c.plan)}</td>
        <td>${chip(c.sub_status)}${c.account_status === 'suspended' ? ' ' + chip('suspended', 'suspended') : ''}</td>
        <td class="sub">${c.trial_started_at ? `${day(c.trial_started_at)} →<br>${day(c.trial_expires_at)}` : '—'}</td>
        <td>${esc(day(c.expires_at))}<div class="sub">${esc(ago(c.expires_at))}</div></td>
        <td>${num(c.devices)}${c.devices_online ? ` <span class="chip connected">${c.devices_online} online</span>` : ''}</td>
        <td class="sub">${esc(ago(c.last_active))}</td>
        <td>${num(c.links)}<div class="sub">${num(c.checks)} scans</div></td>
        <td>${c.threats ? `<b style="color:var(--high)">${num(c.threats)}</b>` : '0'}${c.open_incidents ? `<div class="sub">${c.open_incidents} open</div>` : ''}</td>
        <td>${num(c.blocked)} / ${num(c.resolved)}</td></tr>`).join('') || '<tr><td colspan="11" class="empty">No customers match these filters.</td></tr>'}
    </table></div>${pager('cust', res.total, lim)}</div>`;
};
PAGES.customers.after = () => {
  let t;
  $$('#cust-filters [name]').forEach((el) => el.addEventListener(el.name === 'search' ? 'input' : 'change', () => {
    clearTimeout(t); t = setTimeout(() => { CF[el.name] = el.value; state.page.cust = 0; render().then(() => { if (el.name === 'search') { const s = $('#cust-filters [name=search]'); s.focus(); s.setSelectionRange(s.value.length, s.value.length); } }); }, el.name === 'search' ? 350 : 0);
  }));
  $$('[data-sort]').forEach((h) => (h.onclick = () => { if (CF.sort === h.dataset.sort) CF.desc = !CF.desc; else { CF.sort = h.dataset.sort; CF.desc = true; } render(); }));
  $$('[data-cust]').forEach((r) => (r.onclick = () => { location.hash = '#/customer/' + r.dataset.cust; }));
};

// ================================================================== CUSTOMER DASHBOARD
const DEV_ICON = {
  desktop: '<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  mobile: '<svg viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></svg>',
  tablet: '<svg viewBox="0 0 24 24"><rect x="4" y="2" width="16" height="20" rx="2"/><path d="M11 18h2"/></svg>',
  unknown: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 16h.01M12 8a2 2 0 0 1 1 3.7c-.6.4-1 1-1 1.8"/></svg>',
};
let CU = null; let cuTab = 'overview';
const IF = { severity: '', status: '', verdict: '', from: '', to: '' };
PAGES.customer = async (id) => {
  if (!id) { location.hash = '#/customers'; return ''; }
  if (CU?.profile?.id !== id) cuTab = 'overview';
  CU = await rpc('admin_customer', { p_user: id });
  const p = CU.profile, s = CU.subscription || {}, st = CU.stats || {}, dq = s.devices || {};
  $('#title').textContent = p.name || p.email; $('#subtitle').textContent = 'Customer ' + p.id;
  const initials = (p.name || p.email || '?').split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join('');
  const connected = CU.devices.filter((d) => d.session_status === 'connected').length;
  const tab = (k, l, n) => `<button data-tab="${k}" class="${cuTab === k ? 'on' : ''}">${l}${n != null ? ` <span class="muted">${n}</span>` : ''}</button>`;
  return `<div class="panel"><div class="hero">
      <div class="avatar">${esc(initials)}</div>
      <div><h2>${esc(p.name || '—')}</h2><div class="muted">${esc(p.email)} ${p.email_verified ? chip('verified', 'verified') : chip('email unverified', 'pending')}</div>
        <div class="meta"><span class="muted">Account</span> ${chip(p.account_status === 'suspended' ? 'suspended' : 'active', p.account_status === 'suspended' ? 'suspended' : 'ok')}
          <span class="muted">· ${plan(s.plan)} plan</span> ${chip(s.status)} <span class="muted">· valid to ${esc(day(s.expires_at))} · customer since ${esc(day(p.created_at))}</span></div></div>
      <div class="acts">
        <button class="btn primary sm" data-a="plan">Change plan</button>
        <button class="btn sm" data-a="payment">Record payment</button>
        ${s.status === 'suspended' ? '<button class="btn sm" data-a="sub-reactivate">Reactivate subscription</button>' : '<button class="btn sm" data-a="sub-suspend">Suspend subscription</button>'}
        ${s.cancelled_at ? '<button class="btn sm" data-a="sub-uncancel">Undo cancellation</button>' : '<button class="btn sm" data-a="sub-cancel">Cancel renewal</button>'}
        ${p.account_status === 'suspended' ? '<button class="btn sm" data-a="acct-reactivate">Reactivate account</button>' : '<button class="btn danger sm" data-a="acct-suspend">Suspend account</button>'}
      </div></div>
    ${p.account_status === 'suspended' ? `<div class="callout warn" style="margin-top:12px">Account suspended ${esc(ago(p.suspended_at))}: ${esc(p.suspended_reason)}. Sign-in is blocked and all sessions were ended.</div>` : ''}
    <div class="tabs" role="tablist">${tab('overview', 'Overview')}${tab('devices', 'Devices & sessions', CU.devices.length)}${tab('threats', 'Threats', st.threats_detected)}
      ${tab('activity', 'Activity')}${tab('billing', 'Subscription & payments', CU.payments.length)}</div>
    <div id="cu-body">${CU_TABS[cuTab]()}</div></div>`;
};
PAGES.customer.after = () => {
  $$('.tabs [data-tab]').forEach((b) => (b.onclick = () => { cuTab = b.dataset.tab; $$('.tabs [data-tab]').forEach((x) => x.classList.toggle('on', x === b)); destroyCharts(); $('#cu-body').innerHTML = CU_TABS[cuTab](); cuAfter(); }));
  cuAfter();
};
function cuAfter() {
  if (cuTab === 'overview' && CU.usage_30d?.length) {
    chart('ch-cu-usage', { type: 'bar', data: { labels: CU.usage_30d.map((u) => bucketLabel(u.day)), datasets: [
      { label: 'Scans', data: series(CU.usage_30d, 'checks'), backgroundColor: 'rgba(20,184,166,.6)' },
      { label: 'Threats', data: series(CU.usage_30d, 'threats'), backgroundColor: C.high }] }, options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
  }
  if (cuTab === 'threats') $$('#cu-if [name]').forEach((el) => (el.onchange = () => { IF[el.name] = el.value; $('#cu-body').innerHTML = CU_TABS.threats(); cuAfter(); }));
}
const CU_TABS = {
  overview() {
    const p = CU.profile, s = CU.subscription || {}, st = CU.stats || {}, dq = s.devices || {}, tr = s.trial || {};
    const pct = Math.min(100, Math.round(100 * (dq.used ?? 0) / Math.max(1, dq.limit ?? 1)));
    return `<div class="kpis">
      ${kpi('Links checked', num(st.urls_checked), C.teal, `${num(CU.checks_lifetime)} scans lifetime`)}
      ${kpi('Safe / suspicious / malicious URLs', `${num(st.urls_safe)} / ${num(st.urls_suspicious)} / ${num(st.urls_malicious)}`, C.info)}
      ${kpi('Threats detected', num(st.threats_detected), C.high, `${num(st.severity?.critical)} critical`)}
      ${kpi('Blocked', num(st.blocked), C.info)}${kpi('Resolved', num(st.resolved), C.low, `${num(st.false_positive)} false positive`)}
      ${kpi('Open incidents', num(st.open), C.med, `${num(st.investigating)} investigating`)}
      ${kpi('Devices', `${num(dq.used)} / ${num(dq.limit)}`, C.info, `${CU.devices.filter((d) => d.session_status === 'connected').length} connected now`)}
      ${kpi('Last security activity', esc(ago(st.last_activity)), C.mute)}
    </div>
    <div class="cols">
      <div class="panel"><h3>Profile</h3><dl class="kv" style="margin-top:10px">
        <dt>Customer ID</dt><dd class="mono">${esc(p.id)}</dd><dt>Name</dt><dd>${esc(p.name || '—')}</dd>
        <dt>Email</dt><dd>${esc(p.email)} ${p.email_verified ? `<span class="note">verified ${esc(day(p.email_verified_at))}</span>` : '<span class="note">not verified</span>'}</dd>
        <dt>Phone</dt><dd>${esc(p.phone || '—')}</dd><dt>Created</dt><dd>${esc(when(p.created_at))}</dd><dt>Last sign-in</dt><dd>${esc(when(p.last_sign_in_at))}</dd>
        <dt>Account</dt><dd>${chip(p.account_status === 'suspended' ? 'suspended' : 'active', p.account_status === 'suspended' ? 'suspended' : 'ok')}</dd>
        <dt>Data sharing</dt><dd>${p.share_with_admin ? 'Incident metadata shared with admins' : 'Customer opted out of admin sharing'} · ${esc(p.retention_days)}-day retention</dd>
        ${CU.org ? `<dt>Organisation</dt><dd>${esc(CU.org.name)} (${esc(CU.org.kind)}) · ${esc(CU.org.role)}</dd>` : ''}</dl></div>
      <div class="panel"><h3>Subscription</h3><dl class="kv" style="margin-top:10px">
        <dt>Plan</dt><dd>${plan(s.plan)} ${chip(s.status)}</dd>
        <dt>Price</dt><dd>${s.price_inr != null ? inr(s.price_inr) + (s.billing_period === 'month' ? '/month' : s.billing_period === 'custom' ? '/month (contract)' : '') : 'Custom (not set)'}</dd>
        <dt>Valid</dt><dd>${esc(day(s.started_at))} → <b>${esc(day(s.expires_at))}</b> <span class="note">(${s.status === 'expired' ? 'expired' : s.days_left + ' days left'})</span></dd>
        <dt>Trial</dt><dd>${s.trial_started_at ? `${esc(day(s.trial_started_at))} → ${esc(day(s.trial_expires_at))}` : '—'}${s.converted_at ? ` · converted ${esc(day(s.converted_at))}` : ''}</dd>
        ${s.plan === 'trial' ? `<dt>Trial usage</dt><dd>${tr.used_today}/${tr.daily_limit} today · ${tr.used_total}/${tr.total_limit} total · ${Math.max(0, tr.total_limit - tr.used_total)} remaining</dd>` : ''}
        <dt>Devices</dt><dd>${num(dq.used)} of ${num(dq.limit)}${dq.pooled ? ` (pooled across ${esc(dq.org)})` : ''}<div class="meter ${dq.used > dq.limit ? 'over' : ''}"><i style="width:${pct}%"></i></div></dd>
        <dt>Payment status</dt><dd>${CU.payments[0] ? `${chip(CU.payments[0].status)} ${chip(CU.payments[0].verification === 'provider_verified' ? 'verified' : 'manual', CU.payments[0].verification === 'provider_verified' ? 'verified' : 'manual')} ${inr(CU.payments[0].amount_inr)} on ${esc(day(CU.payments[0].created_at))}` : 'No payments recorded'}</dd>
        ${s.suspended_at ? `<dt>Suspended</dt><dd>${esc(when(s.suspended_at))}: ${esc(s.suspend_reason)}</dd>` : ''}
        ${s.cancelled_at ? `<dt>Cancelled</dt><dd>${esc(when(s.cancelled_at))}: ${esc(s.cancel_reason)}</dd>` : ''}
        ${s.note ? `<dt>Note</dt><dd>${esc(s.note)}</dd>` : ''}</dl></div>
    </div>
    <div class="panel" style="margin-top:14px"><h3>Scans and threats · last 30 days</h3>${CU.usage_30d?.length ? '<div class="chart"><canvas id="ch-cu-usage"></canvas></div>' : '<p class="empty">No scans in the last 30 days.</p>'}</div>`;
  },
  devices() {
    const dq = CU.subscription?.devices || {};
    const act = CU.devices.filter((d) => d.status !== 'revoked');
    return `<div class="row" style="margin-bottom:12px"><b>${act.length} registered device${act.length === 1 ? '' : 's'}</b>
        <span class="muted">· ${CU.devices.filter((d) => d.session_status === 'connected').length} connected · ${CU.sessions.length} active sign-in session${CU.sessions.length === 1 ? '' : 's'} · limit ${num(dq.limit)}</span></div>
      <div class="devices">${CU.devices.map((d, i) => `<div class="device" style="${d.status === 'revoked' ? 'opacity:.6' : ''}">
        <div class="t"><span class="ico">${DEV_ICON[d.device_type] ?? DEV_ICON.unknown}</span>
          <div style="min-width:0"><div class="note">Device ${i + 1}</div><b>${esc(d.name)}</b><div class="note">${esc([d.os, d.browser].filter(Boolean).join(' · ') || d.platform || 'Unknown browser')} · ${esc(d.device_type)}</div>
          <div style="margin-top:6px">${chip(d.status === 'pending' ? 'pending' : d.session_status)}</div></div></div>
        <dl class="kv">
          <dt>Type</dt><dd>${esc(d.device_type)}</dd><dt>Registered</dt><dd>${esc(when(d.registered_at))}</dd>
          <dt>Last activity</dt><dd>${esc(ago(d.last_seen_at))}</dd><dt>Session</dt><dd class="mono">${d.session_id ? short(d.session_id) + ' · since ' + esc(ago(d.session_started_at)) : '—'}</dd>
          <dt>Device ID</dt><dd class="mono">${short(d.id)}</dd><dt>Network</dt><dd class="mono">${esc(d.ip_prefix || '—')}</dd>
          <dt>Scans</dt><dd>${num(d.scans)} · ${num(d.threats)} threats</dd>
          ${d.revoked_reason ? `<dt>Unlinked</dt><dd>${esc(ago(d.revoked_at))}: ${esc(d.revoked_reason)}</dd>` : ''}</dl>
        ${d.status !== 'revoked' ? `<div class="row" style="margin-top:10px">${d.session_id ? `<button class="btn sm" data-a="revoke-session" data-id="${esc(d.session_id)}" data-label="${esc(d.name)}">Sign out device</button>` : ''}
          <button class="btn danger sm" data-a="unlink" data-id="${esc(d.id)}" data-label="${esc(d.name)}">Unlink device</button></div>` : ''}
      </div>`).join('') || '<p class="empty">No devices registered.</p>'}</div>
      <div class="panel" style="margin-top:14px"><h3>Sign-in sessions</h3><p class="note">One device can have several sessions over time; these are the sessions that are currently valid.</p>
        <div class="table-wrap"><table><tr><th>Session</th><th>Started</th><th>Last refresh</th><th>Browser / OS</th><th>Network</th><th>Device</th><th>MFA</th><th></th></tr>
        ${CU.sessions.map((x) => `<tr><td class="mono">${short(x.id)}</td><td>${esc(when(x.created_at))}</td><td>${esc(ago(x.refreshed_at))}</td>
          <td>${esc([x.agent?.browser, x.agent?.os].filter(Boolean).join(' · ') || '—')}<div class="sub">${esc(x.agent?.device_type)}</div></td><td class="mono">${esc(x.ip_prefix || '—')}</td>
          <td>${x.device ? esc(x.device.name) + ' ' + chip(x.device.status) : '<span class="note">not bound to a device</span>'}</td><td>${esc(x.aal)}</td>
          <td><button class="btn sm" data-a="revoke-session" data-id="${esc(x.id)}" data-label="session ${short(x.id)}">Revoke</button></td></tr>`).join('') || '<tr><td colspan="8" class="empty">No active sessions.</td></tr>'}
        </table></div></div>`;
  },
  threats() {
    const st = CU.stats || {};
    const rows = CU.incidents.filter((i) => (i.is_threat || ['resolved', 'false_positive'].includes(i.status))
      && (!IF.severity || i.severity === IF.severity) && (!IF.status || i.status === IF.status || (IF.status === 'open' && ['detected', 'blocked', 'investigating'].includes(i.status)))
      && (!IF.verdict || i.verdict === IF.verdict) && (!IF.from || i.created_at >= IF.from) && (!IF.to || i.created_at <= IF.to + 'T23:59:59'));
    return `<div class="kpis">
      ${kpi('URLs checked', num(st.urls_checked), C.teal)}${kpi('Safe URLs', num(st.urls_safe), C.low)}${kpi('Suspicious URLs', num(st.urls_suspicious), C.med)}
      ${kpi('Malicious URLs', num(st.urls_malicious), C.high)}${kpi('Threats detected', num(st.threats_detected), C.high)}${kpi('Blocked', num(st.blocked), C.info, 'recorded block events')}
      ${kpi('Resolved', num(st.resolved), C.low)}${kpi('Still open', num(st.open), C.med)}
      ${kpi('Critical / high / medium', `${num(st.severity?.critical)} / ${num(st.severity?.high)} / ${num(st.severity?.medium)}`, C.crit)}
      ${kpi('Alerts sent', num(st.alerted), C.info, 'incidents with device notifications')}</div>
      <div class="filters" id="cu-if">
        <select name="severity">${opts([['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], IF.severity)}</select>
        <select name="status">${opts([['', 'Any status'], ['open', 'Open (any)'], ['detected', 'Detected'], ['blocked', 'Blocked'], ['investigating', 'Investigating'], ['resolved', 'Resolved'], ['false_positive', 'False positive']], IF.status)}</select>
        <select name="verdict">${opts([['', 'Any verdict'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious']], IF.verdict)}</select>
        <label class="note">From<input type="date" name="from" value="${esc(IF.from)}"></label><label class="note">To<input type="date" name="to" value="${esc(IF.to)}"></label>
      </div>
      ${incidentTable(rows.map((i) => ({ ...i, email: CU.profile.email })))}
      <p class="note">Detection source for every row: ScamWise heuristic rules plus URLhaus reputation lookup where configured. Click a row for evidence and the response timeline.</p>`;
  },
  activity() {
    const ev = [];
    const LE = { sign_in: ['Signed in', C.low], sign_out: ['Signed out', C.mute], session_revoked: ['Session revoked', C.high], device_registered: ['Device registered', C.info],
      device_unlinked: ['Device unlinked', C.high], account_suspended: ['Account suspended', C.crit], account_reactivated: ['Account reactivated', C.low] };
    CU.logins.forEach((l) => ev.push({ at: l.at, c: (LE[l.kind] || [])[1], t: `${(LE[l.kind] || [l.kind])[0]}${l.device_name ? ' · ' + l.device_name : ''}`,
      s: [l.actor_kind !== 'user' ? 'by ' + l.actor_kind : '', l.ip_prefix, l.note].filter(Boolean).join(' · '), k: 'Login & devices' }));
    CU.subscription_events.forEach((e) => ev.push({ at: e.at, c: C.teal, t: `Subscription ${e.event.replace(/_/g, ' ')}${e.to_plan ? ' · ' + (PLAN[e.to_plan] ?? e.to_plan) : ''}`,
      s: [e.from_plan && e.from_plan !== e.to_plan ? 'from ' + (PLAN[e.from_plan] ?? e.from_plan) : '', e.to_expires ? 'valid to ' + day(e.to_expires) : '', 'by ' + e.actor_kind, e.note].filter(Boolean).join(' · '), k: 'Subscription' }));
    CU.incidents.filter((i) => i.is_threat || i.status !== 'no_threat').forEach((i) => ev.push({ at: i.created_at, c: i.severity === 'critical' ? C.crit : C.high,
      t: `Threat detected · ${String(i.category).replace(/_/g, ' ')} (${i.severity})`, s: `${i.device_name ?? ''} · now ${LABEL[i.status] ?? i.status}`, k: 'Security' }));
    CU.incidents.filter((i) => !i.is_threat && i.status === 'no_threat').slice(0, 50).forEach((i) => ev.push({ at: i.created_at, c: C.mute, t: `URL/message check · ${i.verdict}`, s: `${i.urls_count} link(s) · ${i.device_name ?? ''}`, k: 'Scans' }));
    CU.alerts.forEach((a) => ev.push({ at: a.created_at, c: C.info, t: `Security alert · ${a.title}`, s: `to ${a.target_device ?? 'device'} · ${a.read_at ? 'read' : 'unread'}`, k: 'Alerts' }));
    CU.audit.filter((a) => a.actor_kind === 'admin').forEach((a) => ev.push({ at: a.at, c: C.med, t: `Admin: ${a.action}`, s: a.detail ? JSON.stringify(a.detail).slice(0, 160) : '', k: 'Admin actions' }));
    ev.sort((a, b) => (a.at < b.at ? 1 : -1));
    const kinds = [...new Set(ev.map((e) => e.k))];
    return `<div class="row" style="margin-bottom:10px" id="act-k">${['All', ...kinds].map((k, i) => `<button class="btn sm ${i ? 'ghost' : ''}" data-k="${esc(k)}">${esc(k)}</button>`).join('')}</div>
      <ul class="timeline" id="act-list">${ev.slice(0, 300).map((e) => `<li data-kind="${esc(e.k)}"><span class="when">${esc(when(e.at))}</span><span class="dot" style="--c:${e.c ?? C.teal}"></span>
        <span><b>${esc(e.t)}</b>${e.s ? `<div class="note">${esc(e.s)}</div>` : ''}</span></li>`).join('') || '<li class="empty">No activity recorded.</li>'}</ul>`;
  },
  billing() {
    const s = CU.subscription || {};
    return `<div class="callout info">Online payments are <b>pending integration</b>. Payments entered here are marked <b>manual (unverified)</b>; only a payment-provider webhook can mark a payment provider-verified.</div>
      <div class="panel" style="margin-top:14px"><div class="panel-head"><h3>Transactions</h3><button class="btn sm r" data-a="payment">Record payment</button></div>
      <div class="table-wrap"><table><tr><th>Date</th><th>Amount</th><th>Plan / period</th><th>Status</th><th>Verification</th><th>Method / reference</th><th>Note</th></tr>
      ${CU.payments.map((x) => `<tr><td>${esc(when(x.created_at))}</td><td><b>${inr(x.amount_inr)}</b></td><td>${plan(x.plan_code)}<div class="sub">${x.period_start ? esc(day(x.period_start)) + ' → ' + esc(day(x.period_end)) : ''}</div></td>
        <td>${chip(x.status)}${x.failure_reason ? `<div class="sub">${esc(x.failure_reason)}</div>` : ''}</td><td>${chip(x.verification === 'provider_verified' ? 'verified' : 'manual', x.verification === 'provider_verified' ? 'verified' : 'manual')}</td>
        <td>${esc(x.method || x.provider)}<div class="sub mono">${esc(x.provider_ref || '')}</div></td><td class="sub">${esc(x.note || '')}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">No transactions recorded.</td></tr>'}</table></div></div>
      <div class="panel"><h3>Subscription history</h3><div class="table-wrap"><table><tr><th>When</th><th>Event</th><th>Plan</th><th>Validity</th><th>By</th><th>Note</th></tr>
      ${CU.subscription_events.map((e) => `<tr><td>${esc(when(e.at))}</td><td>${chip(e.event, ['suspended', 'cancelled', 'expired'].includes(e.event) ? 'high' : 'ok')}</td>
        <td>${e.from_plan && e.from_plan !== e.to_plan ? plan(e.from_plan) + ' → ' : ''}${plan(e.to_plan)}</td><td class="sub">${e.to_expires ? 'to ' + esc(day(e.to_expires)) : ''}</td>
        <td>${esc(e.actor_kind)}</td><td class="sub">${esc(e.note || '')}</td></tr>`).join('')}</table></div></div>
      ${CU.plan_requests.length ? `<div class="panel"><h3>Upgrade requests</h3>${CU.plan_requests.map((q) => `<p>${esc(when(q.created_at))} · ${plan(q.plan_code)} ${chip(q.status)} <span class="note">${esc(q.message || '')}</span></p>`).join('')}</div>` : ''}`;
  },
};
document.addEventListener('click', (e) => {
  const k = e.target.closest('#act-k [data-k]'); if (!k) return;
  $$('#act-k [data-k]').forEach((b) => b.classList.toggle('ghost', b !== k));
  $$('#act-list li[data-kind]').forEach((li) => li.classList.toggle('hidden', k.dataset.k !== 'All' && li.dataset.kind !== k.dataset.k));
});

// ------------------------------------------------------------------ customer / device actions (all confirmed, all audited server-side)
const isoDate = (d) => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
const addDays = (base, n) => { const d = new Date(base); d.setDate(d.getDate() + n); return d; };
document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-a]'); if (!b) return;
  const a = b.dataset.a, uid = b.dataset.user || CU?.profile?.id, label = b.dataset.label;
  if (a === 'plan') return planDialog(uid);
  if (a === 'payment') return paymentDialog(uid);
  if (a === 'revoke-session') {
    const v = await dialog({ title: `Sign out ${label}?`, body: 'The session ends immediately and its refresh token stops working. The device stays registered and can sign in again.',
      fields: [{ name: 'reason', label: 'Reason (audit log)', required: true }], confirm: 'Sign out', danger: true });
    if (v) act(() => rpc('admin_revoke_session', { p_session: b.dataset.id, p_reason: v.reason }), 'Session revoked.');
  }
  if (a === 'unlink') {
    const v = await dialog({ title: `Unlink ${label}?`, body: 'The device is removed from the account, its session is ended and it must be re-approved to rejoin.',
      fields: [{ name: 'reason', label: 'Reason (audit log)', required: true }], confirm: 'Unlink device', danger: true });
    if (v) act(() => rpc('admin_revoke_device', { p_device: b.dataset.id, p_reason: v.reason }), 'Device unlinked.');
  }
  if (a === 'acct-suspend') {
    const v = await dialog({ title: 'Suspend this account?', body: 'Sign-in is blocked, every session is ended, and scans are refused until reactivated.',
      fields: [{ name: 'reason', label: 'Reason (audit log)', required: true }], confirm: 'Suspend account', danger: true });
    if (v) act(() => rpc('admin_suspend_account', { p_user: uid, p_reason: v.reason }), 'Account suspended.');
  }
  if (a === 'acct-reactivate') {
    const v = await dialog({ title: 'Reactivate this account?', fields: [{ name: 'note', label: 'Note (audit log)' }], confirm: 'Reactivate' });
    if (v) act(() => rpc('admin_reactivate_account', { p_user: uid, p_note: v.note }), 'Account reactivated. The customer can sign in again.');
  }
  if (a.startsWith('sub-')) {
    const kind = a.slice(4);
    const meta = { suspend: ['Suspend subscription?', 'Scans are refused while suspended. Validity dates are not changed.', true],
      reactivate: ['Reactivate subscription?', '', false], cancel: ['Cancel renewal?', 'Access continues until the current expiry date, then the plan expires.', true],
      uncancel: ['Undo cancellation?', '', false] }[kind];
    const v = await dialog({ title: meta[0], body: meta[1], fields: [{ name: 'reason', label: 'Reason (audit log)', required: meta[2] }], confirm: meta[0].replace('?', ''), danger: meta[2] });
    if (v) act(() => rpc('admin_subscription_action', { p_user: uid, p_action: kind, p_reason: v.reason || kind }), 'Subscription updated.');
  }
});

async function planDialog(uid) {
  const s = CU?.profile?.id === uid ? CU.subscription : null;
  const exp = s ? new Date(s.expires_at) : new Date();
  const base = exp > new Date() ? exp : new Date();
  const v = await dialog({ title: 'Assign or change plan', body: 'Changes take effect immediately and are recorded in the subscription history and audit log.',
    fields: [
      { name: 'plan', label: 'Plan', type: 'select', value: s?.plan ?? 'individual', options: [['trial', 'Free trial (7 days, 2 checks/day, 14 total, 1 device)'], ['individual', 'Individual · ₹299/mo · 1 device'],
        ['family', 'Family · ₹699/mo · 3 devices'], ['business', 'Business · ₹1,899/mo · 8 devices'], ['enterprise', 'Enterprise & Banking · custom']] },
      { name: 'start', label: 'Start date', type: 'date', value: isoDate(s && exp > new Date() ? new Date(s.started_at) : new Date()) },
      { name: 'expires', label: 'Valid until', type: 'date', required: true, value: isoDate(addDays(base, 30)), hint: 'Defaults to one month after the current expiry (or today).' },
      { name: 'devices', label: 'Enterprise device limit (contract)', type: 'number', min: 1, value: s?.device_limit_override ?? '' },
      { name: 'price', label: 'Enterprise price ₹/month (contract)', type: 'number', min: 0, value: s?.custom_price_inr ?? '' },
      { name: 'note', label: 'Note (e.g. invoice or contract reference)', value: s?.note ?? '' },
      { name: 'reset', label: 'Trial check counters', type: 'select', value: 'no', options: [['no', 'Keep'], ['yes', 'Reset to zero']] }],
    confirm: 'Save plan' });
  if (!v) return;
  await act(() => rpc('admin_set_subscription', { p_user: uid, p_plan: v.plan, p_expires_at: new Date(v.expires + 'T23:59:59').toISOString(),
    p_started_at: v.start ? new Date(v.start + 'T00:00:00').toISOString() : null, p_device_limit: v.plan === 'enterprise' && v.devices ? +v.devices : null,
    p_custom_price: v.plan === 'enterprise' && v.price ? +v.price : null, p_note: v.note, p_reset_trial_usage: /^y/i.test(v.reset) }), 'Plan saved.');
}
async function paymentDialog(uid) {
  const v = await dialog({ title: 'Record a payment', body: 'Recorded as <b>manual (unverified)</b>. Never enter card numbers, CVV or UPI PINs — only the transaction / UTR / invoice reference.',
    fields: [
      { name: 'amount', label: 'Amount (₹)', type: 'number', min: 0, step: '0.01', required: true, value: CU?.subscription?.price_inr ?? '' },
      { name: 'status', label: 'Status', type: 'select', value: 'paid', options: [['paid', 'Paid'], ['pending', 'Pending'], ['failed', 'Failed'], ['refunded', 'Refunded'], ['cancelled', 'Cancelled']] },
      { name: 'method', label: 'Method', type: 'select', value: 'upi', options: [['upi', 'UPI'], ['card', 'Card (via gateway)'], ['netbanking', 'Net banking'], ['bank_transfer', 'Bank transfer'], ['cash', 'Cash'], ['cheque', 'Cheque'], ['other', 'Other']] },
      { name: 'ref', label: 'Transaction / UTR / invoice reference', max: 120 },
      { name: 'plan', label: 'Plan', type: 'select', value: CU?.subscription?.plan ?? 'individual', options: Object.entries(PLAN).filter(([k]) => k !== 'trial') },
      { name: 'ps', label: 'Period start', type: 'date', value: isoDate(new Date()) }, { name: 'pe', label: 'Period end', type: 'date', value: isoDate(addDays(new Date(), 30)) },
      { name: 'fail', label: 'Failure reason (failed payments)' }, { name: 'note', label: 'Note' }],
    confirm: 'Record payment' });
  if (!v) return;
  await act(() => rpc('admin_record_payment', { p_user: uid, p_amount: +v.amount, p_status: v.status, p_method: v.method, p_reference: v.ref, p_plan: v.plan,
    p_period_start: v.ps || null, p_period_end: v.pe || null, p_failure_reason: v.fail || null, p_note: v.note || null }), 'Payment recorded.');
}

// ================================================================== DEVICES & SESSIONS
const DF = { search: '', status: '' };
PAGES.devices = async () => {
  const lim = 50, res = await rpc('admin_devices', { p_search: DF.search || null, p_status: DF.status || null, p_limit: lim, p_offset: (state.page.dev ?? 0) * lim });
  return `<div class="callout">"Connected" means an active device with a valid sign-in session and a heartbeat in the last ${res.online_seconds} seconds. A registered device is never assumed to be connected.
      Device identity is a per-browser install ID bound to an authenticated session — clearing browser data creates a new device. ${res.unbound_sessions ? `${res.unbound_sessions} signed-in session(s) are not bound to a device yet.` : ''}</div>
    <div class="panel" style="margin-top:14px"><div class="filters" id="dev-f">
      <input name="search" placeholder="Search customer email, device name or ID" value="${esc(DF.search)}">
      <select name="status">${opts([['', 'Any status'], ['connected', 'Connected'], ['idle', 'Idle (signed in)'], ['signed_out', 'Signed out'], ['session_ended', 'Session ended'], ['pending', 'Pending approval'], ['revoked', 'Unlinked']], DF.status)}</select></div>
    <div class="table-wrap"><table><tr><th>Device</th><th>Customer</th><th>Type</th><th>Status</th><th>Registered</th><th>Last activity</th><th>Session</th><th>Network</th><th></th></tr>
    ${res.rows.map((d) => `<tr><td><b>${esc(d.name)}</b><div class="sub mono">${short(d.id)}</div></td>
      <td><a href="#/customer/${esc(d.user_id)}">${esc(d.email)}</a><div class="sub">${esc(d.display_name || '')}</div></td>
      <td>${esc(d.device_type)}<div class="sub">${esc([d.os, d.browser].filter(Boolean).join(' · '))}</div></td>
      <td>${chip(d.status === 'pending' ? 'pending' : d.session_status)}</td><td class="sub">${esc(day(d.registered_at))}</td><td>${esc(ago(d.last_seen_at))}</td>
      <td class="mono sub">${d.session_id ? short(d.session_id) : '—'}</td><td class="mono sub">${esc(d.ip_prefix || '—')}</td>
      <td class="row">${d.session_id ? `<button class="btn sm" data-a="revoke-session" data-id="${esc(d.session_id)}" data-label="${esc(d.name)}">Sign out</button>` : ''}
        ${d.status !== 'revoked' ? `<button class="btn danger sm" data-a="unlink" data-id="${esc(d.id)}" data-label="${esc(d.name)}">Unlink</button>` : ''}</td></tr>`).join('')
      || '<tr><td colspan="9" class="empty">No devices match.</td></tr>'}</table></div>${pager('dev', res.total, lim)}</div>`;
};
PAGES.devices.after = () => filterBind('#dev-f', DF, 'dev');
function filterBind(sel, F, pg) {
  let t;
  $$(sel + ' [name]').forEach((el) => el.addEventListener(el.tagName === 'INPUT' && el.type !== 'date' ? 'input' : 'change', () => {
    clearTimeout(t); t = setTimeout(() => { F[el.name] = el.value; state.page[pg] = 0; render().then(() => { const s = $(sel + ' [name=' + el.name + ']'); if (s && el.tagName === 'INPUT') { s.focus(); try { s.setSelectionRange(s.value.length, s.value.length); } catch {} } }); }, el.tagName === 'INPUT' ? 350 : 0);
  }));
}

// ================================================================== THREAT MONITORING
let TM = null;
PAGES.threats = async () => {
  const rg = range();
  const [d, ts] = await Promise.all([rpc('admin_dashboard', { p_from: rg.from, p_to: rg.to }), rpc('admin_timeseries', { p_from: rg.from, p_to: rg.to, p_bucket: R.bucket })]);
  TM = { d, ts }; const t = d.threats || {};
  return `<div class="kpis">
    ${kpi('Scans', num(t.scans), C.teal)}${kpi('URLs checked', num(t.urls_checked), C.teal)}
    ${kpi('Safe URLs', num(t.urls_safe), C.low)}${kpi('Suspicious URLs', num(t.urls_suspicious), C.med)}${kpi('Malicious URLs', num(t.urls_malicious), C.high)}
    ${kpi('Threats detected', num(t.threats_detected), C.high)}${kpi('Critical', num(t.severity?.critical), C.crit)}
    ${kpi('Customers alerted', num(t.alerted), C.info, 'incidents with device notifications')}
    ${kpi('Blocked', num(t.blocked), C.info, 'requires a blocking client (pending)')}${kpi('Open', num(t.open), C.med)}</div>
  <div class="callout info">Detection sources: ScamWise heuristic rules engine on every scan, plus abuse.ch URLhaus reputation lookups for links when the API key is configured.
    ScamWise warns the user in the scan result and alerts their other devices; it does <b>not</b> block URLs at the browser, OS or network level. "Blocked" counts only recorded block events from a client that actually blocked.</div>
  <div class="cols"><div class="panel"><h3>Threats over time</h3><div class="chart tall"><canvas id="ch-t1"></canvas></div></div>
    <div class="panel"><h3>Top threat categories</h3><div class="chart tall"><canvas id="ch-t2"></canvas></div></div></div>
  <div class="cols"><div class="panel"><h3>URL verdicts</h3><div class="chart"><canvas id="ch-t3"></canvas></div></div>
    <div class="panel"><h3>Severity</h3><div class="chart"><canvas id="ch-t4"></canvas></div></div></div>`;
};
PAGES.threats.after = () => {
  const { d, ts } = TM, t = d.threats || {}, labels = ts.map((r) => bucketLabel(r.bucket));
  chart('ch-t1', { type: 'bar', data: { labels, datasets: [{ label: 'Threats', data: series(ts, 'threats'), backgroundColor: C.high }, { label: 'Critical', data: series(ts, 'critical'), backgroundColor: C.crit },
    { label: 'Resolved', data: series(ts, 'resolved'), backgroundColor: C.low }] }, options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
  const cat = d.categories || {};
  chart('ch-t2', { type: 'bar', data: { labels: Object.keys(cat).map((k) => k.replace(/_/g, ' ')), datasets: [{ label: 'Incidents', data: Object.values(cat), backgroundColor: C.teal }] },
    options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } } } });
  chart('ch-t3', { type: 'doughnut', data: { labels: ['Safe', 'Suspicious', 'Malicious', 'Inconclusive'], datasets: [{ data: [t.urls_safe, t.urls_suspicious, t.urls_malicious, t.urls_inconclusive],
    backgroundColor: [C.low, C.med, C.high, C.mute], borderWidth: 0 }] }, options: { plugins: { legend: { position: 'bottom' } } } });
  const sv = t.severity || {};
  chart('ch-t4', { type: 'bar', data: { labels: ['Critical', 'High', 'Medium', 'Low'], datasets: [{ data: [sv.critical, sv.high, sv.medium, sv.low], backgroundColor: [C.crit, C.high, C.med, C.low] }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
};

// ================================================================== INCIDENTS
const NF = { severity: '', status: 'open', category: '', verdict: '', search: '' };
PAGES.incidents = async () => {
  const rg = range(), lim = 50;
  const res = await rpc('admin_incidents', { p_from: rg.from, p_to: rg.to, p_severity: NF.severity || null, p_status: NF.status || null, p_category: NF.category || null,
    p_verdict: NF.verdict || null, p_search: NF.search || null, p_limit: lim, p_offset: (state.page.inc ?? 0) * lim });
  return `<div class="panel"><div class="filters" id="inc-f">
      <input name="search" placeholder="Search email, domain or incident ID" value="${esc(NF.search)}">
      <select name="status">${opts([['', 'Any status'], ['open', 'Open (detected / blocked / investigating)'], ['detected', 'Detected'], ['blocked', 'Blocked'], ['investigating', 'Investigating'], ['resolved', 'Resolved'], ['false_positive', 'False positive']], NF.status)}</select>
      <select name="severity">${opts([['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], NF.severity)}</select>
      <select name="verdict">${opts([['', 'Any verdict'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious']], NF.verdict)}</select>
      <select name="category">${opts([['', 'Any threat type'], ...(res.categories || []).map((c) => [c, String(c).replace(/_/g, ' ')])], NF.category)}</select></div>
    ${incidentTable(res.rows)}${pager('inc', res.total, lim)}</div>`;
};
PAGES.incidents.after = () => filterBind('#inc-f', NF, 'inc');

async function openIncident(id) {
  let i;
  try { i = await rpc('admin_incident', { p_incident: id }); } catch (e) { return toast(friendly(e), true); }
  const EV = { detected: C.high, user_warned: C.info, alert_sent: C.info, blocked: C.info, investigating: C.med, resolved: C.low, false_positive: C.mute, reopened: C.high, note: C.teal };
  const d = openDrawer(`
    <div class="row"><h3>Incident ${short(i.id)}</h3><button class="btn sm ghost" style="margin-left:auto" id="dr-close">Close</button></div>
    <p class="mono note">${esc(i.id)}</p>
    <div class="row">${chip(i.verdict)} ${chip(i.severity)} ${chip(i.status)} <span class="note">score ${esc(i.score)}/100</span></div>
    <dl class="kv" style="margin-top:14px">
      <dt>Customer</dt><dd><a href="#/customer/${esc(i.user_id)}">${esc(i.email ?? '—')}</a></dd>
      <dt>Device</dt><dd>${esc(i.device?.name ?? i.device_name ?? '—')} <span class="note">${esc([i.device?.device_type, i.device?.os, i.device?.browser].filter(Boolean).join(' · '))}</span></dd>
      <dt>Session</dt><dd class="mono">${i.session_id ? short(i.session_id) : '—'}</dd>
      <dt>Detected</dt><dd>${esc(when(i.created_at))}</dd><dt>Source</dt><dd>${esc(i.source)} scan · ${esc(i.analysis_method)} (engine ${esc(i.engine_version)})</dd>
      <dt>Threat type</dt><dd>${esc(String(i.category).replace(/_/g, ' '))}</dd>
      <dt>URLs</dt><dd class="mono">${esc((i.url_domains || []).join(', ') || 'none in message')}</dd>
      <dt>Threat intel</dt><dd>${chip(i.ti_status)}${i.ti_detail?.matches?.length ? '<div class="note">' + i.ti_detail.matches.map((m) => esc(`${m.match_type} match: ${m.threat} (${m.url_status})`)).join('<br>') + '</div>' : ''}</dd>
      <dt>Automated response</dt><dd>${chip(i.response_status)} ${i.alerts_sent ? `· ${i.alerts_sent} device alert(s)` : ''} ${i.blocked_at ? '· blocked ' + esc(when(i.blocked_at)) : '· not blocked (ScamWise warns; it cannot block navigation)'}</dd>
      <dt>Auth code</dt><dd>${i.contained_auth_code ? 'Present — redacted on the device, never transmitted' : 'No'}</dd>
      <dt>Resolved</dt><dd>${i.resolved_at ? esc(when(i.resolved_at)) + ' by ' + esc(i.resolved_by_kind) : '—'}</dd></dl>
    <h4 style="margin-top:18px">Detection evidence</h4>
    ${(i.indicators || []).map((x) => `<div class="row" style="padding:6px 0;border-bottom:1px solid var(--line)"><b style="width:44px">+${esc(x.weight)}</b><div><b>${esc(x.label)}</b><div class="note">${esc(x.code)}${x.detail ? ' · ' + esc(x.detail) : ''}</div></div></div>`).join('') || '<p class="note">No indicators recorded.</p>'}
    <p class="note">${i.excerpt ? 'Customer opted in to a masked excerpt: ' + esc(i.excerpt) : 'Message text is not stored.'}</p>
    <h4 style="margin-top:18px">Response timeline</h4>
    <ul class="timeline">${(i.events || []).map((e) => `<li><span class="when">${esc(when(e.at))}</span><span class="dot" style="--c:${EV[e.event] ?? C.teal}"></span>
      <span><b>${esc(LABEL[e.event] ?? e.event.replace(/_/g, ' '))}</b> <span class="note">by ${esc(e.actor_kind)}</span>${e.note ? `<div class="note">${esc(e.note)}</div>` : ''}</span></li>`).join('')}</ul>
    ${(i.alerts || []).length ? `<h4 style="margin-top:18px">Notifications delivered</h4>${i.alerts.map((a) => `<p class="note">${esc(when(a.created_at))} → ${esc(a.device ?? 'device')} · ${a.read_at ? 'read ' + esc(ago(a.read_at)) : 'unread'}</p>`).join('')}` : ''}
    <h4 style="margin-top:18px">Actions</h4>
    <div class="row">
      ${i.status !== 'investigating' ? '<button class="btn sm" data-st="investigating">Start investigation</button>' : ''}
      ${i.status !== 'resolved' ? '<button class="btn primary sm" data-st="resolved">Mark resolved</button>' : ''}
      ${i.status !== 'false_positive' ? '<button class="btn sm" data-st="false_positive">False positive</button>' : ''}
      ${['resolved', 'false_positive'].includes(i.status) ? '<button class="btn sm" data-st="detected">Reopen</button>' : ''}
      <button class="btn sm ghost" data-st="note">Add note</button></div>
    <p class="note">Resolution requires a written note and is recorded with your admin identity. "Blocked" can only be set by a client that actually blocked access.</p>`);
  $('#dr-close').onclick = closeOverlays;
  $$('[data-st]', d).forEach((b) => (b.onclick = async () => {
    const st = b.dataset.st, need = ['resolved', 'false_positive', 'note'].includes(st);
    const v = await dialog({ title: st === 'note' ? 'Add investigation note' : `Set status: ${LABEL[st] ?? st}`, fields: [{ name: 'note', label: 'Note', type: 'textarea', required: need, max: 500,
      hint: st === 'resolved' ? 'Describe the evidence or action that resolved it.' : '' }], confirm: 'Save' });
    if (!v) return;
    try {
      if (st === 'note') await rpc('admin_incident_note', { p_incident: id, p_note: v.note });
      else await rpc('admin_set_incident_status', { p_incident: id, p_status: st, p_note: v.note });
      toast('Incident updated.'); openIncident(id); render();
    } catch (e) { toast(friendly(e), true); }
  }));
}

// ================================================================== SUBSCRIPTIONS & PLANS
const SF = { status: '', plan: '', search: '' }; let subTab = 'subs';
PAGES.subscriptions = async () => {
  const lim = 50;
  const [res, d, orgs] = await Promise.all([
    rpc('admin_subscriptions', { p_status: SF.status || null, p_plan: SF.plan || null, p_search: SF.search || null, p_limit: lim, p_offset: (state.page.sub ?? 0) * lim }),
    rpc('admin_dashboard', {}), rpc('admin_orgs')]);
  const evs = res.events || [], cnt = (k) => evs.filter((e) => e.event === k).length;
  const openReq = (res.requests || []).filter((q) => q.status === 'open').length;
  const t = (k, l) => `<button data-stab="${k}" class="${subTab === k ? 'on' : ''}">${l}</button>`;
  return `<div class="kpis">
    ${kpi('Active paid', num(d.premium_active), C.low)}${kpi('On trial', num(d.trialing), C.med)}${kpi('Expired', num(d.expired), C.high)}
    ${kpi('Suspended', num(d.subscriptions_suspended), C.crit)}${kpi('Expiring ≤ 7 days', num(d.expiring_7d), C.med)}${kpi('MRR', inr(d.mrr_inr), C.teal)}
    ${kpi('Renewals (recent)', num(cnt('renewed')), C.low)}${kpi('Cancellations (recent)', num(cnt('cancelled')), C.high)}${kpi('Failed payments', num(d.revenue?.failed_count), C.high, 'all time')}</div>
  <div class="panel"><div class="tabs" style="margin-top:0">${t('subs', 'Subscriptions')}${t('events', 'Renewals & cancellations')}${t('requests', `Upgrade requests${openReq ? ` (${openReq})` : ''}`)}${t('plans', 'Plans')}${t('orgs', 'Organisations')}</div>
  <div id="sub-body">${subTab === 'subs' ? `<div class="filters" id="sub-f"><input name="search" placeholder="Search customer" value="${esc(SF.search)}">
      <select name="plan">${opts(PLAN_OPTS, SF.plan)}</select><select name="status">${opts([['', 'Any status'], ['trialing', 'Trial'], ['active', 'Active'], ['cancelled', 'Cancelled (until expiry)'], ['expired', 'Expired'], ['suspended', 'Suspended'], ['expiring', 'Expiring in 7 days']], SF.status)}</select></div>
    <div class="table-wrap"><table><tr><th>Customer</th><th>Plan</th><th>Status</th><th>Started</th><th>Expires</th><th>Trial</th><th>Price</th><th>Devices</th><th>Last payment</th><th></th></tr>
    ${res.rows.map((s) => `<tr><td><a href="#/customer/${esc(s.user_id)}">${esc(s.name || s.email)}</a><div class="sub">${esc(s.email)}</div></td><td>${plan(s.plan)}</td><td>${chip(s.status)}</td>
      <td class="sub">${esc(day(s.started_at))}</td><td>${esc(day(s.expires_at))}<div class="sub">${esc(ago(s.expires_at))}</div></td>
      <td class="sub">${s.trial_started_at ? esc(day(s.trial_started_at)) + ' → ' + esc(day(s.trial_expires_at)) : '—'}${s.converted_at ? '<br>converted ' + esc(day(s.converted_at)) : ''}</td>
      <td>${s.price_inr != null ? inr(s.price_inr) : 'custom'}</td><td>${num(s.devices?.used)} / ${num(s.devices?.limit)}</td>
      <td>${s.last_payment_status ? chip(s.last_payment_status) : '<span class="note">none</span>'}${s.last_paid_at ? `<div class="sub">${esc(day(s.last_paid_at))}</div>` : ''}</td>
      <td><button class="btn sm" data-a="plan" data-user="${esc(s.user_id)}">Change</button></td></tr>`).join('') || '<tr><td colspan="10" class="empty">No subscriptions match.</td></tr>'}</table></div>${pager('sub', res.total, lim)}`
  : subTab === 'events' ? `<div class="table-wrap"><table><tr><th>When</th><th>Customer</th><th>Event</th><th>Plan</th><th>Validity</th><th>By</th><th>Note</th></tr>
    ${evs.map((e) => `<tr><td>${esc(when(e.at))}</td><td><a href="#/customer/${esc(e.user_id)}">${esc(e.email)}</a></td><td>${chip(e.event, ['cancelled', 'suspended', 'expired'].includes(e.event) ? 'high' : 'ok')}</td>
      <td>${e.from_plan && e.from_plan !== e.to_plan ? plan(e.from_plan) + ' → ' : ''}${plan(e.to_plan)}</td><td class="sub">${e.to_expires ? 'to ' + esc(day(e.to_expires)) : e.from_expires ? 'ended ' + esc(day(e.from_expires)) : ''}</td>
      <td>${esc(e.actor_kind)}</td><td class="sub">${esc(e.note || '')}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">No events yet.</td></tr>'}</table></div>`
  : subTab === 'requests' ? `<p class="note">Customers request upgrades or renewals from their dashboard. Follow up, record the payment, then assign the plan.</p>
    <div class="table-wrap"><table><tr><th>When</th><th>Customer</th><th>Requested plan</th><th>Message</th><th>Status</th><th></th></tr>
    ${(res.requests || []).map((q) => `<tr><td>${esc(when(q.created_at))}</td><td><a href="#/customer/${esc(q.user_id)}">${esc(q.email)}</a></td><td>${plan(q.plan_code)}</td><td class="sub">${esc(q.message || '')}</td><td>${chip(q.status)}</td>
      <td class="row">${['contacted', 'done', 'declined'].filter((x) => x !== q.status).map((x) => `<button class="btn sm" data-req="${esc(q.id)}" data-to="${x}">${x}</button>`).join('')}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No requests.</td></tr>'}</table></div>`
  : subTab === 'plans' ? `<div class="table-wrap"><table><tr><th>Plan</th><th>Price</th><th>Billing</th><th>Device limit</th><th>Features</th><th>Active</th></tr>
    ${res.plans.map((p) => `<tr><td><b>${esc(p.name)}</b><div class="sub mono">${esc(p.code)}</div></td><td>${p.price_inr != null ? inr(p.price_inr) : 'Custom'}</td><td>${esc(p.billing_period)}</td>
      <td>${p.device_limit ?? 'per contract'}</td><td class="sub">${(p.features || []).map(esc).join(' · ')}</td><td>${p.active ? chip('active') : chip('inactive', 'none')}</td></tr>`).join('')}</table></div>
    <p class="note">Edit prices, limits and the trial policy in <a href="#/settings">Settings</a>.</p>`
  : `<div class="panel-head"><p class="note">Organisations group family, business or enterprise members under one pooled device limit. Owners and org admins see a member summary in their dashboard.</p>
      <button class="btn primary sm r" id="org-new">New organisation</button></div>
    ${orgs.map((o) => `<div class="panel"><div class="panel-head"><h3>${esc(o.name)}</h3>${chip(o.kind, 'info')}<span class="note">devices ${num(o.devices_used)} / ${o.device_limit ?? 'per member plan'} ${o.contract_ref ? '· ' + esc(o.contract_ref) : ''}</span>
        <div class="r"><button class="btn sm" data-org-edit="${esc(o.id)}">Edit</button><button class="btn sm" data-org-add="${esc(o.id)}">Add member</button></div></div>
      <div class="table-wrap"><table><tr><th>Member</th><th>Role</th><th></th></tr>${o.members.map((m) => `<tr><td><a href="#/customer/${esc(m.user_id)}">${esc(m.email)}</a></td><td>${esc(m.role)}</td>
        <td><button class="btn sm ghost" data-org-rm="${esc(o.id)}" data-email="${esc(m.email)}">Remove</button></td></tr>`).join('') || '<tr><td colspan="3" class="empty">No members yet.</td></tr>'}</table></div></div>`).join('') || '<p class="empty">No organisations yet.</p>'}`}
  </div></div>`;
};
let ORGS = [];
PAGES.subscriptions.after = async () => {
  $$('[data-stab]').forEach((b) => (b.onclick = () => { subTab = b.dataset.stab; render(); }));
  if (subTab === 'subs') filterBind('#sub-f', SF, 'sub');
  $$('[data-req]').forEach((b) => (b.onclick = () => act(() => rpc('admin_handle_plan_request', { p_request: b.dataset.req, p_status: b.dataset.to }), 'Request updated.')));
  if (subTab !== 'orgs') return;
  ORGS = await rpc('admin_orgs');
  const orgDialog = async (o) => {
    const v = await dialog({ title: o ? 'Edit organisation' : 'New organisation', fields: [
      { name: 'name', label: 'Name', required: true, value: o?.name }, { name: 'kind', label: 'Type', type: 'select', value: o?.kind ?? 'enterprise', options: [['family', 'Family'], ['business', 'Business'], ['enterprise', 'Enterprise & Banking']] },
      { name: 'limit', label: 'Pooled device limit (leave empty to use each member\'s plan)', type: 'number', min: 1, value: o?.device_limit ?? '' },
      { name: 'ref', label: 'Contract reference', value: o?.contract_ref ?? '' }], confirm: 'Save' });
    if (v) act(() => rpc('admin_save_org', { p_id: o?.id ?? null, p_name: v.name, p_kind: v.kind, p_device_limit: v.limit ? +v.limit : null, p_contract_ref: v.ref || null }), 'Organisation saved.');
  };
  $('#org-new')?.addEventListener('click', () => orgDialog(null));
  $$('[data-org-edit]').forEach((b) => (b.onclick = () => orgDialog(ORGS.find((o) => o.id === b.dataset.orgEdit))));
  $$('[data-org-add]').forEach((b) => (b.onclick = async () => {
    const v = await dialog({ title: 'Add member', fields: [{ name: 'email', label: 'Customer email', type: 'email', required: true },
      { name: 'role', label: 'Role', type: 'select', value: 'member', options: [['owner', 'Owner'], ['admin', 'Org admin'], ['member', 'Member']] }], confirm: 'Add' });
    if (v) act(() => rpc('admin_set_org_member', { p_org: b.dataset.orgAdd, p_email: v.email, p_role: v.role }), 'Member added.');
  }));
  $$('[data-org-rm]').forEach((b) => (b.onclick = async () => {
    const v = await dialog({ title: `Remove ${b.dataset.email}?`, body: 'Their devices then count against their own plan limit.', confirm: 'Remove', danger: true });
    if (v) act(() => rpc('admin_set_org_member', { p_org: b.dataset.orgRm, p_email: b.dataset.email, p_role: null }), 'Member removed.');
  }));
};

// ================================================================== PAYMENTS & REVENUE
const PF = { status: '', search: '' }; let PY = null;
PAGES.payments = async () => {
  const rg = range(), lim = 50;
  const [res, d] = await Promise.all([rpc('admin_payments', { p_from: rg.from, p_to: rg.to, p_status: PF.status || null, p_search: PF.search || null, p_limit: lim, p_offset: (state.page.pay ?? 0) * lim }),
    rpc('admin_dashboard', { p_from: rg.from, p_to: rg.to })]);
  PY = res; const s = res.summary || {};
  return `<div class="callout warn">Payment gateway: <b>pending integration</b>. No payment is shown as provider-verified unless it was written by a trusted payment-provider webhook. Manually recorded payments are labelled as such.</div>
  <div class="kpis" style="margin-top:14px">
    ${kpi('Provider-verified revenue', inr(s.paid_verified), C.low)}${kpi('Manually recorded revenue', inr(s.paid_manual), C.med, 'not provider-verified')}
    ${kpi('Recurring revenue (MRR)', inr(d.mrr_inr), C.teal, 'from active plan prices')}${kpi('Pending', num(s.pending), C.med)}
    ${kpi('Failed payments', num(s.failed), C.high)}${kpi('Refunded', inr(s.refunded), C.mute)}</div>
  <div class="cols"><div class="panel"><h3>Revenue by plan</h3><div class="chart"><canvas id="ch-p1"></canvas></div></div>
    <div class="panel"><h3>Revenue by month (IST)</h3><div class="chart"><canvas id="ch-p2"></canvas></div></div></div>
  <div class="panel" style="margin-top:14px"><div class="filters" id="pay-f"><input name="search" placeholder="Search customer or reference" value="${esc(PF.search)}">
    <select name="status">${opts([['', 'Any status'], ['paid', 'Paid'], ['pending', 'Pending'], ['failed', 'Failed'], ['refunded', 'Refunded'], ['cancelled', 'Cancelled']], PF.status)}</select></div>
  <div class="table-wrap"><table><tr><th>Date</th><th>Customer</th><th>Amount</th><th>Plan / period</th><th>Status</th><th>Verification</th><th>Method / reference</th></tr>
  ${res.rows.map((x) => `<tr><td>${esc(when(x.created_at))}</td><td><a href="#/customer/${esc(x.user_id)}">${esc(x.email)}</a></td><td><b>${inr(x.amount_inr)}</b></td>
    <td>${plan(x.plan_code)}<div class="sub">${x.period_start ? esc(day(x.period_start)) + ' → ' + esc(day(x.period_end)) : ''}</div></td><td>${chip(x.status)}${x.failure_reason ? `<div class="sub">${esc(x.failure_reason)}</div>` : ''}</td>
    <td>${chip(x.verification === 'provider_verified' ? 'verified' : 'manual', x.verification === 'provider_verified' ? 'verified' : 'manual')}</td><td>${esc(x.method || x.provider)}<div class="sub mono">${esc(x.provider_ref || '')}</div></td></tr>`).join('')
    || '<tr><td colspan="7" class="empty">No payments in this range.</td></tr>'}</table></div>${pager('pay', res.total, lim)}</div>`;
};
PAGES.payments.after = () => {
  filterBind('#pay-f', PF, 'pay');
  const bp = PY.summary?.by_plan || {}, bm = PY.summary?.by_month || {};
  chart('ch-p1', { type: 'bar', data: { labels: Object.keys(bp).map((k) => PLAN[k] ?? k), datasets: [{ label: '₹', data: Object.values(bp), backgroundColor: C.teal }] }, options: { plugins: { legend: { display: false } } } });
  const months = Object.keys(bm).sort();
  chart('ch-p2', { type: 'bar', data: { labels: months, datasets: [{ label: '₹', data: months.map((m) => bm[m]), backgroundColor: C.info }] }, options: { plugins: { legend: { display: false } } } });
};

// ================================================================== NOTIFICATIONS / FEEDBACK / AUDIT
let notifKind = '';
PAGES.notifications = async () => {
  const n = await rpc('admin_notifications', { p_kind: notifKind || null, p_limit: 200 });
  const bk = n.by_kind || {};
  return `<div class="kpis">${kpi('Notifications (retained 30 d)', num(Object.values(bk).reduce((a, b) => a + b, 0)), C.teal)}${kpi('Unread', num(n.unread), C.med)}
    ${Object.entries(bk).map(([k, v]) => kpi(k.replace(/_/g, ' '), num(v), C.info)).join('')}</div>
  <div class="panel"><div class="filters"><select id="nk">${opts([['', 'All kinds'], ['incident', 'Threat incidents'], ['auth_code', 'Code exposure'], ['pairing', 'Device pairing'], ['device', 'Device changes']], notifKind)}</select></div>
  <div class="table-wrap"><table><tr><th>When</th><th>Customer</th><th>Kind</th><th>Title</th><th>Delivered to</th><th>Read</th></tr>
  ${n.alerts.map((a) => `<tr ${a.incident_id ? `class="click" data-incident="${esc(a.incident_id)}"` : ''}><td>${esc(when(a.created_at))}</td><td>${esc(a.email)}</td><td>${chip(a.kind, 'info')}</td>
    <td>${esc(a.title)} ${a.risk_level ? chip(a.risk_level) : ''}</td><td>${esc(a.target_device ?? '—')}</td><td>${a.read_at ? esc(ago(a.read_at)) : chip('unread', 'pending')}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No notifications.</td></tr>'}</table></div></div>`;
};
PAGES.notifications.after = () => { $('#nk').onchange = (e) => { notifKind = e.target.value; render(); }; };

PAGES.feedback = async () => {
  const rows = await rpc('admin_list_feedback', { p_limit: 200 });
  return `<div class="panel"><div class="table-wrap"><table><tr><th>Time</th><th>From</th><th>Type</th><th>Message</th></tr>
  ${rows.map((f) => `<tr><td class="sub">${esc(when(f.created_at))}</td><td>${esc(f.name ?? '—')}<div class="sub">${esc(f.email ?? '')}</div></td><td>${esc(f.kind)}</td><td>${esc(f.message)}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">No feedback yet.</td></tr>'}</table></div></div>`;
};

const AF = { search: '', action: '' };
PAGES.audit = async () => {
  const lim = 100, res = await rpc('admin_audit', { p_search: AF.search || null, p_action: AF.action || null, p_limit: lim, p_offset: (state.page.aud ?? 0) * lim });
  return `<div class="panel"><div class="filters" id="aud-f"><input name="search" placeholder="Search actor email, target ID or detail" value="${esc(AF.search)}">
    <select name="action">${opts([['', 'All actions'], ['subscription', 'Subscriptions'], ['payment', 'Payments'], ['account', 'Account suspension'], ['session', 'Sessions'], ['device', 'Devices'],
      ['incident', 'Incidents'], ['org', 'Organisations'], ['plan', 'Plan catalogue'], ['settings', 'Settings'], ['pairing', 'Pairing'], ['admin', 'Admin grants']], AF.action)}</select></div>
  <div class="table-wrap"><table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr>
  ${res.rows.map((a) => `<tr><td class="sub">${a.id}</td><td class="sub">${esc(when(a.at))}</td><td>${chip(a.actor_kind, a.actor_kind === 'admin' ? 'medium' : 'none')} ${esc(a.actor_email ?? '')}</td>
    <td><b>${esc(a.action)}</b></td><td class="mono sub">${a.target_type === 'user' ? `<a href="#/customer/${esc(a.target_id)}">user ${short(a.target_id)}</a>` : esc(a.target_type ?? '') + ' ' + short(a.target_id)}</td>
    <td class="mono sub" style="max-width:380px;overflow-wrap:anywhere">${esc(a.detail ? JSON.stringify(a.detail) : '')}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No entries.</td></tr>'}</table></div>${pager('aud', res.total, lim)}</div>`;
};
PAGES.audit.after = () => filterBind('#aud-f', AF, 'aud');

// ================================================================== SETTINGS
PAGES.settings = async () => {
  const s = await rpc('admin_settings');
  const tr = s.settings?.trial || {};
  return `<div class="cols">
    <div class="panel"><h3>Trial policy</h3><p class="note">Enforced in the database for every scan, using the server clock and IST calendar days. There is no permanent free plan.</p>
      <form id="trial-f" class="grid2"><div><label class="f">Trial length (days)</label><input name="days" type="number" min="1" max="60" value="${esc(tr.days)}"></div>
        <div><label class="f">Checks per day</label><input name="daily" type="number" min="1" value="${esc(tr.daily_checks)}"></div>
        <div><label class="f">Checks in total</label><input name="total" type="number" min="1" value="${esc(tr.total_checks)}"></div>
        <div style="align-self:end"><button class="btn primary" type="submit">Save trial policy</button></div></form></div>
    <div class="panel"><h3>Administrators</h3><table><tr><th>Email</th><th>Since</th><th>MFA</th></tr>
      ${(s.admins || []).map((a) => `<tr><td>${esc(a.email)}</td><td class="sub">${esc(day(a.since))}</td><td>${a.mfa ? chip('enrolled', 'ok') : chip('not enrolled', 'high')}</td></tr>`).join('')}</table>
      <p class="note">Admins are granted only from the database (<span class="mono">select public.grant_admin('email')</span>) and must use an authenticator app. Admin actions are limited to ${esc(s.settings?.admin_rate?.actions_per_minute)} per minute.</p></div></div>
  <div class="panel" style="margin-top:14px"><h3>Plan catalogue</h3><div class="table-wrap"><table><tr><th>Plan</th><th>Price ₹/month</th><th>Device limit</th><th>Active</th><th></th></tr>
    ${s.plans.filter((p) => !p.is_trial).map((p) => `<tr data-plan="${esc(p.code)}"><td><b>${esc(p.name)}</b></td>
      <td><input name="price" type="number" min="0" value="${esc(p.price_inr ?? '')}" placeholder="custom" style="max-width:140px"></td>
      <td><input name="limit" type="number" min="1" value="${esc(p.device_limit ?? '')}" placeholder="per contract" style="max-width:140px"></td>
      <td><input name="active" type="checkbox" ${p.active ? 'checked' : ''} aria-label="Active"></td><td><button class="btn sm" data-save-plan="${esc(p.code)}">Save</button></td></tr>`).join('')}</table></div>
    <p class="note">Changing a device limit applies to new registrations; existing devices above a new limit are flagged, not removed.</p></div>
  <div class="cols"><div class="panel"><h3>Integrations</h3><dl class="kv" style="margin-top:8px">
      <dt>Threat intelligence</dt><dd>${esc(s.integrations?.threat_intel)}</dd>
      <dt>Payments</dt><dd>${chip('pending integration', 'pending')} Razorpay/Stripe webhook → <span class="mono">provider_record_payment()</span></dd>
      <dt>URL blocking</dt><dd>${chip('pending integration', 'pending')} requires a browser extension with navigation control → <span class="mono">record_block()</span></dd></dl></div>
    <div class="panel"><h3>Security model</h3><ul class="note" style="margin:8px 0 0;padding-left:18px">
      <li>Role checks, ownership checks, quotas and limits run in Postgres (RLS + SECURITY DEFINER functions), never only in this page.</li>
      <li>Auth uses bearer tokens (not cookies), so CSRF does not apply; sessions are Supabase Auth with refresh-token revocation.</li>
      <li>Passwords are hashed by Supabase Auth; this console never sees them, OTPs, tokens or card data.</li>
      <li>Only a truncated network prefix (/24 or /48) is kept for devices; login history is kept 180 days, audit logs 365 days.</li>
      <li>The browser only holds the publishable key; service-role and threat-intel keys live in edge-function secrets.</li></ul></div></div>`;
};
PAGES.settings.after = () => {
  $('#trial-f').onsubmit = async (e) => {
    e.preventDefault(); const f = new FormData(e.target);
    if (await dialog({ title: 'Change the trial policy?', body: 'Applies to every current and future trial immediately.', confirm: 'Save' }))
      act(() => rpc('admin_update_trial', { p_days: +f.get('days'), p_daily: +f.get('daily'), p_total: +f.get('total') }), 'Trial policy saved.');
  };
  $$('[data-save-plan]').forEach((b) => (b.onclick = async () => {
    const tr = b.closest('tr'), price = $('[name=price]', tr).value, limit = $('[name=limit]', tr).value;
    if (await dialog({ title: `Update the ${tr.querySelector('b').textContent} plan?`, body: 'Price changes affect MRR figures and new assignments.', confirm: 'Save' }))
      act(() => rpc('admin_update_plan', { p_code: b.dataset.savePlan, p_price: price === '' ? null : +price, p_device_limit: limit === '' ? null : +limit, p_active: $('[name=active]', tr).checked }), 'Plan updated.');
  }));
};

// ------------------------------------------------------------------ boot
if (!location.hash) history.replaceState(null, '', '#/overview');
route();
