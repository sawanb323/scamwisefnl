// SCAMWISE web application.
// The browser is a "device" on the user's account, exactly like the old Android app was:
//   sign in (email + password) -> register this browser -> first device is active, others must be paired
//   -> scan (redacted in the browser first) -> history / alerts / devices / settings, synced in real time.
// All authorisation is enforced server-side by Postgres RLS and SECURITY DEFINER RPCs.
import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm';
import { createEngine } from '../engine/analyzer.js';
import { SUPABASE_URL, SUPABASE_KEY, APP_VERSION } from '../assets/config.js';

// read before the client consumes the URL: a password-reset link lands here with type=recovery
const ARRIVED_FOR_RECOVERY = /type=recovery/.test(location.hash);
const sb = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: true, autoRefreshToken: true, storageKey: 'scamwise-web-app' },
});

// ------------------------------------------------------------------ small helpers
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const COLORS = { high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', inconclusive: 'var(--inc)' };
const LABEL = { high: 'High risk', medium: 'Medium risk', low: 'Low risk', inconclusive: 'Inconclusive' };
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const riskPill = (r) => `<span class="risk ${esc(r)}">${esc(LABEL[r] ?? r)}</span>`;
const when = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
function ago(iso) {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
const store = {
  get(k, d = null) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode: keep going */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};

const VIEWS = ['loading', 'login', 'signup', 'verify', 'forgot', 'reset', 'pending', 'main'];
const AUTH_VIEWS = ['login', 'signup', 'verify', 'forgot', 'reset', 'pending'];
function show(v) {
  VIEWS.forEach((x) => $('#view-' + x).classList.toggle('hidden', x !== v));
  $('#auth-layout').classList.toggle('hidden', !AUTH_VIEWS.includes(v));
  if (AUTH_VIEWS.includes(v)) $('#view-' + v).querySelector('input:not([type=checkbox])')?.focus({ preventScroll: true });
}

function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = 'toast ' + kind;
  t.setAttribute('role', 'status');
  t.textContent = msg;
  $('#toasts').appendChild(t);
  while ($('#toasts').children.length > 3) $('#toasts').firstElementChild.remove();
  setTimeout(() => { t.style.transition = 'opacity .3s'; t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, kind === 'high' ? 8000 : 4000);
}

function modal(html, { onMount } = {}) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  $('#modal-root').appendChild(bg);
  const close = () => bg.remove();
  bg.addEventListener('click', (e) => { if (e.target === bg) close(); });
  onMount?.(bg.firstElementChild, close);
  return close;
}
function confirmBox(title, body, okLabel = 'OK', danger = false) {
  return new Promise((resolve) => {
    modal(`<h3>${esc(title)}</h3><p>${esc(body)}</p>
      <div class="row-end" style="margin-top:8px">
        <button class="btn ghost" data-x="no">Cancel</button>
        <button class="btn ${danger ? 'danger' : 'primary'}" data-x="yes">${esc(okLabel)}</button></div>`, {
      onMount(el, close) {
        el.querySelector('[data-x=no]').onclick = () => { close(); resolve(false); };
        el.querySelector('[data-x=yes]').onclick = () => { close(); resolve(true); };
      },
    });
  });
}
function promptBox(title, value, maxLength = 60) {
  return new Promise((resolve) => {
    modal(`<h3>${esc(title)}</h3><form style="display:flex;flex-direction:column;gap:12px"><input id="prompt-input" maxlength="${maxLength}" value="${esc(value)}">
      <div class="row-end">
        <button type="button" class="btn ghost" data-x="no">Cancel</button>
        <button class="btn primary">Save</button></div></form>`, {
      onMount(el, close) {
        const input = el.querySelector('input');
        input.focus(); input.select();
        el.querySelector('[data-x=no]').onclick = () => { close(); resolve(null); };
        el.querySelector('form').onsubmit = (e) => { e.preventDefault(); close(); resolve(input.value.trim()); };
      },
    });
  });
}

// Maps server error codes (raised by the SQL functions) to plain language
const FRIENDLY = {
  invalid_or_expired_code: 'That pairing code is wrong or has expired. Create a new one on your other device.',
  too_many_attempts: 'Too many wrong codes. Wait 15 minutes and try again.',
  too_many_codes: 'Too many pairing codes created in the last hour. Try again later.',
  device_not_active: 'This device is not an approved device on your account.',
  device_already_active: 'This device is already linked.',
  device_revoked: 'This device was unlinked. Sign out and sign in again to re-link it.',
  device_limit_reached: 'Your plan\'s device limit is reached. Unlink a device or upgrade your plan.',
  trial_daily_limit: 'Free trial limit: 2 checks per day. Try again tomorrow or upgrade your plan.',
  account_suspended: 'This account is suspended. Contact SCAMWISE support.',
  subscription_suspended: 'Your subscription is suspended. Contact SCAMWISE support.',
  too_many_requests: 'You have already sent several requests today. We will be in touch.',
  trial_total_limit: 'You have used all 14 free-trial checks. Upgrade to keep checking messages.',
  trial_expired: 'Your 7-day free trial has ended. Upgrade to keep checking messages.',
  subscription_expired: 'Your subscription has expired. Renew it to keep checking messages.',
  approval_window_expired: 'The request expired. Ask the other device to enter a new code.',
  not_awaiting_approval: 'This request was already handled.',
  admin_accounts_cannot_register_devices: 'Administrator accounts cannot be used in the app. Use the admin dashboard instead.',
  not_found: 'That item no longer exists.',
};
function friendly(raw) {
  const s = String(raw?.message ?? raw ?? '');
  for (const [k, v] of Object.entries(FRIENDLY)) if (s.includes(k)) return v;
  if (/failed to fetch|networkerror|load failed/i.test(s)) return 'Could not reach SCAMWISE. Check your internet connection.';
  return s || 'Something went wrong.';
}
function authError(e) {
  const raw = `${e?.message ?? e} ${e?.code ?? ''} ${e?.status ?? ''}`.toLowerCase();
  const wait = /after (\d+) seconds/.exec(raw);
  if (wait) return `Please wait ${wait[1]} seconds and try again.`;
  if (raw.includes('invalid login credentials') || raw.includes('invalid_credentials')) return 'That email and password don\'t match. Check them, or reset your password.';
  if (raw.includes('email not confirmed') || raw.includes('email_not_confirmed')) return 'Confirm your email first. Open the link we sent you, then sign in.';
  if (raw.includes('already registered') || raw.includes('user_already_exists') || raw.includes('already been registered')) return 'An account with this email already exists. Sign in instead.';
  if (raw.includes('weak_password') || raw.includes('password should')) return 'Choose a stronger password: at least 8 characters with letters and numbers.';
  if (raw.includes('rate limit') || raw.includes('429') || raw.includes('over_email_send_rate_limit')) return 'Too many attempts. Please wait a few minutes and try again.';
  if (raw.includes('signups not allowed') || raw.includes('signup_disabled') || raw.includes('email_provider_disabled')) return 'New sign-ups are switched off on the server right now.';
  if (raw.includes('invalid email') || raw.includes('email_address_invalid') || raw.includes('unable to validate email')) return 'That email address doesn\'t look right.';
  if (/failed to fetch|network|load failed/.test(raw)) return 'No internet connection. Connect and try again.';
  return e?.message ?? String(e);
}

// ------------------------------------------------------------------ engine (same rules as the server)
let engine = null;
let rules = null;
const engineReady = fetch('../engine/rules.json').then((r) => r.json()).then((r) => { rules = r; engine = createEngine(r); });

// ------------------------------------------------------------------ this browser's identity
function installId() {
  let id = store.get('scamwise-install-id');
  if (!id) {
    id = crypto.randomUUID ? crypto.randomUUID()
      : '10000000-1000-4000-8000-100000000000'.replace(/[018]/g, (c) => (c ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (c / 4)))).toString(16));
    store.set('scamwise-install-id', id);
  }
  return id;
}
function browserInfo() {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /SamsungBrowser/.test(ua) ? 'Samsung Internet'
    : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows'
    : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : 'Web';
  return { browser, os };
}
const defaultName = () => { const b = browserInfo(); return `${b.browser} on ${b.os}`; };
const platform = () => { const b = browserInfo(); return `web · ${b.browser} · ${b.os}`.slice(0, 40); };

// ------------------------------------------------------------------ state
const S = {
  device: null, status: 'unknown', profile: null,
  incidents: [], alerts: [], devices: [], pairing: [],
  sync: 'connecting', lastSync: null, realtimeUp: false,
  tab: 'scan', started: false,
};
let heartbeatTimer = null, pendingTimer = null, channel = null;
let pairFromLink = null;   // code from a QR / #pair= link

function setSync(state) {
  S.sync = state;
  const el = $('#sync');
  el.className = 'sync ' + state;
  $('#sync-text').textContent = state === 'synced' ? 'Live' : state === 'offline' ? 'Offline' : 'Connecting';
  el.title = S.lastSync ? 'Last confirmed with server ' + S.lastSync.toLocaleTimeString() : '';
}

// ------------------------------------------------------------------ sign in / sign up
const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);
const redirectUrl = () => location.origin + location.pathname;
function busy(btn, on, label) { btn.disabled = on; if (label) btn.textContent = label; }

$$('.pw-toggle').forEach((b) => (b.onclick = () => {
  const input = $('#' + b.dataset.pw);
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  b.setAttribute('aria-pressed', String(show));
  b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
}));
function strength(pw) {
  let n = 0;
  if (pw.length >= 8) n++;
  if (pw.length >= 12) n++;
  if (/[a-z]/i.test(pw) && /\d/.test(pw)) n++;
  if (/[^a-z0-9]/i.test(pw)) n++;
  return pw ? Math.max(1, Math.min(4, n)) : 0;
}
$('#signup-password').addEventListener('input', (e) => {
  const n = strength(e.target.value);
  $('#pw-meter').dataset.s = n;
  $('#pw-hint').textContent = !n ? 'Use 8 or more characters with a mix of letters, numbers and symbols.'
    : ['', 'Too weak', 'Could be stronger', 'Good password', 'Strong password'][n];
});

$('#to-signup').onclick = () => showAuth('signup');
$('#to-login').onclick = () => showAuth('login');
$('#to-forgot').onclick = () => { $('#forgot-email').value = $('#login-email').value; showAuth('forgot'); };
$('#forgot-back').onclick = () => showAuth('login');
$('#verify-back').onclick = () => showAuth('login');

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#login-email').value.trim(), password = $('#login-password').value;
  const err = $('#login-error');
  if (!validEmail(email)) { err.textContent = 'Enter the email you signed up with.'; return; }
  if (!password) { err.textContent = 'Enter your password.'; return; }
  err.textContent = '';
  const btn = $('#login-submit'); busy(btn, true, 'Signing in…');
  try {
    const { error } = await sb.auth.signInWithPassword({ email, password });
    if (error) throw error;
    S.user = (await sb.auth.getSession()).data.session?.user ?? null;
    $('#login-password').value = '';
    show('loading');
    await registerDevice();
  } catch (ex) {
    err.textContent = authError(ex);
  } finally { busy(btn, false, 'Sign in'); }
});

$('#signup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = $('#signup-name').value.trim(), email = $('#signup-email').value.trim(), password = $('#signup-password').value;
  const err = $('#signup-error');
  if (!validEmail(email)) { err.textContent = 'Enter a valid email address.'; return; }
  if (password.length < 8) { err.textContent = 'Your password needs at least 8 characters.'; return; }
  if (strength(password) < 2) { err.textContent = 'Add numbers or symbols to make your password stronger.'; return; }
  if (!$('#signup-terms').checked) { err.textContent = 'Please accept the privacy terms to continue.'; return; }
  err.textContent = '';
  const btn = $('#signup-submit'); busy(btn, true, 'Creating account…');
  try {
    const { data, error } = await sb.auth.signUp({ email, password, options: { emailRedirectTo: redirectUrl(), data: { full_name: name } } });
    if (error) throw error;
    $('#signup-password').value = '';
    if (data.session) { S.user = data.session.user; show('loading'); toast('Account created. Welcome to SCAMWISE.'); await registerDevice(); return; }
    $('#verify-text').innerHTML = `We sent a confirmation link to <b>${esc(email)}</b>. Open it to finish creating your account, then sign in.`;
    $('#login-email').value = email;
    show('verify');
  } catch (ex) {
    err.textContent = authError(ex);
  } finally { busy(btn, false, 'Create account'); }
});

$('#forgot-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#forgot-email').value.trim();
  const err = $('#forgot-error');
  if (!validEmail(email)) { err.textContent = 'Enter a valid email address.'; return; }
  err.textContent = '';
  const btn = $('#forgot-submit'); busy(btn, true, 'Sending…');
  try {
    const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: redirectUrl() });
    if (error) throw error;
    $('#verify-text').innerHTML = `If an account exists for <b>${esc(email)}</b>, a reset link is on its way. Open it on this device to choose a new password.`;
    show('verify');
  } catch (ex) { err.textContent = authError(ex); } finally { busy(btn, false, 'Send reset link'); }
});

$('#reset-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = $('#reset-password').value;
  const err = $('#reset-error');
  if (password.length < 8) { err.textContent = 'Your password needs at least 8 characters.'; return; }
  err.textContent = '';
  const btn = $('#reset-submit'); busy(btn, true, 'Saving…');
  try {
    const { error } = await sb.auth.updateUser({ password });
    if (error) throw error;
    $('#reset-password').value = '';
    toast('Password updated.');
    show('loading');
    await registerDevice();
  } catch (ex) { err.textContent = authError(ex); } finally { busy(btn, false, 'Save password'); }
});

function showAuth(view, notice) {
  if (view === 'login') {
    const n = $('#login-notice');
    n.classList.toggle('hidden', !notice);
    n.textContent = notice ?? '';
  }
  show(view);
  const want = view === 'signup' ? '#signup' : view === 'login' ? '#signin' : '';
  if (want && ['#signin', '#signup'].includes(location.hash) && location.hash !== want) history.replaceState(null, '', location.pathname + location.search + want);
}
function showLogin(notice) { showAuth('login', notice); }

// ------------------------------------------------------------------ device registration & lifecycle
async function registerDevice() {
  try {
    const { data, error } = await sb.rpc('register_device', {
      p_install_id: installId(),
      p_name: store.get('scamwise-device-name') || defaultName(),
      p_platform: platform(),
      p_app_version: APP_VERSION,
    });
    if (error) throw error;
    S.device = data; S.status = data.status;
    if (S.status === 'active') return startMain();
    return showPending();
  } catch (e) {
    const msg = friendly(e);
    if (/admin_accounts|not_authenticated|JWT/i.test(String(e?.message))) {
      await sb.auth.signOut({ scope: 'local' }).catch(() => {});
      return showLogin(msg);
    }
    showLogin('Could not register this device: ' + msg);
  }
}

function showPending(claimed = false) {
  teardown();
  show('pending');
  const name = S.device?.name ?? 'This device';
  $('#pending-title').textContent = claimed ? 'Waiting for approval' : 'Link this device';
  $('#pending-sub').textContent = `"${name}" is signed in but not yet linked. Your account already has a linked device, so that device must approve this one.`;
  $('#pending-name').textContent = `"${name}"`;
  $('#pending-enter').classList.toggle('hidden', claimed);
  $('#pending-wait').classList.toggle('hidden', !claimed);
  if (pairFromLink && !claimed) { $('#pair-code').value = pairFromLink; pairFromLink = null; }
  clearInterval(pendingTimer);
  pendingTimer = setInterval(pollPending, 4000);
}
async function pollPending() {
  try {
    const { data } = await sb.rpc('my_device');
    if (data?.id) {
      S.device = data;
      if (data.status === 'active') { clearInterval(pendingTimer); toast('This device is now linked.'); return startMain(); }
      if (data.status === 'revoked') return handleRevoked('This device was rejected or unlinked. Sign in again to retry.');
    } else {
      const hb = await sb.rpc('heartbeat');
      if (hb.data === 'revoked') return handleRevoked();
    }
  } catch { /* offline: try again next tick */ }
}
$('#pair-code').addEventListener('input', (e) => {
  const v = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  e.target.value = v.length > 4 ? v.slice(0, 4) + '-' + v.slice(4) : v;
});
$('#pair-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = $('#pair-code').value.replace(/[^A-Za-z0-9]/g, '');
  $('#pair-error').textContent = '';
  if (code.length !== 8) { $('#pair-error').textContent = 'The code has 8 characters.'; return; }
  const btn = $('#pair-submit'); btn.disabled = true;
  try {
    const { data, error } = await sb.rpc('claim_pairing_code', { p_code: code });
    if (error) throw error;
    if (data?.status === 'rejected') throw new Error(data.error);   // wrong code (attempt is counted server-side)
    showPending(true);
  } catch (ex) {
    $('#pair-error').textContent = friendly(ex);
  } finally { btn.disabled = false; }
});
$('#pair-again').onclick = () => showPending(false);
$('#pending-signout').onclick = () => signOut();
$('#nav-signout').onclick = () => signOut();
$('#pending-remove').onclick = async () => {
  if (!(await confirmBox('Remove this device?', 'This cancels its link request and signs it out.', 'Remove', true))) return;
  if (S.device?.id) await sb.rpc('revoke_device', { p_device: S.device.id }).catch(() => {});
  await signOut('This device was removed from your account.');
};

async function startMain() {
  clearInterval(pendingTimer);
  show('main');
  if (S.started) return;
  S.started = true;
  setSync('connecting');
  switchTab(S.tab);
  if (pairFromLink) { toast('This device is already linked to your account.'); pairFromLink = null; }
  await refreshAll();
  subscribe();
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(heartbeat, 30000);
  flushQueue();
}

function teardown() {
  clearInterval(heartbeatTimer); heartbeatTimer = null;
  if (channel) { sb.removeChannel(channel).catch(() => {}); channel = null; }
  S.started = false; S.realtimeUp = false;
  S.incidents = []; S.alerts = []; S.devices = []; S.pairing = []; S.profile = null;
}

async function signOut(notice) {
  // Stop background work first so it cannot redraw the authenticated view.
  teardown();
  clearInterval(pendingTimer);
  pendingTimer = null;
  S.device = null;
  S.status = 'unknown';
  S.user = null;

  const buttons = ['#nav-signout', '#signout', '#pending-signout']
    .map((selector) => $(selector))
    .filter(Boolean);
  buttons.forEach((button) => { button.disabled = true; });

  try {
    try { await sb.rpc('record_sign_out'); } catch { /* best effort: the session still ends */ }
    const { error } = await sb.auth.signOut({ scope: 'local' });
    if (error) throw error;
    // Always land on login after a successful local sign-out.
    showLogin(notice ?? 'You have been signed out.');
  } catch (error) {
    console.error('SCAMWISE sign-out failed:', error);
    toast('Sign-out failed: ' + friendly(error), 'high');
    // Do not pretend sign-out succeeded. Keep the message visible and allow retry.
    showLogin('Sign-out could not be confirmed. Please try again.');
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

async function handleRevoked(msg) {
  await signOut(msg ?? 'This device was unlinked from your SCAMWISE account. Sign in again and link it to reconnect.');
}

async function heartbeat() {
  try {
    const { data, error } = await sb.rpc('heartbeat');
    if (error) throw error;
    if (data === 'revoked') return handleRevoked();
    if (data === 'unregistered') { teardown(); return registerDevice(); }
    if (data === 'pending') { S.status = 'pending'; return showPending(); }
    S.lastSync = new Date();
    setSync(S.realtimeUp ? 'synced' : 'connecting');
    $('#banner').classList.add('hidden');
    flushQueue();
  } catch {
    setSync('offline');
  }
}

document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState !== 'visible' || !S.started) return;
  await heartbeat();
  if (S.started) refreshAll();
});
window.addEventListener('online', () => { if (S.started) { heartbeat(); refreshAll(); } });
window.addEventListener('offline', () => { if (S.started) setSync('offline'); });

// ------------------------------------------------------------------ realtime
function subscribe() {
  const id = S.device?.id;
  const uid = S.device?.user_id;
  if (!id || !uid) return;
  channel = sb.channel('scamwise-web-' + id)
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'alerts', filter: `target_device_id=eq.${id}` },
      (p) => onAlert(p.new))
    .on('postgres_changes', { event: '*', schema: 'public', table: 'devices', filter: `user_id=eq.${uid}` }, () => refreshDevices())
    .on('postgres_changes', { event: '*', schema: 'public', table: 'pairing_codes', filter: `user_id=eq.${uid}` }, () => refreshPairing())
    .on('postgres_changes', { event: '*', schema: 'public', table: 'incidents', filter: `user_id=eq.${uid}` }, () => refreshIncidents())
    .subscribe((status) => {
      S.realtimeUp = status === 'SUBSCRIBED';
      if (S.realtimeUp) S.lastSync = new Date();
      setSync(S.realtimeUp ? 'synced' : (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') ? 'offline' : 'connecting');
    });
}

function onAlert(a) {
  if (!a || S.alerts.some((x) => x.id === a.id)) return;
  S.alerts = [a, ...S.alerts];
  S.lastSync = new Date();
  const high = a.risk_level === 'high' || a.kind === 'auth_code';
  toast(`${a.title} — ${a.body}`, high ? 'high' : '');
  notify(a);
  if (a.kind === 'pairing') refreshPairing();
  renderAlerts();
}

function notify(a) {
  const seen = store.get('scamwise-notified', []);
  if (seen.includes(a.id)) return;
  store.set('scamwise-notified', [...seen, a.id].slice(-300));
  try {
    if ('Notification' in window && Notification.permission === 'granted' && document.visibilityState !== 'visible') {
      new Notification('SCAMWISE: ' + a.title, { body: a.body, tag: a.id });
    }
  } catch { /* some browsers only allow notifications from a service worker */ }
}

// ------------------------------------------------------------------ data
async function refreshAll() {
  await Promise.all([refreshProfile(), refreshIncidents(), refreshAlerts(), refreshDevices(), refreshPairing()]);
  S.lastSync = new Date();
  renderSettings();
}
async function refreshProfile() {
  const { data } = await sb.from('profiles').select('*').eq('id', S.device?.user_id).maybeSingle();
  if (data) S.profile = data;
  renderSettings();
  refreshPlan();
}
const PLAN_NAMES = { trial: 'Free trial', individual: 'Individual', family: 'Family', business: 'Business', enterprise: 'Enterprise & Banking' };
async function refreshPlan() {
  const { data: s, error } = await sb.rpc('my_subscription');
  const el = document.querySelector('#my-plan');
  if (!el || error || !s) return;
  const exp = new Date(s.expires_at);
  const days = Math.max(0, Math.ceil((exp - Date.now()) / 86400000));
  const tag = s.state === 'expired' ? '<span class="tag">Expired</span>' : s.state === 'trial' ? '<span class="tag">Trial</span>' : '<span class="tag ok">Active</span>';
  el.innerHTML = `<dt>Plan</dt><dd>${esc(PLAN_NAMES[s.plan] || s.plan)} ${tag}</dd>
    <dt>${s.state === 'expired' ? 'Expired on' : 'Valid until'}</dt><dd>${esc(exp.toLocaleDateString())}${s.state === 'expired' ? '' : ` (${days} day${days === 1 ? '' : 's'} left)`}</dd>
    <dt>Devices</dt><dd>${s.devices_used} of ${s.device_limit}</dd>
    ${s.plan === 'trial' ? `<dt>Trial checks</dt><dd>${s.checks_today}/2 today · ${s.checks_total}/14 total</dd>` : ''}`;
}
async function refreshIncidents() {
  const { data, error } = await sb.from('incidents').select('*').order('created_at', { ascending: false }).limit(200);
  if (!error) { S.incidents = data ?? []; renderHistory(); renderInsights(); renderFamilySafety(); if (S.tab === 'dashboard') refreshDashboard(); }
}

// ------------------------------------------------------------------ customer dashboard (own data only, computed server-side)
const STATUS_LABEL = { trialing: 'Free trial', active: 'Active', cancelled: 'Cancelled', expired: 'Expired', suspended: 'Suspended',
  detected: 'Detected', blocked: 'Blocked', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive' };
const EVENT_LABEL = { sign_in: 'Signed in', sign_out: 'Signed out', session_revoked: 'Session ended by SCAMWISE', device_registered: 'New device registered',
  device_unlinked: 'Device unlinked', account_suspended: 'Account suspended', account_reactivated: 'Account reactivated', trial_started: 'Free trial started',
  plan_assigned: 'Plan assigned', plan_changed: 'Plan changed', renewed: 'Subscription renewed', converted: 'Upgraded from trial', suspended: 'Subscription suspended',
  reactivated: 'Subscription reactivated', cancelled: 'Renewal cancelled', expired: 'Subscription expired', limit_changed: 'Plan updated', trial_reset: 'Trial counters reset',
  detected: 'Threat detected', user_warned: 'Warning shown', alert_sent: 'Alert sent to your devices', investigating: 'Under investigation',
  resolved: 'Incident resolved', false_positive: 'Marked false positive', reopened: 'Incident reopened', note: 'Note added by SCAMWISE' };
let dashBusy = false;
async function refreshDashboard() {
  if (dashBusy) return; dashBusy = true;
  try {
    const { data: d, error } = await sb.rpc('my_dashboard');
    if (error) { $('#dash-stats').innerHTML = `<p class="err">${esc(friendly(error))}</p>`; return; }
    const s = d.subscription || {}, st = d.stats || {}, dq = s.devices || {}, tr = s.trial || {};
    const banner = $('#dash-banner');
    const msg = s.status === 'expired' ? (s.plan === 'trial' ? 'Your 7-day free trial has ended. Choose a plan below to keep checking messages.' : 'Your subscription has expired. Renew below to keep checking messages.')
      : s.status === 'suspended' ? 'Your subscription is suspended. Contact SCAMWISE support.'
      : s.plan === 'trial' && tr.used_total >= tr.total_limit ? 'You have used all free-trial checks. Upgrade to continue.'
      : s.days_left <= 3 ? `Your ${s.plan === 'trial' ? 'trial' : 'plan'} ends in ${s.days_left} day${s.days_left === 1 ? '' : 's'}.` : '';
    banner.textContent = msg; banner.classList.toggle('hidden', !msg);
    $('#dash-stats').innerHTML = [
      ['URLs checked', st.urls_checked, 'var(--accent)'], ['Threats detected', st.threats_detected, 'var(--high)'],
      ['Blocked', st.blocked, 'var(--inc)'], ['Resolved', st.resolved, 'var(--low)'], ['Open', st.open, 'var(--med)'],
      ...(s.plan === 'trial' ? [['Checks left today', Math.max(0, Math.min(tr.daily_limit - tr.used_today, tr.total_limit - tr.used_total)), 'var(--accent)']] : [['Scans (lifetime)', d.checks_lifetime, 'var(--accent)']]),
    ].map(([l, v, c]) => `<div class="stat"><span><i style="background:${c}"></i>${esc(l)}</span><b>${Number(v ?? 0).toLocaleString('en-IN')}</b></div>`).join('');
    const tag = s.status === 'active' ? 'ok' : s.status === 'trialing' || s.status === 'cancelled' ? 'warn' : 'bad';
    $('#dash-plan-tag').innerHTML = `<span class="tag ${tag}">${esc(STATUS_LABEL[s.status] ?? s.status)}</span>`;
    const pct = Math.min(100, Math.round(100 * (dq.used ?? 0) / Math.max(1, dq.limit ?? 1)));
    $('#dash-plan').innerHTML = `<dt>Plan</dt><dd><b>${esc(s.plan_name)}</b>${s.price_inr ? ` · ₹${Number(s.price_inr).toLocaleString('en-IN')}/month` : ''}</dd>
      <dt>${s.status === 'expired' ? 'Expired on' : 'Valid until'}</dt><dd>${esc(new Date(s.expires_at).toLocaleDateString())}${s.status === 'expired' ? '' : ` · ${s.days_left} day${s.days_left === 1 ? '' : 's'} left`}</dd>
      ${s.trial_started_at ? `<dt>Free trial</dt><dd>${esc(new Date(s.trial_started_at).toLocaleDateString())} – ${esc(new Date(s.trial_expires_at).toLocaleDateString())}</dd>` : ''}
      ${s.plan === 'trial' ? `<dt>Trial checks</dt><dd>${tr.used_today} of ${tr.daily_limit} today · ${tr.used_total} of ${tr.total_limit} in total · ${Math.max(0, tr.total_limit - tr.used_total)} remaining</dd>` : ''}
      <dt>Devices</dt><dd>${dq.used} of ${dq.limit}${dq.pooled ? ` (shared across ${esc(dq.org)})` : ''}<div class="dash-meter"><i style="width:${pct}%"></i></div></dd>
      ${s.cancelled_at ? `<dt>Renewal</dt><dd>Cancelled — access continues until the expiry date</dd>` : ''}
      ${d.open_request ? `<dt>Request</dt><dd>${esc(PLAN_NAMES[d.open_request.plan] ?? d.open_request.plan)} requested ${esc(ago(d.open_request.created_at))} · ${esc(d.open_request.status)}</dd>` : ''}`;
    const online = d.online_seconds ?? 120;
    $('#dash-devices-list').innerHTML = (S.devices || []).filter((x) => x.status !== 'revoked').map((x) => {
      const on = x.status === 'active' && x.session_id && x.last_seen_at && Date.now() - new Date(x.last_seen_at).getTime() < online * 1000;
      return `<div class="row-item"><div><b>${esc(x.name)}</b>${x.id === S.device?.id ? ' <span class="tag accent">This device</span>' : ''}<p class="muted">${esc([x.os, x.browser].filter(Boolean).join(' · ') || x.platform || 'Web browser')} · last active ${esc(ago(x.last_seen_at))}</p></div>
        <span class="tag ${on ? 'ok' : x.status === 'pending' ? 'warn' : ''}">${on ? 'Online' : x.status === 'pending' ? 'Awaiting approval' : x.session_id ? 'Idle' : 'Signed out'}</span></div>`;
    }).join('') || '<p class="muted">No devices.</p>';
    $('#dash-threats').innerHTML = (d.recent_incidents || []).map((i) => `<div class="row-item"><div><b>${esc((rules?.families ?? {})[i.category] ?? i.category)}</b> ${riskPill(i.severity === 'critical' ? 'high' : i.severity)}
        <p class="muted">${esc(i.device_name ?? '')} · ${esc(ago(i.created_at))}${i.url_domains?.length ? ' · ' + esc(i.url_domains.join(', ')) : ''}</p></div>
        <span class="tag ${i.status === 'resolved' ? 'ok' : i.status === 'false_positive' ? '' : 'bad'}">${esc(STATUS_LABEL[i.status] ?? i.status)}</span></div>`).join('') || '<p class="muted">No threats detected. Nice.</p>';
    $('#dash-activity').innerHTML = (d.activity || []).slice(0, 12).map((a) => `<div class="row-item"><div><b>${esc(EVENT_LABEL[a.event] ?? a.event)}</b>
        <p class="muted">${esc([a.subject && (PLAN_NAMES[a.subject] ?? a.subject), ago(a.at)].filter(Boolean).join(' · '))}</p></div></div>`).join('') || '<p class="muted">No activity yet.</p>';
    $('#dash-plans').innerHTML = (d.plans || []).map((p) => `<div class="plan-card ${p.code === s.plan && s.status !== 'expired' ? 'current' : ''}">
        <div><b>${esc(p.name)}</b></div><b class="price">${p.price_inr != null ? '₹' + Number(p.price_inr).toLocaleString('en-IN') + '<small class="muted">/month</small>' : 'Custom pricing'}</b>
        <ul>${(p.features || []).map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
        <button class="btn ${p.code === s.plan ? 'ghost' : 'primary'} sm" data-request-plan="${esc(p.code)}" type="button">${p.code === s.plan ? 'Request renewal' : p.price_inr == null ? 'Contact sales' : 'Request this plan'}</button></div>`).join('');
    $$('#dash-plans [data-request-plan]').forEach((b) => (b.onclick = async () => {
      if (!(await confirmBox(`Request the ${PLAN_NAMES[b.dataset.requestPlan]} plan?`, 'The ScamWise team will contact you to complete payment and activate it. Nothing is charged now.', 'Send request'))) return;
      const { error: e } = await sb.rpc('request_plan', { p_plan: b.dataset.requestPlan, p_message: null });
      if (e) toast(friendly(e)); else { toast('Request sent. We will be in touch.'); refreshDashboard(); }
    }));
    $('#dash-payments').innerHTML = (d.payments || []).length ? `<h3 style="margin-top:16px">Payments</h3><div class="rows">${d.payments.map((p) => `<div class="row-item"><div><b>₹${Number(p.amount_inr).toLocaleString('en-IN')}</b> · ${esc(PLAN_NAMES[p.plan] ?? p.plan ?? '')}
        <p class="muted">${esc(new Date(p.created_at).toLocaleDateString())}${p.period_start ? ` · ${esc(p.period_start)} to ${esc(p.period_end)}` : ''}</p></div><span class="tag ${p.status === 'paid' ? 'ok' : p.status === 'failed' ? 'bad' : 'warn'}">${esc(p.status)}${p.verification === 'manual_recorded' ? ' (recorded by staff)' : ''}</span></div>`).join('')}</div>` : '';
    const { data: org } = await sb.rpc('my_org');
    $('#dash-org-panel').hidden = !org?.members;
    if (org?.members) {
      $('#dash-org-title').textContent = `${org.name} · ${org.members.length} member${org.members.length === 1 ? '' : 's'}`;
      $('#dash-org').innerHTML = org.members.map((m) => `<div class="row-item"><div><b>${esc(m.name || m.email)}</b> <span class="tag">${esc(m.role)}</span><p class="muted">${esc(m.email)} · ${m.devices} device(s), ${m.devices_online} online</p></div>
        <span class="tag ${m.stats?.open ? 'bad' : 'ok'}">${m.stats?.threats_detected ?? 0} threats · ${m.stats?.open ?? 0} open</span></div>`).join('');
    }
  } finally { dashBusy = false; }
}
$('#dash-devices')?.addEventListener('click', () => switchTab('devices'));
$('#dash-history')?.addEventListener('click', () => switchTab('history'));
async function refreshAlerts() {
  const { data, error } = await sb.from('alerts').select('*').order('created_at', { ascending: false }).limit(100);
  if (!error) { S.alerts = data ?? []; renderAlerts(); }
}
async function refreshDevices() {
  const { data, error } = await sb.from('devices').select('*').order('created_at');
  if (error) return;
  S.devices = data ?? [];
  const me = S.devices.find((d) => d.id === S.device?.id);
  if (me) {
    S.device = me;
    if (me.status === 'revoked') return handleRevoked();
  }
  renderDevices(); renderSettings();
}
async function refreshPairing() {
  const { data, error } = await sb.from('pairing_codes').select('*').eq('status', 'claimed').order('claimed_at', { ascending: false });
  if (!error) { S.pairing = data ?? []; renderDevices(); }
}

// ------------------------------------------------------------------ tabs
$$('.side button[data-tab]').forEach((b) => (b.onclick = () => switchTab(b.dataset.tab)));
const TITLES = {
  scan: ['Scan', 'Check a message or link before you act on it'],
  dashboard: ['Dashboard', 'Your plan, devices and security activity'],
  history: ['History', 'Every scan across your linked devices'],
  insights: ['Insights', 'Understand scam patterns across your scans'],
  family: ['Family safety', 'Practical protection guidance for your household'],
  alerts: ['Alerts', 'What your other devices have flagged'],
  devices: ['Devices', 'Who receives this account\'s alerts'],
  settings: ['Settings', 'Alerts, privacy and this device'],
};
function switchTab(tab) {
  if (!TITLES[tab]) return;
  S.tab = tab;
  $('#page-title').textContent = TITLES[tab][0];
  $('#page-sub').textContent = TITLES[tab][1];
  window.scrollTo({ top: 0 });
  $$('.side button[data-tab]').forEach((x) => x.classList.toggle('on', x.dataset.tab === tab));
  ['scan', 'dashboard', 'history', 'insights', 'family', 'alerts', 'devices', 'settings'].forEach((t) => $('#tab-' + t)?.classList.toggle('hidden', t !== tab));
  if (tab === 'dashboard') refreshDashboard();
  if (tab === 'alerts') markAlertsRead();
  if (tab === 'insights') renderInsights();
  if (tab === 'family') renderFamilySafety();
}

// ------------------------------------------------------------------ scan
const SAMPLES = {
  'Bank KYC phishing': 'Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login',
  'Bank OTP SMS': '482913 is your OTP for login to HDFC NetBanking. Valid for 5 mins. Do not share this OTP with anyone.',
  '"Digital arrest"': 'This is Mumbai Cyber Police. A parcel in your name has been seized with drugs. You are under digital arrest. Do not tell anyone. Pay Rs 49,000 clearance fee now.',
  'Task job': 'Part time job! Earn ₹5000 per day by liking YouTube videos. Pay refundable deposit of Rs 2000 to start.',
  'Normal message': 'Hey, are we still meeting for lunch at 1 tomorrow? I booked a table at the cafe.',
};
for (const [k, v] of Object.entries(SAMPLES)) {
  const b = document.createElement('button');
  b.className = 'chip'; b.type = 'button'; b.textContent = k;
  b.onclick = () => { $('#msg').value = v; onMsgInput(); };
  $('#samples').appendChild(b);
}
function onMsgInput() {
  const v = $('#msg').value;
  $('#charcount').textContent = v.length ? `${v.length}/5000` : '';
  if (!engine) return;
  const r = engine.redact(v);
  const n = Object.values(r.counts).reduce((a, b) => a + b, 0);
  $('#redactnote').innerHTML = n ? `${icon('lock')}${n} sensitive value${n > 1 ? 's' : ''} will be removed before sending` : '';
}
$('#msg').addEventListener('input', () => { onMsgInput(); markResultStale('The message changed. Press Analyze to check this text.'); });
const EMPTY_RESULT = `<div class="empty"><span class="ico">${icon('shield')}</span><b>No message checked yet</b><span>Paste a message on the left or pick an example. You'll get a risk score, the reasons behind it and what to do next.</span></div>`;
$('#result').innerHTML = EMPTY_RESULT;
$('#clear').onclick = () => { removeShot(); clearResultStale(); $('#msg').value = ''; onMsgInput(); $('#result').innerHTML = EMPTY_RESULT; $('#msg').focus(); };
$('#analyse').onclick = runScan;
$('#msg').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runScan(); });

async function runScan() {
  await engineReady;
  const text = $('#msg').value.trim();
  if (!text) { toast(shot && !shot.text ? 'Still reading the screenshot… one moment.' : 'Paste a message, link or screenshot first.'); $('#msg').focus(); return; }
  clearResultStale();
  const btn = $('#analyse'); btn.disabled = true; btn.firstChild.textContent = 'Analyzing… ';
  $('#result').innerHTML = '<div class="skeleton"><i style="width:40%;height:26px"></i><i style="width:85%"></i><i style="width:70%"></i><i style="width:90%"></i><i style="width:60%"></i></div>';
  try {
    const out = await analyze(text);
    renderResult(out);
    if (shot?.text && shot.text.trim() === text) {
      $('#result').insertAdjacentHTML('afterbegin', `<div class="shot-result"><img alt="" src="${esc(shot.url)}"><span>Result for the screenshot you added</span></div>`);
    }
  } catch (e) {
    $('#result').innerHTML = `<div class="empty"><span class="ico">${icon('alert')}</span><b>Couldn't analyze this</b><span>${esc(e.message)}</span></div>`;
  } finally { btn.disabled = false; btn.firstChild.textContent = 'Analyze '; }
}

// Redacts in the browser first, then asks the server. Falls back to the in-browser engine
// ONLY when the server cannot be reached, and says so. Never invents a threat lookup.
async function analyze(text) {
  const red = engine.redact(text);
  const { data, error } = await sb.functions.invoke('analyze', { body: { text: red.text, source: 'web' } });
  if (!error) {
    S.lastSync = new Date(); setSync(S.realtimeUp ? 'synced' : 'connecting');
    refreshIncidents();
    return { ...data, offline: false, sent: red.text };
  }
  if (error.name === 'FunctionsHttpError') {
    const status = error.context?.status;
    let body = {};
    try { body = await error.context.json(); } catch { /* not json */ }
    if (body.error === 'device_not_active' || body.error === 'device_not_registered') { heartbeat(); throw new Error('This device is not an active device on your account any more.'); }
    if (status === 402) { refreshPlan(); throw new Error(FRIENDLY[body.error] || 'Your plan does not allow more checks right now. Upgrade to continue.'); }
    if (status === 429) throw new Error('You have scanned a lot in the last hour. Please wait a few minutes.');
    if (status === 401) throw new Error('Your session expired. Please sign in again.');
    if (status === 413) throw new Error('That text is too long. The limit is 5,000 characters.');
    throw new Error(`The server could not analyse this (${status}: ${body.error ?? 'error'}).`);
  }
  // network / relay failure: analyse locally, label it, queue the REDACTED text for later
  setSync('offline');
  enqueue(red.text);
  return { result: engine.analyze(text, { ti: { status: 'unavailable' } }), offline: true, sent: red.text };
}

function enqueue(redacted) {
  const q = store.get('scamwise-offline-queue', []);
  q.push({ text: redacted, at: new Date().toISOString() });
  store.set('scamwise-offline-queue', q.slice(-20));
}
let flushing = false;
async function flushQueue() {
  const q = store.get('scamwise-offline-queue', []);
  if (flushing || !q.length || !S.started) return;
  flushing = true;
  const remaining = [];
  let sent = 0;
  for (const item of q) {
    const { error } = await sb.functions.invoke('analyze', { body: { text: item.text, source: 'web' } });
    if (!error) { sent++; continue; }
    const st = error.context?.status;
    if (error.name !== 'FunctionsHttpError' || st === 429 || st >= 500) remaining.push(item);  // retry later; drop permanent 4xx
  }
  store.set('scamwise-offline-queue', remaining);
  flushing = false;
  if (sent) { toast(`${sent} offline scan(s) synced.`); refreshIncidents(); }
}

function renderResult(out) {
  const r = out.result;
  const c = COLORS[r.risk_level];
  const ti = out.threat_intel;
  const tiLine = out.offline ? 'Not checked (offline)'
    : ti?.status === 'match' ? 'Listed as malicious'
    : ti?.status === 'no_match' ? 'No record (not proof of safety)'
    : ti?.status === 'not_applicable' ? 'No links found'
    : ti?.status === 'not_configured' ? 'Not checked'
    : 'Unavailable';
  const C = 2 * Math.PI * 48;
  const maxW = Math.max(...r.indicators.map((i) => i.weight), 1);
  $('#result').innerHTML = `
    ${out.offline ? '<div class="notice warn" style="margin-bottom:16px"><b>Offline result.</b> Analyzed on this device; link reputation was not checked. It will sync when you reconnect.</div>' : ''}
    <div class="verdict">
      <div class="gauge" role="img" aria-label="Risk score ${r.score} out of 100">
        <svg viewBox="0 0 112 112"><circle class="track" cx="56" cy="56" r="48"/><circle class="fill" cx="56" cy="56" r="48" stroke="${c}" stroke-dasharray="${C}" stroke-dashoffset="${C}"/></svg>
        <div class="val"><b style="color:${c}">${r.score}</b><span>/ 100</span></div>
      </div>
      <div>${riskPill(r.risk_level)}<h3>${esc(r.category_label)}</h3><p>${esc(r.summary)}</p></div>
    </div>
    ${r.contained_auth_code ? `<div class="code-alert">${icon('lock')}<span><b>A one-time code was in this message.</b> It was removed on this device and never sent. Never share it with anyone.</span></div>` : ''}
    ${r.indicators.length ? `<p class="section-label">Why · ${r.indicators.length} signal${r.indicators.length > 1 ? 's' : ''}</p>
    <div>${r.indicators.map((i, n) => `<div class="ind" style="animation-delay:${n * 40}ms"><b>${esc(i.label)}</b><small>${esc(i.detail ?? '')}</small>
      <span class="w" style="color:${c}">+${i.weight}<i style="width:${Math.round((i.weight / maxW) * 56)}px"></i></span></div>`).join('')}</div>` : ''}
    ${r.recommendations.length ? `<p class="section-label">What to do</p><ul class="todo">${r.recommendations.map((x) => `<li>${icon('arrow')}<span>${esc(x)}</span></li>`).join('')}</ul>` : ''}
    ${r.caveats.map((x) => `<p class="caveat">${icon('info')}<span>${esc(x)}</span></p>`).join('')}
    <div class="meta">
      <div><span>Link check</span><b>${tiLine}</b></div>
      <div><span>Alerts sent</span><b>${out.offline ? '—' : out.alerts_sent ? `${out.alerts_sent} device${out.alerts_sent > 1 ? 's' : ''}` : 'None'}</b></div>
      <div><span>Stored</span><b>${out.offline ? 'Queued' : 'Metadata only'}</b></div>
    </div>
    <details class="sent"><summary>What was sent to the server</summary><pre>${esc(out.sent)}</pre></details>`;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const f = $('#result .gauge .fill'); if (f) f.style.strokeDashoffset = String(C * (1 - r.score / 100));
  }));
}

// ------------------------------------------------------------------ insights, reports and family safety
function renderInsights() {
  const root = $('#insight-stats'); if (!root) return;
  const rows = S.incidents || [];
  const count = (risk) => rows.filter((x) => x.risk_level === risk).length;
  root.innerHTML = [
    ['Total scans', rows.length], ['High risk', count('high')], ['Medium risk', count('medium')], ['Inconclusive', count('inconclusive')],
  ].map(([label, n]) => `<div class="stat"><span>${esc(label)}</span><b>${n}</b></div>`).join('');
  const max = Math.max(rows.length, 1);
  $('#insight-bars').innerHTML = ['high','medium','low','inconclusive'].map((risk) => {
    const n = count(risk), width = Math.round(n / max * 100);
    return `<div class="row-item" style="display:block"><div style="display:flex;justify-content:space-between;gap:12px"><b>${esc(LABEL[risk])}</b><span>${n} (${width}%)</span></div><div style="height:8px;background:var(--surface-2);border-radius:99px;margin-top:8px;overflow:hidden"><div style="height:100%;width:${width}%;background:${COLORS[risk]};border-radius:99px"></div></div></div>`;
  }).join('') || '<p class="muted">No scan metadata available yet.</p>';
  $('#report-status').textContent = `${rows.length} records available. Report excludes message text and any stored excerpts.`;
}
function renderFamilySafety() {
  const el = $('#family-device-summary'); if (!el) return;
  const devices = S.devices || [];
  el.innerHTML = devices.length ? devices.map((d) => `<div class="row-item"><div><b>${esc(d.name || 'Unnamed device')}</b><p class="muted">${esc(d.status || 'unknown')} · ${esc(d.platform || 'web')}</p></div><span class="tag ${d.status === 'active' ? 'ok' : 'warn'}">${esc(d.status || 'unknown')}</span></div>`).join('') : '<p class="muted">No linked devices found. Use Devices to link and approve another device.</p>';
}
function downloadJson(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob); const a = document.createElement('a');
  a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('#export-report')?.addEventListener('click', () => {
  const safe = (S.incidents || []).map((i) => ({
    created_at: i.created_at, risk_level: i.risk_level, score: i.score,
    category: i.category, contained_auth_code: !!i.contained_auth_code,
    analysis_method: i.analysis_method, indicators: Array.isArray(i.indicators) ? i.indicators.map((x) => ({ code: x.code, label: x.label, weight: x.weight, family: x.family })) : [],
  }));
  downloadJson(`scamwise-privacy-safe-report-${new Date().toISOString().slice(0,10)}.json`, { generated_at: new Date().toISOString(), privacy_note: 'Message text and excerpts intentionally excluded.', records: safe });
  $('#report-status').textContent = `Exported ${safe.length} privacy-safe scan records to your device.`;
});
$('#family-devices')?.addEventListener('click', () => switchTab('devices'));

// ------------------------------------------------------------------ screenshot scan
// OCR runs locally in the browser. The image is shown on this page only and is never uploaded:
// only the (redacted) text read from it is analysed, exactly like a pasted message.
const SHOT_MAX = 10 * 1024 * 1024;
const SHOT_TYPES = /^image\/(png|jpeg|webp|gif|bmp)$/;
let shot = null;          // { url, name, size, text, conf }
let ocrRun = 0;           // guards against an older OCR finishing after a newer image

// Upscale small images, convert to grayscale, invert dark-mode screenshots and stretch contrast.
// Tesseract is far more accurate on large, dark-text-on-light images.
async function prepareForOcr(file) {
  const img = await createImageBitmap(file);
  let scale = img.width < 1600 ? Math.min(3, 1600 / img.width) : 1;
  if (Math.max(img.width, img.height) * scale > 4000) scale = 4000 / Math.max(img.width, img.height);
  const w = Math.round(img.width * scale), h = Math.round(img.height * scale);
  const c = document.createElement('canvas'); c.width = w; c.height = h;
  const ctx = c.getContext('2d', { willReadFrequently: true });
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(img, 0, 0, w, h); img.close?.();
  const d = ctx.getImageData(0, 0, w, h), p = d.data, n = p.length / 4;
  const hist = new Uint32Array(256); let sum = 0;
  for (let i = 0; i < p.length; i += 4) { const g = (p[i] * 299 + p[i + 1] * 587 + p[i + 2] * 114) / 1000 | 0; p[i] = g; hist[g]++; sum += g; }
  const invert = sum / n < 110;
  let lo = 0, hi = 255, acc = 0;
  for (let i = 0; i < 256; i++) { acc += hist[i]; if (acc > n * 0.01) { lo = i; break; } }
  acc = 0;
  for (let i = 255; i >= 0; i--) { acc += hist[i]; if (acc > n * 0.01) { hi = i; break; } }
  const range = Math.max(1, hi - lo);
  for (let i = 0; i < p.length; i += 4) {
    let g = Math.max(0, Math.min(255, (p[i] - lo) * 255 / range)); if (invert) g = 255 - g;
    p[i] = p[i + 1] = p[i + 2] = g; p[i + 3] = 255;
  }
  ctx.putImageData(d, 0, 0);
  return c;
}

// Remove phone UI noise (clock, battery) and repair links that OCR breaks ("site xyz/login").
const OCR_TLDS = 'com|in|net|org|xyz|top|info|online|site|live|club|shop|co|io|me|ly|link|click|buzz|icu|vip|app|store|tk|ml|ga|cf|gq|cc|biz|gov|sbi|bank';
function cleanOcrText(t) {
  let lines = String(t || '').replace(/\r/g, '').split('\n').map((l) => l.trim());
  lines = lines.filter((l) => !l || !(/^\d{1,2}[:.]\d{2}\s*(am|pm)?$/i.test(l) || /^\d{1,2}[:.]?\d{2}\s*(am|pm)$/i.test(l)
    || (l.length < 14 && /^[\W\d]{0,3}(\d{1,3}%|4g|5g|lte|volte)[\W\d\s%a-z]{0,10}$/i.test(l))
    || (l.length < 30 && /^\d{1,2}[:.]\d{2}\b/.test(l) && /\d{1,3}\s?%|\b(4g|5g|lte|volte|wifi)\b/i.test(l))     // status bar: "9:41 87%"
    || /^(today|yesterday|mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+\d{1,2}[:.]?\d{2}\s*(am|pm)?$/i.test(l)));   // "Yesterday 7:15 PM
  lines = lines.map((l) => l.replace(/\s+((today|yesterday)\s+)?\d{1,2}[:.]\d{2}\s*(am|pm)?$/i, '').replace(/\s+((today|yesterday)\s+)?\d{1,2}[:.]?\d{2}\s*(am|pm)$/i, ''));
  const out = [];
  for (const l of lines) {
    const prev = out[out.length - 1];
    if (l && prev && !/[.!?:।]$/.test(prev) && (/^[a-z0-9(ऀ-ॿ]/.test(l) || (prev.length > 20 && /^[A-Z]/.test(l)))) out[out.length - 1] = prev + ' ' + l;
    else out.push(l);
  }
  t = out.join('\n').replace(/\n{3,}/g, '\n\n');
  t = t.replace(/\b(h\s*t\s*t\s*p\s*s?)\s*:\s*\/\s*\//gi, (m) => m.replace(/\s+/g, '').toLowerCase());
  t = t.replace(/\b(https?:\/\/)\s+/gi, '$1');
  t = t.replace(new RegExp(`([a-z0-9-]{2,})\\s*[,\\s]\\s*(${OCR_TLDS})(?=[\\/\\s]|$)`, 'gi'), (m, host, tld, off, str) => {
    const before = str.slice(Math.max(0, off - 40), off);
    return (/(https?:\/\/|www\.)[\w.-]*$/i.test(before) || str.charAt(off + m.length) === '/') ? `${host}.${tld}` : m;
  });
  return t.trim();
}

function fmtSize(b) { return b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`; }

function renderShot(state) {
  const box = $('#shot');
  if (!shot) { box.hidden = true; box.querySelector('img').removeAttribute('src'); return; }
  box.hidden = false;
  box.querySelector('img').src = shot.url;
  box.querySelector('.shot-name').textContent = `${shot.name} · ${fmtSize(shot.size)}`;
  box.querySelector('.shot-state').textContent = state || '';
  const det = box.querySelector('details');
  det.hidden = !shot.text;
  box.querySelector('.shot-text').textContent = shot.text || '';
}

function removeShot({ keepText = false } = {}) {
  ocrRun++;
  if (shot && !keepText && $('#msg').value.trim() === (shot.text || '').trim()) { $('#msg').value = ''; onMsgInput(); }
  if (shot?.url) URL.revokeObjectURL(shot.url);
  shot = null; renderShot();
  $('#ocr-status').textContent = 'PNG, JPG or WebP · up to 10 MB · or paste a screenshot with Ctrl+V';
}

// Mark the current verdict as out of date so it is never read as the answer for different input.
function markResultStale(msg) {
  const r = $('#result');
  if (!r.querySelector('.verdict')) return;
  r.dataset.staleMsg = msg; r.classList.add('stale');
}
function clearResultStale() { $('#result').classList.remove('stale'); }

async function scanScreenshot(file) {
  const status = $('#ocr-status');
  if (!file) return;
  if (!SHOT_TYPES.test(file.type)) { status.textContent = 'That file is not a supported image. Use a PNG, JPG or WebP screenshot.'; return; }
  if (file.size > SHOT_MAX) { status.textContent = 'That image is larger than 10 MB. Crop it or take a smaller screenshot.'; return; }
  if (!window.Tesseract?.recognize) { status.textContent = 'The text reader did not load. Check your internet connection and try again.'; return; }
  if (shot?.url) URL.revokeObjectURL(shot.url);
  const run = ++ocrRun;
  shot = { url: URL.createObjectURL(file), name: file.name || 'pasted-screenshot.png', size: file.size, text: '', conf: null };
  renderShot('Reading text…');
  status.textContent = 'Reading the screenshot on this device…';
  $('#result').innerHTML = `<div class="empty"><span class="ico">${icon('shield')}</span><b>Reading your screenshot…</b><span>The text is read on this device. The check starts automatically.</span></div>`;
  clearResultStale();
  try {
    let input = file;
    try { input = await prepareForOcr(file); } catch { /* fall back to the original image */ }
    let result;
    try { result = await window.Tesseract.recognize(input, 'eng+hin'); }
    catch { result = await window.Tesseract.recognize(input, 'eng'); }   // Hindi data unavailable -> English only
    if (run !== ocrRun) return;                                            // a newer image replaced this one
    const text = cleanOcrText(result.data?.text).slice(0, 5000);
    if (!text) throw new Error('No readable text found in this image. Try a clearer screenshot or paste the message.');
    shot.text = text; shot.conf = Math.round(result.data?.confidence ?? 0);
    $('#msg').value = text; onMsgInput();
    const low = shot.conf && shot.conf < 60;
    renderShot(low ? `Text read (${shot.conf}% confidence) · checking…` : 'Text read · checking…');
    status.textContent = low
      ? 'The screenshot was hard to read. Check the text below, fix any mistakes and press Analyze again.'
      : 'Text read on this device. The image was not uploaded.';
    await runScan();
    if (run === ocrRun && shot) renderShot(low ? `Checked · ${shot.conf}% read confidence` : 'Checked');
  } catch (err) {
    if (run !== ocrRun) return;
    renderShot('Could not read text');
    status.textContent = err.message || 'Could not read the screenshot.';
    $('#result').innerHTML = EMPTY_RESULT;
  }
}

$('#screenshot-file')?.addEventListener('change', (e) => { const f = e.target.files?.[0]; e.target.value = ''; scanScreenshot(f); });
$('#shot-remove')?.addEventListener('click', () => { removeShot(); markResultStale('Screenshot removed. Paste a message or add another screenshot.'); });
function imageFromClipboard(e) {
  for (const it of e.clipboardData?.items || []) if (it.kind === 'file' && it.type.startsWith('image/')) return it.getAsFile();
  return null;
}
// paste a screenshot into the message box, or anywhere on the Scan tab
document.addEventListener('paste', (e) => {
  if ($('#tab-scan').classList.contains('hidden') || $('#tab-scan').offsetParent === null) return;
  if (e.target !== $('#msg') && e.target?.matches?.('input, textarea, [contenteditable]')) return;
  const f = imageFromClipboard(e);
  if (f) { e.preventDefault(); scanScreenshot(f); }
});
// drag and drop an image onto the composer
{
  const card = $('#tab-scan .composer');
  card?.addEventListener('dragover', (e) => { if ([...(e.dataTransfer?.types || [])].includes('Files')) { e.preventDefault(); card.classList.add('drop'); } });
  card?.addEventListener('dragleave', (e) => { if (!card.contains(e.relatedTarget)) card.classList.remove('drop'); });
  card?.addEventListener('drop', (e) => { card.classList.remove('drop'); const f = e.dataTransfer?.files?.[0]; if (f) { e.preventDefault(); scanScreenshot(f); } });
}

// ------------------------------------------------------------------ history
$('#hist-filter').onchange = renderHistory;
function renderHistory() {
  const f = $('#hist-filter').value;
  const rows = S.incidents.filter((i) => !f || i.risk_level === f);
  const fam = rules?.families ?? {};
  const count = (lv) => S.incidents.filter((i) => i.risk_level === lv).length;
  $('#hist-stats').innerHTML = [
    ['Total scans', S.incidents.length, 'var(--accent)'], ['High risk', count('high'), 'var(--high)'],
    ['Medium risk', count('medium'), 'var(--med)'], ['Codes caught', S.incidents.filter((i) => i.contained_auth_code).length, 'var(--low)'],
  ].map(([l, v, c]) => `<div class="stat"><span><i style="background:${c}"></i>${l}</span><b>${v}</b></div>`).join('');
  $('#history').innerHTML = !rows.length ? `<div class="blank"><span class="ico">${icon('history')}</span><b>No scans${f ? ' at this risk level' : ' yet'}</b><span>Results from every linked device show up here.</span></div>`
    : rows.map((i) => `<div class="item">
        <span class="lead ${esc(i.risk_level)}"><b>${i.score}</b></span>
        <div class="body">
          <div class="title">${esc(fam[i.category] ?? i.category)} ${riskPill(i.risk_level)}${i.contained_auth_code ? '<span class="tag ok">Code removed</span>' : ''}${i.ti_status === 'match' ? '<span class="tag bad">Malicious link</span>' : ''}</div>
          <div class="sub">${esc(i.device_name ?? 'Unknown device')}${i.url_domains?.length ? ' · ' + esc(i.url_domains.join(', ')) : ''}${(i.indicators ?? []).length ? ' · ' + (i.indicators ?? []).slice(0, 3).map((x) => esc(x.label)).join(' · ') : ''}</div>
          ${i.redacted_excerpt ? `<div class="sub mono">“${esc(i.redacted_excerpt)}”</div>` : ''}
        </div>
        <div class="side-col">
          <span class="when" title="${esc(when(i.created_at))} · expires ${esc(new Date(i.expires_at).toLocaleDateString())}">${esc(ago(i.created_at))}</span>
          <div class="acts">
            <select class="select-sm" data-status="${esc(i.id)}" aria-label="Status">
              ${(i.status === 'no_threat' ? [['no_threat', 'No threat'], ['investigating', 'Report as suspicious']] : [['detected', 'Detected'], ...(i.status === 'blocked' ? [['blocked', 'Blocked']] : []), ['investigating', 'Investigating'], ['resolved', 'Resolved'], ['false_positive', 'False positive']]).map(([v, l]) => `<option value="${v}" ${v === i.status ? 'selected' : ''} ${v === 'blocked' || v === 'no_threat' ? 'disabled' : ''}>${l}</option>`).join('')}
            </select>
            <button class="icon-btn" data-del="${esc(i.id)}" aria-label="Delete scan" title="Delete">${icon('trash')}</button>
          </div>
        </div></div>`).join('');
  $$('#history [data-status]').forEach((s) => (s.onchange = async () => {
    const { error } = await sb.rpc('set_incident_status', { p_incident: s.dataset.status, p_status: s.value });
    if (error) toast(friendly(error)); else { toast('Status updated.'); refreshIncidents(); }
  }));
  $$('#history [data-del]').forEach((b) => (b.onclick = async () => {
    if (!(await confirmBox('Delete this scan record?', 'It is removed for every device on your account.', 'Delete', true))) return;
    const { error } = await sb.from('incidents').delete().eq('id', b.dataset.del);
    if (error) toast(friendly(error)); else refreshIncidents();
  }));
}

// ------------------------------------------------------------------ alerts
const ICON = { incident: 'alert', auth_code: 'lock', pairing: 'link', device: 'devices' };
function renderAlerts() {
  const unread = S.alerts.filter((a) => !a.read_at).length;
  const badge = $('#alert-badge');
  badge.textContent = unread; badge.classList.toggle('hidden', !unread);
  document.title = (unread ? `(${unread}) ` : '') + 'SCAMWISE';
  $('#alerts').innerHTML = !S.alerts.length ? `<div class="blank"><span class="ico">${icon('bell')}</span><b>You're all caught up</b><span>When a linked device scans something high-risk, it appears here.</span></div>`
    : S.alerts.map((a) => {
      const tone = a.kind === 'pairing' || a.kind === 'device' ? 'accent' : (a.risk_level ?? 'high');
      return `<div class="item ${a.read_at ? '' : 'unread'}">
        <span class="lead ${esc(tone)}">${icon(ICON[a.kind] ?? 'bell')}</span>
        <div class="body"><div class="title">${esc(a.title)}</div><div class="sub">${esc(a.body)}</div></div>
        <div class="side-col"><span class="when" title="${esc(when(a.created_at))}">${esc(ago(a.created_at))}</span>
        ${a.kind === 'pairing' ? '<button class="btn ghost sm" data-goto="devices">Review</button>' : ''}</div>
      </div>`;
    }).join('');
  $$('#alerts [data-goto]').forEach((b) => (b.onclick = () => switchTab(b.dataset.goto)));
  if (S.tab === 'alerts' && unread && document.visibilityState === 'visible') setTimeout(markAlertsRead, 1500);
}
let marking = false;
async function markAlertsRead() {
  if (marking || !S.alerts.some((a) => !a.read_at)) return;
  marking = true;
  await sb.rpc('mark_alerts_read', {}).catch(() => {});
  marking = false;
  await refreshAlerts();
}
$('#mark-read').onclick = markAlertsRead;

// ------------------------------------------------------------------ devices & pairing
function renderDevices() {
  const badge = $('#device-badge');
  badge.textContent = S.pairing.length; badge.classList.toggle('hidden', !S.pairing.length);
  $('#pair-requests').innerHTML = S.pairing.map((p) => `<div class="panel request">
      <div class="item" style="padding:0;border:0"><span class="lead accent">${icon('link')}</span>
      <div class="body"><div class="title">“${esc(p.claimed_device_name ?? 'New device')}” wants to join</div>
      <div class="sub">Entered your code ${esc(ago(p.claimed_at))}. Only approve a device you or your family own. Requests expire after 15 minutes.</div></div></div>
      <div class="row-end"><button class="btn primary sm" data-approve="${esc(p.id)}">${icon('check')}Approve</button><button class="btn ghost sm" data-reject="${esc(p.id)}">Reject</button></div>
    </div>`).join('');
  $$('#pair-requests [data-approve]').forEach((b) => (b.onclick = () => respondPairing(b.dataset.approve, true)));
  $$('#pair-requests [data-reject]').forEach((b) => (b.onclick = () => respondPairing(b.dataset.reject, false)));

  const visible = S.devices.filter((d) => d.status !== 'revoked').concat(S.devices.filter((d) => d.status === 'revoked'));
  $('#devices').innerHTML = !visible.length ? '<div class="skeleton"><i></i><i style="width:70%"></i></div>' : visible.map((d) => {
    const me = d.id === S.device?.id;
    const online = d.status === 'active' && (me || (d.last_seen_at && Date.now() - new Date(d.last_seen_at).getTime() < 120000));
    const st = d.status === 'active' ? (online ? '<span class="tag ok">Online</span>' : `<span class="tag">Seen ${esc(ago(d.last_seen_at))}</span>`)
      : d.status === 'pending' ? '<span class="tag warn">Awaiting approval</span>' : '<span class="tag">Unlinked</span>';
    return `<div class="item" style="${d.status === 'revoked' ? 'opacity:.55' : ''}">
      <span class="lead">${icon('devices')}</span>
      <div class="body"><div class="title">${esc(d.name)}${me ? '<span class="tag accent">This device</span>' : ''}${d.is_primary ? '<span class="tag">Primary</span>' : ''}</div>
        <div class="sub">${esc((d.platform ?? '').replace(/^web · /, ''))} · added ${esc(new Date(d.created_at).toLocaleDateString())}</div></div>
      <div class="side-col">${st}${d.status !== 'revoked' && !me ? `<button class="btn danger-ghost sm" data-revoke="${esc(d.id)}" data-name="${esc(d.name)}">Unlink</button>` : ''}</div>
    </div>`;
  }).join('');
  $$('#devices [data-revoke]').forEach((b) => (b.onclick = async () => {
    if (!(await confirmBox(`Unlink "${b.dataset.name}"?`, 'It is signed out immediately and stops receiving alerts. It will need approval to rejoin.', 'Unlink', true))) return;
    const { error } = await sb.rpc('revoke_device', { p_device: b.dataset.revoke });
    if (error) toast(friendly(error)); else { toast('Device unlinked.'); refreshDevices(); }
  }));
}

async function respondPairing(id, approve) {
  const { error } = await sb.rpc('respond_pairing', { p_pairing: id, p_approve: approve });
  if (error) toast(friendly(error));
  else toast(approve ? 'Device approved. It is now linked.' : 'Request rejected.');
  await Promise.all([refreshPairing(), refreshDevices()]);
}

$('#add-device').onclick = openAddDevice;
function openAddDevice() {
  let timer = null, poll = null, pairing = null;
  const close = modal(`<h3>Add a device</h3><div id="ad-body" style="display:flex;flex-direction:column;gap:12px"><div class="skeleton"><i></i><i style="height:60px"></i></div></div>
    <div class="row-end" style="margin-top:4px"><button class="btn ghost hidden" id="ad-new">New code</button><button class="btn ghost" id="ad-close">Close</button></div>`, {
    onMount(el, closeFn) {
      el.querySelector('#ad-close').onclick = () => { stop(); closeFn(); };
      el.querySelector('#ad-new').onclick = create;
    },
  });
  const body = () => document.querySelector('#ad-body');
  const stop = () => { clearInterval(timer); clearInterval(poll); };
  async function create() {
    stop();
    document.querySelector('#ad-new')?.classList.add('hidden');
    const { data, error } = await sb.rpc('create_pairing_code');
    if (!body()) return;
    if (error) { body().innerHTML = `<p class="err">${esc(friendly(error))}</p>`; document.querySelector('#ad-new')?.classList.remove('hidden'); return; }
    pairing = data;
    const pretty = data.code.slice(0, 4) + '-' + data.code.slice(4);
    const link = `${location.origin}${location.pathname}#pair=${data.code}`;
    let qrHtml = '';
    try {
      const qr = window.qrcode(0, 'M'); qr.addData(link); qr.make();
      qrHtml = `<div class="qr"><img alt="QR code that opens SCAMWISE with this pairing code" src="${qr.createDataURL(5, 2)}"></div>`;
    } catch { /* QR library did not load: the typed code still works */ }
    body().innerHTML = `
      <p>On the new device, open SCAMWISE, sign in to the <b>same account</b>, then enter this code or scan the QR.</p>
      <div class="code-big" id="ad-code">${esc(pretty)}</div>
      ${qrHtml ? `<div style="display:flex;justify-content:center">${qrHtml}</div>` : ''}
      <p class="mono center" style="font-size:12.5px" id="ad-left"></p>
      <div class="waiting"><span class="pulse"></span><div><b>Waiting for the new device</b><p>You'll be asked to approve it here.</p></div></div>`;
    const exp = new Date(data.expires_at).getTime();
    const tick = () => {
      const s = Math.max(0, Math.round((exp - Date.now()) / 1000));
      const el = document.querySelector('#ad-left');
      if (!el) return stop();
      el.textContent = s ? `Expires in ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} · single use` : 'This code has expired.';
      if (!s) { stop(); document.querySelector('#ad-code').style.opacity = .4; document.querySelector('#ad-new')?.classList.remove('hidden'); }
    };
    tick(); timer = setInterval(tick, 1000);
    poll = setInterval(check, 3000);
  }
  async function check() {
    if (!pairing || !body()) return stop();
    const { data } = await sb.from('pairing_codes').select('*').eq('id', pairing.id).maybeSingle();
    if (!data || data.status === 'open') return;
    stop();
    if (data.status === 'claimed') {
      body().innerHTML = `<div class="notice"><b>“${esc(data.claimed_device_name)}”</b> entered your code. Is this your device?</div>
        <div class="row-end"><button class="btn ghost" id="ad-rej">Reject</button><button class="btn primary" id="ad-ok">${icon('check')}Approve</button></div>`;
      const decide = async (ok) => {
        await respondPairing(data.id, ok);
        if (body()) body().innerHTML = `<p class="${ok ? 'ok' : 'note'}">${ok ? `“${esc(data.claimed_device_name)}” is now linked and will receive alerts.` : 'The request was rejected.'}</p>`;
        const c = document.querySelector('#ad-close'); if (c) c.textContent = 'Done';
      };
      document.querySelector('#ad-ok').onclick = () => decide(true);
      document.querySelector('#ad-rej').onclick = () => decide(false);
    } else if (data.status === 'approved') {
      body().innerHTML = `<p class="ok">“${esc(data.claimed_device_name)}” is now linked.</p>`;
    } else {
      body().innerHTML = `<p class="note">This code is no longer valid (${esc(data.status)}).</p>`;
      document.querySelector('#ad-new')?.classList.remove('hidden');
    }
  }
  create();
  return close;
}

// ------------------------------------------------------------------ settings
function renderSettings() {
  const d = S.device, p = S.profile;
  const name = S.user?.user_metadata?.full_name || '';
  $('#acct-name').textContent = name || '—';
  $('#acct-email').textContent = S.user?.email ?? '—';
  const initials = (name || S.user?.email || '?').split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((x) => x[0].toUpperCase()).join('');
  $('#avatar').textContent = initials;
  if (d) {
    $('#this-device').innerHTML = `<dt>Name</dt><dd>${esc(d.name)}</dd><dt>Status</dt><dd>${d.status === 'active' ? '<span class="tag ok">Linked</span>' : esc(d.status)}</dd>
      <dt>Browser</dt><dd>${esc((d.platform ?? platform()).replace(/^web · /, ''))}</dd><dt>Device ID</dt><dd class="mono">${esc(String(d.id).split('-')[0])}</dd>
      <dt>Last sync</dt><dd class="mono">${S.lastSync ? esc(S.lastSync.toLocaleTimeString()) : '—'}</dd>`;
  }
  if (p) {
    $$('[data-pref]').forEach((el) => {
      const v = p[el.dataset.pref];
      if (el.type === 'checkbox') el.checked = !!v; else el.value = String(v);
    });
  }
  const n = 'Notification' in window ? Notification.permission : 'unsupported';
  $('#notif-btn').classList.toggle('hidden', n !== 'default');
  $('#notif-text').innerHTML = `<b>Browser notifications</b><small>${n === 'granted' ? 'On. Shown while SCAMWISE is open in a tab.' : n === 'denied' ? 'Blocked. Allow them in your browser\'s site settings.' : n === 'unsupported' ? 'Not supported in this browser.' : 'Shown while SCAMWISE is open in a tab.'}</small>`;
  $('#version').textContent = `v${APP_VERSION} · rules ${rules?.version ?? '…'}`;
}
$$('[data-pref]').forEach((el) => el.addEventListener('change', async () => {
  const key = el.dataset.pref;
  const value = el.type === 'checkbox' ? el.checked : +el.value;
  const { error } = await sb.from('profiles').update({ [key]: value }).eq('id', S.device?.user_id);
  if (error) { toast('Could not save: ' + friendly(error)); renderSettings(); return; }
  toast('Saved.');
  refreshProfile();
}));
$('#notif-btn').onclick = async () => { try { await Notification.requestPermission(); } catch { /* ignore */ } renderSettings(); };
$('#rename').onclick = async () => {
  const name = await promptBox('Rename this device', S.device?.name ?? '');
  if (!name) return;
  store.set('scamwise-device-name', name);
  const { error } = await sb.rpc('rename_device', { p_device: S.device.id, p_name: name });
  if (error) toast(friendly(error)); else { toast('Renamed.'); refreshDevices(); }
};
$('#sync-now').onclick = async () => { await heartbeat(); await refreshAll(); await flushQueue(); toast('Synced.'); };
$('#delete-all').onclick = async () => {
  if (!(await confirmBox('Delete all scan history?', 'This permanently deletes your incident records for every device on this account.', 'Delete', true))) return;
  const { data, error } = await sb.rpc('delete_my_incidents');
  if (error) toast(friendly(error)); else { toast(`Deleted ${data ?? 0} record(s).`); refreshAll(); }
};
$('#signout').onclick = () => signOut();
$('#unlink-self').onclick = async () => {
  if (!(await confirmBox('Unlink this device?', 'It will be signed out and stop receiving alerts. Your history stays with your account.', 'Unlink', true))) return;
  if (S.device?.id) await sb.rpc('revoke_device', { p_device: S.device.id }).catch(() => {});
  await signOut('This device has been unlinked. Your incident history stays with your account.');
};

// ------------------------------------------------------------------ boot
function readPairLink() {
  const m = /[#&]pair=([A-Za-z0-9-]{8,9})/.exec(location.hash);
  if (!m) return;
  pairFromLink = m[1].toUpperCase().replace(/-/g, '');
  pairFromLink = pairFromLink.slice(0, 4) + '-' + pairFromLink.slice(4);
  history.replaceState(null, '', location.pathname + location.search);
}

sb.auth.onAuthStateChange((event, session) => {
  // Clear stale in-memory user state on sign-out instead of retaining the previous user.
  S.user = event === 'SIGNED_OUT' ? null : (session?.user ?? S.user);
  if (event === 'PASSWORD_RECOVERY') setTimeout(() => { teardown(); show('reset'); }, 0);
  // The server deleted this session (device unlinked elsewhere) -> refresh fails -> SIGNED_OUT.
  if (event === 'SIGNED_OUT' && S.device) setTimeout(() => handleRevoked(), 0);
});

// rotating live examples on the sign-in panel (scored by the real engine)
const PITCH = [
  'Your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login',
  'This is Mumbai Cyber Police. You are under digital arrest. Do not tell anyone. Pay Rs 49,000 clearance fee now.',
  'Part time job! Earn ₹5000 per day by liking YouTube videos. Pay refundable deposit of Rs 2000 to start.',
];
let pitchIdx = 0;
function pitchTick() {
  if (!engine || $('#auth-layout').classList.contains('hidden') || document.visibilityState !== 'visible') return;
  const card = $('#pitch-card');
  card.classList.add('swap');
  setTimeout(() => {
    pitchIdx = (pitchIdx + 1) % PITCH.length;
    const text = PITCH[pitchIdx];
    const r = engine.analyze(text, { ti: { status: 'not_configured' } });
    $('#pc-risk').className = 'risk ' + r.risk_level;
    $('#pc-risk').textContent = LABEL[r.risk_level];
    $('#pc-score').textContent = r.score;
    $('#pc-msg').textContent = '“' + engine.defang(text.replace(/https?:\/\//, '')) + '”';
    $('#pc-list').innerHTML = r.indicators.filter((i) => i.family !== 'suspicious_link' || i.weight >= 20).slice(0, 3)
      .map((i) => `<li><b>+${i.weight}</b>${esc(i.label)}</li>`).join('');
    $$('#pc-dots i').forEach((d, n) => d.classList.toggle('on', n === pitchIdx));
    card.classList.remove('swap');
  }, 350);
}
if (!matchMedia('(prefers-reduced-motion: reduce)').matches) setInterval(pitchTick, 4500);

// the logo inside the app goes to the app's home (Scan), never to the marketing page
$$('.app-home').forEach((a) => (a.onclick = (e) => { e.preventDefault(); if (S.started) switchTab('scan'); }));
$('#avatar').onclick = () => switchTab('settings');
$('#change-pw').onclick = async () => {
  if (!S.user?.email) return;
  const { error } = await sb.auth.resetPasswordForEmail(S.user.email, { redirectTo: redirectUrl() });
  toast(error ? authError(error) : `Reset link sent to ${S.user.email}.`);
};
window.addEventListener('hashchange', () => {
  if (S.started || S.device) return;
  if (location.hash === '#signup') show('signup');
  else if (location.hash === '#signin') show('login');
});

(async function boot() {
  readPairLink();
  await engineReady.catch(() => {});
  onMsgInput();
  const { data: { session } } = await sb.auth.getSession();
  S.user = session?.user ?? null;
  if (!session) {
    if (pairFromLink) return showLogin('Sign in with the same account as your other device to link this one.');
    return location.hash === '#signup' ? showAuth('signup') : showLogin();
  }
  if (ARRIVED_FOR_RECOVERY) return show('reset');
  await registerDevice();
})();
