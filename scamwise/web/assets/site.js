// SCAMWISE landing page: live checker, session-aware nav, reveal and count-up, feedback form.
import { createEngine } from '../engine/analyzer.js';
import { SUPABASE_URL, SUPABASE_KEY } from './config.js';

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
const LABEL = { high: 'High risk', medium: 'Medium risk', low: 'Low risk', inconclusive: 'Inconclusive' };
const STROKE = { high: '#F97066', medium: '#FDB022', low: '#47CD89', inconclusive: '#98A2B3' };

function toast(msg) {
  const t = document.createElement('div');
  t.className = 'toast'; t.textContent = msg;
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ------------------------------------------------------------ signed-in visitors see "Open dashboard"
function hasSession() {
  try {
    const v = JSON.parse(localStorage.getItem('scamwise-web-app') || 'null');
    return !!(v && (v.access_token || v.currentSession));
  } catch { return false; }
}
function applyAuth() {
  const inn = hasSession();
  $$('[data-auth="in"]').forEach((el) => el.classList.toggle('hidden', !inn));
  $$('[data-auth="out"]').forEach((el) => el.classList.toggle('hidden', inn));
}
applyAuth();
window.addEventListener('storage', applyAuth);

// ------------------------------------------------------------ nav
const nav = $('#lp-nav');
const onScroll = () => nav.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true }); onScroll();
$('#lp-burger').onclick = () => {
  const open = $('#lp-links').classList.toggle('open');
  $('#lp-burger').setAttribute('aria-expanded', String(open));
};
$$('#lp-links a').forEach((a) => a.addEventListener('click', () => { $('#lp-links').classList.remove('open'); $('#lp-burger').setAttribute('aria-expanded', 'false'); }));
// highlight the section in view
const sections = ['product', 'how', 'security', 'pricing', 'faq'].map((id) => document.getElementById(id)).filter(Boolean);
if ('IntersectionObserver' in window) {
  const so = new IntersectionObserver((es) => es.forEach((e) => {
    if (e.isIntersecting) $$('#lp-links a').forEach((a) => a.classList.toggle('on', a.getAttribute('href') === '#' + e.target.id));
  }), { rootMargin: '-45% 0px -50% 0px' });
  sections.forEach((s) => so.observe(s));
}

// ------------------------------------------------------------ reveal + count-up (content is visible at rest)
if ('IntersectionObserver' in window && !REDUCED) {
  const below = [...$$('.lp-reveal')].filter((el) => el.getBoundingClientRect().top > innerHeight);
  const ro = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    const sibs = [...e.target.parentElement.children];
    e.target.style.animationDelay = `${Math.min(sibs.indexOf(e.target), 5) * 70}ms`;
    e.target.classList.add('in');
    ro.unobserve(e.target);
  }), { rootMargin: '0px 0px -8% 0px' });
  below.forEach((el) => ro.observe(el));

  const co = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    co.unobserve(e.target);
    const el = e.target, end = +el.dataset.count, scale = +(el.dataset.scale || 1), dec = +(el.dataset.decimals || 0);
    const fmt = (v) => (el.dataset.prefix || '') + (v * scale).toLocaleString('en-IN', { minimumFractionDigits: dec, maximumFractionDigits: dec }) + (el.dataset.suffix || '');
    const t0 = performance.now(), dur = 1200;
    const step = (t) => { const k = Math.min(1, (t - t0) / dur); el.textContent = fmt(end * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }), { threshold: .6 });
  $$('[data-count]').forEach((el) => co.observe(el));
}

// ------------------------------------------------------------ live checker
const SAMPLES = [
  ['Bank KYC', 'Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login'],
  ['Digital arrest', 'This is Mumbai Cyber Police. A parcel in your name has been seized. You are under digital arrest. Do not tell anyone. Pay Rs 49,000 clearance fee now.'],
  ['Bank OTP', '482913 is your OTP for login to HDFC NetBanking. Valid for 5 mins. Do not share this OTP with anyone.'],
  ['Task job', 'Part time job! Earn ₹5000 per day by liking YouTube videos. Pay refundable deposit of Rs 2000 to start.'],
  ['Normal', 'Hey, are we still meeting for lunch at 1 tomorrow? I booked a table at the cafe.'],
];
let engine = null;
let auto = true, autoIdx = 0, typer = null;
const msg = $('#lp-msg');
SAMPLES.forEach(([label, text], i) => {
  const b = document.createElement('button');
  b.type = 'button'; b.textContent = label;
  b.onclick = () => { stopAuto(); msg.value = text; markSample(i); check(); };
  $('#lp-samples').appendChild(b);
});
const markSample = (i) => $$('#lp-samples button').forEach((b, n) => b.classList.toggle('on', n === i));

function check() {
  if (!engine) return;
  const text = msg.value.trim();
  const f = $('#lp-gauge-f');
  if (!text) {
    $('#lp-score').textContent = '0'; f.style.strokeDashoffset = '169.6'; f.style.stroke = STROKE.inconclusive;
    $('#lp-risk').className = 'risk inconclusive'; $('#lp-risk').textContent = 'Waiting';
    $('#lp-cat').textContent = 'Type or pick an example'; $('#lp-inds').innerHTML = ''; $('#lp-redact').textContent = '';
    return;
  }
  const r = engine.analyze(text, { ti: { status: 'not_configured' } });
  $('#lp-score').textContent = r.score;
  f.style.stroke = STROKE[r.risk_level];
  f.style.strokeDashoffset = String(169.6 * (1 - r.score / 100));
  $('#lp-risk').className = 'risk ' + r.risk_level;
  $('#lp-risk').textContent = LABEL[r.risk_level];
  $('#lp-cat').textContent = r.category_label;
  $('#lp-inds').innerHTML = r.indicators.slice(0, 3).map((i, n) => `<li style="animation-delay:${n * 60}ms"><b>+${i.weight}</b><span>${esc(i.label)}</span></li>`).join('')
    || '<li><b>·</b><span>No strong scam pattern found. Still verify payment requests through official apps.</span></li>';
  const n = r.redaction_counts.auth_code + r.redaction_counts.card + r.redaction_counts.password + r.redaction_counts.national_id;
  $('#lp-redact').textContent = n ? `${n} sensitive value${n > 1 ? 's' : ''} would be removed before sending` : '';
}
let debounce;
msg.addEventListener('input', () => { stopAuto(); markSample(-1); clearTimeout(debounce); debounce = setTimeout(check, 120); });
msg.addEventListener('focus', stopAuto);
function stopAuto() { auto = false; clearTimeout(typer); msg.classList.remove('typing'); }

function typeSample() {
  if (!auto) return;
  const [, text] = SAMPLES[autoIdx];
  markSample(autoIdx);
  msg.classList.add('typing');
  let k = 0;
  const tick = () => {
    if (!auto) return;
    k = Math.min(text.length, k + 3);
    msg.value = text.slice(0, k);
    if (k % 12 < 3 || k === text.length) check();
    if (k < text.length) typer = setTimeout(tick, 22);
    else { msg.classList.remove('typing'); typer = setTimeout(() => { autoIdx = (autoIdx + 1) % 4; typeSample(); }, 3600); }
  };
  tick();
}

fetch('engine/rules.json').then((r) => r.json()).then((rules) => {
  engine = createEngine(rules);
  if (REDUCED) { msg.value = SAMPLES[0][1]; markSample(0); check(); auto = false; }
  else typeSample();
}).catch(() => { $('#lp-cat').textContent = 'The checker could not load. Refresh to try again.'; });

// ------------------------------------------------------------ contact form -> feedback table (insert-only)
$('#lp-contact').addEventListener('submit', async (e) => {
  e.preventDefault();
  const st = $('#lp-c-status');
  const body = { name: $('#lp-c-name').value.trim() || null, email: $('#lp-c-email').value.trim() || null, kind: $('#lp-c-kind').value, message: $('#lp-c-msg').value.trim() };
  if (body.message.length < 5) { st.textContent = 'Write a short message first.'; return; }
  if (/\b\d{4,8}\b/.test(body.message) && /otp|pin|password|cvv/i.test(body.message)) { st.textContent = 'Please remove any codes or passwords from your message.'; return; }
  st.textContent = 'Sending…';
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/feedback`, {
      method: 'POST',
      headers: { apikey: SUPABASE_KEY, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await res.text());
    e.target.reset();
    st.textContent = 'Thanks. Your message was received.';
    toast('Message sent.');
  } catch {
    st.textContent = 'Could not send right now. Please try again later.';
  }
});
