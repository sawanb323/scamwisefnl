// node --test tests/engine.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createEngine } from '../shared/engine/analyzer.js';

const rules = JSON.parse(readFileSync(new URL('../shared/engine/rules.json', import.meta.url)));
const E = createEngine(rules);
const A = (t, o) => E.analyze(t, o);

// ---------------------------------------------------------------- scams => high
const HIGH = [
  'Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login',
  'Your HDFC netbanking is suspended. Share the OTP sent to your mobile to reactivate within 30 minutes.',
  'This is Mumbai Cyber Police. A parcel in your name has been seized with drugs. You are under digital arrest. Do not tell anyone. Pay Rs 49,000 clearance fee now.',
  'Congratulations! You have won Rs 25,00,000 in KBC lucky draw. Pay registration fee of Rs 5000 to claim your prize: bit.ly/kbc-claim',
  'Your electricity connection will be disconnected tonight at 9.30 pm as your previous month bill was not updated. Contact officer immediately and install AnyDesk.',
  'Part time job! Earn ₹5000 per day by liking YouTube videos. Pay refundable deposit of Rs 2000 to start. Telegram now',
  'Amazon refund pending. Download the refund app http://198.51.100.23/amazon-refund.apk and enter your UPI PIN to receive money',
];
for (const t of HIGH) test(`HIGH: ${t.slice(0, 60)}`, () => {
  const r = A(t);
  assert.equal(r.risk_level, 'high', JSON.stringify(r.indicators.map((i) => i.code)) + ' score=' + r.score);
});

// ---------------------------------------------------------------- ordinary => not high (test scenario 9)
const ORDINARY = [
  'Hey, are we still meeting for lunch at 1 tomorrow? I booked a table at the cafe.',
  'Happy birthday! Have a wonderful year ahead 🎉',
  'Meeting moved to 3pm, room 204. Bring the Q3 slides please.',
  'Your Swiggy order #4521 is out for delivery and will arrive in 20 minutes.',
  'Please send me the project report by Friday, thanks.',
  "Mom: Call me when you reach home. Dinner is at 8.",
  'The new office pin code is 560001, please update the courier address.',
];
for (const t of ORDINARY) test(`ORDINARY not high: ${t.slice(0, 50)}`, () => {
  const r = A(t);
  assert.notEqual(r.risk_level, 'high', JSON.stringify(r.indicators));
  assert.notEqual(r.risk_level, 'medium', JSON.stringify(r.indicators));
});

// ---------------------------------------------------------------- OTP redaction (scenario 8)
test('bank OTP is redacted, flagged, and at least medium', () => {
  const msg = '482913 is your OTP for txn of Rs 2,499.00 at AMAZON on HDFC Bank card XX4521. Valid for 10 mins. Do not share OTP with anyone.';
  const r = A(msg);
  assert.equal(r.contained_auth_code, true);
  assert.ok(!r.redacted_text.includes('482913'), r.redacted_text);
  assert.ok(r.redacted_text.includes('2,499.00'), 'amount must survive');
  assert.ok(r.redacted_text.includes('XX4521'), 'masked card suffix is not an OTP');
  assert.ok(['medium', 'high'].includes(r.risk_level));
  assert.ok(!JSON.stringify(r).includes('482913'), 'code must not appear anywhere in the result');
});
test('Google style G-code redacted', () => {
  const r = A('G-552871 is your Google verification code.');
  assert.ok(!r.redacted_text.includes('552871'));
  assert.equal(r.contained_auth_code, true);
});
test('OTP request + code = high', () => {
  const r = A('Your OTP is 7731. Sir please share the OTP with me for KYC verification, urgent');
  assert.equal(r.risk_level, 'high');
  assert.ok(!JSON.stringify(r).includes('7731'));
});
test('card numbers and passwords redacted', () => {
  const r = A('card 4111 1111 1111 1111 and password: Hunter2!');
  assert.ok(r.redacted_text.includes('[REDACTED-CARD]'));
  assert.ok(r.redacted_text.includes('[REDACTED-PASSWORD]'));
  assert.ok(!r.redacted_text.includes('Hunter2'));
});
test('postal pin code is not treated as an OTP', () => {
  const r = A('Deliver to pin code 560102 please');
  assert.equal(r.contained_auth_code, false);
});

// ---------------------------------------------------------------- URLs & TI honesty (scenario 10)
test('plain link with no TI => inconclusive, never "safe"', () => {
  const r = A('https://example.org/news/article');
  assert.equal(r.risk_level, 'inconclusive');
  assert.equal(r.ti_status, 'not_configured');
  assert.ok(r.caveats.some((c) => /NOT checked/.test(c)));
});
test('TI unavailable is reported as unavailable, not as no_match', () => {
  const r = A('check this www.some-random-site.com/page', { ti: { status: 'unavailable' } });
  assert.equal(r.ti_status, 'unavailable');
  assert.notEqual(r.risk_level, 'low');
});
test('TI no_match => low with caveat, not safe', () => {
  const r = A('https://example.org/', { ti: { status: 'no_match', matches: [] } });
  assert.equal(r.risk_level, 'low');
  assert.ok(r.caveats.some((c) => /does NOT mean it is safe/.test(c)));
});
test('TI match => high, known_threat', () => {
  const r = A('http://malware.example.test/x', { ti: { status: 'match', matches: [{ threat: 'malware_download', url_status: 'online', match_type: 'url' }] } });
  assert.equal(r.risk_level, 'high'); assert.equal(r.category, 'known_threat');
});
test('official domains are not flagged as brand impersonation', () => {
  const r = A('Login at https://www.onlinesbi.sbi/ or https://netbanking.hdfcbank.com/netbanking/');
  assert.ok(!r.indicators.some((i) => i.code === 'url_brand_mismatch'), JSON.stringify(r.indicators));
});
test('look-alike domain flagged', () => {
  const r = A('https://hdfcbank-secure-verify.top/login');
  assert.ok(r.indicators.some((i) => i.code === 'url_brand_mismatch'));
  assert.ok(r.urls[0].display.includes('[.]'), 'urls are defanged in output');
});
test('filenames and abbreviations are not URLs', () => {
  assert.equal(E.extractUrls('see report.pdf and notes.docx, e.g. tomorrow').length, 0);
});
test('very short input => inconclusive', () => {
  assert.equal(A('ok').risk_level, 'inconclusive');
});
test('every indicator has a label and explanation', () => {
  const r = A(HIGH[0]);
  for (const i of r.indicators) { assert.ok(i.label); assert.ok(i.advice); assert.ok(typeof i.weight === 'number'); }
});
test('storage mask removes numbers and defangs links', () => {
  const s = E.maskForStorage('call 9876543210 or mail a@b.com http://x.com');
  assert.ok(!s.includes('9876543210') && !s.includes('a@b.com') && s.includes('hxxp'));
});
test('code pre-redacted on the phone still counts as an auth-code event', () => {
  const r = A('[REDACTED-CODE] is your OTP for login. Do not share.');
  assert.equal(r.contained_auth_code, true);
  assert.ok(['medium', 'high'].includes(r.risk_level));
});
test('protective phrasing "do not share this OTP" is not a credential request', () => {
  const r = A('482913 is your OTP for login to HDFC NetBanking. Valid for 5 mins. Do not share this OTP with anyone.');
  assert.ok(!r.indicators.some((i) => i.code === 'credential_request'), JSON.stringify(r.indicators.map((i) => i.code)));
  assert.equal(r.category, 'auth_code_exposure');
  assert.equal(r.risk_level, 'medium');
});
test('a real credential request still matches even if negation appears elsewhere', () => {
  const r = A('Do not worry. Please share the OTP you received to verify your account.');
  assert.ok(r.indicators.some((i) => i.code === 'credential_request'));
});
test('phishing text with a link is categorised by the text, not just "suspicious link"', () => {
  const r = A('Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login');
  assert.equal(r.category, 'phishing');
});

// ---------------------------------------------------------------- Hindi/Hinglish scam cues
 test('Hinglish OTP request is detected', () => {
  const r = A('OTP mujhe bhejo, jaldi karo warna account band ho jayega');
  assert.ok(r.indicators.some((i) => i.code === 'hinglish_otp_request'));
  assert.ok(['medium', 'high'].includes(r.risk_level));
 });
 test('Hinglish urgency is detected without declaring an ordinary sentence high risk', () => {
  const r = A('Aapka bank account band ho jayega, abhi ke abhi KYC update karo');
  assert.ok(r.indicators.some((i) => i.code === 'hinglish_urgency'));
  assert.notEqual(r.risk_level, 'high');
 });
