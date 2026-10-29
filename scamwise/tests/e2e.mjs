// SCAMWISE live end-to-end test against the real Supabase backend.
// Simulates Phone A, Phone B (same account) and Phone C (a different account) using
// two email + password test accounts.
//
// Env: SCAMWISE_TEST_USERS="a@example.com:passwordA,b@example.com:passwordB"
//      two existing, email-confirmed accounts (create them in Supabase Auth > Users)
//      first account = devices A and B, second account = device C
import { createClient } from '@supabase/supabase-js';
import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const URL = process.env.SUPABASE_URL ?? 'https://qgmupbixiqkoyfjsdvrw.supabase.co';
const KEY = process.env.SUPABASE_KEY ?? 'sb_publishable_ZF_Q-SoJ61E6O9pODIcmrA_g5PbI31l';
const USERS = (process.env.SCAMWISE_TEST_USERS ?? '').split(',').map((p) => { const t = p.trim(); const k = t.indexOf(':'); return k > 0 ? [t.slice(0, k), t.slice(k + 1)] : []; }).filter((p) => p.length === 2);

const results = [];
const summary = process.env.GITHUB_STEP_SUMMARY;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function record(id, name, pass, detail = '') {
  results.push({ id, name, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id}  ${name}${detail ? '  — ' + detail : ''}`);
}
async function finish(code) {
  writeFileSync('e2e-report.json', JSON.stringify({ at: new Date().toISOString(), results }, null, 2));
  if (summary) {
    const { appendFileSync } = await import('node:fs');
    appendFileSync(summary, `## SCAMWISE live e2e\n\n| | Test | Detail |\n|---|---|---|\n` +
      results.map((r) => `| ${r.pass ? '✅' : '❌'} | ${r.id} ${r.name} | ${String(r.detail).replace(/\|/g, '/')} |`).join('\n') + '\n');
  }
  process.exit(code);
}

if (USERS.length < 2) {
  console.log('SKIPPED: SCAMWISE_TEST_USERS secret is not set (needs two "email:password" pairs).');
  if (summary) (await import('node:fs')).appendFileSync(summary, '## SCAMWISE live e2e\n\nSKIPPED: `SCAMWISE_TEST_USERS` secret not set.\n');
  process.exit(0);
}
const [[email1, pass1], [email2, pass2]] = USERS;

// claim_pairing_code returns {status:'rejected', error} for a wrong code (so the attempt is counted)
const refused = (r) => !!r.error || r.data?.status === 'rejected';
const why = (r) => r.error?.message ?? r.data?.error;

const newClient = () => createClient(URL, KEY, { auth: { persistSession: false, autoRefreshToken: false } });

async function signIn(client, email, password, label) {
  const { data, error } = await client.auth.signInWithPassword({ email, password });
  if (error) throw new Error(`${label} signInWithPassword: ${error.message}`);
  return data.session;
}
async function analyze(client, text) {
  const { data, error } = await client.functions.invoke('analyze', { body: { text, source: 'share' } });
  if (error) {
    let status = error.context?.status, body = null;
    try { body = await error.context.json(); } catch {}
    return { error: true, status, body };
  }
  return data;
}

// Stable install IDs per role so repeated CI runs reuse the same device rows.
const INSTALL = { A: '00000000-0000-4000-8000-00000000000a', B: '00000000-0000-4000-8000-00000000000b', C: '00000000-0000-4000-8000-00000000000c' };

try {
  // ------------------------------------------------------------------ email login
  const A = newClient(), B = newClient(), C = newClient(), W = newClient();
  const sA = await signIn(A, email1, pass1, 'A');
  record('AUTH-1', 'Device A signs in with email and password', !!sA?.access_token, `user ${sA.user.id.slice(0, 8)}`);

  const bad = await W.auth.signInWithPassword({ email: email2, password: pass2 + '-wrong' });
  record('AUTH-2', 'Wrong password is rejected', !!bad.error, bad.error?.message ?? 'accepted!');

  // ------------------------------------------------------------------ device registration
  let { data: devA, error: eA } = await A.rpc('register_device', { p_install_id: INSTALL.A, p_name: 'E2E Phone A', p_platform: 'CI', p_app_version: 'e2e' });
  if (eA) throw new Error('register A: ' + eA.message);
  if (devA.status !== 'active') {
    // account has another active device from a manual demo; record and continue only if A was approved before
    record('DEV-1', 'Phone A registered and active', false, `status=${devA.status} (another active device exists on this test account)`);
    await finish(1);
  }
  record('DEV-1', 'Phone A registered and active', true, `device ${devA.id.slice(0, 8)}`);

  await sleep(6000); // Auth enforces a short wait between codes for the same number
  await signIn(B, email1, pass1, 'B');
  let { data: devB, error: eB } = await B.rpc('register_device', { p_install_id: INSTALL.B, p_name: 'E2E Phone B', p_platform: 'CI', p_app_version: 'e2e' });
  if (eB) throw new Error('register B: ' + eB.message);
  if (devB.status === 'active') {            // left active by a failed previous run: reset it
    await A.rpc('revoke_device', { p_device: devB.id });
    await sleep(6000);
    await signIn(B, email1, pass1, 'B');
    ({ data: devB } = await B.rpc('register_device', { p_install_id: INSTALL.B, p_name: 'E2E Phone B', p_platform: 'CI', p_app_version: 'e2e' }));
  }
  record('DEV-2', 'Second phone on same account starts as PENDING (needs approval)', devB.status === 'pending', `status=${devB.status}`);

  const { data: bInc } = await B.from('incidents').select('id');
  const bScan = await analyze(B, 'test');
  record('DEV-3', 'Pending phone can read no incidents and cannot scan', (bInc ?? []).length === 0 && bScan.error && bScan.status === 403,
    `incidents=${(bInc ?? []).length}, scan=${bScan.status} ${bScan.body?.error ?? ''}`);

  await signIn(C, email2, pass2, 'C');
  const { data: devC } = await C.rpc('register_device', { p_install_id: INSTALL.C, p_name: 'E2E Other account', p_platform: 'CI', p_app_version: 'e2e' });
  record('DEV-4', 'Phone C on a different account registers independently', devC?.status === 'active', `status=${devC?.status}`);

  // ------------------------------------------------------------------ pairing (scenario 2)
  const { data: code } = await A.rpc('create_pairing_code');
  record('PAIR-1', 'Phone A creates a single-use pairing code', /^[A-Z0-9]{8}$/.test(code?.code ?? ''), `expires ${code?.expires_at}`);

  const cClaim = await C.rpc('claim_pairing_code', { p_code: code.code });
  record('PAIR-2', "Another account cannot use A's pairing code", refused(cClaim), why(cClaim));

  const wrong = await B.rpc('claim_pairing_code', { p_code: 'ZZZZ9999' });
  record('PAIR-3', 'Wrong code is rejected', refused(wrong), why(wrong));

  const ok = await B.rpc('claim_pairing_code', { p_code: code.code });
  record('PAIR-4', 'Phone B claims the correct code', !refused(ok), why(ok) ?? 'claimed');

  const again = await B.rpc('claim_pairing_code', { p_code: code.code });
  record('PAIR-5', 'Code cannot be reused', refused(again), why(again));

  const self = await B.rpc('respond_pairing', { p_pairing: code.id, p_approve: true });
  record('PAIR-6', 'Phone B cannot approve itself', !!self.error, self.error?.message);

  const { data: reqs } = await A.from('pairing_codes').select('*').eq('status', 'claimed');
  record('PAIR-7', 'Phone A sees the approval request', (reqs ?? []).some((r) => r.id === code.id), `${(reqs ?? []).length} request(s)`);

  const appr = await A.rpc('respond_pairing', { p_pairing: code.id, p_approve: true });
  const { data: bNow } = await B.rpc('my_device');
  record('PAIR-8', 'Explicit approval on A activates phone B', !appr.error && bNow?.status === 'active', `B status=${bNow?.status}`);

  // ------------------------------------------------------------------ realtime alert to B (scenarios 4-7)
  const received = [];
  let subscribed = false;
  const ch = B.channel('e2e-b').on('postgres_changes',
    { event: 'INSERT', schema: 'public', table: 'alerts', filter: `target_device_id=eq.${devB.id}` },
    (p) => received.push(p.new)).subscribe((s) => { if (s === 'SUBSCRIBED') subscribed = true; });
  await B.realtime.setAuth((await B.auth.getSession()).data.session.access_token);
  for (let i = 0; i < 20 && !subscribed; i++) await sleep(500);
  record('RT-1', 'Phone B realtime subscription established', subscribed);
  await sleep(1500);

  const phishing = 'Dear Customer, your SBI account will be blocked today. Update KYC immediately at http://sbi-kyc-update.xyz/login';
  const r1 = await analyze(A, phishing);
  record('SCAN-1', 'Shared phishing link analysed as HIGH on phone A', r1.result?.risk_level === 'high',
    `score=${r1.result?.score}, category=${r1.result?.category}, ti=${r1.threat_intel?.status}, alerts_sent=${r1.alerts_sent}`);
  record('SCAN-2', 'Server stores no raw text', r1.stored?.raw_text === false, JSON.stringify(r1.stored));

  for (let i = 0; i < 20 && !received.some((a) => a.incident_id === r1.incident_id); i++) await sleep(500);
  const got = received.find((a) => a.incident_id === r1.incident_id);
  record('RT-2', 'Phone B receives the high-risk alert in real time', !!got, got ? `"${got.title}"` : `received ${received.length}`);

  const { data: cSeesAlerts } = await C.from('alerts').select('id').eq('incident_id', r1.incident_id);
  const { data: cSeesInc } = await C.from('incidents').select('id').eq('id', r1.incident_id);
  record('ISO-1', "Other account cannot see account 1's incident or alert", (cSeesAlerts ?? []).length === 0 && (cSeesInc ?? []).length === 0);

  // ------------------------------------------------------------------ OTP redaction (scenario 8)
  const OTP = '482913';
  const r2 = await analyze(A, `${OTP} is your OTP for login to HDFC NetBanking. Valid for 5 mins. Do not share this OTP with anyone.`);
  const respStr = JSON.stringify(r2);
  record('OTP-R1', 'Message with an OTP is flagged as auth-code exposure', r2.result?.contained_auth_code === true, `risk=${r2.result?.risk_level}`);
  record('OTP-R2', 'The code appears nowhere in the server response', !respStr.includes(OTP));
  for (let i = 0; i < 20 && !received.some((a) => a.incident_id === r2.incident_id); i++) await sleep(500);
  const otpAlert = received.find((a) => a.incident_id === r2.incident_id);
  record('OTP-R3', 'Phone B gets "Potential authentication-code exposure" alert without the code',
    !!otpAlert && /authentication-code/i.test(otpAlert.title) && !JSON.stringify(otpAlert).includes(OTP), otpAlert?.title ?? 'no alert');
  const { data: stored } = await A.from('incidents').select('*').eq('id', r2.incident_id).single();
  record('OTP-R4', 'Stored incident contains no code and no message text', !!stored && !JSON.stringify(stored).includes(OTP) && stored.redacted_excerpt === null);

  // ------------------------------------------------------------------ ordinary message (scenario 9)
  const r3 = await analyze(A, 'Hey, are we still meeting for lunch at 1 tomorrow? I booked a table at the cafe.');
  record('SCAN-3', 'Ordinary message is not high risk', r3.result && r3.result.risk_level !== 'high', `risk=${r3.result?.risk_level}`);

  // ------------------------------------------------------------------ TI honesty (scenario 10)
  const r4 = await analyze(A, 'https://example.org/');
  const ti = r4.threat_intel?.status;
  const honest = ti === 'no_match' ? r4.result.caveats.some((c) => /NOT mean it is safe/.test(c))
    : ['not_configured', 'unavailable', 'error'].includes(ti) ? r4.result.risk_level === 'inconclusive' : ti === 'match';
  record('TI-1', 'Threat-intel status is reported honestly (never a fake "safe")', honest, `ti=${ti}, risk=${r4.result?.risk_level}`);

  // ------------------------------------------------------------------ admin protection (scenario 11)
  const adm = await A.rpc('admin_overview');
  const admInc = await C.rpc('admin_list_incidents', { p_limit: 5 });
  record('ADM-1', 'Ordinary users cannot call admin functions', !!adm.error && !!admInc.error, adm.error?.message);

  // ------------------------------------------------------------------ revoke (scenarios 3 and 12)
  const rev = await A.rpc('revoke_device', { p_device: devB.id });
  const { data: bAfterInc } = await B.from('incidents').select('id');
  const { data: bAfterAl } = await B.from('alerts').select('id');
  const bScan2 = await analyze(B, phishing);
  const refresh = await B.auth.refreshSession();
  const hb = await B.rpc('heartbeat');
  record('REV-1', 'After unlinking, phone B reads nothing, cannot scan, and its session cannot be refreshed',
    !rev.error && (bAfterInc ?? []).length === 0 && (bAfterAl ?? []).length === 0 && bScan2.error && !!refresh.error,
    `incidents=${(bAfterInc ?? []).length}, alerts=${(bAfterAl ?? []).length}, scan=${bScan2.status}, refresh=${refresh.error?.message ?? 'OK?!'}, heartbeat=${hb.data}`);

  const r5 = await analyze(A, phishing);
  await sleep(3000);
  record('REV-2', 'Revoked phone B receives no new alerts', r5.alerts_sent === 0 && !received.some((a) => a.incident_id === r5.incident_id), `alerts_sent=${r5.alerts_sent}`);
  B.removeChannel(ch);

  // ------------------------------------------------------------------ deletion
  const del = await A.from('incidents').delete().eq('id', r5.incident_id);
  const { data: gone } = await A.from('incidents').select('id').eq('id', r5.incident_id);
  record('DEL-1', 'User can delete an incident record', !del.error && (gone ?? []).length === 0);

  const hbA = await A.rpc('heartbeat');
  record('SYNC-1', 'Heartbeat reports phone A as active (last-seen updated)', hbA.data === 'active', `heartbeat=${hbA.data}`);

  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  await finish(failed.length ? 1 : 0);
} catch (e) {
  record('FATAL', 'Test run aborted', false, e.message);
  await finish(1);
}
