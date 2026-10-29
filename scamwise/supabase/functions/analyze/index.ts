// SCAMWISE `analyze` edge function
// POST { text: string, source?: 'web'|'paste'|'share' }   Authorization: Bearer <user JWT>
//
// 1. Verifies the caller's device is ACTIVE (bound to this auth session) - via RLS-protected RPC.
// 2. Re-redacts secrets server-side (defence in depth; the app already redacts before upload).
// 3. Runs the shared heuristic engine + optional URLhaus lookup (never visits the link itself).
// 4. Stores a minimal incident (no raw text; domains + indicator codes; opt-in redacted excerpt).
// 5. Creates alerts for the account's OTHER active devices (realtime delivers them).
import { createClient } from 'npm:@supabase/supabase-js@2';
import { createEngine } from './analyzer.js';
import rules from './rules.json' with { type: 'json' };

const engine = createEngine(rules);
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const ANON_KEY = Deno.env.get('SUPABASE_ANON_KEY')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const URLHAUS_KEY = Deno.env.get('URLHAUS_AUTH_KEY') ?? '';
const MAX_PER_HOUR = 60;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-region, x-supabase-api-version',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

// Shared hosting platforms: a host-level URLhaus hit there says nothing about this specific link.
const SHARED_PLATFORMS = ['github.com', 'githubusercontent.com', 'google.com', 'googleusercontent.com', 'dropbox.com',
  'dropboxusercontent.com', 'discord.com', 'discordapp.com', 'onedrive.live.com', '1drv.ms', 'mediafire.com',
  'amazonaws.com', 'cloudfront.net', 'azureedge.net', 'blob.core.windows.net', 'pages.dev', 'workers.dev',
  'vercel.app', 'netlify.app', 'web.app', 'firebaseapp.com', 'gitlab.com', 'bitbucket.org', 'wa.me', 'whatsapp.com',
  't.me', 'telegram.org', 'bit.ly', 'tinyurl.com'];

type TiMatch = { url: string; host: string; threat?: string; url_status?: string; match_type: 'url' | 'host'; reference?: string };

async function urlhaus(endpoint: 'url' | 'host', key: string, value: string) {
  const res = await fetch(`https://urlhaus-api.abuse.ch/v1/${endpoint}/`, {
    method: 'POST',
    headers: { 'Auth-Key': URLHAUS_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ [key]: value }),
    signal: AbortSignal.timeout(5000),
  });
  if (res.status === 401 || res.status === 403) throw Object.assign(new Error('urlhaus_auth'), { kind: 'error' });
  if (!res.ok) throw Object.assign(new Error('urlhaus_http_' + res.status), { kind: 'unavailable' });
  return await res.json();
}

async function threatIntel(urls: ReturnType<typeof engine.extractUrls>) {
  if (urls.length === 0) return { status: 'not_applicable', matches: [], checked: 0 };
  if (!URLHAUS_KEY) return { status: 'not_configured', matches: [], checked: 0, provider: 'URLhaus' };
  const matches: TiMatch[] = [];
  let checked = 0, failed = 0, authError = false;
  for (const u of urls.slice(0, 3)) {
    const full = u.hasScheme ? u.raw.replace(/^hxxp/i, 'http') : 'http://' + u.raw;
    try {
      const r = await urlhaus('url', 'url', full);
      if (r.query_status === 'ok') {
        matches.push({ url: engine.defang(full), host: u.host, threat: r.threat, url_status: r.url_status, match_type: 'url', reference: r.urlhaus_reference });
      } else if (r.query_status === 'no_results') {
        const domain = engine.registrable(u.host);
        if (!SHARED_PLATFORMS.includes(domain) && !SHARED_PLATFORMS.includes(u.host)) {
          const h = await urlhaus('host', 'host', u.host);
          if (h.query_status === 'ok' && Number(h.url_count) > 0) {
            const online = (h.urls ?? []).find((x: any) => x.url_status === 'online');
            matches.push({ url: engine.defang(full), host: u.host, threat: (online ?? h.urls?.[0])?.threat ?? 'malware_download',
              url_status: online ? 'online' : 'offline', match_type: 'host', reference: h.urlhaus_reference });
          }
        }
      } else if (r.query_status !== 'invalid_url') {
        failed++; continue;
      }
      checked++;
    } catch (e: any) {
      failed++;
      if (e?.kind === 'error') authError = true;
    }
  }
  const status = matches.length > 0 ? 'match'
    : authError ? 'error'
    : failed > 0 ? 'unavailable'           // never report no_match unless every lookup succeeded
    : 'no_match';
  return { status, matches, checked, failed, provider: 'URLhaus', ...(authError ? { error: 'URLhaus rejected the API key' } : {}) };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  const authHeader = req.headers.get('Authorization') ?? '';
  if (!authHeader.startsWith('Bearer ')) return json({ error: 'not_authenticated' }, 401);

  // --- identity + device check, evaluated by Postgres with the caller's own JWT
  const userClient = createClient(SUPABASE_URL, ANON_KEY, { global: { headers: { Authorization: authHeader } } });
  const { data: device, error: devErr } = await userClient.rpc('my_device');
  if (devErr) return json({ error: 'not_authenticated', detail: devErr.message }, 401);
  if (!device?.id) return json({ error: 'device_not_registered' }, 403);
  if (device.status !== 'active') return json({ error: 'device_not_active', status: device.status }, 403);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: 'invalid_json' }, 400); }
  const text = typeof body?.text === 'string' ? body.text : '';
  if (text.trim().length === 0) return json({ error: 'empty_text' }, 400);
  if (text.length > 5000) return json({ error: 'text_too_long', max: 5000 }, 413);
  const source = ['share', 'paste', 'web'].includes(body?.source) ? body.source : 'web';

  const admin = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
  const uid = device.user_id as string;

  // --- rate limit
  const { count } = await admin.from('incidents').select('id', { count: 'exact', head: true })
    .eq('user_id', uid).gte('created_at', new Date(Date.now() - 3600_000).toISOString());
  if ((count ?? 0) >= MAX_PER_HOUR) return json({ error: 'rate_limited', retry_after_seconds: 600 }, 429);

  // --- subscription / trial quota (atomic check-and-count in Postgres)
  const { data: quota, error: qErr } = await admin.rpc('consume_check', { p_user: uid });
  if (qErr) return json({ error: 'quota_check_failed', detail: qErr.message }, 500);
  if (!quota?.allowed) return json({ error: quota?.reason ?? 'subscription_required', ...quota }, 402);

  // --- analyse (redaction happens first inside the engine; raw text is never stored or logged)
  const redacted = engine.redact(text);
  const ti = await threatIntel(engine.extractUrls(redacted.text));
  const result = engine.analyze(text, { ti });

  const { data: profile } = await admin.from('profiles').select('*').eq('id', uid).single();

  // store only what monitoring needs: indicator codes/labels; text-match snippets are dropped
  const storedIndicators = result.indicators.map((i: any) => ({
    code: i.code, label: i.label, weight: i.weight, family: i.family,
    ...(i.family === 'suspicious_link' || i.family === 'known_threat' ? { detail: i.detail } : {}),
  }));

  const { data: incident, error: insErr } = await admin.from('incidents').insert({
    user_id: uid,
    device_id: device.id,
    device_name: device.name,
    source,
    risk_level: result.risk_level,
    score: result.score,
    category: result.category,
    indicators: storedIndicators,
    analysis_method: `heuristic-rules v${result.engine_version}` + (ti.status === 'not_applicable' ? '' : ' + URLhaus lookup'),
    engine_version: result.engine_version,
    ti_status: ti.status,
    ti_detail: ti,
    url_domains: result.domains,
    contained_auth_code: result.contained_auth_code,
    redacted_excerpt: profile?.share_excerpt ? engine.maskForStorage(result.redacted_text) : null,
    shared_with_admin: profile?.share_with_admin ?? true,
  }).select('id, created_at, verdict, severity, status, response_status').single();
  if (insErr) return json({ error: 'store_failed', detail: insErr.message }, 500);

  // --- alerts for the account's other ACTIVE devices
  const riskWord = { high: 'High', medium: 'Medium', low: 'Low', inconclusive: 'Inconclusive' }[result.risk_level as string];
  let alert: { kind: string; title: string; body: string } | null = null;
  if (result.contained_auth_code) {
    alert = { kind: 'auth_code', title: 'Potential authentication-code exposure detected',
      body: `${riskWord} risk · scanned on "${device.name}". The code itself was redacted and never left that device.` };
  } else if (result.risk_level === 'high' && (profile?.notify_high ?? true)) {
    alert = { kind: 'incident', title: 'New high-risk incident detected',
      body: `${result.category_label} · score ${result.score}/100 · scanned on "${device.name}".` };
  } else if (result.risk_level === 'medium' && profile?.notify_medium) {
    alert = { kind: 'incident', title: 'Medium-risk message scanned',
      body: `${result.category_label} · score ${result.score}/100 · scanned on "${device.name}".` };
  }
  let alertsSent = 0;
  if (alert) {
    const { data: targets } = await admin.from('devices').select('id')
      .eq('user_id', uid).eq('status', 'active').neq('id', device.id);
    if (targets && targets.length) {
      const { error: aErr } = await admin.from('alerts').insert(targets.map((t: any) => ({
        user_id: uid, incident_id: incident.id, target_device_id: t.id, source_device_name: device.name,
        kind: alert!.kind, title: alert!.title, body: alert!.body, risk_level: result.risk_level,
      })));
      if (!aErr) alertsSent = targets.length;
    }
  }
  await admin.from('devices').update({ last_seen_at: new Date().toISOString() }).eq('id', device.id);

  return json({
    incident_id: incident.id,
    quota: { plan: quota.plan, remaining_today: quota.remaining_today ?? null, remaining_total: quota.remaining_total ?? null },
    created_at: incident.created_at,
    alerts_sent: alertsSent,
    // detection and response are recorded separately; the web app warns, it does not block navigation
    incident: { verdict: incident.verdict, severity: incident.severity, status: incident.status,
                response: alertsSent > 0 ? 'alert_sent' : incident.response_status, blocked: false },
    stored: {
      raw_text: false,
      redacted_excerpt: !!profile?.share_excerpt,
      shared_with_admin: profile?.share_with_admin ?? true,
      domains: result.domains,
    },
    threat_intel: { provider: 'URLhaus', status: ti.status, checked: ti.checked ?? 0, matches: ti.matches ?? [] },
    result,
  });
});
