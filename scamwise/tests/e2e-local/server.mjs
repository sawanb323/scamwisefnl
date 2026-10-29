// Local E2E harness: serves the real ScamWise web/ folder and emulates the Supabase APIs the pages use,
// executing every call as REAL SQL against a local Postgres that has the real migrations applied.
// Customer calls run as role `authenticated` with request.uid/jwt set, so RLS + SECURITY DEFINER checks apply.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

const WEB = process.env.WEB_DIR;
const pool = new pg.Pool({ host: process.env.PGHOST, port: +process.env.PGPORT, user: 'postgres', database: process.env.PGDATABASE });
const { createEngine } = await import(path.join(WEB, 'engine/analyzer.js'));
const engine = createEngine(JSON.parse(fs.readFileSync(path.join(WEB, 'engine/rules.json'), 'utf8')));
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };

async function asIdentity(id, fn) {
  const c = await pool.connect();
  try {
    await c.query('begin');
    if (id?.uid) {
      await c.query('set local role authenticated');
      await c.query("select set_config('request.uid', $1, true), set_config('request.jwt', $2, true)",
        [id.uid, JSON.stringify({ session_id: id.sid, aal: id.aal || 'aal1' })]);
    } else await c.query('set local role anon');
    const r = await fn(c);
    await c.query('commit');
    return r;
  } catch (e) { await c.query('rollback').catch(() => {}); throw e; } finally { c.release(); }
}
const IDENT = /^[a-z_][a-z0-9_]*$/;
async function rpc(c, name, params = {}) {
  if (!IDENT.test(name)) throw new Error('bad function');
  const meta = (await c.query(`select p.proretset, t.typtype from pg_proc p join pg_type t on t.oid = p.prorettype
      join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = $1 limit 1`, [name])).rows[0];
  const keys = Object.keys(params).filter((k) => IDENT.test(k) && params[k] !== undefined);
  const args = keys.map((k, i) => `${k} => $${i + 1}`).join(', ');
  const vals = keys.map((k) => (params[k] !== null && typeof params[k] === 'object' ? JSON.stringify(params[k]) : params[k] === null ? null : String(params[k])));
  if (meta?.proretset) return (await c.query(`select * from public.${name}(${args})`, vals)).rows;
  if (meta?.typtype === 'c') return (await c.query(`select * from public.${name}(${args})`, vals)).rows[0] ?? null;
  return (await c.query(`select public.${name}(${args}) as r`, vals)).rows[0]?.r ?? null;
}
async function table(c, q) {
  if (!IDENT.test(q.table)) throw new Error('bad table');
  const where = [], vals = [];
  for (const [col, v] of q.eq || []) { if (!IDENT.test(col)) throw new Error('bad col'); vals.push(v); where.push(`${col} = $${vals.length}`); }
  const w = where.length ? ' where ' + where.join(' and ') : '';
  if (q.kind === 'delete') return (await c.query(`delete from public.${q.table}${w} returning *`, vals)).rows;
  if (q.kind === 'update') {
    const sets = Object.keys(q.values).map((k) => { if (!IDENT.test(k)) throw new Error('bad col'); vals.push(q.values[k]); return `${k} = $${vals.length}`; });
    return (await c.query(`update public.${q.table} set ${sets.join(', ')}${w} returning *`, vals)).rows;
  }
  let sql = `select * from public.${q.table}${w}`;
  if (q.order) { if (!IDENT.test(q.order[0])) throw new Error('bad col'); sql += ` order by ${q.order[0]} ${q.order[1] ? 'asc' : 'desc'}`; }
  if (q.limit) sql += ` limit ${Number(q.limit) | 0}`;
  return (await c.query(sql, vals)).rows;
}
// emulation of supabase/functions/analyze (same order: device check -> quota -> analyse -> store -> alerts)
async function analyze(id, body) {
  const device = await asIdentity(id, (c) => rpc(c, 'my_device'));
  if (!device?.id) return [403, { error: 'device_not_registered' }];
  if (device.status !== 'active') return [403, { error: 'device_not_active', status: device.status }];
  const text = String(body?.text ?? '');
  if (!text.trim()) return [400, { error: 'empty_text' }];
  const c = await pool.connect();
  try {
    const q = (await c.query('select public.consume_check($1) as r', [device.user_id])).rows[0].r;
    if (!q.allowed) return [402, { error: q.reason, ...q }];
    const urls = engine.extractUrls(engine.redact(text).text);
    const ti = urls.length ? { status: 'not_configured', matches: [], checked: 0 } : { status: 'not_applicable', matches: [], checked: 0 };
    const result = engine.analyze(text, { ti });
    const inc = (await c.query(`insert into public.incidents(user_id, device_id, device_name, source, risk_level, score, category, indicators, analysis_method, engine_version, ti_status, ti_detail, url_domains, contained_auth_code)
      values ($1,$2,$3,'web',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) returning id, created_at, verdict, severity, status, response_status`,
      [device.user_id, device.id, device.name, result.risk_level, result.score, result.category,
       JSON.stringify(result.indicators.map((i) => ({ code: i.code, label: i.label, weight: i.weight, family: i.family }))),
       `heuristic-rules v${result.engine_version}`, result.engine_version, ti.status, JSON.stringify(ti), result.domains, result.contained_auth_code])).rows[0];
    let alertsSent = 0;
    if (result.risk_level === 'high' || result.contained_auth_code) {
      const r = await c.query(`insert into public.alerts(user_id, incident_id, target_device_id, source_device_name, kind, title, body, risk_level)
        select $1, $2, d.id, $3, 'incident', 'New high-risk incident detected', 'scanned on ' || $3, $4 from public.devices d
        where d.user_id = $1 and d.status = 'active' and d.id <> $5`, [device.user_id, inc.id, device.name, result.risk_level, device.id]);
      alertsSent = r.rowCount;
    }
    await c.query('update public.devices set last_seen_at = now() where id = $1', [device.id]);
    return [200, { incident_id: inc.id, created_at: inc.created_at, alerts_sent: alertsSent, quota: q, threat_intel: { provider: 'URLhaus', ...ti },
      stored: { raw_text: false, redacted_excerpt: false, shared_with_admin: true, domains: result.domains },
      incident: { verdict: inc.verdict, severity: inc.severity, status: inc.status, response: alertsSent ? 'alert_sent' : inc.response_status, blocked: false }, result }];
  } finally { c.release(); }
}

const FAKE = fs.readFileSync(new URL('./fake-supabase.mjs', import.meta.url), 'utf8');
http.createServer(async (req, res) => {
  const send = (status, body, type = 'application/json') => { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/__fake/supabase.mjs') return send(200, FAKE, 'text/javascript');
    if (url.pathname === '/__fake/chart.js') return send(200, fs.readFileSync(new URL('./node_modules/chart.js/dist/chart.umd.js', import.meta.url)), 'text/javascript');
    if (url.pathname === '/__api') {
      let raw = ''; for await (const ch of req) raw += ch;
      const b = JSON.parse(raw || '{}');
      try {
        if (b.op === 'login') {
          const u = (await pool.query('select id, email, raw_user_meta_data from auth.users where lower(email) = lower($1)', [b.email])).rows[0];
          if (!u) return send(200, { error: { message: 'Invalid login credentials' } });
          if ((await pool.query('select banned_until from auth.users where id = $1', [u.id])).rows[0].banned_until) return send(200, { error: { message: 'User is banned' } });
          const sid = (await pool.query("insert into auth.sessions(user_id, user_agent, ip) values ($1, $2, '127.0.0.1') returning id", [u.id, b.ua])).rows[0].id;
          await pool.query('update auth.users set last_sign_in_at = now() where id = $1', [u.id]);
          return send(200, { data: { uid: u.id, sid, aal: 'aal1', email: u.email, meta: u.raw_user_meta_data } });
        }
        if (b.op === 'mfa') { await pool.query("update auth.sessions set aal = 'aal2' where id = $1", [b.id.sid]); return send(200, { data: { aal: 'aal2' } }); }
        if (b.op === 'session_alive') return send(200, { data: (await pool.query('select 1 from auth.sessions where id = $1', [b.id?.sid])).rowCount > 0 });
        if (b.op === 'logout') { await pool.query('delete from auth.sessions where id = $1', [b.id?.sid]); return send(200, { data: true }); }
        if (b.op === 'rpc') return send(200, { data: await asIdentity(b.id, (c) => rpc(c, b.name, b.params)) });
        if (b.op === 'table') return send(200, { data: await asIdentity(b.id, (c) => table(c, b.q)) });
        if (b.op === 'invoke') { const [status, body] = await analyze(b.id, b.body); return send(200, { status, body }); }
        return send(400, { error: { message: 'unknown op' } });
      } catch (e) { return send(200, { error: { message: e.message, code: e.code } }); }
    }
    let p = path.join(WEB, decodeURIComponent(url.pathname));
    if (!p.startsWith(WEB)) return send(403, 'no', 'text/plain');
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, 'index.html');
    if (!fs.existsSync(p)) return send(404, 'not found', 'text/plain');
    res.writeHead(200, { 'content-type': MIME[path.extname(p)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    fs.createReadStream(p).pipe(res);
  } catch (e) { send(500, { error: e.message }); }
}).listen(+process.env.PORT || 8790, () => console.log('e2e server on', process.env.PORT || 8790));
