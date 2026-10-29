// Test double for @supabase/supabase-js used ONLY by the local E2E harness.
// Every call is forwarded to the harness, which runs it as real SQL under the caller's identity.
const KEY = 'fake-sb-identity';
const load = () => { try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { return null; } };
const save = (v) => (v ? localStorage.setItem(KEY, JSON.stringify(v)) : localStorage.removeItem(KEY));
async function api(body) {
  const r = await fetch('/__api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, id: load() }) });
  return r.json();
}
const session = (id) => (id ? { access_token: 'test', user: { id: id.uid, email: id.email, user_metadata: id.meta || {} } } : null);

class Query {
  constructor(table) { this.q = { table, kind: 'select', eq: [] }; this.single = false; }
  select() { return this; }
  eq(c, v) { this.q.eq.push([c, v]); return this; }
  order(c, o = {}) { this.q.order = [c, o.ascending !== false]; return this; }
  limit(n) { this.q.limit = n; return this; }
  update(values) { this.q.kind = 'update'; this.q.values = values; return this; }
  delete() { this.q.kind = 'delete'; return this; }
  maybeSingle() { this.single = true; return this; }
  then(ok, bad) {
    return api({ op: 'table', q: this.q }).then((r) => (r.error ? { data: null, error: r.error } : { data: this.single ? (r.data[0] ?? null) : r.data, error: null })).then(ok, bad);
  }
}
export function createClient() {
  const listeners = [];
  const emit = (evt) => listeners.forEach((cb) => { try { cb(evt, session(load())); } catch (e) { console.error(e); } });
  return {
    auth: {
      async getSession() {
        const id = load();
        if (id && !(await api({ op: 'session_alive' })).data) { save(null); return { data: { session: null } }; }
        return { data: { session: session(id) } };
      },
      onAuthStateChange(cb) { listeners.push(cb); return { data: { subscription: { unsubscribe() {} } } }; },
      async signInWithPassword({ email }) {
        const r = await fetch('/__api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op: 'login', email, ua: navigator.userAgent }) }).then((x) => x.json());
        if (r.error) return { data: null, error: r.error };
        save(r.data); emit('SIGNED_IN'); return { data: { session: session(r.data) }, error: null };
      },
      async signOut() { await api({ op: 'logout' }); save(null); emit('SIGNED_OUT'); return { error: null }; },
      async refreshSession() { return { data: { session: session(load()) }, error: null }; },
      async signUp() { return { error: { message: 'not supported in harness' } }; },
      async resetPasswordForEmail() { return { error: null }; },
      async updateUser() { return { error: null }; },
      mfa: {
        async getAuthenticatorAssuranceLevel() { return { data: { currentLevel: load()?.aal ?? 'aal1' } }; },
        async listFactors() { return { data: { totp: [{ id: 'f1', status: 'verified' }], all: [{ id: 'f1', status: 'verified' }] } }; },
        async challengeAndVerify({ code }) {
          if (!/^\d{6}$/.test(code)) return { error: { message: 'bad code' } };
          await api({ op: 'mfa' }); const id = load(); id.aal = 'aal2'; save(id); return { data: {}, error: null };
        },
        async enroll() { return { error: { message: 'n/a' } }; }, async unenroll() { return {}; },
      },
    },
    async rpc(name, params) { const r = await api({ op: 'rpc', name, params }); return r.error ? { data: null, error: r.error } : { data: r.data, error: null }; },
    from(table) { return new Query(table); },
    functions: {
      async invoke(name, { body }) {
        const r = await api({ op: 'invoke', name, body });
        if (r.error) return { data: null, error: { name: 'FunctionsFetchError', message: r.error.message } };
        if (r.status !== 200) return { data: null, error: { name: 'FunctionsHttpError', message: 'http ' + r.status, context: { status: r.status, json: async () => r.body } } };
        return { data: r.body, error: null };
      },
    },
    channel() { const ch = { on() { return ch; }, subscribe(cb) { setTimeout(() => cb && cb('SUBSCRIBED'), 10); return ch; } }; return ch; },
    removeChannel() { return Promise.resolve('ok'); },
  };
}
