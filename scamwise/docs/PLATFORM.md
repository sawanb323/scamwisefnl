# ScamWise subscription platform — admin panel, plans, devices and incidents

This document covers release 008. It adds a full admin console, subscription and trial enforcement, device and session tracking, an incident lifecycle, payments, organisations and a customer dashboard. Everything else in ScamWise stays as it was.

## 1. Architecture (what was already there, and what changed)

| Layer | Before | Now |
|---|---|---|
| Frontend | Static HTML/JS in `web/` (landing page, `app/` customer app, `admin/` console), hosted on Vercel | Same structure. `admin/` rebuilt with 11 sections. `app/` gained a **Dashboard** tab. |
| Backend | Supabase: Postgres + Auth + RLS + the `analyze` edge function | Same backend. **No new server was needed.** All new rules live in Postgres (migration 008) and the `analyze` function. |
| Auth | Supabase Auth with email + password. Admins need TOTP MFA (aal2). | Unchanged. Account suspension now also bans sign-in (`auth.users.banned_until`). |

Why there's no FastAPI or SQLite: the project already has a secure backend. Supabase provides managed authentication, persistent PostgreSQL, Row-Level Security and server functions. Every requirement that needs a backend is enforced there:

- centralised analytics
- persistent customer records
- quota enforcement
- cross-device sync
- admin RBAC

**What works on the frontend only:** layout, charts, filtering of data already fetched, and dialogs. **What needs the backend (and has it):** everything that decides access, counts usage or changes records.

## 2. Database schema (migration `supabase/migrations/20261029000008_platform.sql`)

New tables have RLS on and no client policies. They're reachable only through `SECURITY DEFINER` functions that re-check identity.

| Table | Purpose |
|---|---|
| `subscription_plans` | Plan catalogue: trial, Individual ₹299 (1 device), Family ₹699 (3), Business ₹1,899 (8), Enterprise custom (limit per contract) |
| `subscriptions` | One row per customer: plan, start and expiry, trial start and expiry, conversion, suspension, cancellation, enterprise limit and price |
| `subscription_events` | History: trial started, assigned, changed, renewed, converted, suspended, reactivated, cancelled, expired, trial reset |
| `usage_daily` | Per customer, per IST day: checks, trial checks, threats. This is the source of quota and lifetime statistics. |
| `payments` | Transactions. `verification` is `provider_verified` (service-role webhook only) or `manual_recorded` (admin). There are no card fields. |
| `plan_requests` | Upgrade and renewal requests from customers |
| `organizations`, `org_members` | Family, business and enterprise groups with a pooled device limit and owner/admin/member roles |
| `login_events` | Sign-in, sign-out, session revoked, device registered or unlinked, account suspended or reactivated |
| `incident_events` | Incident timeline: detected, user warned, alert sent, blocked, investigating, resolved, false positive, reopened, note |
| `app_settings` | Trial policy (7 days, 2 per day, 14 total), presence timeout (120 s), admin rate limit |

The existing tables were extended as follows:

- **`profiles`:** account status and suspension fields.
- **`devices`:** user agent, device type, browser, OS, network prefix (/24 or /48 only), session start time.
- **`incidents`:** verdict, severity, `is_threat`, session id, URL count, response status, alerts sent, `blocked_at`, `resolved_at`, `resolved_by_kind`. Statuses are now `no_threat`, `detected`, `blocked`, `investigating`, `resolved` and `false_positive`. Existing rows are migrated: open becomes detected (or no_threat), and acknowledged becomes investigating.

## 3. API (Postgres RPCs called with supabase-js)

**Customer (own data only):**

- `my_subscription()`, `my_dashboard()`, `my_org()` (owners and org admins only), `request_plan(plan, message)`
- `record_sign_out()`, `set_incident_status(id, status)`
- Existing calls are unchanged: `register_device` (now enforces plan limits), `heartbeat`, `revoke_device`, pairing.

**Admin (MFA + `admin_users` membership checked server-side; every write is rate-limited and audited):**

- **Read:** `admin_dashboard(from, to)`, `admin_timeseries(from, to, day|week|month)`, `admin_customers(search, plan, status, joined_from, joined_to, threat, sort, desc, limit, offset)`, `admin_customer(id)`, `admin_devices(...)`, `admin_incidents(...)`, `admin_incident(id)`, `admin_subscriptions(...)`, `admin_payments(...)`, `admin_orgs()`, `admin_notifications(...)`, `admin_audit(...)`, `admin_settings()`
- **Write:** `admin_set_subscription`, `admin_subscription_action(suspend|reactivate|cancel|uncancel)`, `admin_record_payment`, `admin_suspend_account`, `admin_reactivate_account`, `admin_revoke_session`, `admin_revoke_device`, `admin_set_incident_status` (resolution needs a note), `admin_incident_note`, `admin_handle_plan_request`, `admin_save_org`, `admin_set_org_member`, `admin_update_plan`, `admin_update_trial`

**Service role only (edge functions and webhooks):**

- `consume_check(user)`: the atomic quota check, called by `analyze`.
- `record_block(incident, detail)`: pending integration.
- `provider_record_payment(...)`: pending integration.

## 4. How the key rules are enforced

- **Trial:** `consume_check` locks the subscription row, reads `usage_daily` for the current IST day (from the server clock) and refuses with `trial_daily_limit`, `trial_total_limit` or `trial_expired`. The client sends no date, and customers cannot execute it or write the tables. Refreshing the page or changing the device clock has no effect; both are verified in a real browser.
- **Device limits:** `register_device` refuses `device_limit_reached:N` based on the plan, the enterprise contract limit or a pooled organisation limit.
- **Connected vs registered:** a device counts as "connected" only when it is active, has a valid auth session and sent a heartbeat in the last 120 s. Otherwise it shows as idle, signed out, session ended or unlinked. Device identity is a per-browser install ID bound to an authenticated session; it is not a fingerprint.
- **Detection, response and resolution are separate:** a scan inserts the incident and records "detected" and "user warned". An alert to other devices records "alert sent". "Blocked" can only be written by `record_block` (service role), and admins cannot set it. "Resolved" or "false positive" needs an authorised user or admin action, and an admin must write a note.
- **Honest about blocking:** the web app warns; it does not block navigation. The Blocked counter therefore stays at 0 until a blocking client (such as a browser extension with navigation control) calls `record_block`.
- **Honest about payments:** there is no payment gateway yet. Admin-entered payments are labelled "manual (unverified)", and revenue is reported as verified and manual separately.

## 5. Security controls

- Role-based access: separate `admin_users` table, MFA (aal2) required, and checks inside every function (not in the page).
- RLS on every table. The new tables have no client grants. Customers cannot change their own plan, usage or account status (tested).
- Admin writes are rate-limited (60 per minute per admin) and every one is in `audit_log`. Destructive UI actions need a confirmation dialog and a reason.
- Input validation: whitelisted sort columns and statuses, length checks, and card-number-like references refused.
- Data minimisation: no message text (unless the customer opts in to a masked excerpt), no OTPs, no passwords, no tokens, no card data, and only an IP prefix. Login history is kept 180 days and audit logs 365 days.
- Secrets: the browser holds only the publishable key. The service-role and URLhaus keys are edge-function secrets (see `supabase/.env.example`).
- CSRF: Supabase uses bearer tokens in headers, not cookies, so CSRF doesn't apply and there are no auth cookies to harden. Sign-in rate limits are Supabase Auth's.

## 6. Deploying to your Supabase project

1. **Database:** SQL Editor → run `supabase/migrations/20261028000006_web_app_fixes.sql`, then `20261028000007_email_accounts.sql`, then `20261029000008_platform.sql` (or run `supabase db push`). Existing customers start a 7-day trial at that moment.
2. **Edge function:** `supabase functions deploy analyze`. Optionally `supabase secrets set URLHAUS_AUTH_KEY=...`.
3. **Admin:** in the SQL Editor, `select public.grant_admin('you@example.com');`. Then open `/admin/` and enrol the authenticator app.
4. **Web:** push `web/` to GitHub. Vercel (root directory `scamwise/web`) redeploys.
5. **Auth URLs:** Authentication → URL Configuration → Site URL `https://scamwise.vercel.app`, Redirect URL `https://scamwise.vercel.app/**`.

## 7. Running locally

```bash
cd web && python3 -m http.server 8080      # app: http://localhost:8080/app/   admin: http://localhost:8080/admin/
```

Add `http://localhost:8080` to Supabase Auth → URL Configuration. The pages use the project in `web/assets/config.js`.

## 8. Tests

**Database acceptance tests** (any Postgres 15+; uses a Supabase stub for `auth.*`):

```bash
PGHOST=localhost PGUSER=postgres tests/db/run.sh
```

This runs migrations 001–007, then legacy data, then the 008 upgrade, then 97 checks. They cover acceptance tests 1–13 and 15 plus the upgrade path. Test 14 (persistence) was checked by restarting Postgres and comparing row counts.

**Browser end-to-end** (the real pages, with every call executed as real SQL under the caller's identity and RLS):

```bash
cd tests/e2e-local && npm install && ./setup.sh
PGDATABASE=scamwise_e2e WEB_DIR=$(pwd)/../../web node server.mjs &   # port 8790
node run.mjs                                                          # 38 checks, screenshots in ./shots
```

The harness emulates the `analyze` function with the same steps (device check, quota, analysis, store, alerts). `fake-supabase.mjs` is a test double used only by this harness; it is never served by the real site.

| # | Acceptance test | Result |
|---|---|---|
| 1 | Admin sees real aggregate statistics | ✅ DB + browser |
| 2 | Search a customer and open their dashboard | ✅ DB + browser |
| 3 | Customer on two devices shows both devices and sessions | ✅ DB + browser (Windows Chrome + Android) |
| 4 | Device activity and session status update accurately | ✅ connected → idle → signed out → revoked |
| 5 | Plan device limits (1 / 3 / 8 / contract) | ✅ DB, and trial refusal in browser |
| 6 | Trial: 2 per day, 14 total, 7 days | ✅ |
| 7 | No bypass by refresh or client clock | ✅ browser |
| 8 | Expired trial cannot scan | ✅ |
| 9 | Threat updates customer and global statistics | ✅ |
| 10 | Blocked, resolved and open counted separately | ✅ |
| 11 | Customers can't see other customers' data | ✅ RLS + RPC + browser |
| 12 | Unauthorised users can't use admin APIs | ✅ customer, aal1 admin, anon |
| 13 | Admin actions are audited | ✅ |
| 14 | Data survives restart | ✅ |
| 15 | Existing features still work | ✅ pairing, unlink, scans, history, settings |

## 9. Pending integrations (clearly marked in the UI)

- **Payment gateway** (Razorpay or Stripe): the webhook should call `provider_record_payment` and then `admin_set_subscription`-equivalent logic. Until then plans are assigned by admins after manual payment, and customers send upgrade requests from their dashboard.
- **URL blocking:** needs a browser extension with navigation control that calls `record_block`.
- **Background push** when every tab is closed: unchanged from the previous release.
