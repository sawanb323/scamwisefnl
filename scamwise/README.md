# SCAMWISE — Detect. Understand. Act.


## Subscription platform & admin console (release 008)

Plans (Individual ₹299 · Family ₹699 · Business ₹1,899 · Enterprise custom), the 7-day limited trial, device/session tracking, the incident lifecycle, payments and the 11-section admin console are documented in **[docs/PLATFORM.md](docs/PLATFORM.md)** — schema, API, security model, deployment steps and test results.

A connected, privacy-conscious scam-detection prototype, delivered **entirely on the web**: a public website, a
signed-in **web application** that analyses messages and links the user pastes, alerts the user's other linked
devices in real time, and an MFA-protected admin dashboard. Built as an academic Digital Business Strategy project.

There is **no mobile app** any more. Every device (phone, tablet, laptop) uses the same web app in its browser.

| Part | Tech | Where |
|---|---|---|
| Website (landing page + quick checker) | Static HTML/JS | `web/index.html` |
| **Web application** (sign in, scan, history, alerts, devices, settings) | Static HTML/JS + supabase-js | `web/app/` |
| Admin dashboard | Static HTML/JS, email + password + TOTP | `web/admin/` |
| Backend | Supabase: Postgres + row-level security, Auth (email + password for users, email + TOTP MFA for admins), Realtime, Edge Functions (Deno), pg_cron | `supabase/` |
| Analysis engine | One rule set (`rules.json`) + JS engine used by the server, the web app and the quick checker | `shared/engine/` |
| CI | GitHub Actions: tests → GitHub Pages → live e2e | `.github/workflows/ci.yml` |

**Live backend:** Supabase project `scamwise` (`qgmupbixiqkoyfjsdvrw`, region ap-south-1 Mumbai).
**Website:** https://akankshjoshi.github.io/scamwise/ · **Web app:** `/app/` · **Admin:** `/admin/`

## What changed in 2.1
* **Email + password accounts replace SMS OTP**: sign in, sign up (with password strength meter), forgot / reset
  password via emailed link, and confirmation-email handling. Migration `20261028000007_email_accounts.sql` stores a
  masked email and display name on profiles and shows them in the admin views.
* **New landing page** (`web/index.html`) with a live checker that scores example scams as they are typed, section
  highlighting, mobile menu, and an "Open dashboard" button for visitors who are already signed in.
* **Redesigned sign-in / sign-up pages** with rotating, engine-scored examples on the brand panel.
* Inside the app the SCAMWISE logo returns to the Scan screen; it only leads to the landing page when signed out.

## What changed in 2.0 (web-only release)
* **Removed the Flutter/Android app** (`app/`) and the APK build/release CI job. The website's "Download APK" section,
  which could never activate without a successful Android build, is replaced by the web app.
* **New web app `web/app/`** with everything the phone app did: SMS-OTP sign-in, device registration, pairing with an
  8-character code or QR (`/app/#pair=CODE`), explicit approval, scanning with in-browser redaction, offline fallback
  and queue, history with status/delete, real-time alerts (+ browser notifications), device list with unlink,
  rename, privacy/retention settings, delete-all, sign out and unlink.
* **Bug fix – pairing brute-force limit never worked.** `claim_pairing_code()` recorded a failed attempt and then
  raised an exception, which rolled the attempt back, so the "5 wrong codes per 15 minutes" lockout could never trigger.
  Migration `20261028000006_web_app_fixes.sql` returns `{"status":"rejected","error":"invalid_or_expired_code"}`
  instead, so the attempt is committed. New SQL test T16 checks the lockout; e2e and SQL tests updated.
* Edge function accepts `source: 'web'` (already allowed by the table) and a wider CORS header list.
* Admin page pins `@supabase/supabase-js@2.45.4` instead of the floating `@2`.

## Why this stack
Supabase replaces Firebase from the brief because it could be created, migrated, deployed and tested end-to-end from
the build environment. It provides the same capabilities: managed email/password auth, a managed database with
server-side authorisation, realtime sync and server functions.

## Architecture & security model
```
 Browser A ──paste──▶ SCAMWISE web app ──(OTP redacted in browser)──▶ Edge Function `analyze` ──▶ URLhaus (optional)
                         │                                                  │
                         │◀───────────── risk result ───────────────────────┤
                         │                                         incidents / alerts (Postgres, RLS)
 Browser B ◀── Realtime alert (only active devices of same account) ◀──────┘
 Admin dashboard ── email+password+TOTP (aal2) ──▶ admin_* RPCs (membership + MFA checked in SQL, audited)
```
* **Device binding.** Each browser gets a random install id (localStorage). Its device row is bound to the auth
  session that registered it (`session_id` JWT claim). All reads go through RLS that requires an **active** device
  bound to the caller's current session.
* **Pairing.** First device on an account is active. Any further device is **pending** until an active device creates
  an 8-character code (10-minute expiry, single use, only its SHA-256 hash stored, 5 wrong tries per 15 min), the new
  device claims it, and the active device **explicitly approves**.
* **Revocation** sets the device to revoked **and deletes its auth session**, so its refresh token dies immediately and
  its still-valid access token no longer maps to an active device (RLS denies everything). The web app notices on the
  next heartbeat (30 s) or token refresh and signs out.
* **Admin** = row in `admin_users` **and** an MFA-verified (`aal2`) session. A phone number never grants admin.
* **Privacy.** OTPs, card numbers, passwords and Aadhaar-style numbers are redacted in the browser before upload and
  again on the server. Message text is never stored (opt-in 280-char masked excerpt only). Incidents expire after
  7/30/90 days (user choice) via a nightly `pg_cron` job.

## What is real vs simulated
| Item | Status |
|---|---|
| Database, RLS, pairing, revocation, admin MFA gating | **Real**; 16 SQL security tests (`tests/rls_pairing_test.sql`) |
| Analysis engine | **Real**; 33 Node tests in CI |
| `analyze` edge function | **Real** (redeploy for the `web` source label) |
| Email sign-in / sign-up / reset | **Real Supabase email auth.** Confirmation and reset emails use Supabase's mailer (rate-limited) or your SMTP. |
| URLhaus lookups | **Real code path**, returns `not_configured` until `URLHAUS_AUTH_KEY` is set. Never reported as "safe". |
| Alerts to linked devices | **Real** realtime delivery + in-page toast + browser notification while the web app is open in a tab. Not background push when every tab is closed (see Limitations). |


## SCAMWISE 2.2 local upgrade (MBA demo)

The current upgrade adds: explainable risk evidence (already shown by the shared analyzer), screenshot OCR in the browser, Hindi/Hinglish scam cues, an Insights tab, privacy-safe JSON incident export, and a Family Safety guidance hub that summarizes existing approved devices. URLhaus live reputation lookup already exists in the Edge Function and remains optional until `URLHAUS_AUTH_KEY` is configured.

A starter Chrome extension is included in `extension/`. It performs local heuristic analysis only; it has no host permissions, does not read page contents, does not use Supabase/URLhaus, and is not a replacement for the signed-in app. See `extension/README.md`.

**Prototype boundaries:** the report export is a user-downloaded metadata-only JSON file, not a community report submission service. Family Safety uses the existing same-account linked-device model; cross-account family sharing is not implemented. Screenshot OCR loads Tesseract.js from a CDN and processes the selected image locally; extracted text is then shown in the existing scanner, where normal redaction applies before server analysis.

## Setup

### 1. Supabase Auth – email sign-in (dashboard, ~2 min)
Authentication → Sign In / Providers:
1. **Email**: enabled (default). Keep **Confirm email** on for production; turn it off for a classroom demo so new
   accounts can sign in immediately.
2. **Phone**: disabled. SCAMWISE 2.1 no longer uses SMS one-time codes.
3. Authentication → URL Configuration: set **Site URL** to the web app (e.g. `https://<user>.github.io/scamwise/app/`)
   and add it under **Redirect URLs**, so confirmation and password-reset links return to the app.
4. Optional: configure custom SMTP (Project Settings → Auth) – Supabase's built-in mailer is rate-limited.

### 2. Admin account
1. Authentication → Users → **Add user** → email + strong password, *Auto-confirm*.
2. SQL editor: `select public.grant_admin('admin@example.com', 'faculty demo');`
3. Open `/admin/`, sign in, scan the QR with an authenticator app (TOTP enrolment is forced on first login).

### 3. Optional – URLhaus threat intelligence
Get a free Auth-Key at https://auth.abuse.ch/ and set it as Edge Function secret `URLHAUS_AUTH_KEY`
(Project Settings → Edge Functions → Secrets). No redeploy needed.

### 4. Apply the new migration and redeploy the function
* Run `supabase/migrations/20261028000006_web_app_fixes.sql` and `20261028000007_email_accounts.sql` in the SQL editor (or `supabase db push`).
* Redeploy the edge function so it accepts `source: 'web'`: `supabase functions deploy analyze`.
  (Until you redeploy, the old function still works; web scans are just recorded as `paste`.)
* Authentication → URL Configuration: add your site URL (e.g. `https://<user>.github.io/scamwise/`).

### 5. GitHub
* Settings → Pages → Source: **GitHub Actions** (the workflow tries to enable this automatically).
* Settings → Secrets → Actions → `SCAMWISE_TEST_USERS` = `email:password,email:password` for two confirmed test
  accounts (enables the live end-to-end test job).

## Run it locally
Any static file server works; the app talks directly to Supabase.
```bash
cd web && python3 -m http.server 8080      # then open http://localhost:8080/app/
```
Add `http://localhost:8080` to Supabase Auth → URL Configuration if you test sign-in locally.

## Demo with two devices
1. **Device A** (e.g. laptop): open the site → **Get started** → create an account (confirm the email if confirmation
   is on) → sign in. A becomes the first, active device.
2. **Device B** (e.g. a phone browser, or a second browser profile): open `/app/`, sign in to the **same account** →
   it shows *Link this device*.
3. **Device A:** Devices → **Add a device** → shows a code + QR. **Device B:** type the code (or scan the QR with the
   phone camera, which opens `/app/#pair=CODE` and pre-fills it) → *Request to link*.
4. **Device A:** tap **Approve** (in the dialog or on the Devices page). B switches to the main app automatically.
5. On B, paste a scam message (or tap a sample) → **Analyse**. A high-risk result raises an alert on A within seconds.
6. Open `/admin/` to see the incident, devices, last-seen times and audit log.

## Tests
```bash
node --test tests/engine.test.mjs            # engine rules (33 tests)
SCAMWISE_TEST_USERS=... node tests/e2e.mjs   # live backend: sign-in, pairing, realtime, redaction, isolation, revocation
# tests/rls_pairing_test.sql – paste into the SQL editor; self-rolls-back; prints the report as an error message
```

## Limitations (honest list)
* **Background push:** alerts arrive in real time while the web app is open in any tab (foreground or background) and
  are shown in the Alerts tab on next open. Push to a closed browser would need a service worker + Web Push (VAPID keys,
  store push subscriptions on `devices`, send from the `analyze` function).
* **Email delivery:** Supabase's built-in mailer is rate-limited; configure SMTP for real use.
* **No share-sheet integration:** users copy and paste text into the web app.
* **Each browser is a device:** clearing site data creates a new install id, so that browser must be linked again
  (old entries can be unlinked from Devices).
* **Detection:** transparent heuristics + URLhaus, not ML. Absence of findings is never reported as "safe".
* Pricing on the website is a proposal; no payments are processed.
* Same-account linking only (family accounts with separate logins are on the roadmap).
