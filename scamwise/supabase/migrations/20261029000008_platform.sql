-- =====================================================================================
-- SCAMWISE 008 — subscription platform, device/session tracking, incident lifecycle,
--                payments, organisations, admin analytics.
--
-- Design rules
--  * Every rule (trial quota, device limits, suspension, ownership, admin role) is enforced
--    in Postgres. The web pages only display what these functions return.
--  * New tables have RLS ON and NO client policies: clients reach them only through the
--    SECURITY DEFINER functions below, each of which re-checks identity.
--  * Day boundaries for quotas use Asia/Kolkata (IST) computed from the SERVER clock.
--  * Detection, warning, alerting, blocking and resolution are separate recorded events.
--  * A payment is "provider_verified" only when written by the service role (payment
--    webhook — pending integration). Admin-entered payments are "manual_recorded".
-- =====================================================================================

-- ------------------------------------------------------------------ settings
create table public.app_settings (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid
);
insert into public.app_settings(key, value) values
  ('trial',    '{"days": 7, "daily_checks": 2, "total_checks": 14}'),
  ('presence', '{"online_seconds": 120}'),
  ('admin_rate', '{"actions_per_minute": 60}');

create or replace function public._setting(p_key text, p_field text)
returns int language sql stable security definer set search_path = '' as $$
  select (value ->> p_field)::int from public.app_settings where key = p_key
$$;

create or replace function public._ist_today()
returns date language sql stable set search_path = '' as $$
  select (now() at time zone 'Asia/Kolkata')::date
$$;

-- ------------------------------------------------------------------ plan catalogue
create table public.subscription_plans (
  code           text primary key check (code ~ '^[a-z_]{2,30}$'),
  name           text not null,
  price_inr      int check (price_inr >= 0),           -- null = custom contract price
  billing_period text not null check (billing_period in ('trial', 'month', 'custom')),
  device_limit   int check (device_limit between 1 and 100000),  -- null = set per contract
  is_trial       boolean not null default false,
  active         boolean not null default true,
  sort           int not null default 0,
  features       jsonb not null default '[]'
);
insert into public.subscription_plans(code, name, price_inr, billing_period, device_limit, is_trial, sort, features) values
 ('trial', 'Free trial', 0, 'trial', 1, true, 0,
  '["7 days", "2 checks per day", "14 checks in total", "1 device"]'),
 ('individual', 'Individual', 299, 'month', 1, false, 1,
  '["Protection for 1 device", "Scam and suspicious-link detection", "Threat analysis and incident history", "Security notifications"]'),
 ('family', 'Family', 699, 'month', 3, false, 2,
  '["Protection for up to 3 devices", "Scam and suspicious-link detection", "Threat alerts and incident history", "Centralised subscription management"]'),
 ('business', 'Business', 1899, 'month', 8, false, 3,
  '["Protection for up to 8 devices", "Scam and suspicious-link detection", "Threat monitoring and incident history", "Security notifications and centralised administration"]'),
 ('enterprise', 'Enterprise & Banking', null, 'custom', null, false, 4,
  '["For large organisations and banks", "Device limit set by contract", "Customised deployment", "Centralised monitoring, reporting and admin controls"]');

-- ------------------------------------------------------------------ organisations
create table public.organizations (
  id           uuid primary key default gen_random_uuid(),
  name         text not null check (length(name) between 2 and 120),
  kind         text not null check (kind in ('family', 'business', 'enterprise')),
  device_limit int check (device_limit between 1 and 100000),   -- pooled across members
  contract_ref text check (length(contract_ref) <= 120),
  created_at   timestamptz not null default now(),
  created_by   uuid
);
create table public.org_members (
  org_id   uuid not null references public.organizations(id) on delete cascade,
  user_id  uuid not null unique references auth.users(id) on delete cascade,  -- one org per user
  role     text not null check (role in ('owner', 'admin', 'member')),
  added_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

-- ------------------------------------------------------------------ accounts & subscriptions
alter table public.profiles add column if not exists account_status text not null default 'active'
  check (account_status in ('active', 'suspended'));
alter table public.profiles add column if not exists suspended_at timestamptz;
alter table public.profiles add column if not exists suspended_reason text check (length(suspended_reason) <= 300);

create table public.subscriptions (
  user_id               uuid primary key references auth.users(id) on delete cascade,
  plan_code             text not null references public.subscription_plans(code),
  org_id                uuid references public.organizations(id) on delete set null,
  started_at            timestamptz not null default now(),
  expires_at            timestamptz not null,
  trial_started_at      timestamptz,
  trial_expires_at      timestamptz,
  converted_at          timestamptz,                 -- first move from trial to a paid plan
  suspended_at          timestamptz,
  suspend_reason        text check (length(suspend_reason) <= 300),
  cancelled_at          timestamptz,                 -- no renewal; access continues until expires_at
  cancel_reason         text check (length(cancel_reason) <= 300),
  device_limit_override int check (device_limit_override between 1 and 100000),
  custom_price_inr      int check (custom_price_inr >= 0),
  note                  text check (length(note) <= 300),
  updated_at            timestamptz not null default now()
);
create index subscriptions_plan_idx on public.subscriptions(plan_code, expires_at);
create index subscriptions_org_idx on public.subscriptions(org_id);

create table public.subscription_events (
  id           bigserial primary key,
  user_id      uuid not null references auth.users(id) on delete cascade,
  at           timestamptz not null default now(),
  event        text not null check (event in ('trial_started', 'plan_assigned', 'plan_changed', 'renewed', 'converted',
                                              'suspended', 'reactivated', 'cancelled', 'expired', 'limit_changed', 'trial_reset')),
  from_plan    text, to_plan text,
  from_expires timestamptz, to_expires timestamptz,
  actor_kind   text not null check (actor_kind in ('admin', 'user', 'system')),
  actor_id     uuid,
  note         text check (length(note) <= 300)
);
create index subscription_events_user_idx on public.subscription_events(user_id, at desc);
create index subscription_events_event_idx on public.subscription_events(event, at desc);

-- 'suspended' > 'expired' > 'trialing' > 'cancelled' (still usable until expiry) > 'active'
create or replace function public.sub_status(p_plan text, p_expires timestamptz, p_suspended timestamptz, p_cancelled timestamptz)
returns text language sql stable set search_path = '' as $$
  select case
    when p_suspended is not null then 'suspended'
    when p_expires <= now() then 'expired'
    when p_plan = 'trial' then 'trialing'
    when p_cancelled is not null then 'cancelled'
    else 'active' end
$$;

create table public.usage_daily (
  user_id      uuid not null references auth.users(id) on delete cascade,
  day          date not null,                 -- IST calendar day, from the server clock
  checks       int not null default 0,
  trial_checks int not null default 0,
  threats      int not null default 0,
  primary key (user_id, day)
);
create index usage_daily_day_idx on public.usage_daily(day);

create table public.payments (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references auth.users(id) on delete cascade,
  plan_code      text references public.subscription_plans(code),
  amount_inr     numeric(12, 2) not null check (amount_inr >= 0),
  currency       text not null default 'INR' check (currency = 'INR'),
  period_start   date,
  period_end     date,
  status         text not null check (status in ('pending', 'paid', 'failed', 'refunded', 'cancelled')),
  verification   text not null check (verification in ('provider_verified', 'manual_recorded')),
  provider       text not null default 'manual' check (provider in ('manual', 'razorpay', 'stripe', 'other')),
  provider_ref   text check (length(provider_ref) <= 120),      -- transaction / UTR / invoice no. — never card data
  method         text check (method in ('upi', 'card', 'netbanking', 'bank_transfer', 'cash', 'cheque', 'other')),
  failure_reason text check (length(failure_reason) <= 300),
  note           text check (length(note) <= 300),
  created_at     timestamptz not null default now(),
  recorded_by    uuid
);
create index payments_user_idx on public.payments(user_id, created_at desc);
create index payments_created_idx on public.payments(created_at desc);

create table public.plan_requests (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  plan_code  text not null references public.subscription_plans(code),
  message    text check (length(message) <= 500),
  status     text not null default 'open' check (status in ('open', 'contacted', 'done', 'declined')),
  created_at timestamptz not null default now(),
  handled_at timestamptz,
  handled_by uuid
);
create index plan_requests_status_idx on public.plan_requests(status, created_at desc);

-- ------------------------------------------------------------------ devices & sessions
alter table public.devices add column if not exists user_agent text check (length(user_agent) <= 400);
alter table public.devices add column if not exists device_type text check (device_type in ('desktop', 'mobile', 'tablet', 'unknown'));
alter table public.devices add column if not exists browser text check (length(browser) <= 40);
alter table public.devices add column if not exists os text check (length(os) <= 40);
alter table public.devices add column if not exists ip_prefix text check (length(ip_prefix) <= 50);   -- /24 (IPv4) or /48 (IPv6) only
alter table public.devices add column if not exists session_started_at timestamptz;

create table public.login_events (
  id          bigserial primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  device_id   uuid references public.devices(id) on delete set null,
  session_id  uuid,
  at          timestamptz not null default now(),
  kind        text not null check (kind in ('sign_in', 'sign_out', 'session_revoked', 'device_registered',
                                            'device_unlinked', 'account_suspended', 'account_reactivated')),
  user_agent  text check (length(user_agent) <= 400),
  ip_prefix   text check (length(ip_prefix) <= 50),
  actor_kind  text not null default 'user' check (actor_kind in ('admin', 'user', 'system')),
  note        text check (length(note) <= 300)
);
create index login_events_user_idx on public.login_events(user_id, at desc);

-- truncated network prefix only (data minimisation): 203.0.113.0/24, 2001:db8:1::/48
create or replace function public._ip_prefix(p inet)
returns text language sql immutable set search_path = '' as $$
  select case when p is null then null
              else text(network(set_masklen(p, case when family(p) = 4 then 24 else 48 end))) end
$$;

create or replace function public._parse_ua(ua text)
returns jsonb language sql immutable set search_path = '' as $$
  select jsonb_build_object(
    'device_type', case when ua is null then 'unknown'
                        when ua ~* 'ipad|tablet|(android(?!.*mobile))' then 'tablet'
                        when ua ~* 'mobi|iphone|android' then 'mobile'
                        when ua ~* 'windows|macintosh|x11|linux|cros' then 'desktop' else 'unknown' end,
    'os', case when ua ~* 'windows nt' then 'Windows' when ua ~* 'iphone|ipad|ios' then 'iOS'
               when ua ~* 'android' then 'Android' when ua ~* 'mac os x|macintosh' then 'macOS'
               when ua ~* 'cros' then 'ChromeOS' when ua ~* 'linux' then 'Linux' else null end,
    'browser', case when ua ~* 'edg/' then 'Edge' when ua ~* 'opr/|opera' then 'Opera'
                    when ua ~* 'samsungbrowser' then 'Samsung Internet' when ua ~* 'firefox|fxios' then 'Firefox'
                    when ua ~* 'chrome|crios' then 'Chrome' when ua ~* 'safari' then 'Safari' else null end)
$$;

-- ------------------------------------------------------------------ incident lifecycle
alter table public.incidents drop constraint if exists incidents_status_check;
alter table public.incidents add column if not exists verdict text check (verdict in ('safe', 'suspicious', 'malicious', 'inconclusive'));
alter table public.incidents add column if not exists severity text check (severity in ('none', 'low', 'medium', 'high', 'critical'));
alter table public.incidents add column if not exists is_threat boolean not null default false;
alter table public.incidents add column if not exists session_id uuid;
alter table public.incidents add column if not exists urls_count int not null default 0;
alter table public.incidents add column if not exists response_status text not null default 'none'
  check (response_status in ('none', 'user_warned', 'alert_sent', 'blocked'));
alter table public.incidents add column if not exists alerts_sent int not null default 0;
alter table public.incidents add column if not exists blocked_at timestamptz;
alter table public.incidents add column if not exists resolved_at timestamptz;
alter table public.incidents add column if not exists resolved_by_kind text check (resolved_by_kind in ('user', 'admin'));
alter table public.incidents add column if not exists status_updated_at timestamptz;

create table public.incident_events (
  id          bigserial primary key,
  incident_id uuid not null references public.incidents(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  at          timestamptz not null default now(),
  event       text not null check (event in ('detected', 'user_warned', 'alert_sent', 'blocked', 'investigating',
                                             'resolved', 'false_positive', 'reopened', 'note')),
  actor_kind  text not null check (actor_kind in ('system', 'user', 'admin')),
  actor_id    uuid,
  note        text check (length(note) <= 500)
);
create index incident_events_incident_idx on public.incident_events(incident_id, at);
create index incident_events_user_idx on public.incident_events(user_id, at desc);
create index incidents_created_idx on public.incidents(created_at desc);
create index incidents_threat_idx on public.incidents(is_threat, status, created_at desc);

create or replace function public._classify(p_risk text, p_score int, p_ti text)
returns jsonb language sql immutable set search_path = '' as $$
  select jsonb_build_object(
    'verdict', case when p_ti = 'match' then 'malicious'
                    when p_risk = 'high' and p_score >= 80 then 'malicious'
                    when p_risk in ('high', 'medium') then 'suspicious'
                    when p_risk = 'low' then 'safe' else 'inconclusive' end,
    'severity', case when p_ti = 'match' or (p_risk = 'high' and p_score >= 90) then 'critical'
                     when p_risk = 'high' then 'high' when p_risk = 'medium' then 'medium'
                     else 'none' end)
$$;

-- backfill existing scans (status map: open -> detected / no_threat, acknowledged -> investigating)
update public.incidents i set
  verdict = c ->> 'verdict', severity = c ->> 'severity',
  is_threat = (c ->> 'verdict') in ('suspicious', 'malicious'),
  urls_count = coalesce(cardinality(i.url_domains), 0),
  response_status = case when (c ->> 'verdict') in ('suspicious', 'malicious') then 'user_warned' else 'none' end,
  status = case when i.status = 'acknowledged' then 'investigating'
                when i.status in ('resolved', 'false_positive') then i.status
                when (c ->> 'verdict') in ('suspicious', 'malicious') then 'detected' else 'no_threat' end,
  resolved_at = case when i.status in ('resolved', 'false_positive') then i.created_at end
from (select id, public._classify(risk_level, score, ti_status) c from public.incidents) x
where x.id = i.id;
insert into public.incident_events(incident_id, user_id, at, event, actor_kind, note)
select id, user_id, created_at, 'detected', 'system', 'recorded before lifecycle tracking (backfill)'
  from public.incidents where is_threat;

alter table public.incidents alter column status set default 'detected';
alter table public.incidents add constraint incidents_status_check
  check (status in ('no_threat', 'detected', 'blocked', 'investigating', 'resolved', 'false_positive'));
alter table public.incidents alter column verdict set not null;
alter table public.incidents alter column severity set not null;

-- ------------------------------------------------------------------ incident triggers
create or replace function public._incident_before_insert()
returns trigger language plpgsql security definer set search_path = '' as $$
declare c jsonb := public._classify(new.risk_level, new.score, new.ti_status);
begin
  new.verdict    := c ->> 'verdict';
  new.severity   := c ->> 'severity';
  new.is_threat  := new.verdict in ('suspicious', 'malicious');
  new.urls_count := coalesce(cardinality(new.url_domains), 0);
  new.status     := case when new.is_threat then 'detected' else 'no_threat' end;
  -- the scan result (with its warning) is returned to the scanning user by the analyze function
  new.response_status := case when new.is_threat then 'user_warned' else 'none' end;
  new.alerts_sent := 0; new.blocked_at := null; new.resolved_at := null; new.resolved_by_kind := null;
  if new.device_id is not null then
    select d.session_id into new.session_id from public.devices d where d.id = new.device_id;
  end if;
  return new;
end $$;

create or replace function public._incident_after_insert()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.is_threat then
    insert into public.incident_events(incident_id, user_id, at, event, actor_kind, note) values
      (new.id, new.user_id, new.created_at, 'detected', 'system',
       format('%s · %s severity · score %s · %s', new.verdict, new.severity, new.score, new.analysis_method)),
      (new.id, new.user_id, new.created_at, 'user_warned', 'system', 'Warning shown to the user in the ScamWise scan result');
    insert into public.usage_daily(user_id, day, threats) values (new.user_id, public._ist_today(), 1)
      on conflict (user_id, day) do update set threats = public.usage_daily.threats + 1;
  end if;
  return null;
end $$;

drop trigger if exists incident_before_insert on public.incidents;
create trigger incident_before_insert before insert on public.incidents
  for each row execute function public._incident_before_insert();
drop trigger if exists incident_after_insert on public.incidents;
create trigger incident_after_insert after insert on public.incidents
  for each row execute function public._incident_after_insert();

-- an alert delivered to another device is a recorded automated response
create or replace function public._alert_after_insert()
returns trigger language plpgsql security definer set search_path = '' as $$
declare v_prev int;
begin
  if new.incident_id is null then return null; end if;
  update public.incidents set alerts_sent = alerts_sent + 1,
         response_status = case when response_status = 'blocked' then 'blocked' else 'alert_sent' end
   where id = new.incident_id
  returning alerts_sent - 1 into v_prev;
  if v_prev = 0 then
    insert into public.incident_events(incident_id, user_id, event, actor_kind, note)
    values (new.incident_id, new.user_id, 'alert_sent', 'system', 'Security notification delivered to the account''s other active devices');
  end if;
  return null;
end $$;
drop trigger if exists alert_after_insert on public.alerts;
create trigger alert_after_insert after insert on public.alerts
  for each row execute function public._alert_after_insert();

-- ------------------------------------------------------------------ provisioning
-- new account: profile + 7-day trial (no permanent free plan)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare v_days int := coalesce(public._setting('trial', 'days'), 7);
begin
  insert into public.profiles (id, phone_masked, email_masked, display_name)
  values (new.id, public.mask_phone(new.phone), public.mask_email(new.email),
          nullif(left(trim(coalesce(new.raw_user_meta_data ->> 'full_name', '')), 80), ''))
  on conflict (id) do nothing;
  insert into public.subscriptions(user_id, plan_code, started_at, expires_at, trial_started_at, trial_expires_at)
  values (new.id, 'trial', now(), now() + make_interval(days => v_days), now(), now() + make_interval(days => v_days))
  on conflict (user_id) do nothing;
  insert into public.subscription_events(user_id, event, to_plan, to_expires, actor_kind, note)
  values (new.id, 'trial_started', 'trial', now() + make_interval(days => v_days), 'system', 'account created');
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;

-- existing accounts: start their 7-day trial now
insert into public.subscriptions(user_id, plan_code, started_at, expires_at, trial_started_at, trial_expires_at)
select p.id, 'trial', now(), now() + interval '7 days', now(), now() + interval '7 days'
  from public.profiles p on conflict (user_id) do nothing;
insert into public.subscription_events(user_id, event, to_plan, to_expires, actor_kind, note)
select user_id, 'trial_started', 'trial', expires_at, 'system', 'trial started for existing account at platform launch'
  from public.subscriptions;
-- existing scans count towards lifetime usage statistics (not towards the new trial)
insert into public.usage_daily(user_id, day, checks, threats)
select user_id, (created_at at time zone 'Asia/Kolkata')::date, count(*), count(*) filter (where is_threat)
  from public.incidents group by 1, 2
on conflict (user_id, day) do update set checks = excluded.checks, threats = excluded.threats;

-- ------------------------------------------------------------------ limits
-- returns {limit, used, pooled}; pooled = organisation-wide limit across all members
create or replace function public._device_quota(p_user uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare s public.subscriptions; v_org public.organizations; v_limit int; v_used int;
begin
  select * into s from public.subscriptions where user_id = p_user;
  if s.org_id is not null then select * into v_org from public.organizations where id = s.org_id; end if;
  if v_org.id is not null and v_org.device_limit is not null then
    select count(*) into v_used from public.devices d
     where d.status <> 'revoked' and d.user_id in (select m.user_id from public.org_members m where m.org_id = v_org.id);
    return jsonb_build_object('limit', v_org.device_limit, 'used', v_used, 'pooled', true, 'org', v_org.name);
  end if;
  select coalesce(s.device_limit_override, p.device_limit, 1) into v_limit
    from public.subscription_plans p where p.code = coalesce(s.plan_code, 'trial');
  select count(*) into v_used from public.devices d where d.user_id = p_user and d.status <> 'revoked';
  return jsonb_build_object('limit', coalesce(v_limit, 1), 'used', v_used, 'pooled', false);
end $$;

-- Atomic check-and-count for one protected scan. Service role only (analyze edge function).
create or replace function public.consume_check(p_user uuid)
returns json language plpgsql security definer set search_path = '' as $$
declare
  s public.subscriptions;
  v_acct text;
  v_today date := public._ist_today();
  v_daily int := coalesce(public._setting('trial', 'daily_checks'), 2);
  v_total int := coalesce(public._setting('trial', 'total_checks'), 14);
  v_used_today int; v_used_total int; v_status text;
begin
  select account_status into v_acct from public.profiles where id = p_user;
  if v_acct is null then return json_build_object('allowed', false, 'reason', 'no_profile'); end if;
  if v_acct = 'suspended' then return json_build_object('allowed', false, 'reason', 'account_suspended'); end if;

  select * into s from public.subscriptions where user_id = p_user for update;   -- serialises concurrent scans
  if not found then return json_build_object('allowed', false, 'reason', 'subscription_required'); end if;
  v_status := public.sub_status(s.plan_code, s.expires_at, s.suspended_at, s.cancelled_at);
  if v_status = 'suspended' then return json_build_object('allowed', false, 'reason', 'subscription_suspended'); end if;
  if v_status = 'expired' then
    return json_build_object('allowed', false, 'reason', case when s.plan_code = 'trial' then 'trial_expired' else 'subscription_expired' end,
                             'expires_at', s.expires_at);
  end if;

  if s.plan_code = 'trial' then
    select coalesce(sum(trial_checks), 0) into v_used_total from public.usage_daily where user_id = p_user;
    select coalesce(trial_checks, 0) into v_used_today from public.usage_daily where user_id = p_user and day = v_today;
    v_used_today := coalesce(v_used_today, 0);
    if v_used_total >= v_total then
      return json_build_object('allowed', false, 'reason', 'trial_total_limit', 'used_total', v_used_total, 'limit_total', v_total);
    end if;
    if v_used_today >= v_daily then
      return json_build_object('allowed', false, 'reason', 'trial_daily_limit', 'used_today', v_used_today, 'limit_daily', v_daily);
    end if;
  end if;

  insert into public.usage_daily(user_id, day, checks, trial_checks)
  values (p_user, v_today, 1, case when s.plan_code = 'trial' then 1 else 0 end)
  on conflict (user_id, day) do update set
    checks = public.usage_daily.checks + 1,
    trial_checks = public.usage_daily.trial_checks + case when s.plan_code = 'trial' then 1 else 0 end;

  return json_build_object('allowed', true, 'plan', s.plan_code,
    'remaining_today', case when s.plan_code = 'trial' then v_daily - v_used_today - 1 end,
    'remaining_total', case when s.plan_code = 'trial' then v_total - v_used_total - 1 end);
end $$;

-- ------------------------------------------------------------------ device registration (plan limits + session capture)
create or replace function public.register_device(
  p_install_id uuid, p_name text, p_platform text default null, p_app_version text default null)
returns public.devices language plpgsql security definer set search_path = '' as $$
declare
  v_uid  uuid := auth.uid();
  v_sid  uuid := public.jwt_session_id();
  v_dev  public.devices;
  v_active_count int;
  v_quota jsonb;
  v_ua text; v_ip inet; v_parsed jsonb; v_new_session boolean;
begin
  if v_uid is null or v_sid is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;
  if exists (select 1 from public.admin_users where user_id = v_uid) then
    raise exception 'admin_accounts_cannot_register_devices' using errcode = '42501';
  end if;
  if (select account_status from public.profiles where id = v_uid) = 'suspended' then
    raise exception 'account_suspended' using errcode = '42501';
  end if;

  select s.user_agent, s.ip into v_ua, v_ip from auth.sessions s where s.id = v_sid;
  v_parsed := public._parse_ua(v_ua);

  update public.devices set session_id = null
   where session_id = v_sid and not (user_id = v_uid and install_id = p_install_id);

  select * into v_dev from public.devices where user_id = v_uid and install_id = p_install_id for update;
  select count(*) into v_active_count from public.devices where user_id = v_uid and status = 'active';
  v_quota := public._device_quota(v_uid);

  if v_dev.id is not null then
    if v_dev.status = 'revoked' and (v_quota ->> 'used')::int >= (v_quota ->> 'limit')::int then
      raise exception 'device_limit_reached:%', v_quota ->> 'limit' using errcode = 'P0001';
    end if;
    v_new_session := v_dev.session_id is distinct from v_sid;
    update public.devices set
      session_id   = v_sid,
      session_started_at = case when v_new_session then now() else session_started_at end,
      name         = coalesce(nullif(trim(p_name), ''), name),
      platform     = coalesce(p_platform, platform),
      app_version  = coalesce(p_app_version, app_version),
      user_agent   = coalesce(left(v_ua, 400), user_agent),
      device_type  = coalesce(v_parsed ->> 'device_type', device_type),
      browser      = coalesce(v_parsed ->> 'browser', browser),
      os           = coalesce(v_parsed ->> 'os', os),
      ip_prefix    = coalesce(public._ip_prefix(v_ip), ip_prefix),
      last_seen_at = now(),
      status       = case when status = 'revoked'
                          then (case when v_active_count = 0 then 'active' else 'pending' end)::public.device_status
                          else status end,
      revoked_at   = case when status = 'revoked' then null else revoked_at end,
      approved_at  = case when status = 'revoked' and v_active_count = 0 then now() else approved_at end
    where id = v_dev.id
    returning * into v_dev;
  else
    if (v_quota ->> 'used')::int >= (v_quota ->> 'limit')::int then
      raise exception 'device_limit_reached:%', v_quota ->> 'limit' using errcode = 'P0001';
    end if;
    v_new_session := true;
    insert into public.devices (user_id, install_id, session_id, session_started_at, name, platform, app_version,
                                user_agent, device_type, browser, os, ip_prefix,
                                status, is_primary, approved_at, last_seen_at)
    values (v_uid, p_install_id, v_sid, now(), coalesce(nullif(trim(p_name), ''), 'Web browser'), p_platform, p_app_version,
            left(v_ua, 400), v_parsed ->> 'device_type', v_parsed ->> 'browser', v_parsed ->> 'os', public._ip_prefix(v_ip),
            case when v_active_count = 0 then 'active' else 'pending' end::public.device_status,
            v_active_count = 0, case when v_active_count = 0 then now() end, now())
    returning * into v_dev;
    insert into public.login_events(user_id, device_id, session_id, kind, user_agent, ip_prefix)
    values (v_uid, v_dev.id, v_sid, 'device_registered', left(v_ua, 400), public._ip_prefix(v_ip));
  end if;

  if v_new_session then
    insert into public.login_events(user_id, device_id, session_id, kind, user_agent, ip_prefix)
    values (v_uid, v_dev.id, v_sid, 'sign_in', left(v_ua, 400), public._ip_prefix(v_ip));
  end if;
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (v_uid, 'user', 'device.register', 'device', v_dev.id::text, jsonb_build_object('status', v_dev.status));
  return v_dev;
end $$;

-- the app calls this just before signing out, so the disconnection is recorded
create or replace function public.record_sign_out()
returns void language plpgsql security definer set search_path = '' as $$
declare v_dev uuid;
begin
  if auth.uid() is null then return; end if;
  select id into v_dev from public.devices where user_id = auth.uid() and session_id = public.jwt_session_id();
  insert into public.login_events(user_id, device_id, session_id, kind)
  values (auth.uid(), v_dev, public.jwt_session_id(), 'sign_out');
  update public.devices set session_id = null, last_session_id = session_id where id = v_dev;
end $$;

-- unlinking also logs a connection event
create or replace function public._revoke_device(p_device uuid, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_old_sid uuid; v_uid uuid;
begin
  select session_id, user_id into v_old_sid, v_uid from public.devices where id = p_device for update;
  update public.devices
     set status = 'revoked', revoked_at = now(), revoked_reason = left(p_reason, 200),
         session_id = null, last_session_id = coalesce(v_old_sid, last_session_id)
   where id = p_device;
  if v_old_sid is not null then
    delete from auth.sessions where id = v_old_sid;
  end if;
  delete from public.alerts where target_device_id = p_device and read_at is null;
  insert into public.login_events(user_id, device_id, session_id, kind, actor_kind, note)
  values (v_uid, p_device, v_old_sid, 'device_unlinked',
          case when p_reason like 'admin%' then 'admin' else 'user' end, left(p_reason, 300));
end $$;

-- ------------------------------------------------------------------ incident status (shared core)
create or replace function public._set_incident_status(p_incident uuid, p_status text, p_actor_kind text, p_actor uuid, p_note text)
returns void language plpgsql security definer set search_path = '' as $$
declare i public.incidents; v_event text;
begin
  if p_status not in ('detected', 'investigating', 'resolved', 'false_positive') then
    raise exception 'bad_status' using errcode = '22023';    -- 'blocked' is only set by record_block()
  end if;
  select * into i from public.incidents where id = p_incident for update;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  if i.status = p_status then return; end if;
  v_event := case p_status when 'detected' then 'reopened' else p_status end;
  if p_status = 'detected' and i.status = 'no_threat' then raise exception 'bad_status' using errcode = '22023'; end if;
  update public.incidents set
    status = p_status,
    is_threat = case when p_status in ('investigating', 'resolved') then true
                     when p_status = 'false_positive' then false else is_threat end,
    resolved_at = case when p_status in ('resolved', 'false_positive') then now() else null end,
    resolved_by_kind = case when p_status in ('resolved', 'false_positive') then p_actor_kind else null end,
    status_updated_at = now()
  where id = p_incident;
  insert into public.incident_events(incident_id, user_id, event, actor_kind, actor_id, note)
  values (p_incident, i.user_id, v_event, p_actor_kind, p_actor, left(p_note, 500));
end $$;

-- account owner (from an active device) manages their own incidents
create or replace function public.set_incident_status(p_incident uuid, p_status text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if public.current_device_id() is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  if not exists (select 1 from public.incidents where id = p_incident and user_id = auth.uid()) then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  perform public._set_incident_status(p_incident, p_status, 'user', auth.uid(), 'set by account owner');
end $$;

-- a real block (e.g. a browser extension that refused navigation) — service role only.
-- The web app cannot block navigation, so it never calls this. Pending integration.
create or replace function public.record_block(p_incident uuid, p_detail text)
returns void language plpgsql security definer set search_path = '' as $$
declare i public.incidents;
begin
  select * into i from public.incidents where id = p_incident for update;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  update public.incidents set blocked_at = coalesce(blocked_at, now()), response_status = 'blocked',
         status = case when status in ('detected', 'investigating') then 'blocked' else status end, status_updated_at = now()
   where id = p_incident;
  insert into public.incident_events(incident_id, user_id, event, actor_kind, note)
  values (p_incident, i.user_id, 'blocked', 'system', left(p_detail, 500));
end $$;

-- ================================================================== customer-facing (own data only)
create or replace function public._require_active_device()
returns void language plpgsql stable security definer set search_path = '' as $$
begin
  if auth.uid() is null or public.current_device_id() is null then
    raise exception 'device_not_active' using errcode = '42501';
  end if;
end $$;

-- incident counters for one account (or null = everyone, for admins)
create or replace function public._threat_stats(p_user uuid, p_from timestamptz, p_to timestamptz)
returns jsonb language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'scans',          count(*),
    'urls_checked',   coalesce(sum(urls_count), 0),
    'urls_safe',      coalesce(sum(urls_count) filter (where verdict = 'safe'), 0),
    'urls_suspicious',coalesce(sum(urls_count) filter (where verdict = 'suspicious'), 0),
    'urls_malicious', coalesce(sum(urls_count) filter (where verdict = 'malicious'), 0),
    'urls_inconclusive', coalesce(sum(urls_count) filter (where verdict = 'inconclusive'), 0),
    'threats_detected', count(*) filter (where verdict in ('suspicious', 'malicious') or status in ('investigating', 'resolved', 'blocked')),
    'blocked',        count(*) filter (where blocked_at is not null),
    'resolved',       count(*) filter (where status = 'resolved'),
    'false_positive', count(*) filter (where status = 'false_positive'),
    'investigating',  count(*) filter (where status = 'investigating'),
    'open',           count(*) filter (where status in ('detected', 'blocked', 'investigating')),
    'alerted',        count(*) filter (where alerts_sent > 0),
    'severity', jsonb_build_object(
        'critical', count(*) filter (where severity = 'critical' and verdict <> 'safe'),
        'high',     count(*) filter (where severity = 'high'),
        'medium',   count(*) filter (where severity = 'medium'),
        'low',      count(*) filter (where severity = 'low')),
    'last_activity',  max(created_at))
  from public.incidents
  where (p_user is null or user_id = p_user)
    and created_at >= coalesce(p_from, '-infinity') and created_at < coalesce(p_to, 'infinity')
$$;

create or replace function public._subscription_json(p_user uuid)
returns jsonb language sql stable security definer set search_path = '' as $$
  select jsonb_build_object(
    'plan', s.plan_code, 'plan_name', p.name,
    'status', public.sub_status(s.plan_code, s.expires_at, s.suspended_at, s.cancelled_at),
    'started_at', s.started_at, 'expires_at', s.expires_at,
    'days_left', greatest(0, ceil(extract(epoch from (s.expires_at - now())) / 86400))::int,
    'trial_started_at', s.trial_started_at, 'trial_expires_at', s.trial_expires_at, 'converted_at', s.converted_at,
    'suspended_at', s.suspended_at, 'suspend_reason', s.suspend_reason,
    'cancelled_at', s.cancelled_at, 'cancel_reason', s.cancel_reason,
    'price_inr', case when s.plan_code = 'enterprise' then s.custom_price_inr else p.price_inr end,
    'billing_period', p.billing_period,
    'device_limit_override', s.device_limit_override, 'custom_price_inr', s.custom_price_inr, 'note', s.note,
    'devices', public._device_quota(s.user_id),
    'org', (select jsonb_build_object('id', o.id, 'name', o.name, 'kind', o.kind, 'role', m.role, 'device_limit', o.device_limit)
              from public.org_members m join public.organizations o on o.id = m.org_id where m.user_id = s.user_id),
    'trial', jsonb_build_object(
      'daily_limit', public._setting('trial', 'daily_checks'), 'total_limit', public._setting('trial', 'total_checks'),
      'used_today', coalesce((select trial_checks from public.usage_daily u where u.user_id = s.user_id and u.day = public._ist_today()), 0),
      'used_total', coalesce((select sum(trial_checks) from public.usage_daily u where u.user_id = s.user_id), 0)))
  from public.subscriptions s join public.subscription_plans p on p.code = s.plan_code
  where s.user_id = p_user
$$;

create or replace function public.my_subscription()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  if auth.uid() is null then raise exception 'not_authenticated' using errcode = '42501'; end if;
  return public._subscription_json(auth.uid());   -- allowed for pending devices too: shows why they wait
end $$;

create or replace function public.my_dashboard()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_uid uuid := auth.uid();
begin
  perform public._require_active_device();
  return jsonb_build_object(
    'subscription', public._subscription_json(v_uid),
    'stats', public._threat_stats(v_uid, null, null),
    'checks_lifetime', (select coalesce(sum(checks), 0) from public.usage_daily where user_id = v_uid),
    'online_seconds', public._setting('presence', 'online_seconds'),
    'recent_incidents', (select coalesce(jsonb_agg(x order by x.created_at desc), '[]') from (
        select id, created_at, verdict, severity, status, category, score, device_name, url_domains, response_status, blocked_at
          from public.incidents where user_id = v_uid and is_threat order by created_at desc limit 10) x),
    'activity', (select coalesce(jsonb_agg(a order by a.at desc), '[]') from (
        (select at, 'session' as type, kind as event, coalesce(d.name, '') as subject, e.note
           from public.login_events e left join public.devices d on d.id = e.device_id
          where e.user_id = v_uid order by at desc limit 15)
        union all
        (select at, 'subscription', event, coalesce(to_plan, ''), note
           from public.subscription_events where user_id = v_uid order by at desc limit 10)
        union all
        (select ie.at, 'incident', ie.event, coalesce(i.category, ''), ie.note
           from public.incident_events ie join public.incidents i on i.id = ie.incident_id
          where ie.user_id = v_uid order by ie.at desc limit 15)
        order by at desc limit 25) a),
    'unread_alerts', (select count(*) from public.alerts where target_device_id = public.current_device_id() and read_at is null),
    'plans', (select jsonb_agg(jsonb_build_object('code', code, 'name', name, 'price_inr', price_inr,
                       'device_limit', device_limit, 'features', features) order by sort)
                from public.subscription_plans where active and not is_trial),
    'open_request', (select jsonb_build_object('plan', plan_code, 'created_at', created_at, 'status', status)
                       from public.plan_requests where user_id = v_uid and status in ('open', 'contacted')
                      order by created_at desc limit 1),
    'payments', (select coalesce(jsonb_agg(jsonb_build_object('created_at', created_at, 'amount_inr', amount_inr, 'status', status,
                         'verification', verification, 'plan', plan_code, 'period_start', period_start, 'period_end', period_end)
                         order by created_at desc), '[]')
                   from (select * from public.payments where user_id = v_uid order by created_at desc limit 12) p));
end $$;

-- the customer asks for an upgrade / renewal (no online payment yet: staff follow up)
create or replace function public.request_plan(p_plan text, p_message text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'not_authenticated' using errcode = '42501'; end if;
  if not exists (select 1 from public.subscription_plans where code = p_plan and active and not is_trial) then
    raise exception 'invalid_plan' using errcode = '22023';
  end if;
  if (select count(*) from public.plan_requests where user_id = auth.uid() and created_at > now() - interval '1 day') >= 3 then
    raise exception 'too_many_requests' using errcode = 'P0001';
  end if;
  insert into public.plan_requests(user_id, plan_code, message) values (auth.uid(), p_plan, left(p_message, 500))
  returning id into v_id;
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'user', 'subscription.request', 'plan_request', v_id::text, jsonb_build_object('plan', p_plan));
  return jsonb_build_object('id', v_id, 'status', 'open');
end $$;

-- organisation owners/admins: members' device and threat summary (no message data)
create or replace function public.my_org()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare m public.org_members; o public.organizations;
begin
  perform public._require_active_device();
  select * into m from public.org_members where user_id = auth.uid();
  if m.org_id is null then return null; end if;
  select * into o from public.organizations where id = m.org_id;
  if m.role = 'member' then
    return jsonb_build_object('id', o.id, 'name', o.name, 'kind', o.kind, 'role', m.role);
  end if;
  return jsonb_build_object('id', o.id, 'name', o.name, 'kind', o.kind, 'role', m.role, 'device_limit', o.device_limit,
    'members', (select coalesce(jsonb_agg(jsonb_build_object(
        'name', p.display_name, 'email', p.email_masked, 'role', mm.role,
        'devices', (select count(*) from public.devices d where d.user_id = mm.user_id and d.status <> 'revoked'),
        'devices_online', (select count(*) from public.devices d where d.user_id = mm.user_id and d.status = 'active'
                              and d.session_id is not null and d.last_seen_at > now() - make_interval(secs => public._setting('presence', 'online_seconds'))),
        'stats', public._threat_stats(mm.user_id, now() - interval '30 days', null)) order by mm.role, p.display_name), '[]')
      from public.org_members mm join public.profiles p on p.id = mm.user_id where mm.org_id = o.id));
end $$;

-- ================================================================== admin (MFA-gated, audited)
-- every admin write goes through this: role check + per-admin rate limit
create or replace function public._admin_write_guard()
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  if (select count(*) from public.audit_log where actor_id = auth.uid() and actor_kind = 'admin'
        and at > now() - interval '1 minute') >= coalesce(public._setting('admin_rate', 'actions_per_minute'), 60) then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;
end $$;

create or replace function public._audit(p_action text, p_type text, p_id text, p_detail jsonb)
returns void language sql security definer set search_path = '' as $$
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'admin', p_action, p_type, p_id, p_detail)
$$;

create or replace function public._customers()
returns setof uuid language sql stable security definer set search_path = '' as $$
  select p.id from public.profiles p where not exists (select 1 from public.admin_users a where a.user_id = p.id)
$$;

-- ------------------------------------------------------------------ overview + analytics
create or replace function public.admin_dashboard(p_from timestamptz default null, p_to timestamptz default null)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_online int := coalesce(public._setting('presence', 'online_seconds'), 120); r jsonb;
begin
  perform public._require_admin();
  with c as (select id from public._customers() id),
       s as (select su.*, public.sub_status(su.plan_code, su.expires_at, su.suspended_at, su.cancelled_at) st
               from public.subscriptions su where su.user_id in (select id from c))
  select jsonb_build_object(
    'range', jsonb_build_object('from', p_from, 'to', p_to),
    'customers_total',    (select count(*) from c),
    'customers_new',      (select count(*) from auth.users u where u.id in (select id from c)
                             and u.created_at >= coalesce(p_from, '-infinity') and u.created_at < coalesce(p_to, 'infinity')),
    'customers_active',   (select count(*) from s join public.profiles p on p.id = s.user_id
                             where s.st in ('trialing', 'active', 'cancelled') and p.account_status = 'active'),
    'customers_active_in_range', (select count(distinct user_id) from public.usage_daily
                             where user_id in (select id from c) and checks > 0
                               and day >= coalesce((p_from at time zone 'Asia/Kolkata')::date, '-infinity'::date)
                               and day <= coalesce((p_to at time zone 'Asia/Kolkata')::date, 'infinity'::date)),
    'accounts_suspended', (select count(*) from public.profiles where account_status = 'suspended' and id in (select id from c)),
    'trialing',           (select count(*) from s where st = 'trialing'),
    'premium_active',     (select count(*) from s where st in ('active', 'cancelled')),
    'expired',            (select count(*) from s where st = 'expired'),
    'trial_expired',      (select count(*) from s where st = 'expired' and plan_code = 'trial'),
    'subscriptions_suspended', (select count(*) from s where st = 'suspended'),
    'expiring_7d',        (select count(*) from s where st in ('trialing', 'active', 'cancelled') and expires_at < now() + interval '7 days'),
    'conversions',        (select count(*) from public.subscription_events where event = 'converted'
                             and at >= coalesce(p_from, '-infinity') and at < coalesce(p_to, 'infinity')),
    'plan_distribution',  (select coalesce(jsonb_object_agg(plan_code, n), '{}') from
                             (select plan_code, count(*) n from s where st <> 'expired' group by 1) x),
    'mrr_inr',            (select coalesce(sum(case when s.plan_code = 'enterprise' then s.custom_price_inr else p.price_inr end), 0)
                             from s join public.subscription_plans p on p.code = s.plan_code where s.st in ('active', 'cancelled')),
    'revenue', (select jsonb_build_object(
                   'paid_verified', coalesce(sum(amount_inr) filter (where status = 'paid' and verification = 'provider_verified'), 0),
                   'paid_manual',   coalesce(sum(amount_inr) filter (where status = 'paid' and verification = 'manual_recorded'), 0),
                   'failed_count',  count(*) filter (where status = 'failed'),
                   'refunded',      coalesce(sum(amount_inr) filter (where status = 'refunded'), 0),
                   'by_plan', (select coalesce(jsonb_object_agg(plan_code, amt), '{}') from (
                       select coalesce(plan_code, 'unspecified') plan_code, sum(amount_inr) amt from public.payments
                        where status = 'paid' and created_at >= coalesce(p_from, '-infinity') and created_at < coalesce(p_to, 'infinity')
                        group by 1) y))
                 from public.payments where created_at >= coalesce(p_from, '-infinity') and created_at < coalesce(p_to, 'infinity')),
    'devices_registered', (select count(*) from public.devices where status <> 'revoked'),
    'devices_active',     (select count(*) from public.devices where status = 'active'),
    'devices_pending',    (select count(*) from public.devices where status = 'pending'),
    'devices_connected',  (select count(*) from public.devices where status = 'active' and session_id is not null
                             and last_seen_at > now() - make_interval(secs => v_online)),
    'sessions_active',    (select count(*) from auth.sessions se where se.user_id in (select id from c)
                             and (se.not_after is null or se.not_after > now())),
    'checks_in_range',    (select coalesce(sum(checks), 0) from public.usage_daily
                             where day >= coalesce((p_from at time zone 'Asia/Kolkata')::date, '-infinity'::date)
                               and day <= coalesce((p_to at time zone 'Asia/Kolkata')::date, 'infinity'::date)),
    'checks_lifetime',    (select coalesce(sum(checks), 0) from public.usage_daily),
    'threats',            public._threat_stats(null, p_from, p_to),
    'categories',         (select coalesce(jsonb_object_agg(category, n), '{}') from (
                             select category, count(*) n from public.incidents where is_threat
                               and created_at >= coalesce(p_from, '-infinity') and created_at < coalesce(p_to, 'infinity')
                             group by 1 order by 2 desc limit 8) z),
    'recent_incidents',   (select coalesce(jsonb_agg(x order by x.created_at desc), '[]') from (
                             select i.id, i.created_at, i.verdict, i.severity, i.status, i.category, i.score, i.device_name,
                                    i.response_status, u.email
                               from public.incidents i left join auth.users u on u.id = i.user_id
                              where i.is_threat and i.shared_with_admin order by i.created_at desc limit 8) x),
    'open_plan_requests', (select count(*) from public.plan_requests where status = 'open')
  ) into r;
  return r;
end $$;

-- time series in IST buckets: day | week | month
create or replace function public.admin_timeseries(p_from timestamptz, p_to timestamptz, p_bucket text default 'day')
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_from date; v_to date; v_step interval; r jsonb;
begin
  perform public._require_admin();
  if p_bucket not in ('day', 'week', 'month') then raise exception 'bad_bucket' using errcode = '22023'; end if;
  v_from := date_trunc(p_bucket, (coalesce(p_from, now() - interval '30 days') at time zone 'Asia/Kolkata'))::date;
  v_to   := (coalesce(p_to, now()) at time zone 'Asia/Kolkata')::date;
  if v_to - v_from > 800 then raise exception 'range_too_large' using errcode = '22023'; end if;
  v_step := ('1 ' || p_bucket)::interval;
  select coalesce(jsonb_agg(jsonb_build_object(
      'bucket', b::date,
      'checks',  (select coalesce(sum(checks), 0) from public.usage_daily where day >= b::date and day < (b + v_step)::date),
      'threats', (select coalesce(sum(threats), 0) from public.usage_daily where day >= b::date and day < (b + v_step)::date),
      'critical', (select count(*) from public.incidents where severity = 'critical'
                     and (created_at at time zone 'Asia/Kolkata')::date >= b::date and (created_at at time zone 'Asia/Kolkata')::date < (b + v_step)::date),
      'resolved', (select count(*) from public.incident_events where event = 'resolved'
                     and (at at time zone 'Asia/Kolkata')::date >= b::date and (at at time zone 'Asia/Kolkata')::date < (b + v_step)::date),
      'active_customers', (select count(distinct user_id) from public.usage_daily where checks > 0 and day >= b::date and day < (b + v_step)::date),
      'signups', (select count(*) from auth.users u where u.id in (select public._customers())
                    and (u.created_at at time zone 'Asia/Kolkata')::date >= b::date and (u.created_at at time zone 'Asia/Kolkata')::date < (b + v_step)::date),
      'conversions', (select count(*) from public.subscription_events where event = 'converted'
                    and (at at time zone 'Asia/Kolkata')::date >= b::date and (at at time zone 'Asia/Kolkata')::date < (b + v_step)::date),
      'revenue', (select coalesce(sum(amount_inr), 0) from public.payments where status = 'paid'
                    and (created_at at time zone 'Asia/Kolkata')::date >= b::date and (created_at at time zone 'Asia/Kolkata')::date < (b + v_step)::date)
    ) order by b), '[]')
  into r
  from generate_series(v_from::timestamp, v_to::timestamp, v_step) b;
  return r;
end $$;

-- ------------------------------------------------------------------ customers
create or replace function public.admin_customers(
  p_search text default null, p_plan text default null, p_status text default null,
  p_joined_from timestamptz default null, p_joined_to timestamptz default null, p_threat text default null,
  p_sort text default 'joined', p_desc boolean default true, p_limit int default 25, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_online int := coalesce(public._setting('presence', 'online_seconds'), 120); r jsonb; v_total int;
begin
  perform public._require_admin();
  if p_sort not in ('joined', 'name', 'email', 'plan', 'expires', 'devices', 'last_active', 'checks', 'threats') then
    raise exception 'bad_sort' using errcode = '22023';
  end if;
  with base as (
  select p.id, u.email::text email, u.email_confirmed_at is not null email_verified, p.display_name name,
         p.account_status, u.created_at joined_at, s.plan_code plan, sp.name plan_name,
         public.sub_status(s.plan_code, s.expires_at, s.suspended_at, s.cancelled_at) sub_status,
         s.trial_started_at, s.trial_expires_at, s.expires_at,
         (select count(*)::int from public.devices d where d.user_id = p.id and d.status <> 'revoked') devices,
         (select count(*)::int from public.devices d where d.user_id = p.id and d.status = 'active' and d.session_id is not null
             and d.last_seen_at > now() - make_interval(secs => v_online)) devices_online,
         greatest((select max(d.last_seen_at) from public.devices d where d.user_id = p.id), u.last_sign_in_at) last_active,
         (select coalesce(sum(ud.checks), 0)::int from public.usage_daily ud where ud.user_id = p.id) checks,
         (select coalesce(sum(i.urls_count), 0)::int from public.incidents i where i.user_id = p.id) links,
         (select count(*)::int from public.incidents i where i.user_id = p.id and i.verdict in ('suspicious', 'malicious')) threats,
         (select count(*)::int from public.incidents i where i.user_id = p.id and i.blocked_at is not null) blocked,
         (select count(*)::int from public.incidents i where i.user_id = p.id and i.status = 'resolved') resolved,
         (select count(*)::int from public.incidents i where i.user_id = p.id and i.status in ('detected', 'blocked', 'investigating')) open_incidents
    from public.profiles p join auth.users u on u.id = p.id
    left join public.subscriptions s on s.user_id = p.id
    left join public.subscription_plans sp on sp.code = s.plan_code
   where p.id in (select public._customers())
     and (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or p.display_name ilike '%' || p_search || '%'
          or p.id::text ilike p_search || '%')
     and (p_plan is null or p_plan = '' or s.plan_code = p_plan)
     and (p_joined_from is null or u.created_at >= p_joined_from)
     and (p_joined_to is null or u.created_at < p_joined_to)),
  filt as (
  select * from base where
       (p_status is null or p_status = '' or sub_status = p_status
        or (p_status = 'account_suspended' and account_status = 'suspended')
        or (p_status = 'expiring' and sub_status in ('trialing', 'active', 'cancelled') and expires_at < now() + interval '7 days'))
   and (p_threat is null or p_threat = '' or (p_threat = 'with_threats' and threats > 0)
        or (p_threat = 'open' and open_incidents > 0) or (p_threat = 'none' and threats = 0)))
  select (select count(*) from filt),
         (select coalesce(jsonb_agg(to_jsonb(c)), '[]') from (
    select * from filt order by
      case when not p_desc then null
           when p_sort = 'joined' then extract(epoch from joined_at) when p_sort = 'expires' then extract(epoch from expires_at)
           when p_sort = 'devices' then devices when p_sort = 'last_active' then extract(epoch from last_active)
           when p_sort = 'checks' then checks when p_sort = 'threats' then threats end desc nulls last,
      case when p_desc then null
           when p_sort = 'joined' then extract(epoch from joined_at) when p_sort = 'expires' then extract(epoch from expires_at)
           when p_sort = 'devices' then devices when p_sort = 'last_active' then extract(epoch from last_active)
           when p_sort = 'checks' then checks when p_sort = 'threats' then threats end asc nulls last,
      case when p_sort in ('name', 'email', 'plan') and p_desc then
           case p_sort when 'name' then lower(coalesce(name, email)) when 'email' then lower(email) else plan end end desc,
      case when p_sort in ('name', 'email', 'plan') and not p_desc then
           case p_sort when 'name' then lower(coalesce(name, email)) when 'email' then lower(email) else plan end end asc,
      joined_at desc
    limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)) c)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r);
end $$;

-- the complete record for one customer
create or replace function public.admin_customer(p_user uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_online int := coalesce(public._setting('presence', 'online_seconds'), 120); r jsonb;
begin
  perform public._require_admin();
  if p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  select jsonb_build_object(
    'profile', jsonb_build_object(
       'id', p.id, 'name', p.display_name, 'email', u.email, 'email_verified', u.email_confirmed_at is not null,
       'email_verified_at', u.email_confirmed_at, 'phone', coalesce(u.phone::text, p.phone_masked),
       'created_at', u.created_at, 'last_sign_in_at', u.last_sign_in_at,
       'account_status', p.account_status, 'suspended_at', p.suspended_at, 'suspended_reason', p.suspended_reason,
       'share_with_admin', p.share_with_admin, 'retention_days', p.retention_days),
    'subscription', public._subscription_json(p.id),
    'subscription_events', (select coalesce(jsonb_agg(e order by e.at desc), '[]') from
        (select * from public.subscription_events where user_id = p.id order by at desc limit 100) e),
    'payments', (select coalesce(jsonb_agg(pm order by pm.created_at desc), '[]') from
        (select * from public.payments where user_id = p.id order by created_at desc limit 100) pm),
    'plan_requests', (select coalesce(jsonb_agg(q order by q.created_at desc), '[]') from
        (select * from public.plan_requests where user_id = p.id order by created_at desc limit 20) q),
    'devices', (select coalesce(jsonb_agg(jsonb_build_object(
        'id', d.id, 'name', d.name, 'status', d.status, 'device_type', coalesce(d.device_type, 'unknown'),
        'browser', d.browser, 'os', d.os, 'platform', d.platform, 'app_version', d.app_version,
        'registered_at', d.created_at, 'approved_at', d.approved_at, 'last_seen_at', d.last_seen_at,
        'revoked_at', d.revoked_at, 'revoked_reason', d.revoked_reason, 'is_primary', d.is_primary,
        'ip_prefix', d.ip_prefix, 'session_id', d.session_id, 'session_started_at', d.session_started_at,
        'session_status', case when d.status = 'revoked' then 'unlinked'
                               when d.session_id is null then 'signed_out'
                               when not exists (select 1 from auth.sessions se where se.id = d.session_id
                                                  and (se.not_after is null or se.not_after > now())) then 'session_ended'
                               when d.last_seen_at > now() - make_interval(secs => v_online) then 'connected'
                               else 'idle' end,
        'scans', (select count(*) from public.incidents i where i.device_id = d.id),
        'threats', (select count(*) from public.incidents i where i.device_id = d.id and i.verdict in ('suspicious', 'malicious'))
      ) order by d.status, d.created_at), '[]') from public.devices d where d.user_id = p.id),
    'sessions', (select coalesce(jsonb_agg(jsonb_build_object(
        'id', se.id, 'created_at', se.created_at, 'refreshed_at', coalesce(se.refreshed_at, se.updated_at), 'not_after', se.not_after,
        'aal', se.aal, 'ip_prefix', public._ip_prefix(se.ip), 'user_agent', left(se.user_agent, 200),
        'agent', public._parse_ua(se.user_agent),
        'device', (select jsonb_build_object('id', d.id, 'name', d.name, 'status', d.status) from public.devices d where d.session_id = se.id)
      ) order by se.created_at desc), '[]') from auth.sessions se where se.user_id = p.id),
    'stats', public._threat_stats(p.id, null, null),
    'checks_lifetime', (select coalesce(sum(checks), 0) from public.usage_daily where user_id = p.id),
    'usage_30d', (select coalesce(jsonb_agg(jsonb_build_object('day', day, 'checks', checks, 'threats', threats) order by day), '[]')
                    from public.usage_daily where user_id = p.id and day > public._ist_today() - 30),
    'incidents', (select coalesce(jsonb_agg(to_jsonb(i) - 'redacted_excerpt' || jsonb_build_object(
                     'excerpt', case when i.shared_with_admin then i.redacted_excerpt end) order by i.created_at desc), '[]')
                    from (select * from public.incidents where user_id = p.id order by created_at desc limit 300) i),
    'logins', (select coalesce(jsonb_agg(l order by l.at desc), '[]') from
        (select e.*, d.name device_name from public.login_events e left join public.devices d on d.id = e.device_id
          where e.user_id = p.id order by e.at desc limit 100) l),
    'alerts', (select coalesce(jsonb_agg(a order by a.created_at desc), '[]') from
        (select al.id, al.created_at, al.kind, al.title, al.risk_level, al.read_at, d.name target_device
           from public.alerts al left join public.devices d on d.id = al.target_device_id
          where al.user_id = p.id order by al.created_at desc limit 100) a),
    'audit', (select coalesce(jsonb_agg(x order by x.at desc), '[]') from
        (select * from public.audit_log where actor_id = p.id or (target_type = 'user' and target_id = p.id::text)
          order by at desc limit 100) x),
    'org', (select jsonb_build_object('id', o.id, 'name', o.name, 'kind', o.kind, 'role', m.role, 'device_limit', o.device_limit)
              from public.org_members m join public.organizations o on o.id = m.org_id where m.user_id = p.id)
  ) into r
  from public.profiles p join auth.users u on u.id = p.id where p.id = p_user;
  return r;
end $$;

-- ------------------------------------------------------------------ devices & sessions
create or replace function public.admin_devices(p_search text default null, p_status text default null,
  p_limit int default 50, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_online int := coalesce(public._setting('presence', 'online_seconds'), 120); r jsonb; v_total int;
begin
  perform public._require_admin();
  with b as (
    select d.id, d.name, d.status::text status, coalesce(d.device_type, 'unknown') device_type, d.browser, d.os, d.platform,
           d.created_at registered_at, d.last_seen_at, d.session_id, d.session_started_at, d.ip_prefix, d.revoked_reason,
           d.user_id, u.email::text email, p.display_name,
           case when d.status = 'revoked' then 'unlinked' when d.session_id is null then 'signed_out'
                when not exists (select 1 from auth.sessions se where se.id = d.session_id and (se.not_after is null or se.not_after > now())) then 'session_ended'
                when d.last_seen_at > now() - make_interval(secs => v_online) then 'connected' else 'idle' end session_status
      from public.devices d join auth.users u on u.id = d.user_id join public.profiles p on p.id = d.user_id
     where (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or d.name ilike '%' || p_search || '%'
            or d.id::text ilike p_search || '%')),
  f as (select * from b where p_status is null or p_status = '' or session_status = p_status or status = p_status)
  select (select count(*) from f),
         (select coalesce(jsonb_agg(to_jsonb(x)), '[]') from (select * from f order by last_seen_at desc nulls last
            limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)) x)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r, 'online_seconds', v_online,
    'unbound_sessions', (select count(*) from auth.sessions se where se.user_id in (select public._customers())
        and not exists (select 1 from public.devices d where d.session_id = se.id)));
end $$;

create or replace function public.admin_revoke_session(p_session uuid, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_uid uuid; v_dev uuid;
begin
  perform public._admin_write_guard();
  if coalesce(trim(p_reason), '') = '' then raise exception 'reason_required' using errcode = '22023'; end if;
  select user_id into v_uid from auth.sessions where id = p_session;
  if v_uid is null or v_uid not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  select id into v_dev from public.devices where session_id = p_session;
  update public.devices set session_id = null, last_session_id = p_session where id = v_dev;
  delete from auth.sessions where id = p_session;             -- refresh token stops working; RLS denies the device
  insert into public.login_events(user_id, device_id, session_id, kind, actor_kind, note)
  values (v_uid, v_dev, p_session, 'session_revoked', 'admin', left(p_reason, 300));
  perform public._audit('session.revoke', 'user', v_uid::text, jsonb_build_object('session', p_session, 'device', v_dev, 'reason', left(p_reason, 300)));
end $$;

-- replaces the older version: requires a reason, audited
create or replace function public.admin_revoke_device(p_device uuid, p_reason text default null)
returns void language plpgsql security definer set search_path = '' as $$
declare v_uid uuid;
begin
  perform public._admin_write_guard();
  select user_id into v_uid from public.devices where id = p_device;
  if v_uid is null then raise exception 'not_found' using errcode = 'P0002'; end if;
  perform public._revoke_device(p_device, 'admin: ' || coalesce(nullif(trim(p_reason), ''), 'no reason given'));
  perform public._audit('device.revoke', 'device', p_device::text, jsonb_build_object('user', v_uid, 'reason', left(p_reason, 300)));
end $$;

-- ------------------------------------------------------------------ accounts
create or replace function public.admin_suspend_account(p_user uuid, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if coalesce(trim(p_reason), '') = '' then raise exception 'reason_required' using errcode = '22023'; end if;
  if p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  update public.profiles set account_status = 'suspended', suspended_at = now(), suspended_reason = left(p_reason, 300) where id = p_user;
  update auth.users set banned_until = 'infinity' where id = p_user;          -- blocks sign-in and token refresh
  update public.devices set last_session_id = session_id, session_id = null where user_id = p_user and session_id is not null;
  delete from auth.sessions where user_id = p_user;
  insert into public.login_events(user_id, kind, actor_kind, note) values (p_user, 'account_suspended', 'admin', left(p_reason, 300));
  perform public._audit('account.suspend', 'user', p_user::text, jsonb_build_object('reason', left(p_reason, 300)));
end $$;

create or replace function public.admin_reactivate_account(p_user uuid, p_note text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  update public.profiles set account_status = 'active', suspended_at = null, suspended_reason = null where id = p_user;
  update auth.users set banned_until = null where id = p_user;
  insert into public.login_events(user_id, kind, actor_kind, note) values (p_user, 'account_reactivated', 'admin', left(p_note, 300));
  perform public._audit('account.reactivate', 'user', p_user::text, jsonb_build_object('note', left(p_note, 300)));
end $$;

-- ------------------------------------------------------------------ incidents
create or replace function public.admin_incidents(
  p_from timestamptz default null, p_to timestamptz default null, p_severity text default null, p_status text default null,
  p_category text default null, p_verdict text default null, p_user uuid default null, p_search text default null,
  p_threats_only boolean default true, p_limit int default 50, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb; v_total int;
begin
  perform public._require_admin();
  with f as (
    select i.id, i.created_at, i.user_id, u.email::text email, i.device_id, i.device_name, i.session_id, i.source,
           i.verdict, i.severity, i.status, i.category, i.score, i.ti_status, i.url_domains, i.urls_count,
           i.response_status, i.alerts_sent, i.blocked_at, i.resolved_at, i.contained_auth_code
      from public.incidents i left join auth.users u on u.id = i.user_id
     where i.shared_with_admin
       and (not p_threats_only or i.is_threat or i.status in ('false_positive', 'resolved'))
       and (p_from is null or i.created_at >= p_from) and (p_to is null or i.created_at < p_to)
       and (p_severity is null or p_severity = '' or i.severity = p_severity)
       and (p_status is null or p_status = '' or i.status = p_status or (p_status = 'open' and i.status in ('detected', 'blocked', 'investigating')))
       and (p_category is null or p_category = '' or i.category = p_category)
       and (p_verdict is null or p_verdict = '' or i.verdict = p_verdict)
       and (p_user is null or i.user_id = p_user)
       and (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or i.id::text ilike p_search || '%'
            or array_to_string(i.url_domains, ' ') ilike '%' || p_search || '%'))
  select (select count(*) from f),
         (select coalesce(jsonb_agg(to_jsonb(x)), '[]') from (select * from f order by created_at desc
            limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)) x)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r,
    'categories', (select coalesce(jsonb_agg(distinct category), '[]') from public.incidents));
end $$;

create or replace function public.admin_incident(p_incident uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb;
begin
  perform public._require_admin();
  select to_jsonb(i) - 'redacted_excerpt' || jsonb_build_object(
           'excerpt', i.redacted_excerpt, 'email', u.email,
           'device', (select jsonb_build_object('id', d.id, 'name', d.name, 'device_type', d.device_type, 'browser', d.browser, 'os', d.os, 'status', d.status)
                        from public.devices d where d.id = i.device_id),
           'events', (select coalesce(jsonb_agg(e order by e.at, e.id), '[]') from public.incident_events e where e.incident_id = i.id),
           'alerts', (select coalesce(jsonb_agg(jsonb_build_object('created_at', a.created_at, 'title', a.title, 'read_at', a.read_at,
                         'device', (select name from public.devices d where d.id = a.target_device_id)) order by a.created_at), '[]')
                        from public.alerts a where a.incident_id = i.id))
    into r
    from public.incidents i left join auth.users u on u.id = i.user_id
   where i.id = p_incident and i.shared_with_admin;
  if r is null then raise exception 'not_found' using errcode = 'P0002'; end if;
  return r;
end $$;

-- replaces the older version. Resolution / false positive need a written note.
create or replace function public.admin_set_incident_status(p_incident uuid, p_status text, p_note text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if not exists (select 1 from public.incidents where id = p_incident and shared_with_admin) then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  if p_status in ('resolved', 'false_positive') and coalesce(trim(p_note), '') = '' then
    raise exception 'note_required' using errcode = '22023';
  end if;
  perform public._set_incident_status(p_incident, p_status, 'admin', auth.uid(), p_note);
  perform public._audit('incident.set_status', 'incident', p_incident::text, jsonb_build_object('status', p_status, 'note', left(p_note, 300)));
end $$;

create or replace function public.admin_incident_note(p_incident uuid, p_note text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_uid uuid;
begin
  perform public._admin_write_guard();
  if coalesce(trim(p_note), '') = '' then raise exception 'note_required' using errcode = '22023'; end if;
  select user_id into v_uid from public.incidents where id = p_incident and shared_with_admin;
  if v_uid is null then raise exception 'not_found' using errcode = 'P0002'; end if;
  insert into public.incident_events(incident_id, user_id, event, actor_kind, actor_id, note)
  values (p_incident, v_uid, 'note', 'admin', auth.uid(), left(p_note, 500));
  perform public._audit('incident.note', 'incident', p_incident::text, jsonb_build_object('note', left(p_note, 300)));
end $$;

-- ------------------------------------------------------------------ subscriptions
create or replace function public.admin_subscriptions(p_status text default null, p_plan text default null,
  p_search text default null, p_limit int default 50, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb; v_total int;
begin
  perform public._require_admin();
  with f as (
    select s.user_id, u.email::text email, p.display_name name, s.plan_code plan, sp.name plan_name,
           public.sub_status(s.plan_code, s.expires_at, s.suspended_at, s.cancelled_at) status,
           s.started_at, s.expires_at, s.trial_started_at, s.trial_expires_at, s.converted_at, s.suspended_at, s.cancelled_at,
           case when s.plan_code = 'enterprise' then s.custom_price_inr else sp.price_inr end price_inr,
           public._device_quota(s.user_id) devices, s.note,
           (select max(created_at) from public.payments pm where pm.user_id = s.user_id and pm.status = 'paid') last_paid_at,
           (select status from public.payments pm where pm.user_id = s.user_id order by created_at desc limit 1) last_payment_status
      from public.subscriptions s join auth.users u on u.id = s.user_id join public.profiles p on p.id = s.user_id
      join public.subscription_plans sp on sp.code = s.plan_code
     where s.user_id in (select public._customers())
       and (p_plan is null or p_plan = '' or s.plan_code = p_plan)
       and (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or p.display_name ilike '%' || p_search || '%')),
  g as (select * from f where p_status is null or p_status = '' or status = p_status
          or (p_status = 'expiring' and status in ('trialing', 'active', 'cancelled') and expires_at < now() + interval '7 days'))
  select (select count(*) from g),
         (select coalesce(jsonb_agg(to_jsonb(x)), '[]') from (select * from g order by expires_at
            limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)) x)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r,
    'plans', (select jsonb_agg(to_jsonb(sp) order by sort) from public.subscription_plans sp),
    'events', (select coalesce(jsonb_agg(e order by e.at desc), '[]') from (
        select se.*, u.email from public.subscription_events se join auth.users u on u.id = se.user_id
         where se.event in ('renewed', 'converted', 'cancelled', 'suspended', 'reactivated', 'expired', 'plan_changed', 'plan_assigned')
         order by se.at desc limit 100) e),
    'requests', (select coalesce(jsonb_agg(q order by q.created_at desc), '[]') from (
        select pr.*, u.email from public.plan_requests pr join auth.users u on u.id = pr.user_id
         order by (pr.status = 'open') desc, pr.created_at desc limit 100) q));
end $$;

create or replace function public.admin_set_subscription(
  p_user uuid, p_plan text, p_expires_at timestamptz, p_started_at timestamptz default null,
  p_device_limit int default null, p_custom_price int default null, p_note text default null,
  p_reset_trial_usage boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare old public.subscriptions; v_event text; v_plan public.subscription_plans;
begin
  perform public._admin_write_guard();
  select * into v_plan from public.subscription_plans where code = p_plan;
  if v_plan.code is null then raise exception 'invalid_plan' using errcode = '22023'; end if;
  if p_expires_at is null then raise exception 'expiry_required' using errcode = '22023'; end if;
  if p_plan = 'enterprise' and p_device_limit is null and not exists (
       select 1 from public.org_members m join public.organizations o on o.id = m.org_id
        where m.user_id = p_user and o.device_limit is not null) then
    raise exception 'enterprise_device_limit_required' using errcode = '22023';
  end if;
  if p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  select * into old from public.subscriptions where user_id = p_user for update;

  v_event := case when old.user_id is null then 'plan_assigned'
                  when old.plan_code = 'trial' and p_plan <> 'trial' and old.converted_at is null then 'converted'
                  when old.plan_code <> p_plan then 'plan_changed'
                  when p_expires_at > old.expires_at then 'renewed'
                  else 'limit_changed' end;

  insert into public.subscriptions(user_id, plan_code, started_at, expires_at, device_limit_override, custom_price_inr, note,
                                   trial_started_at, trial_expires_at, converted_at)
  values (p_user, p_plan, coalesce(p_started_at, now()), p_expires_at,
          case when p_plan = 'enterprise' then p_device_limit end, case when p_plan = 'enterprise' then p_custom_price end,
          nullif(trim(coalesce(p_note, '')), ''),
          case when p_plan = 'trial' then coalesce(p_started_at, now()) end, case when p_plan = 'trial' then p_expires_at end,
          case when p_plan <> 'trial' then now() end)
  on conflict (user_id) do update set
    plan_code = excluded.plan_code,
    started_at = coalesce(p_started_at, case when public.subscriptions.plan_code = excluded.plan_code
                                             then public.subscriptions.started_at else now() end),
    expires_at = excluded.expires_at,
    device_limit_override = excluded.device_limit_override,
    custom_price_inr = excluded.custom_price_inr,
    note = excluded.note,
    trial_started_at = case when excluded.plan_code = 'trial' and public.subscriptions.trial_started_at is null
                            then excluded.started_at else public.subscriptions.trial_started_at end,
    trial_expires_at = case when excluded.plan_code = 'trial' then excluded.expires_at else public.subscriptions.trial_expires_at end,
    converted_at = coalesce(public.subscriptions.converted_at, case when excluded.plan_code <> 'trial' then now() end),
    cancelled_at = null, cancel_reason = null,
    updated_at = now();

  if p_reset_trial_usage then
    update public.usage_daily set trial_checks = 0 where user_id = p_user;
    insert into public.subscription_events(user_id, event, actor_kind, actor_id, note)
    values (p_user, 'trial_reset', 'admin', auth.uid(), 'trial check counters reset');
  end if;
  insert into public.subscription_events(user_id, event, from_plan, to_plan, from_expires, to_expires, actor_kind, actor_id, note)
  values (p_user, v_event, old.plan_code, p_plan, old.expires_at, p_expires_at, 'admin', auth.uid(), left(p_note, 300));
  perform public._audit('subscription.set', 'user', p_user::text, jsonb_build_object(
    'event', v_event, 'from_plan', old.plan_code, 'to_plan', p_plan, 'from_expires', old.expires_at, 'to_expires', p_expires_at,
    'device_limit', p_device_limit, 'custom_price', p_custom_price, 'reset_trial_usage', p_reset_trial_usage));
  return jsonb_build_object('ok', true, 'event', v_event);
end $$;

create or replace function public.admin_subscription_action(p_user uuid, p_action text, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
declare s public.subscriptions;
begin
  perform public._admin_write_guard();
  if p_action not in ('suspend', 'reactivate', 'cancel', 'uncancel') then raise exception 'bad_action' using errcode = '22023'; end if;
  if p_action in ('suspend', 'cancel') and coalesce(trim(p_reason), '') = '' then raise exception 'reason_required' using errcode = '22023'; end if;
  select * into s from public.subscriptions where user_id = p_user for update;
  if not found or p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  if p_action = 'suspend' then
    update public.subscriptions set suspended_at = now(), suspend_reason = left(p_reason, 300), updated_at = now() where user_id = p_user;
  elsif p_action = 'reactivate' then
    update public.subscriptions set suspended_at = null, suspend_reason = null, updated_at = now() where user_id = p_user;
  elsif p_action = 'cancel' then
    update public.subscriptions set cancelled_at = now(), cancel_reason = left(p_reason, 300), updated_at = now() where user_id = p_user;
  else
    update public.subscriptions set cancelled_at = null, cancel_reason = null, updated_at = now() where user_id = p_user;
  end if;
  insert into public.subscription_events(user_id, event, from_plan, to_plan, actor_kind, actor_id, note)
  values (p_user, case p_action when 'suspend' then 'suspended' when 'cancel' then 'cancelled' else 'reactivated' end,
          s.plan_code, s.plan_code, 'admin', auth.uid(), left(coalesce(p_reason, p_action), 300));
  perform public._audit('subscription.' || p_action, 'user', p_user::text, jsonb_build_object('reason', left(p_reason, 300)));
end $$;

create or replace function public.admin_handle_plan_request(p_request uuid, p_status text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if p_status not in ('open', 'contacted', 'done', 'declined') then raise exception 'bad_status' using errcode = '22023'; end if;
  update public.plan_requests set status = p_status, handled_at = now(), handled_by = auth.uid() where id = p_request;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  perform public._audit('subscription.request_' || p_status, 'plan_request', p_request::text, null);
end $$;

-- ------------------------------------------------------------------ payments
create or replace function public.admin_record_payment(
  p_user uuid, p_amount numeric, p_status text, p_method text, p_reference text,
  p_plan text default null, p_period_start date default null, p_period_end date default null,
  p_failure_reason text default null, p_note text default null)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  perform public._admin_write_guard();
  if p_user not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  if p_status not in ('pending', 'paid', 'failed', 'refunded', 'cancelled') then raise exception 'bad_status' using errcode = '22023'; end if;
  if p_amount is null or p_amount < 0 then raise exception 'bad_amount' using errcode = '22023'; end if;
  if p_reference ~ '\d{12,19}' then raise exception 'reference_looks_like_card_number' using errcode = '22023'; end if;
  insert into public.payments(user_id, plan_code, amount_inr, period_start, period_end, status, verification, provider,
                              provider_ref, method, failure_reason, note, recorded_by)
  values (p_user, p_plan, p_amount, p_period_start, p_period_end, p_status, 'manual_recorded', 'manual',
          left(p_reference, 120), p_method, left(p_failure_reason, 300), left(p_note, 300), auth.uid())
  returning id into v_id;
  perform public._audit('payment.record', 'user', p_user::text, jsonb_build_object('payment', v_id, 'amount', p_amount, 'status', p_status,
    'verification', 'manual_recorded'));
  return jsonb_build_object('id', v_id);
end $$;

-- payment-provider webhook (service role only) — pending integration
create or replace function public.provider_record_payment(
  p_user uuid, p_amount numeric, p_status text, p_provider text, p_provider_ref text, p_plan text,
  p_period_start date, p_period_end date, p_failure_reason text default null)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  insert into public.payments(user_id, plan_code, amount_inr, period_start, period_end, status, verification, provider, provider_ref, failure_reason)
  values (p_user, p_plan, p_amount, p_period_start, p_period_end, p_status, 'provider_verified', p_provider, p_provider_ref, p_failure_reason)
  returning id into v_id;
  insert into public.audit_log(actor_kind, action, target_type, target_id, detail)
  values ('system', 'payment.provider', 'user', p_user::text, jsonb_build_object('payment', v_id, 'status', p_status));
  return v_id;
end $$;

create or replace function public.admin_payments(p_from timestamptz default null, p_to timestamptz default null,
  p_status text default null, p_search text default null, p_limit int default 50, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb; v_total int;
begin
  perform public._require_admin();
  with f as (
    select pm.*, u.email::text email from public.payments pm join auth.users u on u.id = pm.user_id
     where (p_from is null or pm.created_at >= p_from) and (p_to is null or pm.created_at < p_to)
       and (p_status is null or p_status = '' or pm.status = p_status)
       and (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or pm.provider_ref ilike '%' || p_search || '%'))
  select (select count(*) from f),
         (select coalesce(jsonb_agg(to_jsonb(x)), '[]') from (select * from f order by created_at desc
            limit least(greatest(p_limit, 1), 200) offset greatest(p_offset, 0)) x)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r,
    'summary', (select jsonb_build_object(
        'paid_verified', coalesce(sum(amount_inr) filter (where status = 'paid' and verification = 'provider_verified'), 0),
        'paid_manual', coalesce(sum(amount_inr) filter (where status = 'paid' and verification = 'manual_recorded'), 0),
        'pending', count(*) filter (where status = 'pending'), 'failed', count(*) filter (where status = 'failed'),
        'refunded', coalesce(sum(amount_inr) filter (where status = 'refunded'), 0),
        'by_plan', (select coalesce(jsonb_object_agg(k, v), '{}') from (select coalesce(plan_code, 'unspecified') k, sum(amount_inr) v
                      from public.payments where status = 'paid' and (p_from is null or created_at >= p_from) and (p_to is null or created_at < p_to)
                     group by 1) y),
        'by_month', (select coalesce(jsonb_object_agg(k, v), '{}') from (select to_char(created_at at time zone 'Asia/Kolkata', 'YYYY-MM') k, sum(amount_inr) v
                      from public.payments where status = 'paid' and (p_from is null or created_at >= p_from) and (p_to is null or created_at < p_to)
                     group by 1) z))
      from public.payments where (p_from is null or created_at >= p_from) and (p_to is null or created_at < p_to)));
end $$;

-- ------------------------------------------------------------------ organisations
create or replace function public.admin_orgs()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return (select coalesce(jsonb_agg(jsonb_build_object('id', o.id, 'name', o.name, 'kind', o.kind, 'device_limit', o.device_limit,
      'contract_ref', o.contract_ref, 'created_at', o.created_at,
      'members', (select coalesce(jsonb_agg(jsonb_build_object('user_id', m.user_id, 'email', u.email, 'role', m.role)), '[]')
                    from public.org_members m join auth.users u on u.id = m.user_id where m.org_id = o.id),
      'devices_used', (select count(*) from public.devices d join public.org_members m on m.user_id = d.user_id
                        where m.org_id = o.id and d.status <> 'revoked')) order by o.created_at desc), '[]')
    from public.organizations o);
end $$;

create or replace function public.admin_save_org(p_id uuid, p_name text, p_kind text, p_device_limit int, p_contract_ref text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare v_id uuid;
begin
  perform public._admin_write_guard();
  if p_id is null then
    insert into public.organizations(name, kind, device_limit, contract_ref, created_by)
    values (p_name, p_kind, p_device_limit, p_contract_ref, auth.uid()) returning id into v_id;
  else
    update public.organizations set name = p_name, kind = p_kind, device_limit = p_device_limit, contract_ref = p_contract_ref
     where id = p_id returning id into v_id;
    if v_id is null then raise exception 'not_found' using errcode = 'P0002'; end if;
  end if;
  perform public._audit('org.save', 'org', v_id::text, jsonb_build_object('name', p_name, 'kind', p_kind, 'device_limit', p_device_limit));
  return v_id;
end $$;

create or replace function public.admin_set_org_member(p_org uuid, p_email text, p_role text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_uid uuid;
begin
  perform public._admin_write_guard();
  select id into v_uid from auth.users where lower(email) = lower(trim(p_email));
  if v_uid is null or v_uid not in (select public._customers()) then raise exception 'not_found' using errcode = 'P0002'; end if;
  if p_role is null then
    delete from public.org_members where org_id = p_org and user_id = v_uid;
    update public.subscriptions set org_id = null where user_id = v_uid and org_id = p_org;
  else
    if p_role not in ('owner', 'admin', 'member') then raise exception 'bad_role' using errcode = '22023'; end if;
    insert into public.org_members(org_id, user_id, role) values (p_org, v_uid, p_role)
    on conflict (user_id) do update set org_id = excluded.org_id, role = excluded.role;
    update public.subscriptions set org_id = p_org where user_id = v_uid;
  end if;
  perform public._audit('org.member', 'org', p_org::text, jsonb_build_object('user', v_uid, 'role', p_role));
end $$;

-- ------------------------------------------------------------------ notifications, audit, settings
create or replace function public.admin_notifications(p_kind text default null, p_limit int default 100)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return jsonb_build_object(
    'alerts', (select coalesce(jsonb_agg(x order by x.created_at desc), '[]') from (
        select a.id, a.created_at, a.kind, a.title, a.risk_level, a.read_at, a.incident_id, u.email, d.name target_device
          from public.alerts a join auth.users u on u.id = a.user_id left join public.devices d on d.id = a.target_device_id
         where p_kind is null or p_kind = '' or a.kind = p_kind
         order by a.created_at desc limit least(p_limit, 500)) x),
    'by_kind', (select coalesce(jsonb_object_agg(kind, n), '{}') from (select kind, count(*) n from public.alerts group by 1) y),
    'unread', (select count(*) from public.alerts where read_at is null));
end $$;

create or replace function public.admin_audit(p_search text default null, p_action text default null, p_limit int default 100, p_offset int default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare r jsonb; v_total int;
begin
  perform public._require_admin();
  with f as (select a.*, u.email::text actor_email from public.audit_log a left join auth.users u on u.id = a.actor_id
              where (p_action is null or p_action = '' or a.action like p_action || '%')
                and (p_search is null or p_search = '' or u.email ilike '%' || p_search || '%' or a.target_id ilike p_search || '%'
                     or a.detail::text ilike '%' || p_search || '%'))
  select (select count(*) from f), (select coalesce(jsonb_agg(to_jsonb(x)), '[]') from
           (select * from f order by id desc limit least(greatest(p_limit, 1), 500) offset greatest(p_offset, 0)) x)
  into v_total, r;
  return jsonb_build_object('total', v_total, 'rows', r);
end $$;

create or replace function public.admin_settings()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return jsonb_build_object(
    'settings', (select jsonb_object_agg(key, value) from public.app_settings),
    'plans', (select jsonb_agg(to_jsonb(p) order by sort) from public.subscription_plans p),
    'admins', (select jsonb_agg(jsonb_build_object('email', u.email, 'since', a.created_at,
                 'mfa', exists (select 1 from auth.mfa_factors f where f.user_id = a.user_id and f.status = 'verified')))
                 from public.admin_users a join auth.users u on u.id = a.user_id),
    'integrations', jsonb_build_object('payments', 'pending_integration', 'url_blocking', 'pending_integration',
                                       'threat_intel', 'URLhaus (configured via the analyze function secret)'));
end $$;

create or replace function public.admin_update_plan(p_code text, p_price int, p_device_limit int, p_active boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if p_code = 'trial' then raise exception 'use_trial_settings' using errcode = '22023'; end if;
  update public.subscription_plans set price_inr = p_price, device_limit = p_device_limit, active = p_active where code = p_code;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  perform public._audit('plan.update', 'plan', p_code, jsonb_build_object('price', p_price, 'device_limit', p_device_limit, 'active', p_active));
end $$;

create or replace function public.admin_update_trial(p_days int, p_daily int, p_total int)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._admin_write_guard();
  if p_days not between 1 and 60 or p_daily not between 1 and 100 or p_total not between 1 and 1000 then
    raise exception 'bad_value' using errcode = '22023';
  end if;
  update public.app_settings set value = jsonb_build_object('days', p_days, 'daily_checks', p_daily, 'total_checks', p_total),
         updated_at = now(), updated_by = auth.uid() where key = 'trial';
  perform public._audit('settings.trial', 'settings', 'trial', jsonb_build_object('days', p_days, 'daily', p_daily, 'total', p_total));
end $$;

-- ------------------------------------------------------------------ retention: also record expiries
create or replace function public.run_retention()
returns json language plpgsql security definer set search_path = '' as $$
declare a int; b int; c int; e int;
begin
  insert into public.subscription_events(user_id, event, from_plan, to_plan, from_expires, actor_kind, note)
  select s.user_id, 'expired', s.plan_code, s.plan_code, s.expires_at, 'system', 'validity ended'
    from public.subscriptions s
   where s.expires_at <= now()
     and not exists (select 1 from public.subscription_events x where x.user_id = s.user_id and x.event = 'expired' and x.from_expires = s.expires_at);
  get diagnostics e = row_count;
  delete from public.incidents where expires_at < now();               get diagnostics a = row_count;
  delete from public.alerts where created_at < now() - interval '30 days'; get diagnostics b = row_count;
  update public.pairing_codes set status = 'expired' where status in ('open','claimed') and expires_at < now() - interval '5 minutes';
  delete from public.pairing_codes where created_at < now() - interval '7 days';
  delete from public.pairing_attempts where created_at < now() - interval '1 day';
  delete from public.login_events where at < now() - interval '180 days';
  delete from public.audit_log where at < now() - interval '365 days'; get diagnostics c = row_count;
  return json_build_object('incidents', a, 'alerts', b, 'audit', c, 'expired_logged', e);
end $$;

-- ------------------------------------------------------------------ RLS + execute grants
alter table public.app_settings        enable row level security;
alter table public.subscription_plans  enable row level security;
alter table public.organizations       enable row level security;
alter table public.org_members         enable row level security;
alter table public.subscriptions       enable row level security;
alter table public.subscription_events enable row level security;
alter table public.usage_daily         enable row level security;
alter table public.payments            enable row level security;
alter table public.plan_requests       enable row level security;
alter table public.login_events        enable row level security;
alter table public.incident_events     enable row level security;
-- plan catalogue is public information; everything else: no client policies (RPC only)
create policy plans_read on public.subscription_plans for select to anon, authenticated using (active);
grant select on public.subscription_plans to anon, authenticated;
revoke all on public.app_settings, public.organizations, public.org_members, public.subscriptions, public.subscription_events,
  public.usage_daily, public.payments, public.plan_requests, public.login_events, public.incident_events from anon, authenticated;
-- clients still may not write incident lifecycle columns directly
revoke update on public.incidents from authenticated, anon;

revoke execute on all functions in schema public from public, anon;
grant execute on all functions in schema public to authenticated;
revoke execute on function
  public._revoke_device(uuid, text), public.grant_admin(text, text), public.run_retention(), public.handle_new_user(),
  public._require_admin(), public._admin_write_guard(), public._audit(text, text, text, jsonb), public._customers(),
  public._setting(text, text), public._device_quota(uuid), public._threat_stats(uuid, timestamptz, timestamptz),
  public._subscription_json(uuid), public._set_incident_status(uuid, text, text, uuid, text),
  public._incident_before_insert(), public._incident_after_insert(), public._alert_after_insert(),
  public.consume_check(uuid), public.record_block(uuid, text),
  public.provider_record_payment(uuid, numeric, text, text, text, text, date, date, text)
from authenticated;
grant execute on function public.consume_check(uuid), public.record_block(uuid, text),
  public.provider_record_payment(uuid, numeric, text, text, text, text, date, date, text) to service_role;
