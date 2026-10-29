-- SCAMWISE platform acceptance tests (run by tests/db/run.sh against a real Postgres).
-- Every check raises on failure, so the run stops at the first broken requirement.
\set ON_ERROR_STOP 1
\set QUIET 1
set client_min_messages = notice;

create schema t;
grant usage on schema t to authenticated, anon;
create table t.ids(k text primary key, v uuid);
grant select on t.ids to authenticated, anon;

create function t.ok(c boolean, m text) returns void language plpgsql as $$
begin
  if c is not true then raise exception 'FAIL: %', m; end if;
  raise notice 'PASS  %', m;
end $$;
create function t.id(k text) returns uuid language sql stable as $$ select v from t.ids where ids.k = $1 $$;
create function t.login(p_uid uuid, p_sid uuid, p_aal text default 'aal1') returns void language plpgsql as $$
begin
  perform set_config('request.uid', coalesce(p_uid::text, ''), false);
  perform set_config('request.jwt', case when p_uid is null then '' else json_build_object('session_id', p_sid, 'aal', p_aal)::text end, false);
end $$;
create function t.err(p_sql text) returns text language plpgsql as $$
begin
  execute p_sql;
  return null;
exception when others then
  return sqlerrm;
end $$;
grant execute on all functions in schema t to authenticated, anon;

-- a new account (trigger creates profile + 7-day trial)
create function t.new_user(p_key text, p_email text, p_name text) returns uuid language plpgsql as $$
declare v uuid;
begin
  insert into auth.users(email, email_confirmed_at, raw_user_meta_data, last_sign_in_at)
  values (p_email, now(), jsonb_build_object('full_name', p_name), now()) returning id into v;
  insert into t.ids values (p_key, v);
  return v;
end $$;
-- a sign-in on some device: creates an auth session and registers the browser install
create function t.sign_in(p_key text, p_user uuid, p_install uuid, p_name text, p_ua text, p_ip inet) returns uuid language plpgsql as $$
declare v_sid uuid; v_dev uuid;
begin
  insert into auth.sessions(user_id, user_agent, ip) values (p_user, p_ua, p_ip) returning id into v_sid;
  perform t.login(p_user, v_sid);
  select (public.register_device(p_install, p_name, 'web', 'test')).id into v_dev;
  insert into t.ids values (p_key || '_sid', v_sid), (p_key || '_dev', v_dev) on conflict (k) do update set v = excluded.v;
  return v_dev;
end $$;
-- what the analyze edge function does (service role): quota first, then store the scan
create function t.scan(p_user uuid, p_dev uuid, p_risk text, p_score int, p_ti text default 'no_match', p_domains text[] default '{}')
returns uuid language plpgsql as $$
declare q json; v uuid;
begin
  q := public.consume_check(p_user);
  if not (q ->> 'allowed')::boolean then raise exception 'quota:%', q ->> 'reason'; end if;
  insert into public.incidents(user_id, device_id, device_name, source, risk_level, score, category, analysis_method, engine_version, ti_status, url_domains)
  values (p_user, p_dev, (select name from public.devices where id = p_dev), 'web', p_risk, p_score, 'kyc_bank', 'heuristic-rules vtest', 'test', p_ti, p_domains)
  returning id into v;
  return v;
end $$;

\echo '--- upgrade path (data created before migration 008)'
do $$ begin
  perform t.ok((select count(*) from public.subscriptions where user_id = '00000000-0000-0000-0000-00000000000e' and plan_code = 'trial') = 1,
               'existing account received a 7-day trial');
  perform t.ok((select status from public.incidents where risk_level = 'high' and user_id = '00000000-0000-0000-0000-00000000000e') = 'detected',
               'legacy "open" threat became "detected"');
  perform t.ok((select status from public.incidents where risk_level = 'medium' and user_id = '00000000-0000-0000-0000-00000000000e') = 'investigating',
               'legacy "acknowledged" became "investigating"');
  perform t.ok((select status from public.incidents where risk_level = 'low' and user_id = '00000000-0000-0000-0000-00000000000e') = 'no_threat',
               'legacy safe scan is not counted as a threat');
  perform t.ok((select sum(checks) from public.usage_daily where user_id = '00000000-0000-0000-0000-00000000000e') = 3,
               'legacy scans counted in lifetime usage');
end $$;

\echo '--- accounts'
select t.new_user('alice', 'alice@example.com', 'Alice Trial') \gset
select t.new_user('bob', 'bob@example.com', 'Bob Family') \gset
select t.new_user('carol', 'carol@example.com', 'Carol Business') \gset
select t.new_user('dave', 'dave@example.com', 'Dave Individual') \gset
select t.new_user('erin', 'erin@bank.example', 'Erin Enterprise') \gset
select t.new_user('admin', 'admin@scamwise.example', 'Admin') \gset
insert into public.admin_users(user_id) values (t.id('admin'));
delete from public.subscriptions where user_id = t.id('admin');
insert into auth.sessions(id, user_id, aal) values ('aaaaaaaa-0000-0000-0000-00000000aaaa', t.id('admin'), 'aal2');
insert into t.ids values ('admin_sid', 'aaaaaaaa-0000-0000-0000-00000000aaaa');

do $$ begin
  perform t.ok((select plan_code from public.subscriptions where user_id = t.id('alice')) = 'trial', 'new account starts on the trial plan');
  perform t.ok((select expires_at between now() + interval '6 days 23 hours' and now() + interval '7 days 1 minute'
                  from public.subscriptions where user_id = t.id('alice')), 'trial expires 7 days after activation');
  perform t.ok(exists (select 1 from public.subscription_events where user_id = t.id('alice') and event = 'trial_started'), 'trial start recorded');
end $$;

\echo '--- admin assigns plans (test 13: audited)'
do $$ begin
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  perform public.admin_set_subscription(t.id('bob'), 'family', now() + interval '30 days', null, null, null, 'UPI ref 1001', false);
  perform public.admin_set_subscription(t.id('carol'), 'business', now() + interval '30 days', null, null, null, 'invoice 7', false);
  perform public.admin_set_subscription(t.id('dave'), 'individual', now() + interval '30 days', null, null, null, null, false);
  perform t.ok(t.err($q$select public.admin_set_subscription(t.id('erin'), 'enterprise', now() + interval '1 year')$q$) like '%enterprise_device_limit_required%',
               'enterprise plan requires a contract device limit');
  perform public.admin_set_subscription(t.id('erin'), 'enterprise', now() + interval '1 year', null, 2, 50000, 'contract BNK-1', false);
  perform t.ok((select count(*) from public.audit_log where action = 'subscription.set' and actor_id = t.id('admin')) = 4,
               'TEST 13: every plan change is in the audit log');
  perform t.ok((select event from public.subscription_events where user_id = t.id('bob') order by id desc limit 1) = 'converted',
               'trial -> paid recorded as a conversion');
  perform public.admin_record_payment(t.id('bob'), 699, 'paid', 'upi', 'UTR123456', 'family', current_date, current_date + 30);
  perform t.ok((select verification from public.payments where user_id = t.id('bob')) = 'manual_recorded',
               'admin-entered payment is marked manual_recorded, never provider_verified');
  perform t.ok(t.err($q$select public.admin_record_payment(t.id('bob'), 699, 'paid', 'card', '4111111111111111')$q$) like '%card_number%',
               'card numbers are refused in payment references');
  perform t.login(null, null);
end $$;

\echo '--- devices (tests 3, 4, 5)'
select t.sign_in('bob_laptop', t.id('bob'), 'b0000000-0000-0000-0000-000000000001', 'Windows laptop',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36', '203.0.113.45') \gset
select t.sign_in('bob_phone', t.id('bob'), 'b0000000-0000-0000-0000-000000000002', 'Android phone',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36', '198.51.100.7') \gset
-- the phone is pending until the laptop approves it (existing pairing model); approve as the system would
update public.devices set status = 'active', approved_at = now() where id = t.id('bob_phone_dev');

do $$ declare c jsonb; begin
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  c := public.admin_customer(t.id('bob'));
  perform t.ok(jsonb_array_length(c -> 'devices') = 2, 'TEST 3: both devices appear under the same customer');
  perform t.ok(jsonb_array_length(c -> 'sessions') = 2, 'TEST 3: both login sessions are tracked separately');
  perform t.ok((select count(*) from jsonb_array_elements(c -> 'devices') d where d ->> 'device_type' = 'desktop' and d ->> 'os' = 'Windows') = 1
           and (select count(*) from jsonb_array_elements(c -> 'devices') d where d ->> 'device_type' = 'mobile' and d ->> 'os' = 'Android') = 1,
               'device type, OS and browser derived from the session user agent');
  perform t.ok((select bool_and(d ->> 'ip_prefix' in ('203.0.113.0/24', '198.51.100.0/24')) from jsonb_array_elements(c -> 'devices') d),
               'only a truncated IP prefix is stored');
  perform t.ok((select count(*) from jsonb_array_elements(c -> 'devices') d where d ->> 'session_status' = 'connected') = 2,
               'TEST 4: freshly active devices show as connected');
  perform t.login(null, null);
end $$;

-- laptop goes quiet (no heartbeat for 10 min); phone signs out
update public.devices set last_seen_at = now() - interval '10 minutes' where id = t.id('bob_laptop_dev');
do $$ declare c jsonb; begin
  perform t.login(t.id('bob'), t.id('bob_phone_sid'));
  perform public.record_sign_out();
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  c := public.admin_customer(t.id('bob'));
  perform t.ok((select d ->> 'session_status' from jsonb_array_elements(c -> 'devices') d where d ->> 'id' = t.id('bob_laptop_dev')::text) = 'idle',
               'TEST 4: a registered device without recent heartbeat is NOT shown as connected');
  perform t.ok((select d ->> 'session_status' from jsonb_array_elements(c -> 'devices') d where d ->> 'id' = t.id('bob_phone_dev')::text) = 'signed_out',
               'TEST 4: sign-out is reflected in session status');
  perform t.ok(exists (select 1 from public.login_events where user_id = t.id('bob') and kind = 'sign_out'), 'sign-out recorded in login history');
  -- heartbeat brings the laptop back
  perform t.login(t.id('bob'), t.id('bob_laptop_sid'));
  perform t.ok(public.heartbeat() = 'active', 'heartbeat accepted');
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  c := public.admin_customer(t.id('bob'));
  perform t.ok((select d ->> 'session_status' from jsonb_array_elements(c -> 'devices') d where d ->> 'id' = t.id('bob_laptop_dev')::text) = 'connected',
               'TEST 4: heartbeat updates last activity');
  -- admin revokes the laptop session
  perform public.admin_revoke_session(t.id('bob_laptop_sid'), 'lost laptop reported');
  perform t.ok(not exists (select 1 from auth.sessions where id = t.id('bob_laptop_sid')), 'admin session revoke ends the auth session');
  perform t.ok(exists (select 1 from public.login_events where kind = 'session_revoked' and user_id = t.id('bob')), 'session revoke in login history');
  perform t.ok(t.err($q$select public.admin_revoke_session(gen_random_uuid(), '')$q$) like '%reason_required%', 'revoking needs a reason');
  perform t.login(null, null);
end $$;

\echo '--- device limits per plan (test 5)'
do $$ declare i int; begin
  -- trial / individual: 1 device
  perform t.sign_in('alice1', t.id('alice'), gen_random_uuid(), 'Alice laptop', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605', '192.0.2.1');
  perform t.ok(t.err($q$select t.sign_in('alice2', t.id('alice'), gen_random_uuid(), 'Alice phone', 'iPhone', '192.0.2.2')$q$) like '%device_limit_reached:1%',
               'TEST 5: trial allows 1 device');
  perform t.sign_in('dave1', t.id('dave'), gen_random_uuid(), 'Dave PC', 'Windows NT', '192.0.2.3');
  perform t.ok(t.err($q$select t.sign_in('dave2', t.id('dave'), gen_random_uuid(), 'Dave phone', 'Android Mobile', '192.0.2.4')$q$) like '%device_limit_reached:1%',
               'TEST 5: Individual allows 1 device');
  -- family: 3 (bob has 2)
  perform t.sign_in('bob3', t.id('bob'), gen_random_uuid(), 'Bob tablet', 'iPad', '192.0.2.5');
  perform t.ok(t.err($q$select t.sign_in('bob4', t.id('bob'), gen_random_uuid(), 'Bob TV', 'Linux', '192.0.2.6')$q$) like '%device_limit_reached:3%',
               'TEST 5: Family allows 3 devices');
  -- business: 8
  for i in 1..8 loop perform t.sign_in('carol' || i, t.id('carol'), gen_random_uuid(), 'Shop PC ' || i, 'Windows NT', '192.0.2.10'); end loop;
  perform t.ok(t.err($q$select t.sign_in('carol9', t.id('carol'), gen_random_uuid(), 'Shop PC 9', 'Windows NT', '192.0.2.10')$q$) like '%device_limit_reached:8%',
               'TEST 5: Business allows 8 devices');
  -- enterprise: contract limit 2
  perform t.sign_in('erin1', t.id('erin'), gen_random_uuid(), 'Branch PC 1', 'Windows NT', '192.0.2.20');
  perform t.sign_in('erin2', t.id('erin'), gen_random_uuid(), 'Branch PC 2', 'Windows NT', '192.0.2.21');
  perform t.ok(t.err($q$select t.sign_in('erin3', t.id('erin'), gen_random_uuid(), 'Branch PC 3', 'Windows NT', '192.0.2.22')$q$) like '%device_limit_reached:2%',
               'TEST 5: Enterprise enforces its configured contract limit');
  perform t.login(null, null);
end $$;

\echo '--- trial quota (tests 6, 7, 8)'
do $$ begin
  perform t.scan(t.id('alice'), t.id('alice1_dev'), 'low', 5);
  perform t.scan(t.id('alice'), t.id('alice1_dev'), 'low', 5);
  perform t.ok(public.consume_check(t.id('alice')) ->> 'reason' = 'trial_daily_limit', 'TEST 6: third check on the same day is refused');
  perform t.ok(public.consume_check(t.id('alice')) ->> 'reason' = 'trial_daily_limit', 'TEST 7: retrying ("refreshing") is still refused');
  -- 6 more days of 2 checks (server-side day rows; the client never supplies a date)
  update public.usage_daily set day = day - 1 where user_id = t.id('alice');
  insert into public.usage_daily(user_id, day, checks, trial_checks)
  select t.id('alice'), public._ist_today() - g, 2, 2 from generate_series(2, 6) g;
  perform t.ok((select sum(trial_checks) from public.usage_daily where user_id = t.id('alice')) = 12, '12 trial checks used over 6 days');
  perform t.scan(t.id('alice'), t.id('alice1_dev'), 'low', 5);
  perform t.scan(t.id('alice'), t.id('alice1_dev'), 'low', 5);
  perform t.ok(public.consume_check(t.id('alice')) ->> 'reason' = 'trial_total_limit', 'TEST 6: 14 checks in total, then refused');
  perform t.ok(not exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'public' and p.proname = 'consume_check' and pg_get_function_arguments(p.oid) ~* 'time|date'),
               'TEST 7: the quota function takes no client-supplied time');
  update public.subscriptions set expires_at = now() - interval '1 second' where user_id = t.id('dave');
  perform t.ok(public.consume_check(t.id('dave')) ->> 'reason' = 'subscription_expired', 'expired paid plan cannot scan');
  update public.subscriptions set expires_at = now() + interval '30 days' where user_id = t.id('dave');
  update public.subscriptions set expires_at = now() - interval '1 second' where user_id = t.id('alice');
  perform t.ok(public.consume_check(t.id('alice')) ->> 'reason' = 'trial_expired', 'TEST 8: expired trial cannot scan');
  perform t.ok((public.consume_check(t.id('bob')) ->> 'allowed')::boolean, 'paid plan scans without the trial cap');
end $$;

\echo '--- client cannot bypass (test 7)'
set role authenticated;
do $$ begin perform t.login(t.id('alice'), t.id('alice1_sid')); end $$;
do $$ begin
  perform t.ok(t.err('select public.consume_check(auth.uid())') like '%permission denied%', 'TEST 7: customers cannot call the quota function');
  perform t.ok(t.err('update public.usage_daily set trial_checks = 0') like '%permission denied%', 'TEST 7: customers cannot reset usage');
  perform t.ok(t.err($q$update public.subscriptions set expires_at = now() + interval '1 year'$q$) like '%permission denied%', 'TEST 7: customers cannot extend their plan');
  perform t.ok(t.err($q$update public.profiles set account_status = 'active'$q$) like '%permission denied%', 'customers cannot change account status');
end $$;
reset role;

\echo '--- threats (tests 9, 10)'
do $$ declare d0 jsonb; d1 jsonb; a0 jsonb; a1 jsonb; i1 uuid; i2 uuid; i3 uuid; begin
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  a0 := public.admin_dashboard();
  perform t.login(t.id('carol'), t.id('carol1_sid'));
  d0 := public.my_dashboard();
  i1 := t.scan(t.id('carol'), t.id('carol1_dev'), 'high', 95, 'match', '{evil.example,sbi-kyc.example}');
  i2 := t.scan(t.id('carol'), t.id('carol1_dev'), 'medium', 55, 'no_match', '{parcel.example}');
  i3 := t.scan(t.id('carol'), t.id('carol1_dev'), 'high', 85, 'no_match', '{}');
  perform t.scan(t.id('carol'), t.id('carol1_dev'), 'low', 3, 'no_match', '{bank.example}');
  insert into t.ids values ('inc_block', i1), ('inc_resolve', i2), ('inc_open', i3);
  perform t.ok((select severity from public.incidents where id = i1) = 'critical' and (select verdict from public.incidents where id = i1) = 'malicious',
               'threat-intel match is malicious / critical');
  perform t.ok((select event from public.incident_events where incident_id = i1 order by id limit 1) = 'detected', 'detection recorded as its own event');
  -- an alert to another device is a separate recorded response
  insert into public.alerts(user_id, incident_id, target_device_id, kind, title, body) values (t.id('carol'), i1, t.id('carol2_dev'), 'incident', 'x', 'y');
  perform t.ok((select response_status from public.incidents where id = i1) = 'alert_sent', 'alert delivery recorded as response');
  perform t.ok((select status from public.incidents where id = i1) = 'detected', 'TEST 10: detecting/alerting does not resolve');
  -- block only via a real block event (service role); resolution only via an authorised action
  perform public.record_block(i1, 'navigation refused by ScamWise extension');
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  perform t.ok(t.err(format($q$select public.admin_set_incident_status(%L, 'resolved', '')$q$, i2)) like '%note_required%', 'resolving requires a note');
  perform public.admin_set_incident_status(i2, 'investigating', 'checking with customer');
  perform public.admin_set_incident_status(i2, 'resolved', 'customer confirmed no data shared; sender reported');
  perform t.ok(t.err(format($q$select public.admin_set_incident_status(%L, 'blocked', 'x')$q$, i3)) like '%bad_status%', 'admins cannot fake a block');
  a1 := public.admin_dashboard();
  perform t.login(t.id('carol'), t.id('carol1_sid'));
  d1 := public.my_dashboard();
  perform t.ok((d1 #>> '{stats,threats_detected}')::int = (d0 #>> '{stats,threats_detected}')::int + 3, 'TEST 9: threats update the customer dashboard');
  perform t.ok((a1 #>> '{threats,threats_detected}')::int = (a0 #>> '{threats,threats_detected}')::int + 3, 'TEST 9: threats update global statistics');
  perform t.ok((d1 #>> '{stats,blocked}')::int = 1 and (d1 #>> '{stats,resolved}')::int = 1 and (d1 #>> '{stats,open}')::int = 2,
               'TEST 10: blocked (1), resolved (1) and open (2: blocked + detected) counted separately');
  perform t.ok((select array_agg(event order by id) from public.incident_events where incident_id = i2)
                 = array['detected', 'user_warned', 'investigating', 'resolved'], 'incident timeline: detected -> warned -> investigating -> resolved');
  perform t.ok((d1 #>> '{stats,urls_malicious}')::int = 2 and (d1 #>> '{stats,urls_safe}')::int = 1, 'URL verdict counts');
  perform t.login(null, null);
end $$;

\echo '--- isolation (tests 11, 12)'
update public.devices set status = 'active' where id = t.id('bob3_dev');
set role authenticated;
do $$ begin perform t.login(t.id('bob'), t.id('bob3_sid')); end $$;
do $$ begin
  perform t.ok((select count(*) from public.incidents where user_id <> auth.uid()) = 0, 'TEST 11: RLS hides other customers'' scans');
  perform t.ok((select count(*) from public.devices where user_id <> auth.uid()) = 0, 'TEST 11: RLS hides other customers'' devices');
  perform t.ok((public.my_dashboard() #>> '{stats,scans}')::int = (select count(*) from public.incidents), 'TEST 11: dashboard is own data only');
  perform t.ok(t.err(format($q$select public.set_incident_status(%L, 'resolved')$q$, t.id('inc_open'))) like '%not_found%',
               'TEST 11: cannot change another customer''s incident by id');
  perform t.ok(t.err('select * from public.subscriptions') like '%permission denied%', 'TEST 11: no direct table access to subscriptions');
  perform t.ok(t.err('select * from public.payments') like '%permission denied%', 'TEST 11: no direct table access to payments');
  perform t.ok(t.err(format('select public.admin_customer(%L)', t.id('carol'))) like '%admin_required%', 'TEST 12: customers cannot call admin APIs');
end $$;
do $$ begin perform t.login(t.id('admin'), t.id('admin_sid'), 'aal1'); end $$;
do $$ begin
  perform t.ok(t.err('select public.admin_dashboard()') like '%admin_required%', 'TEST 12: admin without MFA (aal1) is refused');
end $$;
reset role;
set role anon;
do $$ begin
  perform t.ok(t.err('select public.admin_dashboard()') like '%permission denied%', 'TEST 12: anonymous callers cannot execute admin APIs');
  perform t.ok(t.err('select public.my_dashboard()') like '%permission denied%', 'anonymous callers cannot read dashboards');
end $$;
reset role;

\echo '--- admin views (tests 1, 2)'
do $$ declare r jsonb; a jsonb; ts jsonb; begin
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  a := public.admin_dashboard();
  perform t.ok((a ->> 'customers_total')::int = (select count(*) from public.profiles) - 1, 'TEST 1: customer count from real data (admins excluded)');
  perform t.ok((a ->> 'premium_active')::int = 4 and (a ->> 'trial_expired')::int = 1, 'TEST 1: premium (bob, carol, dave, erin) and expired trial (alice)');
  perform t.ok((a ->> 'devices_registered')::int = (select count(*) from public.devices where status <> 'revoked'), 'TEST 1: device totals');
  perform t.ok((a #>> '{revenue,paid_manual}')::numeric = 699 and (a #>> '{revenue,paid_verified}')::numeric = 0,
               'TEST 1: revenue separates provider-verified from manually recorded');
  perform t.ok((a ->> 'mrr_inr')::int = 699 + 1899 + 299 + 50000, 'MRR from active plan prices');
  r := public.admin_customers('carol');
  perform t.ok((r ->> 'total')::int = 1 and r #>> '{rows,0,email}' = 'carol@example.com', 'TEST 2: search finds the customer');
  perform t.ok((r #>> '{rows,0,devices}')::int = 8 and (r #>> '{rows,0,threats}')::int = 3, 'TEST 2: list shows devices and threats');
  r := public.admin_customers(null, null, null, null, null, 'with_threats', 'threats', true, 2, 0);
  perform t.ok(jsonb_array_length(r -> 'rows') <= 2, 'pagination limit applied');
  perform t.ok(public.admin_customer(t.id('carol')) #>> '{profile,email}' = 'carol@example.com', 'TEST 2: customer dashboard opens');
  perform t.ok(t.err($q$select public.admin_customers(null, null, null, null, null, null, 'email; drop table x')$q$) like '%bad_sort%', 'sort column whitelisted');
  ts := public.admin_timeseries(now() - interval '7 days', now(), 'day');
  perform t.ok(jsonb_array_length(ts) = 8 and (ts -> -1 ->> 'threats')::int >= 3, 'daily analytics series');
  perform t.ok(jsonb_array_length(public.admin_timeseries(now() - interval '90 days', now(), 'month')) between 3 and 4, 'monthly analytics series');
  perform t.ok((public.admin_incidents(null, null, 'critical') ->> 'total')::int >= 1, 'incident filter by severity');
  perform t.ok(jsonb_array_length(public.admin_incident(t.id('inc_resolve')) -> 'events') = 4, 'incident detail with full timeline');
  -- suspension
  perform public.admin_suspend_account(t.id('dave'), 'chargeback investigation');
  perform t.ok(public.consume_check(t.id('dave')) ->> 'reason' = 'account_suspended', 'suspended account cannot scan');
  perform t.ok((select banned_until from auth.users where id = t.id('dave')) = 'infinity', 'suspended account cannot sign in');
  perform public.admin_reactivate_account(t.id('dave'), 'resolved');
  perform public.admin_subscription_action(t.id('dave'), 'suspend', 'payment dispute');
  perform t.ok(public.consume_check(t.id('dave')) ->> 'reason' = 'subscription_suspended', 'suspended subscription cannot scan');
  perform public.admin_subscription_action(t.id('dave'), 'reactivate', 'dispute closed');
  perform t.ok((public.consume_check(t.id('dave')) ->> 'allowed')::boolean, 'reactivated subscription works');
  perform t.ok((select count(*) from public.audit_log where action in ('account.suspend', 'account.reactivate', 'subscription.suspend', 'subscription.reactivate', 'session.revoke', 'incident.set_status')) >= 7,
               'TEST 13: admin security actions are audited');
  perform t.login(null, null);
end $$;

\echo '--- organisations (enterprise pooled limit + org view)'
do $$ declare o uuid; begin
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  o := public.admin_save_org(null, 'Example Bank', 'enterprise', 3, 'BNK-1');
  perform public.admin_set_org_member(o, 'erin@bank.example', 'owner');
  perform public.admin_set_org_member(o, 'dave@example.com', 'member');
  perform t.ok((public._device_quota(t.id('erin')) ->> 'used')::int = 3 and (public._device_quota(t.id('erin')) ->> 'pooled')::boolean,
               'org device limit is pooled across members');
  perform t.login(t.id('erin'), t.id('erin1_sid'));
  perform t.ok(jsonb_array_length(public.my_org() -> 'members') = 2, 'org owner sees member summary');
  -- suspension ended Dave's sessions: he signs in again on the same browser install
  perform t.ok((select session_id from public.devices where id = t.id('dave1_dev')) is null, 'suspension signed the device out');
  perform t.sign_in('dave1b', t.id('dave'), (select install_id from public.devices where id = t.id('dave1_dev')), 'Dave PC', 'Windows NT', '192.0.2.3');
  perform t.ok(t.id('dave1b_dev') = t.id('dave1_dev'), 're-sign-in re-binds the same device record (no duplicate)');
  perform t.ok(public.my_org() -> 'members' is null, 'org members do not see other members');
  perform t.login(null, null);
end $$;

\echo '--- existing features still work (test 15)'
do $$ declare code text; b uuid; begin
  -- pairing flow from the original release, now under a plan limit
  perform t.login(t.id('admin'), t.id('admin_sid'), 'aal2');
  perform public.admin_set_subscription(t.id('bob'), 'family', now() + interval '30 days', null, null, null, 'renewal', false);
  perform t.ok((select event from public.subscription_events where user_id = t.id('bob') order by id desc limit 1) = 'renewed', 'renewal recorded');
  perform t.login(t.id('bob'), t.id('bob3_sid'));
  perform public.revoke_device(t.id('bob_phone_dev'));
  perform t.ok((select status from public.devices where id = t.id('bob_phone_dev')) = 'revoked', 'user can unlink a device');
  perform t.ok(exists (select 1 from public.login_events where kind = 'device_unlinked' and device_id = t.id('bob_phone_dev')), 'unlink recorded as a disconnection');
  perform t.ok((public.create_pairing_code() ->> 'code') is not null, 'pairing code creation still works');
  perform t.ok(public.request_plan('business', 'need more devices') ->> 'status' = 'open', 'customer can request an upgrade');
  perform t.ok((public.my_subscription() ->> 'plan') = 'family', 'customer sees own subscription');
  perform t.ok(jsonb_array_length(public.my_dashboard() -> 'plans') = 4, 'upgrade options list the four paid plans');
  perform t.login(null, null);
  perform t.ok((public.run_retention() ->> 'expired_logged')::int >= 1, 'retention job records expiries');
end $$;
\echo 'ALL ACCEPTANCE CHECKS PASSED'
