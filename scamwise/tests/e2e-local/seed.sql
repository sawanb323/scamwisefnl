-- E2E seed: realistic data created through the real functions (no hand-written aggregates).
\set ON_ERROR_STOP 1
create or replace function pg_temp.login(p_uid uuid, p_sid uuid) returns void language sql as $$
  select set_config('request.uid', p_uid::text, false), set_config('request.jwt', json_build_object('session_id', p_sid, 'aal', 'aal1')::text, false) $$;
create or replace function pg_temp.device(p_email text, p_name text, p_ua text, p_ip inet) returns uuid language plpgsql as $$
declare u uuid; s uuid; d uuid;
begin
  select id into u from auth.users where email = p_email;
  insert into auth.sessions(user_id, user_agent, ip) values (u, p_ua, p_ip) returning id into s;
  perform pg_temp.login(u, s);
  select (public.register_device(gen_random_uuid(), p_name, 'web', '2.1.0')).id into d;
  update public.devices set status = 'active', approved_at = now() where id = d;
  return d;
end $$;
create or replace function pg_temp.scan(p_dev uuid, p_risk text, p_score int, p_ti text, p_cat text, p_domains text[], p_ago interval) returns uuid language plpgsql as $$
declare u uuid; i uuid; q json;
begin
  select user_id into u from public.devices where id = p_dev;
  q := public.consume_check(u);
  if not (q ->> 'allowed')::boolean then raise exception 'quota %', q; end if;
  insert into public.incidents(user_id, device_id, device_name, source, risk_level, score, category, indicators, analysis_method, engine_version, ti_status, url_domains, created_at)
  values (u, p_dev, (select name from public.devices where id = p_dev), 'web', p_risk, p_score, p_cat,
          '[{"code":"brand_lookalike","label":"Brand name on an unofficial domain","weight":30,"family":"suspicious_link"},{"code":"urgency","label":"Threatens to block your account","weight":20,"family":"pressure"}]',
          'heuristic-rules v3', '3', p_ti, p_domains, now() - p_ago)
  returning id into i;
  return i;
end $$;

insert into auth.users(email, email_confirmed_at, raw_user_meta_data, created_at) values
 ('alice@example.com', now(), '{"full_name":"Alice Sharma"}', now() - interval '1 day'),
 ('bob@example.com', now(), '{"full_name":"Bob Mehta"}', now() - interval '12 days'),
 ('carol@shop.example', now(), '{"full_name":"Carol D''Souza"}', now() - interval '40 days'),
 ('erin@bank.example', now(), '{"full_name":"Erin Rao"}', now() - interval '60 days'),
 ('frank@example.com', null, '{"full_name":"Frank Iyer"}', now() - interval '20 days'),
 ('admin@scamwise.example', now(), '{"full_name":"Security Admin"}', now() - interval '90 days');
insert into public.admin_users(user_id) select id from auth.users where email = 'admin@scamwise.example';
delete from public.subscriptions where user_id in (select user_id from public.admin_users);
insert into auth.mfa_factors(user_id, status) select user_id, 'verified' from public.admin_users;
-- frank's trial ran out
update public.subscriptions set started_at = now() - interval '20 days', expires_at = now() - interval '13 days',
  trial_started_at = now() - interval '20 days', trial_expires_at = now() - interval '13 days'
 where user_id = (select id from auth.users where email = 'frank@example.com');

-- admin actions (as an MFA-verified admin)
select set_config('request.uid', (select user_id::text from public.admin_users limit 1), false),
       set_config('request.jwt', '{"session_id":"00000000-0000-0000-0000-0000000000aa","aal":"aal2"}', false);
select public.admin_set_subscription((select id from auth.users where email = 'carol@shop.example'), 'business', now() + interval '20 days', now() - interval '10 days', null, null, 'Invoice INV-2026-104', false);
select public.admin_set_subscription((select id from auth.users where email = 'erin@bank.example'), 'enterprise', now() + interval '300 days', now() - interval '65 days', 12, 45000, 'Contract BNK-77', false);
select public.admin_record_payment((select id from auth.users where email = 'carol@shop.example'), 1899, 'paid', 'upi', 'UTR40211', 'business', current_date - 10, current_date + 20);
select public.admin_record_payment((select id from auth.users where email = 'erin@bank.example'), 45000, 'paid', 'bank_transfer', 'NEFT-99812', 'enterprise', current_date - 35, current_date - 5);
select public.admin_record_payment((select id from auth.users where email = 'erin@bank.example'), 45000, 'failed', 'bank_transfer', 'NEFT-99977', 'enterprise', current_date - 5, current_date + 25, 'Beneficiary account mismatch');
select public.admin_save_org(null, 'Example Bank Ltd', 'enterprise', 12, 'BNK-77');
select public.admin_set_org_member((select id from public.organizations limit 1), 'erin@bank.example', 'owner');

-- devices and scans
select pg_temp.device('carol@shop.example', 'Counter PC', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36', '203.0.113.10') as carol_pc \gset
select pg_temp.device('carol@shop.example', 'Carol''s iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1', '198.51.100.20') as carol_phone \gset
select pg_temp.device('erin@bank.example', 'Branch terminal 1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/130.0', '192.0.2.40') as erin_pc \gset
select pg_temp.scan(:'carol_pc', 'high', 96, 'match', 'kyc_bank', '{sbi-kyc-update.xyz}', '2 hours') as i1 \gset
select pg_temp.scan(:'carol_phone', 'high', 82, 'no_match', 'digital_arrest', '{}', '1 day') as i2 \gset
select pg_temp.scan(:'carol_pc', 'medium', 55, 'no_match', 'delivery', '{indiapost-track.top}', '3 days') as i3 \gset
select pg_temp.scan(:'carol_pc', 'low', 4, 'no_match', 'none', '{amazon.in}', '4 days');
select pg_temp.scan(:'carol_phone', 'medium', 48, 'not_applicable', 'job_scam', '{}', '9 days') as i4 \gset
select pg_temp.scan(:'erin_pc', 'high', 91, 'no_match', 'kyc_bank', '{hdfc-netbank-verify.co}', '5 hours');
select pg_temp.scan(:'erin_pc', 'low', 8, 'no_match', 'none', '{hdfcbank.com}', '6 hours');
insert into public.alerts(user_id, incident_id, target_device_id, kind, title, body, risk_level)
select user_id, :'i1', :'carol_phone', 'incident', 'New high-risk incident detected', 'Bank / KYC phishing · score 96/100 · scanned on "Counter PC".', 'high' from public.incidents where id = :'i1';
select set_config('request.uid', (select user_id::text from public.admin_users limit 1), false),
       set_config('request.jwt', '{"session_id":"00000000-0000-0000-0000-0000000000aa","aal":"aal2"}', false);
select public.admin_set_incident_status(:'i3', 'investigating', 'Asked the customer whether the tracking link was opened');
select public.admin_set_incident_status(:'i4', 'resolved', 'Customer confirmed no deposit was paid; sender number reported to 1930');
select public.record_block(:'i2', 'Navigation refused by browser extension (test fixture)');
insert into public.feedback(name, email, kind, message) values ('Ravi', 'ravi@example.com', 'business', 'We would like the Business plan for 6 shop PCs.');
-- seeded scans were back-dated: rebuild their daily usage rows on their real IST days
delete from public.usage_daily;
insert into public.usage_daily(user_id, day, checks, trial_checks, threats)
select i.user_id, (i.created_at at time zone 'Asia/Kolkata')::date, count(*),
       count(*) filter (where s.plan_code = 'trial'), count(*) filter (where i.verdict in ('suspicious','malicious'))
  from public.incidents i join public.subscriptions s on s.user_id = i.user_id group by 1, 2;
