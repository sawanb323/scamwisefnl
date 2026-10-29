-- SCAMWISE database security test (self-rolling-back).
-- Simulates two accounts / three sessions by setting JWT claims, exactly as PostgREST does.
-- Run in the Supabase SQL editor. It always ends with an exception that carries the report,
-- which rolls back every row it created.
do $test$
declare
  u1 uuid := gen_random_uuid(); u2 uuid := gen_random_uuid(); u3 uuid := gen_random_uuid();
  s1a uuid := gen_random_uuid(); s1b uuid := gen_random_uuid(); s2 uuid := gen_random_uuid(); s3 uuid := gen_random_uuid();
  ia uuid := gen_random_uuid(); ib uuid := gen_random_uuid(); i2 uuid := gen_random_uuid();
  log text := ''; v text; j json; n int; code text; pid uuid; dev_b uuid; dev_a uuid; inc uuid;
  pass int := 0; fail int := 0;
begin
  -- fixtures (as table owner)
  insert into auth.users(id, phone, aud, role) values (u1, '919800000001', 'authenticated', 'authenticated'),
                                                      (u2, '919800000002', 'authenticated', 'authenticated');
  insert into auth.users(id, email, aud, role) values (u3, 'admin-test@example.invalid', 'authenticated', 'authenticated');
  insert into auth.sessions(id, user_id) values (s1a, u1), (s1b, u1), (s2, u2), (s3, u3);

  -- helper pattern: set claims, switch role, act, reset role
  ---------------------------------------------------------------- T1 first device auto-active
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1a,'aal','aal1')::text, true);
  set local role authenticated;
  select (public.register_device(ia, 'Phone A', 'android', '1.0.0')).status::text into v;
  reset role;
  if v = 'active' then pass := pass+1; log := log || E'\nPASS T1 first device is active'; else fail := fail+1; log := log || E'\nFAIL T1 got '||v; end if;
  select id into dev_a from public.devices where install_id = ia;

  ---------------------------------------------------------------- T2 second device pending, sees only itself, no data
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1b,'aal','aal1')::text, true);
  set local role authenticated;
  select (public.register_device(ib, 'Phone B', 'android', '1.0.0')).status::text into v;
  select count(*) into n from public.devices;
  reset role;
  if v = 'pending' and n = 1 then pass := pass+1; log := log || E'\nPASS T2 second device pending and sees only itself';
  else fail := fail+1; log := log || format(E'\nFAIL T2 status=%s visible=%s', v, n); end if;
  select id into dev_b from public.devices where install_id = ib;

  ---------------------------------------------------------------- T3 phone A creates pairing code
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1a,'aal','aal1')::text, true);
  set local role authenticated;
  j := public.create_pairing_code(); code := j->>'code'; pid := (j->>'id')::uuid;
  reset role;
  if length(code) = 8 and not exists (select 1 from public.pairing_secrets where code_hash = code)
    then pass := pass+1; log := log || E'\nPASS T3 8-char code issued, only its hash stored';
    else fail := fail+1; log := log || E'\nFAIL T3'; end if;

  ---------------------------------------------------------------- T4 other account cannot use the code or see account 1
  perform set_config('request.jwt.claims', json_build_object('sub',u2,'role','authenticated','session_id',s2,'aal','aal1')::text, true);
  set local role authenticated;
  perform public.register_device(i2, 'Other person', 'android', '1.0.0');
  select count(*) into n from public.devices where user_id = u1;
  begin
    j := public.claim_pairing_code(code); v := coalesce(j->>'error', 'claimed?!');
  exception when others then v := sqlerrm; end;
  reset role;
  if n = 0 and v <> 'claimed?!' then pass := pass+1; log := log || E'\nPASS T4 cross-account: 0 rows visible, claim refused ('||v||')';
  else fail := fail+1; log := log || format(E'\nFAIL T4 n=%s v=%s', n, v); end if;

  ---------------------------------------------------------------- T5 wrong code rejected, right code claimed
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1b,'aal','aal1')::text, true);
  set local role authenticated;
  begin j := public.claim_pairing_code('WRONG123'); v := coalesce(j->>'error', 'accepted?!'); exception when others then v := sqlerrm; end;
  j := public.claim_pairing_code(lower(code));
  reset role;
  if v = 'invalid_or_expired_code' and j->>'status' = 'claimed' then pass := pass+1; log := log || E'\nPASS T5 wrong code refused, correct code claimed';
  else fail := fail+1; log := log || format(E'\nFAIL T5 v=%s j=%s', v, j); end if;

  ---------------------------------------------------------------- T6 code is single use
  set local role authenticated;
  begin j := public.claim_pairing_code(code); v := coalesce(j->>'error', 'reused?!'); exception when others then v := sqlerrm; end;
  reset role;
  if v <> 'reused?!' then pass := pass+1; log := log || E'\nPASS T6 code cannot be reused ('||v||')'; else fail := fail+1; log := log || E'\nFAIL T6'; end if;

  ---------------------------------------------------------------- T16 wrong-code lockout really triggers (attempts are committed)
  -- B already has 2 failed attempts (T5 wrong code, T6 reused code); 3 more reach the limit of 5
  set local role authenticated;
  for n in 1..3 loop j := public.claim_pairing_code('BADCODE' || n); end loop;
  begin j := public.claim_pairing_code('BADCODE9'); v := coalesce(j->>'error', 'no lockout?!'); exception when others then v := sqlerrm; end;
  reset role;
  if v = 'too_many_attempts' and (select count(*) from public.pairing_attempts where device_id = dev_b and not ok) >= 5
    then pass := pass+1; log := log || E'\nPASS T16 5 wrong codes lock the device out for 15 minutes';
    else fail := fail+1; log := log || E'\nFAIL T16 '||v; end if;

  ---------------------------------------------------------------- T7 still pending until A approves; pending device cannot approve itself
  set local role authenticated;
  begin perform public.respond_pairing(pid, true); v := 'self-approved?!'; exception when others then v := sqlerrm; end;
  reset role;
  if v = 'device_not_active' and (select status from public.devices where id = dev_b) = 'pending'
    then pass := pass+1; log := log || E'\nPASS T7 pending device cannot approve itself';
    else fail := fail+1; log := log || E'\nFAIL T7 '||v; end if;

  ---------------------------------------------------------------- T8 A approves -> B active
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1a,'aal','aal1')::text, true);
  set local role authenticated;
  j := public.respond_pairing(pid, true);
  reset role;
  if (select status from public.devices where id = dev_b) = 'active' then pass := pass+1; log := log || E'\nPASS T8 explicit approval activates phone B';
  else fail := fail+1; log := log || E'\nFAIL T8'; end if;

  ---------------------------------------------------------------- T9 incident + alert reach only B; account 2 sees nothing
  insert into public.incidents(user_id, device_id, device_name, risk_level, score, category, analysis_method, engine_version, ti_status, contained_auth_code)
  values (u1, dev_a, 'Phone A', 'high', 85, 'phishing', 'heuristic', 'test', 'not_configured', true) returning id into inc;
  insert into public.alerts(user_id, incident_id, target_device_id, kind, title, body, risk_level)
  values (u1, inc, dev_b, 'incident', 'High-risk incident', 'test', 'high');
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1b,'aal','aal1')::text, true);
  set local role authenticated;
  select count(*) into n from public.alerts;
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub',u2,'role','authenticated','session_id',s2,'aal','aal1')::text, true);
  set local role authenticated;
  select (select count(*) from public.incidents) + (select count(*) from public.alerts) into v;
  reset role;
  if n = 1 and v = '0' then pass := pass+1; log := log || E'\nPASS T9 alert visible to phone B only; other account sees 0';
  else fail := fail+1; log := log || format(E'\nFAIL T9 n=%s other=%s', n, v); end if;

  ---------------------------------------------------------------- T10 ordinary user cannot call admin functions
  set local role authenticated;
  begin perform public.admin_overview(); v := 'allowed?!'; exception when others then v := sqlerrm; end;
  reset role;
  if v = 'admin_required' then pass := pass+1; log := log || E'\nPASS T10 ordinary user blocked from admin RPC';
  else fail := fail+1; log := log || E'\nFAIL T10 '||v; end if;

  ---------------------------------------------------------------- T11 admin needs membership AND MFA (aal2)
  insert into public.admin_users(user_id) values (u3);
  perform set_config('request.jwt.claims', json_build_object('sub',u3,'role','authenticated','session_id',s3,'aal','aal1')::text, true);
  set local role authenticated;
  begin perform public.admin_overview(); v := 'allowed'; exception when others then v := sqlerrm; end;
  perform set_config('request.jwt.claims', json_build_object('sub',u3,'role','authenticated','session_id',s3,'aal','aal2')::text, true);
  select count(*) into n from public.admin_list_incidents(50, null);
  reset role;
  if v = 'admin_required' and n >= 1 then pass := pass+1; log := log || E'\nPASS T11 admin blocked at aal1, allowed at aal2 (MFA)';
  else fail := fail+1; log := log || format(E'\nFAIL T11 aal1=%s n=%s', v, n); end if;

  ---------------------------------------------------------------- T12 admin cannot read tables directly (only via audited RPCs)
  set local role authenticated;
  select count(*) into n from public.incidents;
  reset role;
  if n = 0 then pass := pass+1; log := log || E'\nPASS T12 admin has no direct table access to user incidents';
  else fail := fail+1; log := log || E'\nFAIL T12 n='||n; end if;

  ---------------------------------------------------------------- T13 revoke B -> session killed, data access gone
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1a,'aal','aal1')::text, true);
  set local role authenticated;
  perform public.revoke_device(dev_b);
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub',u1,'role','authenticated','session_id',s1b,'aal','aal1')::text, true);
  set local role authenticated;
  select (select count(*) from public.incidents) + (select count(*) from public.alerts) + (select count(*) from public.profiles) into n;
  v := public.heartbeat();
  reset role;
  if n = 0 and not exists (select 1 from auth.sessions where id = s1b)
    then pass := pass+1; log := log || E'\nPASS T13 revoked device: auth session deleted, 0 rows readable (heartbeat='||v||')';
    else fail := fail+1; log := log || format(E'\nFAIL T13 n=%s', n); end if;

  ---------------------------------------------------------------- T14 anon role cannot call RPCs or read feedback; can submit feedback
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  begin perform public.register_device(gen_random_uuid(), 'x'); v := 'allowed?!'; exception when others then v := sqlerrm; end;
  insert into public.feedback(message) values ('test feedback from anon');
  begin select count(*) into n from public.feedback; exception when others then n := -1; end;
  reset role;
  if v like 'permission denied%' and n = -1 then pass := pass+1; log := log || E'\nPASS T14 anon: RPC denied, feedback write-only';
  else fail := fail+1; log := log || format(E'\nFAIL T14 v=%s n=%s', v, n); end if;

  ---------------------------------------------------------------- T15 admin audit trail recorded
  if exists (select 1 from public.audit_log where action = 'device.revoke' and target_id = dev_b::text)
     and exists (select 1 from public.audit_log where action = 'pairing.approve')
    then pass := pass+1; log := log || E'\nPASS T15 audit trail has pairing + revoke events';
    else fail := fail+1; log := log || E'\nFAIL T15'; end if;

  raise exception 'TEST REPORT (rolled back): % passed, % failed%', pass, fail, log;
end
$test$;
