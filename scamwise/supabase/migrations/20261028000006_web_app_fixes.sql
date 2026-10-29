-- SCAMWISE web-app release fixes
--
-- 1. FIX: wrong pairing-code attempts were never counted.
--    The old claim_pairing_code() inserted a row into pairing_attempts and then RAISED
--    'invalid_or_expired_code'. Raising rolls back the whole call, including that insert,
--    so the "5 wrong tries per 15 minutes" limit could never trigger (unlimited guessing).
--    A wrong code now RETURNS {"status":"rejected","error":"invalid_or_expired_code"}
--    so the attempt row is committed and the lockout works.
--
-- 2. Devices are now web browsers, not Android phones: default device name updated.

create or replace function public.claim_pairing_code(p_code text)
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_dev public.devices;
  v_pid uuid;
  v_norm text := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
begin
  select * into v_dev from public.devices
   where user_id = auth.uid() and session_id = public.jwt_session_id();
  if not found then raise exception 'device_not_registered' using errcode = '42501'; end if;
  if v_dev.status = 'active' then raise exception 'device_already_active' using errcode = 'P0001'; end if;
  if v_dev.status = 'revoked' then raise exception 'device_revoked' using errcode = '42501'; end if;

  if (select count(*) from public.pairing_attempts
       where device_id = v_dev.id and not ok and created_at > now() - interval '15 minutes') >= 5 then
    raise exception 'too_many_attempts' using errcode = 'P0001';
  end if;

  update public.pairing_codes set status = 'expired'
   where user_id = auth.uid() and status = 'open' and expires_at < now();

  select pc.id into v_pid
    from public.pairing_codes pc join public.pairing_secrets ps on ps.pairing_id = pc.id
   where pc.user_id = auth.uid()                       -- codes never cross accounts
     and pc.status = 'open' and pc.expires_at > now()
     and ps.code_hash = encode(extensions.digest(v_norm, 'sha256'), 'hex')
   for update of pc;

  insert into public.pairing_attempts(device_id, ok) values (v_dev.id, v_pid is not null);
  if v_pid is null then
    -- do NOT raise here: raising would roll back the attempt row above
    return json_build_object('status', 'rejected', 'error', 'invalid_or_expired_code');
  end if;

  update public.pairing_codes
     set status = 'claimed', claimed_by_device = v_dev.id, claimed_device_name = v_dev.name, claimed_at = now()
   where id = v_pid;
  delete from public.pairing_secrets where pairing_id = v_pid;   -- single use

  insert into public.alerts(user_id, target_device_id, kind, title, body)
  select auth.uid(), d.id, 'pairing', 'Approve new device?',
         format('"%s" wants to join your SCAMWISE account. Open Devices to approve or reject.', v_dev.name)
    from public.devices d where d.user_id = auth.uid() and d.status = 'active';

  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id)
  values (auth.uid(), 'user', 'pairing.claim', 'pairing', v_pid::text);
  return json_build_object('pairing_id', v_pid, 'status', 'claimed');
end $$;

alter table public.devices alter column name set default 'Web browser';

revoke execute on function public.claim_pairing_code(text) from public, anon;
grant execute on function public.claim_pairing_code(text) to authenticated;
