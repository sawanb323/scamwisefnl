-- SCAMWISE RPCs. Every function re-checks identity server-side.

-- ================================================================ devices
-- Register (or re-bind) this app install to the caller's current auth session.
-- First device on an account becomes ACTIVE; any further device is PENDING until an
-- active device approves it through the pairing flow.
create or replace function public.register_device(
  p_install_id uuid, p_name text, p_platform text default null, p_app_version text default null)
returns public.devices language plpgsql security definer set search_path = '' as $$
declare
  v_uid  uuid := auth.uid();
  v_sid  uuid := public.jwt_session_id();
  v_dev  public.devices;
  v_active_count int;
begin
  if v_uid is null or v_sid is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;
  if exists (select 1 from public.admin_users where user_id = v_uid) then
    raise exception 'admin_accounts_cannot_register_devices' using errcode = '42501';
  end if;

  -- a session can only be bound to one device
  update public.devices set session_id = null
   where session_id = v_sid and not (user_id = v_uid and install_id = p_install_id);

  select * into v_dev from public.devices where user_id = v_uid and install_id = p_install_id;

  select count(*) into v_active_count from public.devices where user_id = v_uid and status = 'active';

  if v_dev.id is not null then
    update public.devices set
      session_id   = v_sid,
      name         = coalesce(nullif(trim(p_name), ''), name),
      platform     = coalesce(p_platform, platform),
      app_version  = coalesce(p_app_version, app_version),
      last_seen_at = now(),
      -- a revoked install must be re-approved (or re-activated if no active device remains)
      status       = case when status = 'revoked'
                          then (case when v_active_count = 0 then 'active' else 'pending' end)::public.device_status
                          else status end,
      revoked_at   = case when status = 'revoked' then null else revoked_at end,
      approved_at  = case when status = 'revoked' and v_active_count = 0 then now() else approved_at end
    where id = v_dev.id
    returning * into v_dev;
  else
    if (select count(*) from public.devices where user_id = v_uid and status <> 'revoked') >= 5 then
      raise exception 'device_limit_reached' using errcode = 'P0001';
    end if;
    insert into public.devices (user_id, install_id, session_id, name, platform, app_version,
                                status, is_primary, approved_at, last_seen_at)
    values (v_uid, p_install_id, v_sid, coalesce(nullif(trim(p_name), ''), 'Android phone'),
            p_platform, p_app_version,
            case when v_active_count = 0 then 'active' else 'pending' end::public.device_status,
            v_active_count = 0,
            case when v_active_count = 0 then now() end,
            now())
    returning * into v_dev;
  end if;

  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (v_uid, 'user', 'device.register', 'device', v_dev.id::text, jsonb_build_object('status', v_dev.status));
  return v_dev;
end $$;

-- The device bound to this session, whatever its status (lets a pending/revoked phone learn its state)
create or replace function public.my_device()
returns public.devices language sql stable security definer set search_path = '' as $$
  select * from public.devices
  where user_id = auth.uid() and session_id = public.jwt_session_id()
  limit 1
$$;

-- Heartbeat: marks this device as seen; returns its status
create or replace function public.heartbeat()
returns text language plpgsql security definer set search_path = '' as $$
declare v_status public.device_status;
begin
  update public.devices set last_seen_at = now()
   where user_id = auth.uid() and session_id = public.jwt_session_id()
  returning status into v_status;
  return coalesce(v_status::text, 'unregistered');
end $$;

create or replace function public.rename_device(p_device uuid, p_name text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if public.current_device_id() is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  update public.devices set name = left(trim(p_name), 60)
   where id = p_device and user_id = auth.uid();
end $$;

-- internal: revoke a device and kill its auth session (refresh token stops working)
create or replace function public._revoke_device(p_device uuid, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_old_sid uuid;
begin
  select session_id into v_old_sid from public.devices where id = p_device for update;
  update public.devices
     set status = 'revoked', revoked_at = now(), revoked_reason = left(p_reason, 200), session_id = null
   where id = p_device;
  -- kill the bound auth session: its refresh token stops working immediately, and the
  -- still-valid access token no longer maps to an active device, so RLS denies everything.
  if v_old_sid is not null then
    delete from auth.sessions where id = v_old_sid;
  end if;
  delete from public.alerts where target_device_id = p_device and read_at is null;
end $$;
revoke all on function public._revoke_device(uuid, text) from public, anon, authenticated;

-- User revokes one of their own devices (including this one = "unlink this phone")
create or replace function public.revoke_device(p_device uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.current_device_id(); v_target public.devices;
begin
  select * into v_target from public.devices where id = p_device and user_id = auth.uid();
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  -- an active device may revoke any of the account's devices; a pending device may only remove itself
  if v_me is null and v_target.session_id is distinct from public.jwt_session_id() then
    raise exception 'device_not_active' using errcode = '42501';
  end if;
  perform public._revoke_device(p_device, 'revoked_by_user');
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id)
  values (auth.uid(), 'user', 'device.revoke', 'device', p_device::text);
  -- tell the account's other active devices
  insert into public.alerts(user_id, target_device_id, kind, title, body)
  select auth.uid(), d.id, 'device', 'Device unlinked',
         format('"%s" was unlinked from your SCAMWISE account.', v_target.name)
    from public.devices d
   where d.user_id = auth.uid() and d.status = 'active' and d.id <> p_device;
end $$;

-- ================================================================ pairing
-- Step 1 (active phone A): create a short-lived, single-use code
create or replace function public.create_pairing_code()
returns json language plpgsql security definer set search_path = '' as $$
declare
  v_me uuid := public.current_device_id();
  v_alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_code text := '';
  v_bytes bytea := extensions.gen_random_bytes(8);
  v_id uuid;
  v_exp timestamptz := now() + interval '10 minutes';
  i int;
begin
  if v_me is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  if (select count(*) from public.pairing_codes
       where user_id = auth.uid() and created_at > now() - interval '1 hour') >= 10 then
    raise exception 'too_many_codes' using errcode = 'P0001';
  end if;
  update public.pairing_codes set status = 'cancelled'
   where user_id = auth.uid() and status = 'open';
  for i in 0..7 loop
    v_code := v_code || substr(v_alphabet, (get_byte(v_bytes, i) % length(v_alphabet)) + 1, 1);
  end loop;
  insert into public.pairing_codes(user_id, created_by_device, expires_at)
  values (auth.uid(), v_me, v_exp) returning id into v_id;
  insert into public.pairing_secrets(pairing_id, code_hash)
  values (v_id, encode(extensions.digest(v_code, 'sha256'), 'hex'));
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id)
  values (auth.uid(), 'user', 'pairing.create', 'pairing', v_id::text);
  return json_build_object('id', v_id, 'code', v_code, 'expires_at', v_exp);
end $$;

-- Step 2 (pending phone B, signed in to the same account): claim the code
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
  if v_pid is null then raise exception 'invalid_or_expired_code' using errcode = 'P0001'; end if;

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

-- Step 3 (active phone A): explicitly approve or reject
create or replace function public.respond_pairing(p_pairing uuid, p_approve boolean)
returns json language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.current_device_id(); v_pc public.pairing_codes;
begin
  if v_me is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  select * into v_pc from public.pairing_codes
   where id = p_pairing and user_id = auth.uid() for update;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  if v_pc.status <> 'claimed' then raise exception 'not_awaiting_approval' using errcode = 'P0001'; end if;
  if v_pc.claimed_at < now() - interval '15 minutes' then
    update public.pairing_codes set status = 'expired', decided_at = now() where id = p_pairing;
    raise exception 'approval_window_expired' using errcode = 'P0001';
  end if;

  update public.pairing_codes
     set status = case when p_approve then 'approved' else 'rejected' end, decided_at = now()
   where id = p_pairing;

  if p_approve then
    update public.devices set status = 'active', approved_at = now(), approved_by = v_me
     where id = v_pc.claimed_by_device and user_id = auth.uid() and status = 'pending';
  end if;

  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'user', case when p_approve then 'pairing.approve' else 'pairing.reject' end,
          'device', v_pc.claimed_by_device::text, jsonb_build_object('pairing_id', p_pairing));
  return json_build_object('status', case when p_approve then 'approved' else 'rejected' end);
end $$;

-- ================================================================ incidents & alerts
create or replace function public.set_incident_status(p_incident uuid, p_status text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if public.current_device_id() is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  if p_status not in ('open','acknowledged','resolved','false_positive') then
    raise exception 'bad_status' using errcode = '22023';
  end if;
  update public.incidents set status = p_status where id = p_incident and user_id = auth.uid();
end $$;

create or replace function public.mark_alerts_read(p_ids uuid[] default null)
returns int language plpgsql security definer set search_path = '' as $$
declare v_me uuid := public.current_device_id(); n int;
begin
  if v_me is null then return 0; end if;
  update public.alerts set read_at = now()
   where target_device_id = v_me and read_at is null and (p_ids is null or id = any(p_ids));
  get diagnostics n = row_count;
  return n;
end $$;

-- "Delete my data": removes every incident (and their alerts) for the account
create or replace function public.delete_my_incidents()
returns int language plpgsql security definer set search_path = '' as $$
declare n int;
begin
  if public.current_device_id() is null then raise exception 'device_not_active' using errcode = '42501'; end if;
  delete from public.incidents where user_id = auth.uid();
  get diagnostics n = row_count;
  delete from public.alerts where user_id = auth.uid() and kind in ('incident','auth_code');
  insert into public.audit_log(actor_id, actor_kind, action, detail)
  values (auth.uid(), 'user', 'incidents.delete_all', jsonb_build_object('count', n));
  return n;
end $$;

-- ================================================================ admin (MFA-gated)
create or replace function public.admin_whoami()
returns json language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'is_member', exists (select 1 from public.admin_users where user_id = auth.uid()),
    'aal', coalesce(auth.jwt() ->> 'aal', 'aal1'),
    'is_admin', public.is_admin())
$$;

create or replace function public._require_admin()
returns void language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then raise exception 'admin_required' using errcode = '42501'; end if;
end $$;

create or replace function public.admin_overview()
returns json language plpgsql security definer set search_path = '' as $$
declare r json;
begin
  perform public._require_admin();
  select json_build_object(
    'users',            (select count(*) from public.profiles p where not exists (select 1 from public.admin_users a where a.user_id = p.id)),
    'devices_total',    (select count(*) from public.devices),
    'devices_active',   (select count(*) from public.devices where status = 'active'),
    'devices_pending',  (select count(*) from public.devices where status = 'pending'),
    'devices_revoked',  (select count(*) from public.devices where status = 'revoked'),
    'devices_online',   (select count(*) from public.devices where status = 'active' and last_seen_at > now() - interval '2 minutes'),
    'devices_synced_15m',(select count(*) from public.devices where status = 'active' and last_seen_at > now() - interval '15 minutes'),
    'analysed_total',   (select count(*) from public.incidents),
    'analysed_24h',     (select count(*) from public.incidents where created_at > now() - interval '24 hours'),
    'risk',             (select coalesce(json_object_agg(risk_level, c), '{}'::json)
                           from (select risk_level, count(*) c from public.incidents group by 1) x),
    'ti',               (select coalesce(json_object_agg(ti_status, c), '{}'::json)
                           from (select ti_status, count(*) c from public.incidents group by 1) x),
    'auth_code_events', (select count(*) from public.incidents where contained_auth_code),
    'feedback_total',   (select count(*) from public.feedback)
  ) into r;
  return r;
end $$;

create or replace function public.admin_list_devices(p_limit int default 200)
returns table (id uuid, name text, platform text, app_version text, status text, is_primary boolean,
               account_id uuid, account_phone text, created_at timestamptz, approved_at timestamptz,
               last_seen_at timestamptz, revoked_at timestamptz, revoked_reason text)
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query
    select d.id, d.name, d.platform, d.app_version, d.status::text, d.is_primary,
           d.user_id, p.phone_masked, d.created_at, d.approved_at, d.last_seen_at, d.revoked_at, d.revoked_reason
      from public.devices d left join public.profiles p on p.id = d.user_id
     order by d.last_seen_at desc nulls last
     limit least(p_limit, 500);
end $$;

-- Only incidents the user allowed admins to see. Never raw content.
create or replace function public.admin_list_incidents(p_limit int default 100, p_risk text default null)
returns table (id uuid, created_at timestamptz, account_id uuid, account_phone text, device_id uuid,
               device_name text, source text, risk_level text, score int, category text, indicators jsonb,
               analysis_method text, engine_version text, ti_status text, ti_detail jsonb,
               url_domains text[], contained_auth_code boolean, redacted_excerpt text, status text)
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query
    select i.id, i.created_at, i.user_id, p.phone_masked, i.device_id, i.device_name, i.source,
           i.risk_level, i.score, i.category, i.indicators, i.analysis_method, i.engine_version,
           i.ti_status, i.ti_detail, i.url_domains, i.contained_auth_code, i.redacted_excerpt, i.status
      from public.incidents i left join public.profiles p on p.id = i.user_id
     where i.shared_with_admin
       and (p_risk is null or i.risk_level = p_risk)
     order by i.created_at desc
     limit least(p_limit, 500);
end $$;

create or replace function public.admin_set_incident_status(p_incident uuid, p_status text, p_note text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  if p_status not in ('open','acknowledged','resolved','false_positive') then
    raise exception 'bad_status' using errcode = '22023';
  end if;
  update public.incidents set status = p_status where id = p_incident and shared_with_admin;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'admin', 'incident.set_status', 'incident', p_incident::text,
          jsonb_build_object('status', p_status, 'note', left(p_note, 300)));
end $$;

create or replace function public.admin_delete_incident(p_incident uuid, p_reason text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  delete from public.incidents where id = p_incident and shared_with_admin;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'admin', 'incident.delete', 'incident', p_incident::text,
          jsonb_build_object('reason', left(p_reason, 300)));
end $$;

create or replace function public.admin_revoke_device(p_device uuid, p_reason text default null)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  if not exists (select 1 from public.devices where id = p_device) then
    raise exception 'not_found' using errcode = 'P0002';
  end if;
  perform public._revoke_device(p_device, coalesce('admin: ' || p_reason, 'revoked_by_admin'));
  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'admin', 'device.revoke', 'device', p_device::text, jsonb_build_object('reason', left(p_reason, 300)));
end $$;

create or replace function public.admin_audit_log(p_limit int default 100)
returns setof public.audit_log language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query select * from public.audit_log order by id desc limit least(p_limit, 500);
end $$;

create or replace function public.admin_list_feedback(p_limit int default 100)
returns setof public.feedback language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query select * from public.feedback order by id desc limit least(p_limit, 500);
end $$;

-- Owner-only bootstrap (run in the SQL editor; not callable from the API)
create or replace function public.grant_admin(p_email text, p_note text default null)
returns text language plpgsql security definer set search_path = '' as $$
declare v_uid uuid;
begin
  select id into v_uid from auth.users where lower(email) = lower(p_email);
  if v_uid is null then return 'no auth user with that email - create it first in Authentication > Users'; end if;
  insert into public.admin_users(user_id, note) values (v_uid, p_note) on conflict do nothing;
  insert into public.audit_log(actor_kind, action, target_type, target_id) values ('system', 'admin.grant', 'user', v_uid::text);
  return 'granted (admin must enrol TOTP MFA on first dashboard login)';
end $$;
revoke all on function public.grant_admin(text, text) from public, anon, authenticated;

-- ================================================================ retention
create or replace function public.run_retention()
returns json language plpgsql security definer set search_path = '' as $$
declare a int; b int; c int;
begin
  delete from public.incidents where expires_at < now();               get diagnostics a = row_count;
  delete from public.alerts where created_at < now() - interval '30 days'; get diagnostics b = row_count;
  update public.pairing_codes set status = 'expired' where status in ('open','claimed') and expires_at < now() - interval '5 minutes';
  delete from public.pairing_codes where created_at < now() - interval '7 days';
  delete from public.pairing_attempts where created_at < now() - interval '1 day';
  delete from public.audit_log where at < now() - interval '365 days'; get diagnostics c = row_count;
  return json_build_object('incidents', a, 'alerts', b, 'audit', c);
end $$;
revoke all on function public.run_retention() from public, anon, authenticated;

-- lock down function execution: nothing callable by anon; internals not callable by users
revoke execute on all functions in schema public from public, anon;
grant execute on all functions in schema public to authenticated;
revoke execute on function public._revoke_device(uuid, text), public.grant_admin(text, text),
  public.run_retention(), public.handle_new_user() from authenticated;
