alter table public.devices add column last_session_id uuid;

create or replace function public._revoke_device(p_device uuid, p_reason text)
returns void language plpgsql security definer set search_path = '' as $$
declare v_old_sid uuid;
begin
  select session_id into v_old_sid from public.devices where id = p_device for update;
  update public.devices
     set status = 'revoked', revoked_at = now(), revoked_reason = left(p_reason, 200),
         session_id = null, last_session_id = coalesce(v_old_sid, last_session_id)
   where id = p_device;
  if v_old_sid is not null then
    delete from auth.sessions where id = v_old_sid;
  end if;
  delete from public.alerts where target_device_id = p_device and read_at is null;
end $$;

create or replace function public.heartbeat()
returns text language plpgsql security definer set search_path = '' as $$
declare v_status public.device_status;
begin
  update public.devices set last_seen_at = now()
   where user_id = auth.uid() and session_id = public.jwt_session_id()
  returning status into v_status;
  if v_status is null and exists (select 1 from public.devices
      where user_id = auth.uid() and last_session_id = public.jwt_session_id() and status = 'revoked') then
    return 'revoked';
  end if;
  return coalesce(v_status::text, 'unregistered');
end $$;

revoke execute on function public._revoke_device(uuid, text) from public, anon, authenticated;
