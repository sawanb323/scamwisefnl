-- SCAMWISE subscriptions
--
-- Plans:  trial (7 days, 1 device, 2 checks/day, 14 checks total)
--         individual ₹299/mo · 1 device     family ₹699/mo · 3 devices
--         business ₹1,899/mo · 8 devices    enterprise custom (device limit set by admin)
-- No permanent free plan: when plan_expires_at passes, the account is "expired" and scans are refused.
-- Plans are assigned by an administrator (no payment gateway yet). Every change is audit-logged.

alter table public.profiles add column if not exists plan text not null default 'trial'
  check (plan in ('trial', 'individual', 'family', 'business', 'enterprise'));
alter table public.profiles add column if not exists plan_started_at timestamptz not null default now();
alter table public.profiles add column if not exists plan_expires_at timestamptz not null default (now() + interval '7 days');
alter table public.profiles add column if not exists device_limit_override int check (device_limit_override between 1 and 10000);
alter table public.profiles add column if not exists custom_price_inr int check (custom_price_inr >= 0);
alter table public.profiles add column if not exists plan_note text check (length(plan_note) <= 300);
alter table public.profiles add column if not exists checks_total int not null default 0;     -- checks since plan start
alter table public.profiles add column if not exists checks_today int not null default 0;
alter table public.profiles add column if not exists checks_day date;                         -- IST date of checks_today

-- clients may not change their own plan or counters (only display_name is client-updatable)
revoke update on public.profiles from authenticated;
grant update (display_name, share_with_admin, share_excerpt, notify_high, notify_medium, retention_days)
  on public.profiles to authenticated;

-- ---------------------------------------------------------------- plan rules
create or replace function public.plan_device_limit(p_plan text, p_override int)
returns int language sql immutable set search_path = '' as $$
  select coalesce(p_override, case p_plan
    when 'trial' then 1 when 'individual' then 1 when 'family' then 3
    when 'business' then 8 when 'enterprise' then 25 else 1 end)
$$;

create or replace function public.plan_price_inr(p_plan text, p_custom int)
returns int language sql immutable set search_path = '' as $$
  select case p_plan when 'trial' then 0 when 'individual' then 299 when 'family' then 699
    when 'business' then 1899 when 'enterprise' then coalesce(p_custom, 0) else 0 end
$$;

-- 'active' | 'trial' | 'expired'
create or replace function public.plan_state(p_plan text, p_expires timestamptz)
returns text language sql stable set search_path = '' as $$
  select case when p_expires <= now() then 'expired' when p_plan = 'trial' then 'trial' else 'active' end
$$;

-- ---------------------------------------------------------------- device limit by plan
create or replace function public.register_device(
  p_install_id uuid, p_name text, p_platform text default null, p_app_version text default null)
returns public.devices language plpgsql security definer set search_path = '' as $$
declare
  v_uid  uuid := auth.uid();
  v_sid  uuid := public.jwt_session_id();
  v_dev  public.devices;
  v_active_count int;
  v_limit int;
begin
  if v_uid is null or v_sid is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;
  if exists (select 1 from public.admin_users where user_id = v_uid) then
    raise exception 'admin_accounts_cannot_register_devices' using errcode = '42501';
  end if;

  update public.devices set session_id = null
   where session_id = v_sid and not (user_id = v_uid and install_id = p_install_id);

  select * into v_dev from public.devices where user_id = v_uid and install_id = p_install_id;
  select count(*) into v_active_count from public.devices where user_id = v_uid and status = 'active';
  select public.plan_device_limit(p.plan, p.device_limit_override) into v_limit
    from public.profiles p where p.id = v_uid;
  v_limit := coalesce(v_limit, 1);

  if v_dev.id is not null then
    if v_dev.status = 'revoked'
       and (select count(*) from public.devices where user_id = v_uid and status <> 'revoked') >= v_limit then
      raise exception 'device_limit_reached:%', v_limit using errcode = 'P0001';
    end if;
    update public.devices set
      session_id   = v_sid,
      name         = coalesce(nullif(trim(p_name), ''), name),
      platform     = coalesce(p_platform, platform),
      app_version  = coalesce(p_app_version, app_version),
      last_seen_at = now(),
      status       = case when status = 'revoked'
                          then (case when v_active_count = 0 then 'active' else 'pending' end)::public.device_status
                          else status end,
      revoked_at   = case when status = 'revoked' then null else revoked_at end,
      approved_at  = case when status = 'revoked' and v_active_count = 0 then now() else approved_at end
    where id = v_dev.id
    returning * into v_dev;
  else
    if (select count(*) from public.devices where user_id = v_uid and status <> 'revoked') >= v_limit then
      raise exception 'device_limit_reached:%', v_limit using errcode = 'P0001';
    end if;
    insert into public.devices (user_id, install_id, session_id, name, platform, app_version,
                                status, is_primary, approved_at, last_seen_at)
    values (v_uid, p_install_id, v_sid, coalesce(nullif(trim(p_name), ''), 'Web browser'),
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

-- ---------------------------------------------------------------- scan quota (called by the analyze function)
-- Atomically checks the plan and, if allowed, counts one check. Service role only.
create or replace function public.consume_check(p_user uuid)
returns json language plpgsql security definer set search_path = '' as $$
declare
  p public.profiles;
  v_today date := (now() at time zone 'Asia/Kolkata')::date;
begin
  select * into p from public.profiles where id = p_user for update;
  if not found then return json_build_object('allowed', false, 'reason', 'no_profile'); end if;
  if p.plan_expires_at <= now() then
    return json_build_object('allowed', false, 'reason', case when p.plan = 'trial' then 'trial_expired' else 'subscription_expired' end,
                             'plan', p.plan, 'expires_at', p.plan_expires_at);
  end if;
  if p.checks_day is distinct from v_today then p.checks_today := 0; end if;
  if p.plan = 'trial' then
    if p.checks_total >= 14 then
      return json_build_object('allowed', false, 'reason', 'trial_total_limit', 'used', p.checks_total, 'limit', 14);
    end if;
    if p.checks_today >= 2 then
      return json_build_object('allowed', false, 'reason', 'trial_daily_limit', 'used_today', p.checks_today, 'limit', 2);
    end if;
  end if;
  update public.profiles set checks_today = p.checks_today + 1, checks_day = v_today, checks_total = p.checks_total + 1
   where id = p_user;
  return json_build_object('allowed', true, 'plan', p.plan, 'used_today', p.checks_today + 1, 'used_total', p.checks_total + 1);
end $$;
revoke execute on function public.consume_check(uuid) from public, anon, authenticated;
grant execute on function public.consume_check(uuid) to service_role;

-- the signed-in user's own subscription (for the app)
create or replace function public.my_subscription()
returns json language sql stable security definer set search_path = '' as $$
  select json_build_object(
    'plan', p.plan, 'state', public.plan_state(p.plan, p.plan_expires_at),
    'started_at', p.plan_started_at, 'expires_at', p.plan_expires_at,
    'device_limit', public.plan_device_limit(p.plan, p.device_limit_override),
    'devices_used', (select count(*) from public.devices d where d.user_id = p.id and d.status <> 'revoked'),
    'checks_today', case when p.checks_day = (now() at time zone 'Asia/Kolkata')::date then p.checks_today else 0 end,
    'checks_total', p.checks_total)
  from public.profiles p where p.id = auth.uid()
$$;
revoke execute on function public.my_subscription() from public, anon;
grant execute on function public.my_subscription() to authenticated;

-- ---------------------------------------------------------------- admin
create or replace function public.admin_list_users(p_limit int default 500)
returns table (id uuid, email text, display_name text, phone text, joined_at timestamptz, last_sign_in_at timestamptz,
               email_confirmed boolean, plan text, plan_state text, plan_started_at timestamptz, plan_expires_at timestamptz,
               days_left int, price_inr int, device_limit int, device_limit_override int, plan_note text,
               devices_total int, devices_active int, devices_pending int, devices_revoked int, devices_online int,
               last_seen_at timestamptz, checks_today int, checks_total int, scans_total int, scans_high int,
               device_names text[])
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query
    select p.id, u.email::text, p.display_name, coalesce(u.phone::text, p.phone_masked), u.created_at, u.last_sign_in_at,
           u.email_confirmed_at is not null,
           p.plan, public.plan_state(p.plan, p.plan_expires_at), p.plan_started_at, p.plan_expires_at,
           greatest(0, ceil(extract(epoch from (p.plan_expires_at - now())) / 86400))::int,
           public.plan_price_inr(p.plan, p.custom_price_inr),
           public.plan_device_limit(p.plan, p.device_limit_override), p.device_limit_override, p.plan_note,
           (select count(*)::int from public.devices d where d.user_id = p.id),
           (select count(*)::int from public.devices d where d.user_id = p.id and d.status = 'active'),
           (select count(*)::int from public.devices d where d.user_id = p.id and d.status = 'pending'),
           (select count(*)::int from public.devices d where d.user_id = p.id and d.status = 'revoked'),
           (select count(*)::int from public.devices d where d.user_id = p.id and d.status = 'active' and d.last_seen_at > now() - interval '2 minutes'),
           (select max(d.last_seen_at) from public.devices d where d.user_id = p.id),
           case when p.checks_day = (now() at time zone 'Asia/Kolkata')::date then p.checks_today else 0 end,
           p.checks_total,
           (select count(*)::int from public.incidents i where i.user_id = p.id),
           (select count(*)::int from public.incidents i where i.user_id = p.id and i.risk_level = 'high'),
           (select array_agg(d.name || ' (' || d.status || ')' order by d.created_at) from public.devices d where d.user_id = p.id)
      from public.profiles p join auth.users u on u.id = p.id
     where not exists (select 1 from public.admin_users a where a.user_id = p.id)
     order by u.created_at desc
     limit least(p_limit, 2000);
end $$;

create or replace function public.admin_set_plan(
  p_user uuid, p_plan text, p_expires_at timestamptz, p_started_at timestamptz default null,
  p_device_limit int default null, p_custom_price int default null, p_note text default null, p_reset_checks boolean default false)
returns json language plpgsql security definer set search_path = '' as $$
declare old public.profiles;
begin
  perform public._require_admin();
  if p_plan not in ('trial', 'individual', 'family', 'business', 'enterprise') then
    raise exception 'invalid_plan' using errcode = '22023';
  end if;
  if p_expires_at is null then raise exception 'expiry_required' using errcode = '22023'; end if;
  select * into old from public.profiles where id = p_user for update;
  if not found then raise exception 'not_found' using errcode = 'P0002'; end if;

  update public.profiles set
    plan = p_plan,
    plan_started_at = coalesce(p_started_at, case when old.plan = p_plan then old.plan_started_at else now() end),
    plan_expires_at = p_expires_at,
    device_limit_override = case when p_plan = 'enterprise' then p_device_limit else null end,
    custom_price_inr = case when p_plan = 'enterprise' then p_custom_price else null end,
    plan_note = nullif(trim(coalesce(p_note, '')), ''),
    checks_total = case when p_reset_checks then 0 else checks_total end,
    checks_today = case when p_reset_checks then 0 else checks_today end
  where id = p_user;

  insert into public.audit_log(actor_id, actor_kind, action, target_type, target_id, detail)
  values (auth.uid(), 'admin', 'subscription.set', 'user', p_user::text,
          jsonb_build_object('from_plan', old.plan, 'from_expires', old.plan_expires_at,
                             'to_plan', p_plan, 'to_expires', p_expires_at, 'device_limit', p_device_limit,
                             'custom_price', p_custom_price, 'reset_checks', p_reset_checks));
  return json_build_object('ok', true);
end $$;

create or replace function public.admin_plan_summary()
returns json language plpgsql security definer set search_path = '' as $$
declare r json;
begin
  perform public._require_admin();
  with u as (
    select p.*, public.plan_state(p.plan, p.plan_expires_at) st
      from public.profiles p
     where not exists (select 1 from public.admin_users a where a.user_id = p.id))
  select json_build_object(
    'by_plan',       (select coalesce(json_object_agg(plan, c), '{}'::json) from (select plan, count(*) c from u where st <> 'expired' group by 1) x),
    'trial',         (select count(*) from u where st = 'trial'),
    'paid_active',   (select count(*) from u where st = 'active'),
    'expired',       (select count(*) from u where st = 'expired'),
    'expiring_7d',   (select count(*) from u where st <> 'expired' and plan_expires_at < now() + interval '7 days'),
    'mrr_inr',       (select coalesce(sum(public.plan_price_inr(plan, custom_price_inr)), 0) from u where st = 'active')
  ) into r;
  return r;
end $$;

revoke execute on function public.admin_list_users(int), public.admin_plan_summary(),
  public.admin_set_plan(uuid, text, timestamptz, timestamptz, int, int, text, boolean) from public, anon;
grant execute on function public.admin_list_users(int), public.admin_plan_summary(),
  public.admin_set_plan(uuid, text, timestamptz, timestamptz, int, int, text, boolean) to authenticated;
