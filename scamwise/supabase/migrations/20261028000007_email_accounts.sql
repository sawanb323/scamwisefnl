-- SCAMWISE: app users sign in with email + password (phone OTP removed).
-- Profiles keep a masked email and the display name given at sign-up; admin views show the
-- masked email where there is no phone number.

create or replace function public.mask_email(p text)
returns text language sql immutable set search_path = '' as $$
  select case
    when p is null or position('@' in p) < 2 then null
    else left(p, 1) || '•••' || substr(p, position('@' in p) - 1, 1) || substr(p, position('@' in p))
  end
$$;

alter table public.profiles add column if not exists email_masked text;
alter table public.profiles add column if not exists display_name text check (length(display_name) <= 80);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, phone_masked, email_masked, display_name)
  values (new.id, public.mask_phone(new.phone), public.mask_email(new.email),
          nullif(left(trim(coalesce(new.raw_user_meta_data ->> 'full_name', '')), 80), ''))
  on conflict (id) do nothing;
  return new;
end $$;

update public.profiles p
   set email_masked = public.mask_email(u.email),
       display_name = coalesce(p.display_name, nullif(left(trim(coalesce(u.raw_user_meta_data ->> 'full_name', '')), 80), ''))
  from auth.users u
 where u.id = p.id;

-- users may edit their own display name
grant update (display_name) on public.profiles to authenticated;

-- admin lists: account = masked phone, else masked email
create or replace function public.admin_list_devices(p_limit int default 200)
returns table (id uuid, name text, platform text, app_version text, status text, is_primary boolean,
               account_id uuid, account_phone text, created_at timestamptz, approved_at timestamptz,
               last_seen_at timestamptz, revoked_at timestamptz, revoked_reason text)
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query
    select d.id, d.name, d.platform, d.app_version, d.status::text, d.is_primary,
           d.user_id, coalesce(p.phone_masked, p.email_masked), d.created_at, d.approved_at, d.last_seen_at, d.revoked_at, d.revoked_reason
      from public.devices d left join public.profiles p on p.id = d.user_id
     order by d.last_seen_at desc nulls last
     limit least(p_limit, 500);
end $$;

create or replace function public.admin_list_incidents(p_limit int default 100, p_risk text default null)
returns table (id uuid, created_at timestamptz, account_id uuid, account_phone text, device_id uuid,
               device_name text, source text, risk_level text, score int, category text, indicators jsonb,
               analysis_method text, engine_version text, ti_status text, ti_detail jsonb,
               url_domains text[], contained_auth_code boolean, redacted_excerpt text, status text)
language plpgsql security definer set search_path = '' as $$
begin
  perform public._require_admin();
  return query
    select i.id, i.created_at, i.user_id, coalesce(p.phone_masked, p.email_masked), i.device_id, i.device_name, i.source,
           i.risk_level, i.score, i.category, i.indicators, i.analysis_method, i.engine_version,
           i.ti_status, i.ti_detail, i.url_domains, i.contained_auth_code, i.redacted_excerpt, i.status
      from public.incidents i left join public.profiles p on p.id = i.user_id
     where i.shared_with_admin
       and (p_risk is null or i.risk_level = p_risk)
     order by i.created_at desc
     limit least(p_limit, 500);
end $$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;
