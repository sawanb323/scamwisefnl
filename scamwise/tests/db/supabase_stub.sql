do $$ begin create role anon; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated; exception when duplicate_object then null; end $$;
do $$ begin create role service_role; exception when duplicate_object then null; end $$;
create schema auth; create schema extensions; create extension pgcrypto schema extensions;
create table auth.users(id uuid primary key default gen_random_uuid(), email text, phone text, created_at timestamptz default now(),
  last_sign_in_at timestamptz, email_confirmed_at timestamptz, banned_until timestamptz, raw_user_meta_data jsonb default '{}');
create table auth.sessions(id uuid primary key default gen_random_uuid(), user_id uuid references auth.users on delete cascade,
  created_at timestamptz default now(), updated_at timestamptz default now(), refreshed_at timestamp, not_after timestamptz,
  aal text default 'aal1', ip inet, user_agent text);
create table auth.mfa_factors(id uuid primary key default gen_random_uuid(), user_id uuid, status text);
create function auth.uid() returns uuid language sql stable as $f$ select nullif(current_setting('request.uid', true),'')::uuid $f$;
create function auth.jwt() returns jsonb language sql stable as $f$ select coalesce(nullif(current_setting('request.jwt', true),''),'{}')::jsonb $f$;
create schema cron; create function cron.schedule(a text,b text,c text) returns int language sql as $f$ select 1 $f$;
create publication supabase_realtime;
grant usage on schema public, auth to authenticated, anon, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;
