-- Daily retention purge (03:17 UTC): expired incidents, old alerts, stale pairing data
create extension if not exists pg_cron;
select cron.schedule('scamwise-retention', '17 3 * * *', $$select public.run_retention()$$);

-- incident expiry follows the owner's retention preference
create or replace function public.set_incident_expiry()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  new.expires_at := new.created_at
    + make_interval(days => coalesce((select retention_days from public.profiles where id = new.user_id), 30));
  return new;
end $$;
create trigger incidents_expiry before insert on public.incidents
  for each row execute function public.set_incident_expiry();
revoke execute on function public.set_incident_expiry() from public, anon, authenticated;
