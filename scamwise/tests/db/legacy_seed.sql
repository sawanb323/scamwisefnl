-- Data that exists BEFORE migration 008 (upgrade-path test): one user with old-style incidents.
insert into auth.users(id, email, email_confirmed_at) values ('00000000-0000-0000-0000-00000000000e', 'legacy@example.com', now());
insert into public.devices(id, user_id, install_id, name, status, is_primary, approved_at, last_seen_at)
values ('0000000e-0000-0000-0000-000000000001', '00000000-0000-0000-0000-00000000000e', gen_random_uuid(), 'Old laptop', 'active', true, now(), now() - interval '1 day');
insert into public.incidents(user_id, device_id, device_name, risk_level, score, category, analysis_method, engine_version, ti_status, status, url_domains)
values
 ('00000000-0000-0000-0000-00000000000e', '0000000e-0000-0000-0000-000000000001', 'Old laptop', 'high', 88, 'kyc_bank', 'heuristic', '1', 'no_match', 'open', '{sbi-kyc.example}'),
 ('00000000-0000-0000-0000-00000000000e', '0000000e-0000-0000-0000-000000000001', 'Old laptop', 'medium', 50, 'delivery', 'heuristic', '1', 'not_applicable', 'acknowledged', '{}'),
 ('00000000-0000-0000-0000-00000000000e', '0000000e-0000-0000-0000-000000000001', 'Old laptop', 'low', 5, 'none', 'heuristic', '1', 'not_applicable', 'open', '{}');
