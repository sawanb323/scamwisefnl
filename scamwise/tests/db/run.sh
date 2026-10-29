#!/usr/bin/env bash
# Runs the database acceptance tests against a throwaway local Postgres database.
# Usage: PGHOST=... PGPORT=... PGUSER=postgres tests/db/run.sh
# Path: legacy migrations 001-007 -> legacy seed data -> migration 008 (upgrade) -> acceptance checks.
set -euo pipefail
cd "$(dirname "$0")/../.."
DB=${TEST_DB:-scamwise_test}
psql -q -d postgres -c "drop database if exists $DB" -c "create database $DB"
P="psql -q -v ON_ERROR_STOP=1 -d $DB"
$P -f tests/db/supabase_stub.sql 2>&1 | grep -v -e NOTICE -e WARNING -e HINT || true
for f in supabase/migrations/2026102[78]*.sql; do
  sed 's/create extension if not exists pg_cron;//' "$f" | $P >/dev/null
done
$P -f tests/db/legacy_seed.sql
for f in supabase/migrations/2026102[9]*.sql; do
  sed 's/create extension if not exists pg_cron;//' "$f" | $P >/dev/null
done
$P -f tests/db/acceptance.sql 2>&1 | sed 's/^psql:[^:]*:[0-9]*: //' | grep -v -e '^CONTEXT' -e '^PL/pgSQL' -e '^SQL statement'
