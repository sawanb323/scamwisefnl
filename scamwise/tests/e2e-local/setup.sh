#!/usr/bin/env bash
set -euo pipefail
export PGHOST=${PGHOST:-/var/run/postgresql} PGPORT=${PGPORT:-5432} PGUSER=${PGUSER:-postgres}
R=$(cd "$(dirname "$0")/../.." && pwd)
psql -q -d postgres -c "drop database if exists scamwise_e2e" -c "create database scamwise_e2e" 2>&1 | grep -v NOTICE || true
P="psql -q -v ON_ERROR_STOP=1 -d scamwise_e2e"
$P -f $R/tests/db/supabase_stub.sql 2>&1 | grep -v -e NOTICE -e WARNING -e HINT || true
for f in $R/supabase/migrations/*.sql; do sed 's/create extension if not exists pg_cron;//' "$f" | $P >/dev/null 2>&1 || { echo "FAILED $f"; exit 1; }; done
$P -f $(dirname "$0")/seed.sql > /dev/null
echo seeded
