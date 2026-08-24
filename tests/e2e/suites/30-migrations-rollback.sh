#!/usr/bin/env bash
# Suite 30: database migration forward/rollback validation, issue #17's
# "validate supported database ... migrations and rollback documentation"
# criterion. Forward-apply idempotence of migrations.Apply itself (the Go
# ledger in control-plane/migrations/migrations.go) is already covered by
# control-plane/migrations/migrations_test.go, which runs in `make
# test-control-plane` and CI's control-plane job against a real Postgres
# service -- cheaper and faster there than reaching for the full Compose
# stack. This suite covers what that unit test cannot: that
# control-plane/migrations/ROLLBACK.md's documented reverse SQL is
# complete (a section for every migration file) and actually correct (it
# undoes a full forward apply back to an empty schema, and the schema is
# re-creatable afterwards).
#
# Runs entirely against a disposable scratch database inside the Compose
# Postgres container -- never against $POSTGRES_DB -- dropped in cleanup
# regardless of outcome.
#
# "protocol migrations" (the third kind issue #17 names) are covered by
# the existing `protocol` CI job (buf's breaking-change lint + the
# generated-bindings diff check), and "runtime migrations" (the Substrate
# runtime's spec_version) by control-plane/internal/blockchainbridge's
# spec_version drift test -- both already real, already in CI, and out of
# scope to duplicate here.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export E2E_REPO_ROOT="$repo_root"
# shellcheck source=tests/e2e/lib/common.sh
. "$repo_root/tests/e2e/lib/common.sh"

require_stack_up postgres

migrations_dir="$repo_root/control-plane/migrations"
rollback_doc="$migrations_dir/ROLLBACK.md"
[[ -f "$rollback_doc" ]] || fail "control-plane/migrations/ROLLBACK.md is missing"

scratch_db="e2e_migrations_rollback_$(unique_suffix | tr -c 'a-zA-Z0-9' '_')"
register_cleanup "psql_exec \"DROP DATABASE IF EXISTS $scratch_db;\" >/dev/null 2>&1 || true"
psql_exec "CREATE DATABASE $scratch_db;" >/dev/null

# --- structural check: every migration file has a ROLLBACK.md section ---
missing=0
for path in "$migrations_dir"/[0-9]*.sql; do
  name="$(basename "$path")"
  grep -qxF "## $name" "$rollback_doc" || { log "ROLLBACK.md has no section for $name"; missing=$((missing + 1)); }
done
[[ "$missing" -eq 0 ]] || fail "$missing migration(s) have no documented rollback in ROLLBACK.md"
log "structural check passed: every migrations/*.sql file has a ROLLBACK.md section"

extract_rollback_sql() {
  # extract_rollback_sql <migration_filename> -- prints the fenced ```sql
  # block under that file's "## <filename>" heading in ROLLBACK.md.
  local name="$1"
  awk -v target="## ${name}" '
    $0 == target { found=1; next }
    found && /^## / { exit }
    found && /^```sql/ { insql=1; next }
    found && /^```/ { insql=0; next }
    found && insql { print }
  ' "$rollback_doc"
}

apply_sql_file_to_scratch() {
  local path="$1"
  "${compose[@]}" exec -T postgres sh -c \
    "psql -U \"\$POSTGRES_USER\" -d '$scratch_db' -v ON_ERROR_STOP=1" <"$path"
}

apply_sql_string_to_scratch() {
  local sql="$1"
  "${compose[@]}" exec -T postgres sh -c \
    "psql -U \"\$POSTGRES_USER\" -d '$scratch_db' -v ON_ERROR_STOP=1" <<<"$sql"
}

table_list() {
  "${compose[@]}" exec -T postgres sh -c \
    "psql -U \"\$POSTGRES_USER\" -d '$scratch_db' -v ON_ERROR_STOP=1 -tA -c \"SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name;\""
}

# --- round 1: forward-apply every migration file in order -----------------
log "applying all migrations forward into $scratch_db"
for path in "$migrations_dir"/[0-9]*.sql; do
  apply_sql_file_to_scratch "$path" >/dev/null
done
tables_after_forward="$(table_list)"
[[ -n "$tables_after_forward" ]] || fail "forward apply produced zero tables"
log "forward apply produced tables: $(tr '\n' ' ' <<<"$tables_after_forward")"

# --- rollback: apply ROLLBACK.md's SQL in reverse migration order --------
log "rolling back via ROLLBACK.md, highest-numbered migration first"
# ls ... | sort -r walks 000015 down to 000001, matching ROLLBACK.md's own
# documented order (see its "Rules for keeping this file honest").
while IFS= read -r path; do
  name="$(basename "$path")"
  sql="$(extract_rollback_sql "$name")"
  [[ -n "$sql" ]] || fail "extracted empty rollback SQL for $name -- ROLLBACK.md section malformed?"
  apply_sql_string_to_scratch "$sql" >/dev/null || fail "rollback SQL for $name failed against the scratch database"
done < <(find "$migrations_dir" -maxdepth 1 -name '[0-9]*.sql' | sort -r)

tables_after_rollback="$(table_list)"
if [[ -n "$tables_after_rollback" ]]; then
  fail "tables remain after full rollback: $(tr '\n' ' ' <<<"$tables_after_rollback")"
fi
log "full rollback reached an empty schema, as expected"

# --- round 2: forward-apply again, confirm the schema is identical -------
log "re-applying all migrations forward (round 2) to confirm a full round trip"
for path in "$migrations_dir"/[0-9]*.sql; do
  apply_sql_file_to_scratch "$path" >/dev/null
done
tables_after_second_forward="$(table_list)"
[[ "$tables_after_second_forward" == "$tables_after_forward" ]] \
  || fail "round-2 forward apply produced a different table set than round 1 (round 1: $(tr '\n' ' ' <<<"$tables_after_forward"); round 2: $(tr '\n' ' ' <<<"$tables_after_second_forward"))"
log "round-2 forward apply matches round 1 exactly: full forward -> rollback -> forward round trip verified"

# --- idempotence: re-applying the same forward files a third time --------
# in place (no rollback in between) must also be a no-op error-wise -- the
# same guarantee migrations_test.go proves at the Go/ledger level, checked
# here at the raw-SQL level against this suite's own scratch database.
log "re-applying all migrations forward once more in place (idempotence)"
for path in "$migrations_dir"/[0-9]*.sql; do
  apply_sql_file_to_scratch "$path" >/dev/null
done
tables_after_third_forward="$(table_list)"
[[ "$tables_after_third_forward" == "$tables_after_forward" ]] \
  || fail "re-applying the forward migrations in place changed the table set"

log "migrations-rollback suite PASSED: forward, rollback, and re-forward all consistent; ROLLBACK.md is complete"
echo "E2E migrations-rollback suite PASSED"
