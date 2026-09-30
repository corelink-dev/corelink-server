#!/usr/bin/env bash
# Read-only deployment fence for the DSR DLQ redrive authority schema.
# Migration application is deliberately an approved operation outside rollout.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$REPO_ROOT/apps/signup-worker/wrangler.toml"
EXEC_MODE="--remote"
PERSIST_TO=""

while (($#)); do
  case "$1" in
    --config)
      CONFIG="${2:?--config requires a Wrangler config path}"
      shift 2
      ;;
    --local)
      EXEC_MODE="--local"
      shift
      ;;
    --persist-to)
      PERSIST_TO="${2:?--persist-to requires a directory}"
      shift 2
      ;;
    *)
      echo "usage: $0 [--config <wrangler.toml>] [--local [--persist-to <dir>]]" >&2
      exit 2
      ;;
  esac
done
if [[ -n "$PERSIST_TO" && "$EXEC_MODE" != "--local" ]]; then
  echo "DSR redrive schema fence: --persist-to is valid only with --local" >&2
  exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "DSR redrive schema fence: Wrangler config not found: $CONFIG" >&2
  exit 2
fi

# B-216 local OAuth operation pins the verified Wrangler version explicitly.
# Preserve the existing default for callers outside that bounded operation.
if [[ -n "${B216_DSR_SCHEMA_WRANGLER_VERSION:-}" ]]; then
  WRANGLER_CMD=(npx --yes "wrangler@$B216_DSR_SCHEMA_WRANGLER_VERSION")
elif command -v wrangler >/dev/null 2>&1; then
  WRANGLER_CMD=(wrangler)
else
  WRANGLER_CMD=(npx --yes wrangler@4.95.0)
fi

check_count() {
  local expected="$1" query="$2" label="$3" output count
  local execute_args=("$EXEC_MODE")
  if [[ -n "$PERSIST_TO" ]]; then
    execute_args+=(--persist-to "$PERSIST_TO")
  fi
  output="$("${WRANGLER_CMD[@]}" d1 execute CONFIG_DB "${execute_args[@]}" --config "$CONFIG" --command "$query" --json)" || {
    echo "DSR redrive schema fence: cannot query $label" >&2
    exit 1
  }
  count="$(printf '%s' "$output" | python3 -c '
import json, sys
try:
    payload = json.load(sys.stdin)
    rows = payload[0]["results"]
    value = rows[0]["count"]
    if not isinstance(value, int):
        raise ValueError("count is not an integer")
    print(value)
except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"unreadable D1 result: {error}")
')" || {
    echo "DSR redrive schema fence: unreadable result for $label" >&2
    exit 1
  }
  if [[ "$count" != "$expected" ]]; then
    echo "DSR redrive schema fence: $label expected $expected, got $count" >&2
    exit 1
  fi
}

check_count 1 \
  "SELECT COUNT(*) AS count FROM d1_migrations WHERE name = '0138_dsr_dlq_delivery_receipts.sql'" \
  "migration 0138"
check_count 1 \
  "SELECT COUNT(*) AS count FROM d1_migrations WHERE name = '0145_dsr_dlq_redrive_authority.sql'" \
  "migration 0145"
check_count 1 \
  "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'dsr_dlq_delivery_receipts'" \
  "delivery receipt table"
check_count 1 \
  "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'index' AND name = 'idx_dsr_dlq_delivery_receipts_status_updated'" \
  "delivery receipt index"
check_count 5 \
  "SELECT COUNT(*) AS count FROM pragma_table_info('dsr_dlq_delivery_receipts') WHERE name IN ('event_id', 'status', 'paging_claimed', 'requeue_claimed', 'updated_at_ms')" \
  "delivery receipt columns"
check_count 2 \
  "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name IN ('dsr_dlq_redrive_envelopes', 'dsr_dlq_redrive_audit')" \
  "redrive tables"
check_count 12 \
  "SELECT COUNT(*) AS count FROM pragma_table_info('dsr_dlq_redrive_envelopes') WHERE name IN ('event_id', 'dsr_id', 'tenant_id', 'queued_at_ms', 'legal_hold', 'requeue_count', 'state', 'actor_ref', 'approval_ref', 'expires_at_ms', 'claim_expires_at_ms', 'updated_at_ms')" \
  "redrive envelope columns"
check_count 2 \
  "SELECT COUNT(*) AS count FROM pragma_table_info('dsr_dlq_redrive_audit') WHERE name IN ('event_id', 'transition')" \
  "redrive audit columns"

echo "DSR redrive schema fence: migrations 0138 and 0145 and required receipt/redrive tables and columns are present."
