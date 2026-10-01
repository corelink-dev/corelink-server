"""Emit aggregate-only SQL for one exact staging B-125 synthetic load run.

No provider operation occurs here. The caller must use the authorized staging
route and exact run ID after the staging-target gates. Output has only a fixed
UTC-hour bucket and numeric aggregates; no tenant IDs, digests, hashes, or rows
are selected.
"""

from __future__ import annotations

import argparse
import re


STAGING_ACCOUNT_ID = "6a1fc1c626fc2628823e60b9db01f5cd"
STAGING_DATABASE_ID = "d72a6b39-6a48-4338-bfda-1111dda98604"
STAGING_ORIGIN = "https://staging.corelink.humangr.com"
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")


def _marker(run_id: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run ID must be canonical positive decimal text")
    return f"_run_{run_id}_endurance_"


def preflight_sql(run_id: str) -> str:
    marker = _marker(run_id)
    return f"""SELECT
      SUM(CASE WHEN instr(COALESCE(digest, ''), '{marker}') > 0 THEN 1 ELSE 0 END) AS run_marker_rows_before,
      SUM(CASE WHEN emitted_at IS NULL THEN 1 ELSE 0 END) AS unsealed_rows_before,
      MAX(CASE WHEN emitted_at IS NULL THEN (strftime('%s','now') * 1000) - enqueued_at ELSE 0 END) AS oldest_unsealed_age_ms_before,
      COUNT(DISTINCT tenant_id || '/' || region) AS partition_count_before
    FROM audit_outbox""".strip()


def result_sql(run_id: str) -> str:
    marker = _marker(run_id)
    return f"""WITH run_rows AS MATERIALIZED (
      SELECT tenant_id, region, enqueued_at, emitted_at,
             CASE WHEN emitted_at IS NOT NULL AND emitted_at < enqueued_at THEN 1 ELSE 0 END AS negative_latency,
             CASE WHEN emitted_at IS NOT NULL AND emitted_at >= enqueued_at THEN emitted_at - enqueued_at END AS latency_ms
      FROM audit_outbox
      WHERE instr(COALESCE(digest, ''), '{marker}') > 0
    ), ranked AS (
      SELECT tenant_id, region, enqueued_at, emitted_at, negative_latency, latency_ms,
             enqueued_at / 3600000 AS hour_bucket,
             ROW_NUMBER() OVER (PARTITION BY enqueued_at / 3600000 ORDER BY latency_ms) AS latency_rank,
             COUNT(latency_ms) OVER (PARTITION BY enqueued_at / 3600000) AS latency_count
      FROM run_rows
    ), hourly AS (
      SELECT hour_bucket, COUNT(*) AS audit_arrivals,
             SUM(CASE WHEN emitted_at IS NOT NULL THEN 1 ELSE 0 END) AS sealed_rows,
             SUM(CASE WHEN emitted_at IS NULL THEN 1 ELSE 0 END) AS unsealed_rows,
             SUM(negative_latency) AS negative_latency_rows,
             MAX(CASE WHEN latency_rank = CAST((latency_count * 90 + 99) / 100 AS INTEGER)
                      THEN latency_ms END) AS p90_seal_latency_ms,
             MAX(CASE WHEN emitted_at IS NULL
                      THEN (strftime('%s','now') * 1000) - enqueued_at ELSE 0 END) AS oldest_unsealed_age_ms,
             COUNT(DISTINCT tenant_id || '/' || region) AS partition_count
      FROM ranked GROUP BY hour_bucket
    ), summary AS (
      SELECT COUNT(*) AS run_audit_rows,
             SUM(CASE WHEN emitted_at IS NOT NULL THEN 1 ELSE 0 END) AS run_sealed_rows,
             SUM(CASE WHEN emitted_at IS NULL THEN 1 ELSE 0 END) AS run_unsealed_rows,
             MIN(enqueued_at) AS first_enqueue_ms, MAX(enqueued_at) AS last_enqueue_ms
      FROM run_rows
    ), global_backlog AS (
      SELECT SUM(CASE WHEN emitted_at IS NULL THEN 1 ELSE 0 END) AS unsealed_rows_after,
             MAX(CASE WHEN emitted_at IS NULL THEN (strftime('%s','now') * 1000) - enqueued_at ELSE 0 END) AS oldest_unsealed_age_ms_after
      FROM audit_outbox
    ), bounded_hours AS (
      SELECT * FROM hourly ORDER BY hour_bucket LIMIT 3
    )
    SELECT strftime('%Y-%m-%dT%H:00:00Z', b.hour_bucket * 3600, 'unixepoch') AS hour_start_utc,
           b.audit_arrivals, b.sealed_rows, b.unsealed_rows, b.negative_latency_rows,
           b.p90_seal_latency_ms, b.oldest_unsealed_age_ms, b.partition_count,
           (SELECT COUNT(*) FROM hourly) AS hour_bucket_count,
           s.run_audit_rows, s.run_sealed_rows, s.run_unsealed_rows,
           s.first_enqueue_ms, s.last_enqueue_ms,
           g.unsealed_rows_after, g.oldest_unsealed_age_ms_after
    FROM bounded_hours AS b CROSS JOIN summary AS s CROSS JOIN global_backlog AS g
    ORDER BY b.hour_bucket""".strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("preflight", "results"))
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(preflight_sql(args.run_id) if args.phase == "preflight" else result_sql(args.run_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
