-- B-127 read-only residual classifier. Output contains stable aliases only;
-- raw tenant, request, digest, subject, and payload values never cross the
-- SELECT boundary.
--
-- The residual is every customer orphan whose tenant has NO completed D1
-- erasure: no dsr_erasure_log entry with backend = 'd1' AND outcome = 'erased'.
-- This is the same erased-lineage condition as scripts/verify_audit_residency.py
-- (ERASED_LINEAGE_BACKEND / ERASED_LINEAGE_OUTCOMES, #1669 policy B as narrowed
-- 2026-10-02). A tenant whose log shows only partial_failure, failed,
-- not_applicable (legal hold: data preserved), pseudonymized, an unknown
-- value, NULL or another backend stays in the residual.
WITH residual_ids AS (
    SELECT DISTINCT a.tenant_id
    FROM audit_outbox AS a
    LEFT JOIN tenant AS t ON t.tenant_id = a.tenant_id
    WHERE t.tenant_id IS NULL
      AND a.tenant_id <> '_public'
      AND NOT EXISTS (
          SELECT 1 FROM dsr_erasure_log AS d
          WHERE d.tenant_id = a.tenant_id
            AND d.backend = 'd1'
            AND d.outcome = 'erased'
      )
),
aliases AS (
    SELECT
        tenant_id,
        'orphan_' || ROW_NUMBER() OVER (ORDER BY tenant_id) AS orphan_alias
    FROM residual_ids
),
classified_ids AS (
    SELECT tenant_id, orphan_alias, 'unexplained_tenant' AS classification
    FROM aliases
    UNION ALL
    SELECT '_public', 'reserved_public', 'reserved_namespace'
    WHERE EXISTS (
        SELECT 1 FROM audit_outbox WHERE tenant_id = '_public'
    )
),
audit_summary AS (
    SELECT
        x.orphan_alias,
        x.classification,
        group_concat(DISTINCT a.region) AS audit_regions,
        group_concat(DISTINCT a.event_type) AS event_types,
        COUNT(*) AS audit_rows,
        MIN(a.enqueued_at) AS first_audit_ms,
        MAX(a.enqueued_at) AS last_audit_ms,
        SUM(a.emitted_at IS NULL) AS pending_audit_rows
    FROM classified_ids AS x
    JOIN audit_outbox AS a ON a.tenant_id = x.tenant_id
    GROUP BY x.orphan_alias, x.classification
),
storage_summary AS (
    SELECT
        x.orphan_alias,
        group_concat(DISTINCT s.region) AS storage_regions,
        COUNT(*) AS storage_rows,
        SUM(s.bytes_used) AS storage_bytes_reported,
        MIN(s.created_at_ms) AS first_storage_ms,
        MAX(s.updated_at_ms) AS last_storage_ms
    FROM classified_ids AS x
    JOIN tenant_storage_state AS s ON s.tenant_id = x.tenant_id
    GROUP BY x.orphan_alias
),
usage_summary AS (
    SELECT
        x.orphan_alias,
        COUNT(*) AS usage_days,
        SUM(u.reads) AS reads,
        SUM(u.writes) AS writes,
        SUM(u.hits) AS hits,
        SUM(u.misses) AS misses
    FROM classified_ids AS x
    JOIN usage_daily AS u ON u.tenant_id = x.tenant_id
    GROUP BY x.orphan_alias
)
SELECT
    a.orphan_alias,
    a.classification,
    a.audit_regions,
    a.event_types,
    a.audit_rows,
    a.first_audit_ms,
    a.last_audit_ms,
    a.pending_audit_rows,
    COALESCE(s.storage_regions, '') AS storage_regions,
    COALESCE(s.storage_rows, 0) AS storage_rows,
    COALESCE(s.storage_bytes_reported, 0) AS storage_bytes_reported,
    COALESCE(s.first_storage_ms, 0) AS first_storage_ms,
    COALESCE(s.last_storage_ms, 0) AS last_storage_ms,
    COALESCE(u.usage_days, 0) AS usage_days,
    COALESCE(u.reads, 0) AS reads,
    COALESCE(u.writes, 0) AS writes,
    COALESCE(u.hits, 0) AS hits,
    COALESCE(u.misses, 0) AS misses
FROM audit_summary AS a
LEFT JOIN storage_summary AS s USING (orphan_alias)
LEFT JOIN usage_summary AS u USING (orphan_alias)
ORDER BY a.orphan_alias;
