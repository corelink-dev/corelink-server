"""Fixed, privacy-bounded B-125 historical-anomaly attribution query.

The query returns only fixed numeric bins and aggregates. It never selects a
tenant, region, event id, digest, chain hash, payload, or quarantine reason.
The signed-head section reports structural evidence only; SQL cannot verify
the resolution signature or recompute the canonical candidate-set commitment.
"""

from __future__ import annotations

import argparse


ATTRIBUTION_SQL = r"""
WITH
source AS MATERIALIZED (
    SELECT id, tenant_id, region, sequence_number, chain_hash, emitted_at,
           enqueued_at, epoch_id, algorithm_id, link_key_id, archived_at,
           quarantined_at, quarantine_reason,
           CASE WHEN epoch_id IS NULL OR epoch_id < 0 THEN -1
                WHEN epoch_id = 0 THEN 0 WHEN epoch_id = 1 THEN 1 ELSE 2 END AS epoch_bin,
           CASE WHEN algorithm_id = 0 THEN 0 WHEN algorithm_id = 1 THEN 1 ELSE 2 END AS algorithm_bin,
           CASE WHEN quarantined_at IS NULL THEN 0 ELSE 1 END AS quarantine_bin,
           CASE WHEN quarantine_reason LIKE 'sequence_gap:%' THEN 1
                WHEN quarantine_reason LIKE 'chain_head_discontinuity:%' THEN 2
                WHEN quarantine_reason LIKE 'link_hash_mismatch:%' THEN 3
                WHEN quarantine_reason LIKE 'malformed_hash:%' THEN 4
                WHEN quarantine_reason LIKE 'mixed_partition:%' THEN 5
                WHEN quarantined_at IS NULL THEN 0 ELSE 6 END AS reason_bin,
           CASE WHEN emitted_at IS NOT NULL AND emitted_at < enqueued_at THEN 1 ELSE 0 END AS negative_latency
    FROM audit_outbox
),
class_stats AS (
    SELECT epoch_bin, algorithm_bin, quarantine_bin, COUNT(*) AS row_count,
           SUM(negative_latency) AS negative_latency_rows
    FROM source GROUP BY epoch_bin, algorithm_bin, quarantine_bin
),
reason_stats AS (
    SELECT reason_bin, COUNT(*) AS row_count,
           SUM(negative_latency) AS negative_latency_rows
    FROM source GROUP BY reason_bin
),
sequence_groups AS (
    SELECT tenant_id, region, sequence_number, COUNT(*) AS sequence_rows,
           SUM(quarantine_bin) AS quarantined_rows
    FROM source
    WHERE emitted_at IS NOT NULL AND sequence_number IS NOT NULL
    GROUP BY tenant_id, region, sequence_number
    HAVING COUNT(*) > 1
),
duplicate_stats AS (
    SELECT CASE WHEN quarantined_rows = 0 THEN 0
                WHEN quarantined_rows = sequence_rows THEN 2 ELSE 1 END AS duplicate_bin,
           COUNT(*) AS duplicate_groups, SUM(sequence_rows) AS duplicate_rows
    FROM sequence_groups GROUP BY duplicate_bin
),
max_tails AS (
    SELECT tenant_id, region, MAX(sequence_number) AS tail_sequence
    FROM source WHERE emitted_at IS NOT NULL AND sequence_number IS NOT NULL
    GROUP BY tenant_id, region
),
tail_candidates AS (
    SELECT m.tenant_id, m.region, m.tail_sequence, h.next_sequence, h.head_hash,
           h.head_signature, o.sequence_number, o.id, o.chain_hash, o.epoch_id,
           o.algorithm_id, o.link_key_id, o.archived_at, o.quarantined_at,
           o.quarantine_reason, r.resolution_version, r.tail_sequence AS resolution_tail_sequence,
           r.selected_row_id, r.selected_chain_hash, r.checkpoint_head_hash,
           r.checkpoint_next_sequence, r.checkpoint_head_signature,
           r.candidate_count, r.resolution_signature,
           COUNT(o.id) OVER (PARTITION BY m.tenant_id, m.region) AS candidate_count_actual,
           SUM(CASE WHEN o.chain_hash = h.head_hash THEN 1 ELSE 0 END)
               OVER (PARTITION BY m.tenant_id, m.region) AS checkpoint_hash_matches,
           SUM(CASE WHEN o.chain_hash = h.head_hash AND o.quarantined_at IS NULL
                         AND o.quarantine_reason IS NULL AND o.archived_at IS NOT NULL
                         AND o.epoch_id = 0 AND o.algorithm_id = 0 AND o.link_key_id IS NULL
                         AND o.sequence_number = 0 AND o.id = r.selected_row_id
                         AND o.chain_hash = r.selected_chain_hash
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY m.tenant_id, m.region) AS selected_candidate_matches,
           SUM(CASE WHEN o.chain_hash != h.head_hash
                         AND (o.archived_at IS NOT NULL OR o.quarantined_at IS NULL
                              OR o.quarantine_reason IS NULL OR trim(o.quarantine_reason) = '')
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY m.tenant_id, m.region) AS invalid_loser_count,
           SUM(CASE WHEN o.epoch_id != 0 OR o.algorithm_id != 0 OR o.link_key_id IS NOT NULL
                    THEN 1 ELSE 0 END)
               OVER (PARTITION BY m.tenant_id, m.region) AS nonlegacy_candidate_count
    FROM max_tails AS m
    LEFT JOIN audit_chain_head AS h
      ON h.tenant_id = m.tenant_id AND h.region = m.region
    LEFT JOIN source AS o
      ON o.tenant_id = m.tenant_id AND o.region = m.region
     AND o.sequence_number = m.tail_sequence AND o.emitted_at IS NOT NULL
    LEFT JOIN audit_chain_legacy_tail_resolution AS r
      ON r.tenant_id = m.tenant_id AND r.region = m.region
),
tail_partitions AS (
    SELECT tenant_id, region, tail_sequence, next_sequence, head_hash, head_signature,
           candidate_count_actual, checkpoint_hash_matches, selected_candidate_matches,
           invalid_loser_count, nonlegacy_candidate_count, resolution_version,
           resolution_tail_sequence, selected_row_id, selected_chain_hash,
           checkpoint_head_hash, checkpoint_next_sequence, checkpoint_head_signature,
           candidate_count, resolution_signature,
           MAX(CASE WHEN sequence_number = tail_sequence THEN 1 ELSE 0 END) AS has_tail
    FROM tail_candidates GROUP BY tenant_id, region
),
head_stats AS (
    SELECT (SELECT COUNT(*) FROM audit_chain_head) AS head_count,
           (SELECT COUNT(*) FROM audit_chain_head AS h
             WHERE NOT EXISTS (SELECT 1 FROM max_tails AS m
                                WHERE m.tenant_id = h.tenant_id AND m.region = h.region))
               AS missing_tail_heads,
           SUM(CASE WHEN next_sequence IS NULL THEN 1 ELSE 0 END) AS tail_without_head_partitions,
           SUM(CASE WHEN has_tail = 1 AND candidate_count_actual = 1
                         AND head_signature IS NOT NULL AND length(trim(head_signature)) > 0
                         AND next_sequence = tail_sequence + 1 AND checkpoint_hash_matches = 1
                    THEN 1 ELSE 0 END) AS unique_signed_tail_matches,
           SUM(CASE WHEN has_tail = 1 AND candidate_count_actual = 1
                         AND head_signature IS NOT NULL AND length(trim(head_signature)) > 0
                         AND next_sequence = tail_sequence + 1 AND checkpoint_hash_matches != 1
                    THEN 1 ELSE 0 END) AS unique_tail_hash_mismatches,
           SUM(CASE WHEN has_tail = 1 AND next_sequence IS NOT NULL AND candidate_count_actual > 1
                    THEN 1 ELSE 0 END) AS ambiguous_tail_heads,
           SUM(CASE WHEN has_tail = 1 AND next_sequence IS NOT NULL AND candidate_count_actual > 1
                         AND head_signature IS NOT NULL AND length(trim(head_signature)) > 0
                         AND checkpoint_hash_matches = 1
                    THEN 1 ELSE 0 END) AS ambiguous_one_checkpoint_match,
           SUM(CASE WHEN has_tail = 1 AND next_sequence IS NOT NULL AND candidate_count_actual BETWEEN 2 AND 32
                         AND tail_sequence = 0 AND next_sequence = 1
                         AND checkpoint_hash_matches = 1 AND selected_candidate_matches = 1
                         AND invalid_loser_count = 0 AND nonlegacy_candidate_count = 0
                         AND resolution_version = 1 AND resolution_tail_sequence = tail_sequence
                         AND selected_chain_hash = head_hash AND checkpoint_head_hash = head_hash
                         AND checkpoint_next_sequence = next_sequence
                         AND checkpoint_head_signature = head_signature
                         AND candidate_count = candidate_count_actual
                         AND resolution_signature IS NOT NULL
                    THEN 1 ELSE 0 END) AS structurally_resolved_legacy_genesis,
           SUM(CASE WHEN has_tail = 1 AND next_sequence IS NOT NULL AND candidate_count_actual > 1
                         AND COALESCE((tail_sequence = 0 AND next_sequence = 1
                                  AND checkpoint_hash_matches = 1
                                  AND selected_candidate_matches = 1
                                  AND invalid_loser_count = 0 AND nonlegacy_candidate_count = 0
                                  AND resolution_version = 1
                                  AND resolution_tail_sequence = tail_sequence
                                  AND selected_chain_hash = head_hash
                                  AND checkpoint_head_hash = head_hash
                                  AND checkpoint_next_sequence = next_sequence
                                  AND checkpoint_head_signature = head_signature
                                  AND candidate_count = candidate_count_actual
                                  AND resolution_signature IS NOT NULL), 0) = 0
                    THEN 1 ELSE 0 END) AS unresolved_ambiguous_tail_heads,
           SUM(CASE WHEN has_tail = 1 AND next_sequence < tail_sequence + 1
                    THEN 1 ELSE 0 END) AS head_behind,
           SUM(CASE WHEN has_tail = 0 OR next_sequence > tail_sequence + 1
                    THEN 1 ELSE 0 END) AS head_ahead
    FROM tail_partitions
),
row_specs(section, bin_a, bin_b, bin_c, epoch_bin, algorithm_bin, quarantine_bin, reason_bin, duplicate_bin) AS (
    VALUES
      ('class', 'epoch', 'algorithm', 'quarantine', -1,0,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', -1,0,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', -1,1,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', -1,1,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', -1,2,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', -1,2,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,0,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,0,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,1,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,1,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,2,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 0,2,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,0,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,0,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,1,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,1,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,2,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 1,2,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,0,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,0,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,1,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,1,1,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,2,0,-1,-1),
      ('class', 'epoch', 'algorithm', 'quarantine', 2,2,1,-1,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,0,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,1,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,2,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,3,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,4,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,5,-1),
      ('reason','reason','fixed','fixed',-1,-1,-1,6,-1),
      ('duplicate','quarantine_composition','fixed','fixed',-1,-1,-1,-1,0),
      ('duplicate','quarantine_composition','fixed','fixed',-1,-1,-1,-1,1),
      ('duplicate','quarantine_composition','fixed','fixed',-1,-1,-1,-1,2),
      ('heads','fixed','fixed','fixed',-1,-1,-1,-1,-1)
)
SELECT s.section, s.bin_a, s.bin_b, s.bin_c,
       CASE s.epoch_bin WHEN -1 THEN 'invalid_or_null' WHEN 0 THEN '0' WHEN 1 THEN '1' ELSE '2_plus' END AS epoch_bin,
       CASE s.algorithm_bin WHEN 0 THEN '0' WHEN 1 THEN '1' WHEN 2 THEN 'other' ELSE '' END AS algorithm_bin,
       CASE s.quarantine_bin WHEN 0 THEN 'not_quarantined' WHEN 1 THEN 'quarantined' ELSE '' END AS quarantine_bin,
       CASE s.reason_bin WHEN 0 THEN 'not_quarantined' WHEN 1 THEN 'sequence_gap'
            WHEN 2 THEN 'chain_head_discontinuity' WHEN 3 THEN 'link_hash_mismatch'
            WHEN 4 THEN 'malformed_hash' WHEN 5 THEN 'mixed_partition' WHEN 6 THEN 'other_quarantine'
            ELSE '' END AS reason_bin,
       CASE s.duplicate_bin WHEN 0 THEN 'all_live' WHEN 1 THEN 'mixed' WHEN 2 THEN 'all_quarantined' ELSE '' END AS duplicate_bin,
       CASE WHEN s.section='class' THEN COALESCE(c.row_count,0)
            WHEN s.section='reason' THEN COALESCE(r.row_count,0) ELSE 0 END AS row_count,
       CASE WHEN s.section='class' THEN COALESCE(c.negative_latency_rows,0)
            WHEN s.section='reason' THEN COALESCE(r.negative_latency_rows,0) ELSE 0 END AS negative_latency_rows,
       CASE WHEN s.section='duplicate' THEN COALESCE(d.duplicate_groups,0) ELSE 0 END AS duplicate_groups,
       CASE WHEN s.section='duplicate' THEN COALESCE(d.duplicate_rows,0) ELSE 0 END AS duplicate_rows,
       CASE WHEN s.section='heads' THEN COALESCE(h.head_count,0) ELSE 0 END AS chain_heads,
       CASE WHEN s.section='heads' THEN COALESCE(h.missing_tail_heads,0) ELSE 0 END AS missing_tail_heads,
       CASE WHEN s.section='heads' THEN COALESCE(h.tail_without_head_partitions,0) ELSE 0 END AS tail_without_head_partitions,
       CASE WHEN s.section='heads' THEN COALESCE(h.unique_signed_tail_matches,0) ELSE 0 END AS unique_signed_tail_matches,
       CASE WHEN s.section='heads' THEN COALESCE(h.unique_tail_hash_mismatches,0) ELSE 0 END AS unique_tail_hash_mismatches,
       CASE WHEN s.section='heads' THEN COALESCE(h.ambiguous_tail_heads,0) ELSE 0 END AS ambiguous_tail_heads,
       CASE WHEN s.section='heads' THEN COALESCE(h.ambiguous_one_checkpoint_match,0) ELSE 0 END AS ambiguous_one_checkpoint_match,
       CASE WHEN s.section='heads' THEN COALESCE(h.structurally_resolved_legacy_genesis,0) ELSE 0 END AS structurally_resolved_legacy_genesis,
       CASE WHEN s.section='heads' THEN COALESCE(h.unresolved_ambiguous_tail_heads,0) ELSE 0 END AS unresolved_ambiguous_tail_heads,
       CASE WHEN s.section='heads' THEN COALESCE(h.head_behind,0) ELSE 0 END AS head_behind,
       CASE WHEN s.section='heads' THEN COALESCE(h.head_ahead,0) ELSE 0 END AS head_ahead
FROM row_specs AS s
LEFT JOIN class_stats AS c ON s.section='class' AND c.epoch_bin=s.epoch_bin
 AND c.algorithm_bin=s.algorithm_bin AND c.quarantine_bin=s.quarantine_bin
LEFT JOIN reason_stats AS r ON s.section='reason' AND r.reason_bin=s.reason_bin
LEFT JOIN duplicate_stats AS d ON s.section='duplicate' AND d.duplicate_bin=s.duplicate_bin
CROSS JOIN head_stats AS h
ORDER BY s.section, s.epoch_bin, s.algorithm_bin, s.quarantine_bin, s.reason_bin, s.duplicate_bin
""".strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit-sql", action="store_true")
    args = parser.parse_args()
    if not args.emit_sql:
        parser.error("--emit-sql is required")
    print(ATTRIBUTION_SQL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
