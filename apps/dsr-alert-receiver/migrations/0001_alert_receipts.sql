-- No headers, tokens, raw body, DSR/tenant/subject IDs, salts, or provider responses are stored.
CREATE TABLE IF NOT EXISTS dsr_alert_receipts (
  event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id) = 80 AND substr(event_id, 1, 16) = 'dsr-erasure-dlq:' AND substr(event_id, 17) NOT GLOB '*[^0-9a-f]*'),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  event TEXT NOT NULL CHECK (event = 'dsr.erasure.dead_letter'),
  severity TEXT NOT NULL CHECK (severity = 'critical'),
  component TEXT NOT NULL CHECK (component = 'dsr-erasure-dlq'),
  exhausted INTEGER NOT NULL CHECK (exhausted = 1),
  requeue_count INTEGER NOT NULL CHECK (requeue_count IN (0, 1)),
  received_at_ms INTEGER NOT NULL CHECK (received_at_ms >= 0)
);
