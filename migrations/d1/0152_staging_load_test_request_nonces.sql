-- #2576 v2: request-scoped nonce consumption for repeated open-run admission.
--
-- This table deliberately has no UNIQUE(run_id, scenario): each authenticated
-- v2 request consumes one fresh nonce while the run identity remains immutable.
CREATE TABLE IF NOT EXISTS staging_load_test_request_nonces (
    nonce_digest TEXT NOT NULL CHECK (length(nonce_digest) = 64 AND nonce_digest NOT GLOB '*[^0-9a-f]*'),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 20 AND run_id NOT GLOB '*[^0-9]*' AND substr(run_id, 1, 1) <> '0'),
    scenario TEXT NOT NULL CHECK (scenario IN ('signup', 'webhook', 'dsr', 'cas', 'byok', 'endurance-2h', 'b103-cargo-write')),
    target_environment TEXT NOT NULL CHECK (target_environment = 'staging'),
    target_deployment_sha TEXT NOT NULL CHECK (length(target_deployment_sha) = 40 AND target_deployment_sha NOT GLOB '*[^0-9a-f]*'),
    issued_at_ms INTEGER NOT NULL CHECK (issued_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > issued_at_ms AND expires_at_ms - issued_at_ms <= 900000),
    admitted_at_ms INTEGER NOT NULL CHECK (admitted_at_ms >= issued_at_ms AND admitted_at_ms < expires_at_ms),
    PRIMARY KEY (nonce_digest),
    FOREIGN KEY (run_id, scenario) REFERENCES staging_load_test_runs(run_id, scenario)
);

-- Foreign keys can be disabled per SQLite connection, so enforce the exact
-- immutable open identity independently at the table boundary.
CREATE TRIGGER IF NOT EXISTS trg_staging_load_test_request_nonce_requires_exact_open_run
BEFORE INSERT ON staging_load_test_request_nonces
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM staging_load_test_runs
    WHERE run_id = NEW.run_id AND scenario = NEW.scenario
      AND target_environment = NEW.target_environment
      AND target_deployment_sha = NEW.target_deployment_sha
      AND state = 'open'
)
BEGIN
    SELECT RAISE(ABORT, 'staging request nonce requires its exact open run identity');
END;

CREATE TRIGGER IF NOT EXISTS trg_staging_load_test_request_nonce_no_update
BEFORE UPDATE ON staging_load_test_request_nonces FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'staging request nonce record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_staging_load_test_request_nonce_no_delete
BEFORE DELETE ON staging_load_test_request_nonces FOR EACH ROW BEGIN
    SELECT RAISE(ABORT, 'staging request nonce record is append-only');
END;
