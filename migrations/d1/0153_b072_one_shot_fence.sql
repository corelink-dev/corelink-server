-- B-072 single-use staging authorization and durable claim fence.
CREATE TABLE IF NOT EXISTS b072_one_shot_migration_receipt (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    migration_name TEXT NOT NULL CHECK (migration_name = '0153_b072_one_shot_fence.sql'),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms > 0)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_migration_receipt_no_update
BEFORE UPDATE ON b072_one_shot_migration_receipt
BEGIN
    SELECT RAISE(ABORT, 'B-072 migration receipt is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_migration_receipt_no_delete
BEFORE DELETE ON b072_one_shot_migration_receipt
BEGIN
    SELECT RAISE(ABORT, 'B-072 migration receipt is immutable');
END;

CREATE TABLE IF NOT EXISTS b072_one_shot_authorization (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    issue_id INTEGER NOT NULL CHECK (issue_id = 1652),
    serving_sha TEXT NOT NULL CHECK (length(serving_sha) = 40 AND serving_sha NOT GLOB '*[^0-9a-f]*'),
    approval_nonce TEXT NOT NULL CHECK (length(approval_nonce) BETWEEN 32 AND 128 AND approval_nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
    receiver_worker_revision TEXT NOT NULL CHECK (length(receiver_worker_revision) BETWEEN 1 AND 200),
    approved_reviewer TEXT NOT NULL CHECK (length(approved_reviewer) BETWEEN 1 AND 39),
    approved_run_id INTEGER NOT NULL CHECK (approved_run_id > 0),
    authorized_at_ms INTEGER NOT NULL CHECK (authorized_at_ms > 0),
    starts_at_ms INTEGER NOT NULL CHECK (starts_at_ms >= authorized_at_ms + 1200000),
    ends_at_ms INTEGER NOT NULL CHECK (ends_at_ms > starts_at_ms AND ends_at_ms - starts_at_ms <= 7200000)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_authorization_no_update
BEFORE UPDATE ON b072_one_shot_authorization
BEGIN
    SELECT RAISE(ABORT, 'B-072 authorization is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_authorization_no_delete
BEFORE DELETE ON b072_one_shot_authorization
BEGIN
    SELECT RAISE(ABORT, 'B-072 authorization is immutable');
END;

CREATE TABLE IF NOT EXISTS b072_one_shot_activation (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    approval_nonce TEXT NOT NULL CHECK (length(approval_nonce) BETWEEN 32 AND 128),
    receiver_worker_revision TEXT NOT NULL CHECK (length(receiver_worker_revision) BETWEEN 1 AND 200),
    armed_cron TEXT NOT NULL CHECK (armed_cron = '* * * * *'),
    armed_at_ms INTEGER NOT NULL CHECK (armed_at_ms > 0),
    activated_at_ms INTEGER NOT NULL CHECK (activated_at_ms > 0),
    FOREIGN KEY (singleton_id) REFERENCES b072_one_shot_authorization(singleton_id)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_activation_no_update
BEFORE UPDATE ON b072_one_shot_activation
BEGIN
    SELECT RAISE(ABORT, 'B-072 activation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_activation_no_delete
BEFORE DELETE ON b072_one_shot_activation
BEGIN
    SELECT RAISE(ABORT, 'B-072 activation is immutable');
END;

CREATE TABLE IF NOT EXISTS b072_one_shot_revocation (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    approval_nonce TEXT NOT NULL CHECK (length(approval_nonce) BETWEEN 32 AND 128),
    revoked_at_ms INTEGER NOT NULL CHECK (revoked_at_ms > 0),
    reason TEXT NOT NULL CHECK (reason IN ('disarmed', 'partial_arm_recovery', 'failed_execution')),
    FOREIGN KEY (singleton_id) REFERENCES b072_one_shot_authorization(singleton_id)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_revocation_no_update
BEFORE UPDATE ON b072_one_shot_revocation
BEGIN
    SELECT RAISE(ABORT, 'B-072 revocation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_revocation_no_delete
BEFORE DELETE ON b072_one_shot_revocation
BEGIN
    SELECT RAISE(ABORT, 'B-072 revocation is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_revocation_validate
BEFORE INSERT ON b072_one_shot_revocation
WHEN NOT EXISTS (
    SELECT 1 FROM b072_one_shot_authorization a
     WHERE a.singleton_id = NEW.singleton_id AND a.approval_nonce = NEW.approval_nonce
)
BEGIN
    SELECT RAISE(ABORT, 'B-072 revocation does not match its authorization');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_activation_validate
BEFORE INSERT ON b072_one_shot_activation
WHEN NOT EXISTS (
    SELECT 1 FROM b072_one_shot_authorization a
     WHERE a.singleton_id = NEW.singleton_id
       AND a.approval_nonce = NEW.approval_nonce
       AND a.receiver_worker_revision = NEW.receiver_worker_revision
       AND NEW.activated_at_ms >= NEW.armed_at_ms
       AND a.starts_at_ms >= NEW.armed_at_ms + 1200000
       AND NOT EXISTS (SELECT 1 FROM b072_one_shot_revocation r WHERE r.singleton_id = a.singleton_id)
)
BEGIN
    SELECT RAISE(ABORT, 'B-072 activation does not match an active authorization');
END;

CREATE TABLE IF NOT EXISTS b072_one_shot_claim (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    issue_id INTEGER NOT NULL CHECK (issue_id = 1652),
    drill_id TEXT NOT NULL UNIQUE CHECK (length(drill_id) = 16 AND substr(drill_id, 1, 3) = 'SP-' AND substr(drill_id, 4) NOT GLOB '*[^0-9]*'),
    scheduled_at_ms INTEGER NOT NULL CHECK (scheduled_at_ms > 0),
    serving_sha TEXT NOT NULL CHECK (length(serving_sha) = 40 AND serving_sha NOT GLOB '*[^0-9a-f]*'),
    approval_nonce TEXT NOT NULL CHECK (length(approval_nonce) BETWEEN 32 AND 128),
    claimed_at_ms INTEGER NOT NULL CHECK (claimed_at_ms > 0)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_claim_no_update
BEFORE UPDATE ON b072_one_shot_claim
BEGIN
    SELECT RAISE(ABORT, 'B-072 claim is immutable');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_claim_validate
BEFORE INSERT ON b072_one_shot_claim
WHEN NOT EXISTS (
    SELECT 1 FROM b072_one_shot_authorization a
      JOIN b072_one_shot_activation x ON x.singleton_id = a.singleton_id
     WHERE a.singleton_id = NEW.singleton_id AND a.issue_id = NEW.issue_id
       AND a.serving_sha = NEW.serving_sha AND a.approval_nonce = NEW.approval_nonce
       AND x.approval_nonce = a.approval_nonce
       AND x.receiver_worker_revision = a.receiver_worker_revision
       AND x.armed_cron = '* * * * *'
       AND NEW.scheduled_at_ms >= a.starts_at_ms AND NEW.scheduled_at_ms < a.ends_at_ms
       AND NOT EXISTS (SELECT 1 FROM b072_one_shot_revocation r WHERE r.singleton_id = a.singleton_id)
)
BEGIN
    SELECT RAISE(ABORT, 'B-072 claim does not match an active authorization');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_claim_no_delete
BEFORE DELETE ON b072_one_shot_claim
BEGIN
    SELECT RAISE(ABORT, 'B-072 claim is immutable');
END;

CREATE TABLE IF NOT EXISTS b072_one_shot_ingress (
    singleton_id INTEGER NOT NULL PRIMARY KEY CHECK (singleton_id = 1),
    drill_id TEXT NOT NULL CHECK (length(drill_id) = 16 AND substr(drill_id, 1, 3) = 'SP-' AND substr(drill_id, 4) NOT GLOB '*[^0-9]*'),
    scheduled_at_ms INTEGER NOT NULL CHECK (scheduled_at_ms > 0),
    serving_sha TEXT NOT NULL CHECK (length(serving_sha) = 40 AND serving_sha NOT GLOB '*[^0-9a-f]*'),
    receiver_worker_revision TEXT NOT NULL CHECK (length(receiver_worker_revision) BETWEEN 1 AND 200),
    ingress_count INTEGER NOT NULL CHECK (ingress_count > 0),
    last_ingress_at_ms INTEGER NOT NULL CHECK (last_ingress_at_ms > 0)
);

CREATE TRIGGER IF NOT EXISTS b072_one_shot_ingress_update_once
BEFORE UPDATE ON b072_one_shot_ingress
WHEN NEW.singleton_id <> OLD.singleton_id OR NEW.drill_id <> OLD.drill_id OR
     NEW.scheduled_at_ms <> OLD.scheduled_at_ms OR NEW.serving_sha <> OLD.serving_sha OR
     NEW.receiver_worker_revision <> OLD.receiver_worker_revision OR
     NEW.ingress_count <> OLD.ingress_count + 1 OR NEW.last_ingress_at_ms < OLD.last_ingress_at_ms
BEGIN
    SELECT RAISE(ABORT, 'B-072 ingress update is not a correlated increment');
END;

CREATE TRIGGER IF NOT EXISTS b072_one_shot_ingress_no_delete
BEFORE DELETE ON b072_one_shot_ingress
BEGIN
    SELECT RAISE(ABORT, 'B-072 ingress count is durable');
END;
