//! Normal-process CLI regression tests for issue #2614's indeterminate keyring outcome.

use std::fs;
use std::process::{Command, Output};

use corelink_audit_chain::{
    canonical_date_yyyy_mm_dd, link_for_epoch, sealed_chunk_key, ChainEpoch, ChainHash, LinkKey,
    SealedArchiveLine, SEALED_LINE_SCHEMA, SEALED_LINE_SCHEMA_V2,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const SYNTHETIC_KEY_7: [u8; 32] = [0x27; 32];
const SYNTHETIC_KEY_8: [u8; 32] = [0x38; 32];

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("corelink-i2614-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_verifier"))
}

fn write_chain(dir: &TempDir) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    let key_7 = LinkKey::from_bytes(SYNTHETIC_KEY_7);
    let key_8 = LinkKey::from_bytes(SYNTHETIC_KEY_8);
    let canonical = r#"{"event":"synthetic"}"#;
    let day = canonical_date_yyyy_mm_dd(1);
    let first_epoch = ChainEpoch::legacy();
    let first_hash = link_for_epoch(
        &first_epoch,
        &ChainHash::genesis(),
        canonical.as_bytes(),
        None,
    )?;
    let first = SealedArchiveLine {
        schema: SEALED_LINE_SCHEMA.to_owned(),
        algorithm_id: 0,
        epoch_id: 0,
        link_key_id: None,
        tenant_id: "tenant-i2614".to_owned(),
        region: "weur".to_owned(),
        sequence_number: 4,
        prev_hash: ChainHash::genesis().to_hex(),
        chain_hash: first_hash.to_hex(),
        enqueued_at_ms: 1,
        row_id: "row-4".to_owned(),
        canonical_jcs: canonical.to_owned(),
    };
    let second_epoch = ChainEpoch::keyed_successor(1, 7, 5, first_hash, 0)?;
    let second_hash = link_for_epoch(
        &second_epoch,
        &first_hash,
        canonical.as_bytes(),
        Some(&key_7),
    )?;
    let second = SealedArchiveLine {
        schema: SEALED_LINE_SCHEMA_V2.to_owned(),
        algorithm_id: 1,
        epoch_id: 1,
        link_key_id: Some(7),
        tenant_id: "tenant-i2614".to_owned(),
        region: "weur".to_owned(),
        sequence_number: 5,
        prev_hash: first_hash.to_hex(),
        chain_hash: second_hash.to_hex(),
        enqueued_at_ms: 2,
        row_id: "row-5".to_owned(),
        canonical_jcs: canonical.to_owned(),
    };
    let third_epoch = ChainEpoch::keyed_successor(2, 8, 6, second_hash, 1)?;
    let third_hash = link_for_epoch(
        &third_epoch,
        &second_hash,
        canonical.as_bytes(),
        Some(&key_8),
    )?;
    let third = SealedArchiveLine {
        schema: SEALED_LINE_SCHEMA_V2.to_owned(),
        algorithm_id: 1,
        epoch_id: 2,
        link_key_id: Some(8),
        tenant_id: "tenant-i2614".to_owned(),
        region: "weur".to_owned(),
        sequence_number: 6,
        prev_hash: second_hash.to_hex(),
        chain_hash: third_hash.to_hex(),
        enqueued_at_ms: 3,
        row_id: "row-6".to_owned(),
        canonical_jcs: canonical.to_owned(),
    };
    let checkpoint_path = dir.path().join("checkpoint-in.json");
    let mut checkpoint = json!({
        "schema": "corelink.audit.daily-checkpoint.v1",
        "tenant_id": "tenant-i2614",
        "region": "weur",
        "through_day": "1969-12-31",
        "last_sequence": 3,
        "last_chain_hash": ChainHash::genesis().to_hex(),
        "current_epoch_id": 0,
        "current_link_key_id": null,
        "next_sequence": 4,
        "next_prev_hash": ChainHash::genesis().to_hex(),
        "next_day": day,
        "checkpoint_key_id": 8,
        "previous_checkpoint_mac": "00".repeat(32),
        "checkpoint_mac": ""
    });
    let payload = checkpoint_payload(&checkpoint);
    let canonical_checkpoint = serde_jcs::to_vec(&payload)?;
    let checkpoint_key = LinkKey::from_bytes(SYNTHETIC_KEY_8);
    let mut mac = blake3::Hasher::new_keyed(checkpoint_key.as_bytes());
    mac.update(b"corelink/audit-chain/daily-checkpoint/v1\0");
    mac.update(&canonical_checkpoint);
    checkpoint
        .as_object_mut()
        .ok_or("checkpoint fixture is not a JSON object")?
        .insert(
            "checkpoint_mac".to_owned(),
            json!(mac.finalize().to_hex().to_string()),
        );
    fs::write(&checkpoint_path, serde_json::to_vec(&checkpoint)?)?;

    let mut paths = Vec::new();
    for line in [first, second, third] {
        let body = serde_json::to_string(&line)? + "\n";
        let base_key = sealed_chunk_key(&line);
        let key = if line.epoch_id == 0 {
            base_key
        } else {
            let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
            format!("{base_key}.epoch-{}.{}", line.epoch_id, digest)
        };
        let path = dir.path().join(".audit-verify-staging/chunks").join(key);
        fs::create_dir_all(path.parent().ok_or("archive path missing parent")?)?;
        fs::write(&path, body)?;
        paths.push(path);
    }
    Ok(paths)
}

fn checkpoint_payload(checkpoint: &Value) -> Value {
    json!({
        "schema": checkpoint["schema"],
        "tenant_id": checkpoint["tenant_id"],
        "region": checkpoint["region"],
        "through_day": checkpoint["through_day"],
        "last_sequence": checkpoint["last_sequence"],
        "last_chain_hash": checkpoint["last_chain_hash"],
        "current_epoch_id": checkpoint["current_epoch_id"],
        "current_link_key_id": checkpoint["current_link_key_id"],
        "next_sequence": checkpoint["next_sequence"],
        "next_prev_hash": checkpoint["next_prev_hash"],
        "next_day": checkpoint["next_day"],
        "checkpoint_key_id": checkpoint["checkpoint_key_id"],
        "previous_checkpoint_mac": checkpoint["previous_checkpoint_mac"]
    })
}

fn invoke(dir: &TempDir, keyring: &str) -> Result<Output, Box<dyn std::error::Error>> {
    let archives = write_chain(dir)?;
    let keyring_path = dir.path().join("keyring.json");
    fs::write(&keyring_path, keyring)?;
    let checkpoint = dir.path().join("checkpoint.json");
    let output = cli()
        .arg("--chain-keyring")
        .arg(keyring_path)
        .arg("--verify-day")
        .arg(canonical_date_yyyy_mm_dd(1))
        .arg("--checkpoint-key-id")
        .arg("8")
        .arg("--checkpoint-out")
        .arg(checkpoint)
        .arg("--checkpoint-in")
        .arg(dir.path().join("checkpoint-in.json"))
        .args(archives)
        .output()?;
    Ok(output)
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_indeterminate(output: &Output) {
    let text = combined(output);
    assert!(
        !output.status.success(),
        "CLI unexpectedly succeeded: {text}"
    );
    assert!(
        text.contains("AUDIT_CHAIN_VERIFY_INDETERMINATE: {\"outcome\":\"INDETERMINATE\""),
        "missing structured INDETERMINATE: {text}"
    );
    assert!(
        !text.contains("AUDIT_CHAIN_VERIFY_OK"),
        "false success: {text}"
    );
    assert!(
        text.contains("AUDIT_CHAIN_BREAK_DETECTED"),
        "missing existing alert marker: {text}"
    );
}

#[test]
fn cli_reports_indeterminate_for_malformed_keyring_json_and_entry(
) -> Result<(), Box<dyn std::error::Error>> {
    for invalid in ["{", r#"{"7":"not-a-key"}"#] {
        let dir = TempDir::new()?;
        let output = invoke(&dir, invalid)?;
        assert_indeterminate(&output);
        assert!(!dir.path().join("checkpoint.json").exists());
    }
    Ok(())
}

#[test]
fn cli_reports_indeterminate_for_invalid_or_missing_historic_key_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let invalid_id = TempDir::new()?;
    let output = invoke(&invalid_id, &format!(r#"{{"0":"{}"}}"#, "00".repeat(32)))?;
    assert_indeterminate(&output);
    assert!(!invalid_id.path().join("checkpoint.json").exists());

    let missing_id = TempDir::new()?;
    let keyring = format!(r#"{{"8":"{}"}}"#, "38".repeat(32));
    let output = invoke(&missing_id, &keyring)?;
    assert_indeterminate(&output);
    assert!(!missing_id.path().join("checkpoint.json").exists());
    Ok(())
}

#[test]
fn cli_reports_indeterminate_for_unavailable_keyring_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let archives = write_chain(&dir)?;
    let checkpoint = dir.path().join("checkpoint.json");
    let output = cli()
        .arg("--chain-keyring")
        .arg(dir.path().join("absent-keyring.json"))
        .arg("--verify-day")
        .arg(canonical_date_yyyy_mm_dd(1))
        .arg("--checkpoint-key-id")
        .arg("8")
        .arg("--checkpoint-out")
        .arg(&checkpoint)
        .arg("--checkpoint-in")
        .arg(dir.path().join("checkpoint-in.json"))
        .args(archives)
        .output()?;
    assert_indeterminate(&output);
    assert!(!checkpoint.exists());
    Ok(())
}

#[test]
fn cli_keeps_valid_mixed_epoch_history_green() -> Result<(), Box<dyn std::error::Error>> {
    let dir = TempDir::new()?;
    let keyring = format!(r#"{{"7":"{}","8":"{}"}}"#, "27".repeat(32), "38".repeat(32));
    let output = invoke(&dir, &keyring)?;
    let text = combined(&output);
    assert!(
        output.status.success(),
        "valid mixed history failed: {text}"
    );
    assert!(
        text.contains("AUDIT_CHAIN_VERIFY_OK"),
        "missing success marker: {text}"
    );
    assert!(
        !text.contains("INDETERMINATE"),
        "false indeterminate: {text}"
    );
    assert!(dir.path().join("checkpoint.json").exists());
    Ok(())
}
