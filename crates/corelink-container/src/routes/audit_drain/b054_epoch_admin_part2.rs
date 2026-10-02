    /// Optional preflight for the secret-bearing runtime. It proves that the
    /// supplied 32-byte link key is the one committed by the authenticated row;
    /// neither this function nor the returned value retains the secret.
    pub(super) fn b054_verify_link_key_commitment(
        link: &B054AuthenticatedLinkKey,
        key: &[u8; 32],
    ) -> Result<(), String> {
        if hash_domain_payload(B054_ADMIN_LINK_COMMITMENT_DOMAIN, key) != link.record.key_commitment_hex
        {
            return Err("B054 configured link key does not match signed commitment".to_owned());
        }
        Ok(())
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    pub(super) enum B054EpochAdminRequest {
        ProvisionSigningKey {
            registry_jcs_b64: String,
            registry_signature_b64: String,
            approval_jcs_b64: String,
            approval_signature_b64: String,
            executor_signature_b64: String,
        },
        ProvisionLinkKey {
            link_key_id: u64,
            registered_at_ms: u64,
            approval_jcs_b64: String,
            approval_signature_b64: String,
            executor_signature_b64: String,
        },
        BootstrapE0 {
            tenant_id: String,
            region: String,
            approval_jcs_b64: String,
            approval_signature_b64: String,
            executor_signature_b64: String,
        },
        TransitionE1 {
            tenant_id: String,
            region: String,
            link_key_id: u64,
            approval_jcs_b64: String,
            approval_signature_b64: String,
            executor_signature_b64: String,
        },
    }

    #[derive(Debug, serde::Serialize)]
    #[serde(tag = "operation", rename_all = "snake_case")]
    enum B054EpochAdminOperation {
        ProvisionSigningKey {
            registry_jcs_b64: String,
            registry_signature_b64: String,
        },
        ProvisionLinkKey {
            link_key_id: u64,
            registered_at_ms: u64,
        },
        BootstrapE0 {
            tenant_id: String,
            region: String,
        },
        TransitionE1 {
            tenant_id: String,
            region: String,
            link_key_id: u64,
        },
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct B054AdminApprovalJcs {
        approval_id: String,
        approval_version: u8,
        approver_role: String,
        approver_subject_id: String,
        audience: String,
        approver_eligible: bool,
        executor_role: String,
        executor_eligible: bool,
        executor_public_key_b64: String,
        executor_subject_id: String,
        expires_at_ms: u64,
        issuer: String,
        issued_at_ms: u64,
        nonce: String,
        operation_digest_hex: String,
        trust_root_key_id: String,
    }

    struct B054VerifiedAdminApproval {
        claims: B054AdminApprovalJcs,
        claims_jcs: Vec<u8>,
        signature_b64: String,
    }

    impl B054EpochAdminRequest {
        fn operation(&self) -> B054EpochAdminOperation {
            match self {
                Self::ProvisionSigningKey {
                    registry_jcs_b64,
                    registry_signature_b64,
                    ..
                } => B054EpochAdminOperation::ProvisionSigningKey {
                    registry_jcs_b64: registry_jcs_b64.clone(),
                    registry_signature_b64: registry_signature_b64.clone(),
                },
                Self::ProvisionLinkKey {
                    link_key_id,
                    registered_at_ms,
                    ..
                } => B054EpochAdminOperation::ProvisionLinkKey {
                    link_key_id: *link_key_id,
                    registered_at_ms: *registered_at_ms,
                },
                Self::BootstrapE0 {
                    tenant_id, region, ..
                } => B054EpochAdminOperation::BootstrapE0 {
                    tenant_id: tenant_id.clone(),
                    region: region.clone(),
                },
                Self::TransitionE1 {
                    tenant_id,
                    region,
                    link_key_id,
                    ..
                } => B054EpochAdminOperation::TransitionE1 {
                    tenant_id: tenant_id.clone(),
                    region: region.clone(),
                    link_key_id: *link_key_id,
                },
            }
        }

        fn approval_artifact(&self) -> (&str, &str, &str) {
            match self {
                Self::ProvisionSigningKey {
                    approval_jcs_b64,
                    approval_signature_b64,
                    executor_signature_b64,
                    ..
                }
                | Self::ProvisionLinkKey {
                    approval_jcs_b64,
                    approval_signature_b64,
                    executor_signature_b64,
                    ..
                }
                | Self::BootstrapE0 {
                    approval_jcs_b64,
                    approval_signature_b64,
                    executor_signature_b64,
                    ..
                }
                | Self::TransitionE1 {
                    approval_jcs_b64,
                    approval_signature_b64,
                    executor_signature_b64,
                    ..
                } => (approval_jcs_b64, approval_signature_b64, executor_signature_b64),
            }
        }
    }

    const B054_ADMIN_APPROVAL_DOMAIN: &[u8] = b"corelink/audit-chain/admin-approval/v1\0";
    const B054_ADMIN_APPROVAL_AUDIENCE: &str = "corelink-b054-epoch-admin-v1";
    const B054_ADMIN_APPROVAL_MAX_AGE_MS: u64 = 5 * 60 * 1000;

    fn b054_admin_now_ms() -> Result<u64, String> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "B054 approval clock before Unix epoch".to_owned())?
            .as_millis()
            .try_into()
            .map_err(|_| "B054 approval clock exceeds supported range".to_owned())
    }

    fn b054_admin_operation_digest(operation: &B054EpochAdminOperation) -> Result<String, String> {
        let canonical =
            serde_jcs::to_vec(operation).map_err(|error| format!("B054 operation JCS: {error}"))?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"corelink/audit-chain/admin-operation/v1\0");
        hasher.update(&canonical);
        Ok(hasher.finalize().to_hex().to_string())
    }

    const B054_ADMIN_EXECUTOR_DOMAIN: &[u8] = b"corelink/audit-chain/admin-executor/v1\0";

    fn b054_admin_executor_message(claims: &B054AdminApprovalJcs) -> Vec<u8> {
        let mut message = B054_ADMIN_EXECUTOR_DOMAIN.to_vec();
        message.extend_from_slice(claims.approval_id.as_bytes());
        message.push(0);
        message.extend_from_slice(claims.nonce.as_bytes());
        message.push(0);
        message.extend_from_slice(claims.operation_digest_hex.as_bytes());
        message
    }
    fn b054_verify_admin_approval(
        operation: &B054EpochAdminOperation,
        approval_jcs_b64: &str,
        signature_b64: &str,
        executor_signature_b64: &str,
        roots: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
        now_ms: u64,
    ) -> Result<B054VerifiedAdminApproval, String> {
        let claims_jcs = decode_canonical_base64(approval_jcs_b64, None)?;
        let claims: B054AdminApprovalJcs =
            b054_admin_parse_exact(&claims_jcs, "B054 admin approval JCS")?;
        let max_int = i64::MAX as u64;
        if claims.approval_version != 1
            || claims.audience != B054_ADMIN_APPROVAL_AUDIENCE
            || claims.executor_role != "SRE executor"
            || claims.approver_role != "Security approver"
            || !claims.executor_eligible
            || !claims.approver_eligible
            || claims.executor_subject_id.is_empty()
            || claims.approver_subject_id.is_empty()
            || claims.executor_subject_id.len() > 256
            || claims.approver_subject_id.len() > 256
            || !claims
                .executor_subject_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || !claims
                .approver_subject_id
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || claims.executor_subject_id == claims.approver_subject_id
            || !b054_admin_root_id(&claims.approval_id)
            || !b054_admin_root_id(&claims.trust_root_key_id)
            || claims.issuer != claims.trust_root_key_id
            || claims.nonce.len() != 64
            || !claims
                .nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || claims.issued_at_ms > max_int
            || claims.expires_at_ms > max_int
            || claims.expires_at_ms <= claims.issued_at_ms
            || claims.expires_at_ms - claims.issued_at_ms > B054_ADMIN_APPROVAL_MAX_AGE_MS
            || now_ms < claims.issued_at_ms
            || now_ms >= claims.expires_at_ms
            || claims.operation_digest_hex != b054_admin_operation_digest(operation)?
        {
            return Err("B054 admin approval claims do not authorize this operation".to_owned());
        }
        let root = roots
            .get(&claims.trust_root_key_id)
            .ok_or("B054 admin approval names unknown pinned trust root")?;
        let mut signed = Vec::with_capacity(B054_ADMIN_APPROVAL_DOMAIN.len() + claims_jcs.len());
        signed.extend_from_slice(B054_ADMIN_APPROVAL_DOMAIN);
        signed.extend_from_slice(&claims_jcs);
        b054_admin_verify_raw_signature(root, &signed, signature_b64, "B054 admin approval")?;
        let executor_public_key: [u8; 32] = decode_canonical_base64(&claims.executor_public_key_b64, Some(32))?
            .try_into()
            .map_err(|_| "B054 executor public-key length mismatch")?;
        let executor_key = ed25519_dalek::VerifyingKey::from_bytes(&executor_public_key)
            .map_err(|_| "B054 executor public key malformed")?;
        b054_admin_verify_raw_signature(
            &executor_key,
            &b054_admin_executor_message(&claims),
            executor_signature_b64,
            "B054 executor possession",
        )?;
        Ok(B054VerifiedAdminApproval {
            claims,
            claims_jcs,
            signature_b64: signature_b64.to_owned(),
        })
    }

    async fn b054_consume_admin_approval(
        d1: &D1HttpClient,
        approval: &B054VerifiedAdminApproval,
        now_ms: u64,
    ) -> Result<(), String> {
        let nonce_hash = blake3::hash(approval.claims.nonce.as_bytes())
            .to_hex()
            .to_string();
        d1.batch(vec![D1BatchStatement::new(
                    "INSERT INTO audit_chain_admin_approval (approval_id,nonce_hash,executor_subject_id,approver_subject_id,operation_digest_hex,approval_jcs_b64,approval_signature_b64,issued_at_ms,expires_at_ms,consumed_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    vec![json!(approval.claims.approval_id), json!(nonce_hash), json!(approval.claims.executor_subject_id), json!(approval.claims.approver_subject_id), json!(approval.claims.operation_digest_hex), json!(base64::engine::general_purpose::STANDARD.encode(&approval.claims_jcs)), json!(approval.signature_b64), json!(approval.claims.issued_at_ms as i64), json!(approval.claims.expires_at_ms as i64), json!(now_ms as i64)],
                )]).await.map(|_| ()).map_err(|error| format!("B054 admin approval replay/ledger rejection: {}", error.message))
    }

    fn admin_response(status: StatusCode, operation: &str, result: &str) -> Response {
        (
            status,
            Json(json!({ "operation": operation, "result": result })),
        )
            .into_response()
    }

    fn artifact_from_b64(jcs_b64: &str, signature_b64: &str) -> Result<B054SignedArtifact, String> {
        Ok(B054SignedArtifact {
            jcs: decode_canonical_base64(jcs_b64, None)?,
            signature_b64: signature_b64.to_owned(),
        })
    }

    async fn execute_admin_transaction(
        d1: &D1HttpClient,
        transaction: B054AdminTransaction,
    ) -> Result<(), String> {
        d1.batch(transaction.statements)
            .await
            .map(|_| ())
            .map_err(|error| {
                format!(
                    "B054 administrative D1 transaction rolled back at {:?}: {}",
                    error.statement, error.message
                )
            })
    }

    async fn load_authenticated_signing_key(
        d1: &D1HttpClient,
        key_id: u64,
        roots: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
    ) -> Result<B054AuthenticatedSigningKey, String> {
        let rows = d1
                    .query(
                        "SELECT registry_jcs,registry_signature_b64 FROM audit_chain_signing_key_registry WHERE signing_key_id=?1",
                        &[json!(b054_admin_i64(key_id, "signing key id")?)],
                    )
                    .await?;
        if rows.len() != 1 {
            return Err("B054 current signing registry is absent or ambiguous".to_owned());
        }
        let row = Value::Object(
            rows.into_iter()
                .next()
                .ok_or("B054 signing registry disappeared")?,
        );
        let artifact = B054SignedArtifact {
            jcs: decode_d1_blob(
                row.get("registry_jcs")
                    .ok_or("B054 signing registry JCS missing")?,
                "B054 signing registry JCS",
                B054_ADMIN_MAX_JCS_BYTES,
            )?,
            signature_b64: row
                .get("registry_signature_b64")
                .and_then(Value::as_str)
                .ok_or("B054 signing registry signature missing")?
                .to_owned(),
        };
        let key = b054_authenticate_signing_registry(artifact, roots)?;
        if key.record.signing_key_id != key_id {
            return Err("B054 signing registry indexed id mismatch".to_owned());
        }
        Ok(key)
    }

    fn require_current_seed_key(
        key: &B054AuthenticatedSigningKey,
        seed: &[u8; 32],
        region: &str,
    ) -> Result<(), String> {
        let current = ErasureSigningKey::from_seed(
            key.record.signing_key_id,
            region_for_key(region),
            0,
            0,
            *seed,
        )
        .public_key()
        .verifying_key;
        if current != key.verifying_key {
            return Err(
                "B054 current signing seed differs from root-authenticated registry".to_owned(),
            );
        }
        Ok(())
    }

    async fn load_e0_ledger_artifact(
        d1: &D1HttpClient,
        tenant_id: &str,
        region: &str,
    ) -> Result<B054SignedArtifact, String> {
        let rows = d1
                    .query(
                        "SELECT entry_jcs,signature_b64 FROM audit_chain_epoch_ledger WHERE tenant_id=?1 AND region=?2 AND ledger_sequence=0 AND epoch_id=0",
                        &[json!(tenant_id), json!(region)],
                    )
                    .await?;
        if rows.len() != 1 {
            return Err("B054 E0 ledger is absent or ambiguous".to_owned());
        }
        let row = Value::Object(
            rows.into_iter()
                .next()
                .ok_or("B054 E0 ledger disappeared")?,
        );
        Ok(B054SignedArtifact {
            jcs: decode_d1_blob(
                row.get("entry_jcs").ok_or("B054 E0 ledger JCS missing")?,
                "B054 E0 ledger JCS",
                B054_ADMIN_MAX_JCS_BYTES,
            )?,
            signature_b64: row
                .get("signature_b64")
                .and_then(Value::as_str)
                .ok_or("B054 E0 ledger signature missing")?
                .to_owned(),
        })
    }

    async fn load_authenticated_link_key(
        d1: &D1HttpClient,
        link_key_id: u64,
        signing: &B054AuthenticatedSigningKey,
    ) -> Result<B054AuthenticatedLinkKey, String> {
        let rows = d1
                    .query(
                        "SELECT registry_jcs,registry_signature_b64 FROM audit_chain_link_key_registry WHERE link_key_id=?1",
                        &[json!(b054_admin_i64(link_key_id, "link key id")?)],
                    )
                    .await?;
        if rows.len() != 1 {
            return Err("B054 link registry is absent or ambiguous".to_owned());
        }
        let row = Value::Object(
            rows.into_iter()
                .next()
                .ok_or("B054 link registry disappeared")?,
        );
        let artifact = B054SignedArtifact {
            jcs: decode_d1_blob(
                row.get("registry_jcs")
                    .ok_or("B054 link registry JCS missing")?,
                "B054 link registry JCS",
                B054_ADMIN_MAX_JCS_BYTES,
            )?,
            signature_b64: row
                .get("registry_signature_b64")
                .and_then(Value::as_str)
                .ok_or("B054 link registry signature missing")?
                .to_owned(),
        };
        let link = b054_authenticate_link_registry(artifact, signing)?;
        if link.record.link_key_id != link_key_id {
            return Err("B054 link registry indexed id mismatch".to_owned());
        }
        Ok(link)
    }

    async fn load_verified_d1_witness(
        d1: &D1HttpClient,
        client: &WitnessClient,
        tenant_id: &str,
        region: &str,
        witness_sequence: u64,
        witness_hash: &str,
    ) -> Result<VerifiedWitness, String> {
        let rows = d1.query(
                    "SELECT witness_jcs,receipt_jcs,receipt_signature_b64,witness_key_id,witness_record_hash,witness_sequence FROM audit_chain_witness_receipt WHERE tenant_id=?1 AND region=?2 AND witness_sequence=?3 AND witness_record_hash=?4",
                    &[json!(tenant_id),json!(region),json!(b054_admin_i64(witness_sequence, "witness sequence")?),json!(witness_hash)],
                ).await?;
        if rows.len() != 1 {
            return Err("B054 D1 witness predecessor is absent or ambiguous".to_owned());
        }
        let row = Value::Object(
            rows.into_iter()
                .next()
                .ok_or("B054 D1 witness disappeared")?,
        );
        let witness_jcs = decode_d1_blob(
            row.get("witness_jcs")
                .ok_or("B054 D1 witness JCS missing")?,
            "B054 D1 witness JCS",
            B054_ADMIN_MAX_JCS_BYTES,
        )?;
        let receipt_jcs = decode_d1_blob(
            row.get("receipt_jcs")
                .ok_or("B054 D1 receipt JCS missing")?,
            "B054 D1 receipt JCS",
            B054_ADMIN_MAX_JCS_BYTES,
        )?;
        let envelope = WitnessReceipt {
            receipt_jcs_b64: base64::engine::general_purpose::STANDARD.encode(receipt_jcs),
            receipt_signature_b64: row
                .get("receipt_signature_b64")
                .and_then(Value::as_str)
                .ok_or("B054 D1 receipt signature missing")?
                .to_owned(),
            witness_jcs_b64: base64::engine::general_purpose::STANDARD.encode(witness_jcs),
            witness_key_id: row
                .get("witness_key_id")
                .and_then(Value::as_i64)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or("B054 D1 witness key id invalid")?,
            witness_record_hash: row
                .get("witness_record_hash")
                .and_then(Value::as_str)
                .ok_or("B054 D1 witness hash missing")?
                .to_owned(),
            witness_sequence: row
                .get("witness_sequence")
                .and_then(Value::as_i64)
                .and_then(|value| u64::try_from(value).ok())
                .ok_or("B054 D1 witness sequence invalid")?,
        };
        verify_receipt(&envelope, None, &client.witness_id, &client.public_keys)
    }

    fn witness_binds_prepared(
        witness: &VerifiedWitness,
        head: &B054SignedArtifact,
        tenant_id: &str,
        region: &str,
        sequence: u64,
        previous_hash: &str,
    ) -> Result<bool, String> {
        Ok(witness.record.tenant_id == tenant_id
            && witness.record.region == region
            && witness.record.witness_sequence == sequence
            && witness.record.previous_witness_hash == previous_hash
            && decode_canonical_base64(&witness.record.head_message_b64, None)? == head.jcs
            && witness.record.head_signature_b64 == head.signature_b64)
    }

    struct B054LegacyPrefixLoad<'a> {
        d1: &'a D1HttpClient,
        tenant_id: &'a str,
        region: &'a str,
        head_hash: &'a str,
        expected_next_sequence: u64,
        head_signature_b64: &'a str,
        stored_signing_key_id: u64,
        signing_key: &'a B054AuthenticatedSigningKey,
    }

    struct B054LockedEpochContext<'a> {
        state: &'a AuditDrainState,
        roots: &'a std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
        seed: &'a [u8; 32],
        witness_client: &'a WitnessClient,
        tenant_id: &'a str,
        region: &'a str,
        now: i64,
        lease_holder: &'a str,
    }

    async fn load_verified_legacy_prefix(
        input: B054LegacyPrefixLoad<'_>,
    ) -> Result<B054VerifiedLegacyPrefix, String> {
        let B054LegacyPrefixLoad {
            d1,
            tenant_id,
            region,
            head_hash,
            expected_next_sequence,
            head_signature_b64,
            stored_signing_key_id,
            signing_key,
        } = input;
        if !canonical_partition(tenant_id, region)
            || !is_lower_hex_32(head_hash)
            || stored_signing_key_id != signing_key.record.signing_key_id
        {
            return Err("B054 legacy prefix shape mismatch".to_owned());
        }
        let mut cursor = 0_u64;
        let mut previous = [0_u8; 32];
        while cursor < expected_next_sequence {
            let remaining = expected_next_sequence - cursor;
            let limit = remaining.min(1_000);
            let rows = d1
                        .query(
                            "SELECT sequence_number,prev_hash,chain_hash,CAST(canonical_jcs AS TEXT) AS canonical_jcs FROM audit_outbox WHERE tenant_id=?1 AND region=?2 AND emitted_at IS NOT NULL AND sequence_number>=?3 ORDER BY sequence_number LIMIT ?4",
                            &[json!(tenant_id), json!(region), json!(b054_admin_i64(cursor, "legacy cursor")?), json!(b054_admin_i64(limit, "legacy page limit")?)],
                        )
                        .await?;
            if rows.is_empty() {
                return Err("B054 legacy prefix ended before signed head".to_owned());
            }
            for row in rows {
                let sequence_number = row
                    .get("sequence_number")
                    .and_then(Value::as_i64)
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or("B054 legacy sequence missing/invalid")?;
                if sequence_number != cursor {
                    return Err("B054 legacy prefix has a gap/duplicate".to_owned());
                }
                let prev_hash = row
                    .get("prev_hash")
                    .and_then(Value::as_str)
                    .ok_or("B054 legacy prev_hash missing")?;
                let chain_hash = row
                    .get("chain_hash")
                    .and_then(Value::as_str)
                    .ok_or("B054 legacy chain_hash missing")?;
                let canonical_jcs = row
                    .get("canonical_jcs")
                    .and_then(Value::as_str)
                    .ok_or("B054 legacy canonical_jcs missing")?
                    .as_bytes();
                if prev_hash != hex::encode(previous)
                    || !is_lower_hex_32(chain_hash)
                    || canonical_jcs.is_empty()
                    || canonical_jcs.len() > B054_ADMIN_MAX_JCS_BYTES
                {
                    return Err("B054 legacy row continuity/size mismatch".to_owned());
                }
                let canonical_value: Value = serde_json::from_slice(canonical_jcs)
                    .map_err(|_| "B054 legacy row canonical_jcs is malformed")?;
                if serde_jcs::to_vec(&canonical_value)
                    .map_err(|_| "B054 legacy row canonicalization failed")?
                    != canonical_jcs
                {
                    return Err("B054 legacy row is not exact RFC-8785 JCS".to_owned());
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(&previous);
                hasher.update(canonical_jcs);
                let computed = *hasher.finalize().as_bytes();
                if hex::encode(computed) != chain_hash {
                    return Err("B054 legacy row link mismatch".to_owned());
                }
                previous = computed;
                cursor = cursor.checked_add(1).ok_or("B054 legacy cursor overflow")?;
            }
        }
        let extras = d1
                    .query(
                        "SELECT sequence_number FROM audit_outbox WHERE tenant_id=?1 AND region=?2 AND emitted_at IS NOT NULL AND sequence_number>=?3 LIMIT 1",
                        &[json!(tenant_id), json!(region), json!(b054_admin_i64(expected_next_sequence, "legacy signed sequence")?)],
                    )
                    .await?;
        if !extras.is_empty() {
            return Err("B054 sealed legacy rows extend beyond signed head".to_owned());
        }
        if hex::encode(previous) != head_hash {
            return Err("B054 legacy signed head differs from verified row tail".to_owned());
        }
        let head_jcs = canonical_head_bytes(tenant_id, region, head_hash, expected_next_sequence)?;
        b054_admin_verify_raw_signature(
            &signing_key.verifying_key,
            &head_jcs,
            head_signature_b64,
            "B054 legacy v1 head",
        )?;
        Ok(B054VerifiedLegacyPrefix {
            tenant_id: tenant_id.to_owned(),
            region: region.to_owned(),
            head_hash: head_hash.to_owned(),
            next_sequence: expected_next_sequence,
            head_signature_b64: head_signature_b64.to_owned(),
            signing_key_id: stored_signing_key_id,
            row_count: expected_next_sequence,
        })
    }

    async fn renew_admin_lease(
        d1: &D1HttpClient,
        tenant_id: &str,
        region: &str,
        holder: &str,
    ) -> Result<(), String> {
        let renewed_at = now_ms();
        let expires = renewed_at.saturating_add(AUDIT_DRAIN_LEASE_TTL_MS);
        let rows = d1
                    .query(
                        "UPDATE audit_drain_lease SET acquired_ms=?1,expires_ms=?2 WHERE tenant_id=?3 AND region=?4 AND holder=?5 AND expires_ms>=?1 RETURNING holder",
                        &[json!(renewed_at), json!(expires), json!(tenant_id), json!(region), json!(holder)],
                    )
                    .await?;
        if rows.len() != 1 {
            return Err("B054 administrative lease expired or changed owner".to_owned());
        }
        Ok(())
    }

    fn sign_admin_artifact(
        bytes: Vec<u8>,
        seed: &[u8; 32],
        key_id: u64,
        region: &str,
    ) -> B054SignedArtifact {
        let signer = ErasureSigningKey::from_seed(key_id, region_for_key(region), 0, 0, *seed);
        B054SignedArtifact {
            signature_b64: base64::engine::general_purpose::STANDARD
                .encode(signer.signing_key.sign(&bytes).to_bytes()),
            jcs: bytes,
        }
    }

    async fn bootstrap_e0_locked(context: B054LockedEpochContext<'_>) -> Result<&'static str, String> {
        let B054LockedEpochContext {
            state,
            roots,
            seed,
            witness_client,
            tenant_id,
            region,
            now,
            lease_holder,
        } = context;
        if !canonical_partition(tenant_id, region) {
            return Err("B054 bootstrap partition is non-canonical".to_owned());
        }
        let checkpoint = read_checkpoint(&state.d1, tenant_id, region)
            .await?
            .ok_or("B054 bootstrap requires an existing signed v1 head")?;
        let signing = load_authenticated_signing_key(&state.d1, state.signing_key_id, roots).await?;
        require_current_seed_key(&signing, seed, region)?;
        let latest = witness_client.latest(tenant_id, region).await?;
        if checkpoint.head_message_version == Some(2) {
            let latest = latest
                .as_ref()
                .ok_or("B054 bootstrapped D1 head lacks witness latest")?;
            let ledger = load_e0_ledger_artifact(&state.d1, tenant_id, region).await?;
            b054_authenticate_e0_checkpoint(&checkpoint, tenant_id, region, &signing, &ledger, latest)?;
            return Ok("already_committed");
        }
        if checkpoint.epoch_id.is_some()
            || checkpoint.epoch_ledger_sequence.is_some()
            || checkpoint.epoch_ledger_hash.is_some()
            || checkpoint.head_witness_sequence.is_some()
            || checkpoint.head_witness_hash.is_some()
        {
            return Err("B054 legacy head has partial epoch metadata".to_owned());
        }
        let legacy = load_verified_legacy_prefix(B054LegacyPrefixLoad {
            d1: &state.d1,
            tenant_id,
            region,
            head_hash: &checkpoint.head_hex,
            expected_next_sequence: checkpoint.next_sequence,
            head_signature_b64: checkpoint
                .head_signature
                .as_deref()
                .ok_or("B054 legacy head is unsigned")?,
            stored_signing_key_id: checkpoint
                .signing_key_id
                .ok_or("B054 legacy head lacks signing key id")?,
            signing_key: &signing,
        })
        .await?;
        let e0 = sign_admin_artifact(
            b054_e0_ledger_jcs(tenant_id, region, state.signing_key_id)?,
            seed,
            state.signing_key_id,
            region,
        );
        let ledger_hash = b054_admin_ledger_hash(&e0.jcs);
        let head = sign_admin_artifact(
            canonical_head_v2_bytes(
                tenant_id,
                region,
                &checkpoint.head_hex,
                checkpoint.next_sequence,
                0,
                0,
                &ledger_hash,
                state.signing_key_id,
            )?,
            seed,
            state.signing_key_id,
            region,
        );
        if let Some(existing) = latest.as_ref() {
            if !witness_binds_prepared(existing, &head, tenant_id, region, 0, ZERO_HASH_HEX)? {
                return Err("B054 genesis witness contains a divergent head".to_owned());
            }
        }
        renew_admin_lease(&state.d1, tenant_id, region, lease_holder).await?;
        let receipt = witness_client
            .append_genesis(&head.jcs, &head.signature_b64, tenant_id, region)
            .await?;
        let transaction = b054_build_e0_bootstrap_transaction(
            &legacy,
            &signing,
            &e0,
            &head,
            &receipt,
            u64::try_from(now).map_err(|_| "B054 bootstrap clock negative")?,
            lease_holder,
        )?;
        execute_admin_transaction(&state.d1, transaction).await?;
        Ok("committed")
    }

    async fn bootstrap_e0(
        state: &AuditDrainState,
        roots: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
        seed: &[u8; 32],
        witness: &WitnessClient,
        tenant_id: &str,
        region: &str,
    ) -> Result<&'static str, String> {
        let acquired_at = now_ms();
        let holder = new_lease_holder();
        if !acquire_lease(
            &state.d1,
            tenant_id,
            region,
            &holder,
            acquired_at,
            AUDIT_DRAIN_LEASE_TTL_MS,
        )
        .await?
        {
            return Err("B054 bootstrap partition lease is held".to_owned());
        }
        let result = bootstrap_e0_locked(B054LockedEpochContext {
            state,
            roots,
            seed,
            witness_client: witness,
            tenant_id,
            region,
            now: acquired_at,
            lease_holder: &holder,
        })
        .await;
        let release = release_lease(&state.d1, tenant_id, region, &holder).await;
        match (result, release) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(format!("B054 committed but lease release failed: {error}")),
        }
    }

    async fn transition_e1_locked(
        context: B054LockedEpochContext<'_>,
        link_key_id: u64,
    ) -> Result<&'static str, String> {
        let B054LockedEpochContext {
            state,
            roots,
            seed,
            witness_client,
            tenant_id,
            region,
            now,
            lease_holder,
        } = context;
        if !canonical_partition(tenant_id, region) {
            return Err("B054 transition partition is non-canonical".to_owned());
        }
        let checkpoint = read_checkpoint(&state.d1, tenant_id, region)
            .await?
            .ok_or("B054 transition head missing")?;
        let signing = load_authenticated_signing_key(&state.d1, state.signing_key_id, roots).await?;
        require_current_seed_key(&signing, seed, region)?;
        let latest = witness_client
            .latest(tenant_id, region)
            .await?
            .ok_or("B054 transition witness latest is null")?;
        if checkpoint.epoch_id == Some(1) {
            verify_v2_checkpoint_witness(&checkpoint, &latest, seed, tenant_id, region)?;
            let active = read_active_epoch(&state.d1, tenant_id, region).await?;
            authenticate_active_epoch(&active, seed, state.signing_key_id, tenant_id, region)?;
            if active.epoch.epoch_id() != 1 || active.epoch.link_key_id() != Some(link_key_id) {
                return Err("B054 committed E1 differs from requested link key".to_owned());
            }
            return Ok("already_committed");
        }
        let e0_witness_sequence = checkpoint
            .head_witness_sequence
            .ok_or("B054 E0 witness sequence missing")?;
        let e0_witness_hash = checkpoint
            .head_witness_hash
            .as_deref()
            .ok_or("B054 E0 witness hash missing")?;
        let e0_witness = load_verified_d1_witness(
            &state.d1,
            witness_client,
            tenant_id,
            region,
            e0_witness_sequence,
            e0_witness_hash,
        )
        .await?;
        let e0_ledger = load_e0_ledger_artifact(&state.d1, tenant_id, region).await?;
        let authenticated_e0 = b054_authenticate_e0_checkpoint(
            &checkpoint,
            tenant_id,
            region,
            &signing,
            &e0_ledger,
            &e0_witness,
        )?;
        if checkpoint.next_sequence == 0 {
            return Err(
                "B054 E0 must contain at least one sealed event before E1 transition".to_owned(),
            );
        }
        let link = load_authenticated_link_key(&state.d1, link_key_id, &signing).await?;
        let keyring = state
            .link_keyring
            .as_deref()
            .ok_or("B054 transition link keyring unavailable")?;
        let secret = keyring
            .get(link_key_id)
            .ok_or("B054 transition link key unavailable")?;
        b054_verify_link_key_commitment(&link, secret.as_bytes())?;
        let transition = sign_admin_artifact(
            b054_e1_ledger_jcs(
                tenant_id,
                region,
                &checkpoint.head_hex,
                checkpoint.next_sequence,
                checkpoint
                    .epoch_ledger_hash
                    .as_deref()
                    .ok_or("B054 E0 ledger hash missing")?,
                link_key_id,
                state.signing_key_id,
            )?,
            seed,
            state.signing_key_id,
            region,
        );
        let ledger_hash = b054_admin_ledger_hash(&transition.jcs);
        let head = sign_admin_artifact(
            canonical_head_v2_bytes(
                tenant_id,
                region,
                &checkpoint.head_hex,
                checkpoint.next_sequence,
                1,
                1,
                &ledger_hash,
                state.signing_key_id,
            )?,
            seed,
            state.signing_key_id,
            region,
        );
        let latest_is_e0 = latest.witness_record_hash == e0_witness.witness_record_hash
            && latest.witness_jcs == e0_witness.witness_jcs
            && latest.receipt_jcs == e0_witness.receipt_jcs
            && latest.receipt_signature_b64 == e0_witness.receipt_signature_b64;
        let latest_is_candidate = witness_binds_prepared(
            &latest,
            &head,
            tenant_id,
            region,
            e0_witness_sequence
                .checked_add(1)
                .ok_or("B054 witness sequence overflow")?,
            e0_witness_hash,
        )?;
        if !latest_is_e0 && !latest_is_candidate {
            return Err("B054 transition witness latest is divergent".to_owned());
        }
        renew_admin_lease(&state.d1, tenant_id, region, lease_holder).await?;
        let receipt = witness_client
            .append(
                &head.jcs,
                &head.signature_b64,
                tenant_id,
                region,
                &e0_witness,
            )
            .await?;
        execute_admin_transaction(
            &state.d1,
            b054_build_e0_to_e1_transaction(
                &authenticated_e0,
                &signing,
                &link,
                &transition,
                &head,
                &receipt,
                u64::try_from(now).map_err(|_| "B054 transition clock negative")?,
                lease_holder,
            )?,
        )
        .await?;
        Ok("committed")
    }

    async fn transition_e1(
        state: &AuditDrainState,
        roots: &std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
        seed: &[u8; 32],
        witness: &WitnessClient,
        tenant_id: &str,
        region: &str,
        link_key_id: u64,
    ) -> Result<&'static str, String> {
        let acquired_at = now_ms();
        let holder = new_lease_holder();
        if !acquire_lease(
            &state.d1,
            tenant_id,
            region,
            &holder,
            acquired_at,
            AUDIT_DRAIN_LEASE_TTL_MS,
        )
        .await?
        {
            return Err("B054 transition partition lease is held".to_owned());
        }
        let result = transition_e1_locked(
            B054LockedEpochContext {
                state,
                roots,
                seed,
                witness_client: witness,
                tenant_id,
                region,
                now: acquired_at,
                lease_holder: &holder,
            },
            link_key_id,
        )
        .await;
        let release = release_lease(&state.d1, tenant_id, region, &holder).await;
        match (result, release) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(format!("B054 committed but lease release failed: {error}")),
        }
    }

    pub(super) async fn handle_epoch_admin(
        State(state): State<AuditDrainState>,
        headers: HeaderMap,
        Json(request): Json<B054EpochAdminRequest>,
    ) -> Response {
        if !internal_auth_ok(state.internal_auth_key.as_bytes(), &headers) {
            return admin_response(StatusCode::UNAUTHORIZED, "unknown", "unauthorized");
        }
        let Some(approver_key) = state.epoch_admin_approver_auth_key.as_deref() else {
            return admin_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unknown",
                "security_approver_unavailable",
            );
        };
        if !named_auth_ok(
            approver_key.as_bytes(),
            &headers,
            B054_SECURITY_APPROVAL_HEADER,
        ) {
            return admin_response(StatusCode::UNAUTHORIZED, "unknown", "unauthorized");
        }
        let Some(approval_roots) = state.admin_approval_roots.as_deref() else {
            return admin_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unknown",
                "approval_trust_roots_unavailable",
            );
        };
        let Some(roots) = state.trust_roots.as_deref() else {
            return admin_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unknown",
                "trust_roots_unavailable",
            );
        };
        let operation = request.operation();
        let (approval_jcs_b64, approval_signature_b64, executor_signature_b64) = request.approval_artifact();
        let now_ms = match b054_admin_now_ms() {
            Ok(value) => value,
            Err(_) => {
                return admin_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unknown",
                    "approval_clock_unavailable",
                )
            }
        };
        let approval = match b054_verify_admin_approval(
            &operation,
            approval_jcs_b64,
            approval_signature_b64,
            executor_signature_b64,
            approval_roots,
            now_ms,
        ) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(error = %error, "B054 epoch admin approval rejected");
                return admin_response(StatusCode::UNAUTHORIZED, "unknown", "approval_rejected");
            }
        };
        if let Err(error) = b054_consume_admin_approval(&state.d1, &approval, now_ms).await {
            tracing::warn!(error = %error, "B054 epoch admin approval replay rejected");
            return admin_response(StatusCode::CONFLICT, "unknown", "approval_replayed");
        }
        let result = match request {
            B054EpochAdminRequest::ProvisionSigningKey {
                registry_jcs_b64,
                registry_signature_b64,
                ..
            } => {
                let result = async {
                    let artifact = artifact_from_b64(&registry_jcs_b64, &registry_signature_b64)?;
                    let key = b054_authenticate_signing_registry(artifact, roots)?;
                    execute_admin_transaction(
                        &state.d1,
                        b054_build_signing_registry_transaction(&key)?,
                    )
                    .await?;
                    let confirmed =
                        load_authenticated_signing_key(&state.d1, key.record.signing_key_id, roots)
                            .await?;
                    if confirmed.registry_jcs != key.registry_jcs
                        || confirmed.registry_signature_b64 != key.registry_signature_b64
                    {
                        return Err("B054 signing registry readback mismatch".to_owned());
                    }
                    Ok::<_, String>("provisioned")
                }
                .await;
                ("provision_signing_key", result)
            }
            B054EpochAdminRequest::ProvisionLinkKey {
                link_key_id,
                registered_at_ms,
                ..
            } => {
                let result = async {
                    let seed = state
                        .signing_seed
                        .as_deref()
                        .ok_or("B054 link registration requires signing seed")?;
                    let signing =
                        load_authenticated_signing_key(&state.d1, state.signing_key_id, roots).await?;
                    let secret = state
                        .link_keyring
                        .as_deref()
                        .and_then(|keys| keys.get(link_key_id))
                        .ok_or("B054 link registration key unavailable")?;
                    let jcs = b054_link_registry_jcs(
                        link_key_id,
                        &secret.commitment().to_hex(),
                        state.signing_key_id,
                        registered_at_ms,
                    )?;
                    let artifact = sign_admin_artifact(jcs, seed, state.signing_key_id, "wnam");
                    let link = b054_authenticate_link_registry(artifact, &signing)?;
                    execute_admin_transaction(
                        &state.d1,
                        b054_build_link_registry_transaction(&link, &signing)?,
                    )
                    .await?;
                    let confirmed =
                        load_authenticated_link_key(&state.d1, link_key_id, &signing).await?;
                    if confirmed.registry_jcs != link.registry_jcs
                        || confirmed.registry_signature_b64 != link.registry_signature_b64
                    {
                        return Err("B054 link registry readback mismatch".to_owned());
                    }
                    Ok::<_, String>("provisioned")
                }
                .await;
                ("provision_link_key", result)
            }
            B054EpochAdminRequest::BootstrapE0 {
                tenant_id, region, ..
            } => {
                let result = if !state.lease_enabled {
                    Err("B054 bootstrap requires AUDIT_DRAIN_LEASE_ENABLED".to_owned())
                } else {
                    match (state.signing_seed.as_deref(), state.witness.as_deref()) {
                        (Some(seed), Some(witness)) => {
                            bootstrap_e0(&state, roots, seed, witness, &tenant_id, &region).await
                        }
                        _ => Err(
                            "B054 bootstrap requires signing seed and complete witness config"
                                .to_owned(),
                        ),
                    }
                };
                ("bootstrap_e0", result)
            }
            B054EpochAdminRequest::TransitionE1 {
                tenant_id,
                region,
                link_key_id,
                ..
            } => {
                let result = if !state.lease_enabled {
                    Err("B054 transition requires AUDIT_DRAIN_LEASE_ENABLED".to_owned())
                } else {
                    match (state.signing_seed.as_deref(), state.witness.as_deref()) {
                        (Some(seed), Some(witness)) => {
                            transition_e1(
                                &state,
                                roots,
                                seed,
                                witness,
                                &tenant_id,
                                &region,
                                link_key_id,
                            )
                            .await
                        }
                        _ => Err(
                            "B054 transition requires signing seed and complete witness config"
                                .to_owned(),
                        ),
                    }
                };
                ("transition_e1", result)
            }
        };
        match result {
            (operation, Ok(value)) => admin_response(StatusCode::OK, operation, value),
            (operation, Err(error)) => {
                tracing::error!(operation, error = %error, "B054 epoch admin failed closed");
                admin_response(StatusCode::CONFLICT, operation, "indeterminate")
            }
        }

    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used, reason = "test assertions intentionally surface failures")]
    mod admin_approval_tests {
        use super::*;
        use ed25519_dalek::Signer;

        fn signed_proof(
            operation: &B054EpochAdminOperation,
            executor: &str,
            approver: &str,
            approver_role: &str,
            issued_at_ms: u64,
            expires_at_ms: u64,
        ) -> (
            String,
            String,
            String,
            std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
        ) {
            let provider = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let executor_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
            let claims = B054AdminApprovalJcs {
                approval_id: "approval-001".to_owned(),
                approval_version: 1,
                approver_role: approver_role.to_owned(),
                approver_subject_id: approver.to_owned(),
                audience: B054_ADMIN_APPROVAL_AUDIENCE.to_owned(),
                approver_eligible: true,
                executor_role: "SRE executor".to_owned(),
                executor_eligible: true,
                executor_public_key_b64: base64::engine::general_purpose::STANDARD
                    .encode(executor_key.verifying_key().as_bytes()),
                executor_subject_id: executor.to_owned(),
                expires_at_ms,
                issuer: "identity-provider-v1".to_owned(),
                issued_at_ms,
                nonce: "01".repeat(32),
                operation_digest_hex: b054_admin_operation_digest(operation).unwrap(),
                trust_root_key_id: "identity-provider-v1".to_owned(),
            };
            let claims_jcs = b054_admin_canonical_jcs(&claims).unwrap();
            let mut provider_message = B054_ADMIN_APPROVAL_DOMAIN.to_vec();
            provider_message.extend_from_slice(&claims_jcs);
            let provider_signature = base64::engine::general_purpose::STANDARD
                .encode(provider.sign(&provider_message).to_bytes());
            let executor_signature = base64::engine::general_purpose::STANDARD
                .encode(executor_key.sign(&b054_admin_executor_message(&claims)).to_bytes());
            let roots = [("identity-provider-v1".to_owned(), provider.verifying_key())]
                .into_iter()
                .collect();
            (
                base64::engine::general_purpose::STANDARD.encode(claims_jcs),
                provider_signature,
                executor_signature,
                roots,
            )
        }

        fn operation() -> B054EpochAdminOperation {
            B054EpochAdminOperation::BootstrapE0 {
                tenant_id: "tenant-1".to_owned(),
                region: "weur".to_owned(),
            }
        }

        #[test]
        fn accepts_fresh_distinct_provider_bound_executor() {
            let operation = operation();
            let (claims, provider, executor, roots) =
                signed_proof(&operation, "opaque-sre-1", "opaque-sec-2", "Security approver", 1_000, 3_000);
            assert!(b054_verify_admin_approval(&operation, &claims, &provider, &executor, &roots, 2_000).is_ok());
        }

        #[test]
        fn rejects_same_or_unapproved_subjects() {
            let operation = operation();
            let (same, provider, executor, roots) =
                signed_proof(&operation, "same", "same", "Security approver", 1_000, 3_000);
            assert!(b054_verify_admin_approval(&operation, &same, &provider, &executor, &roots, 2_000).is_err());
            let (role, provider, executor, roots) =
                signed_proof(&operation, "opaque-sre-1", "opaque-sec-2", "unapproved", 1_000, 3_000);
            assert!(b054_verify_admin_approval(&operation, &role, &provider, &executor, &roots, 2_000).is_err());
        }

        #[test]
        fn rejects_digest_mismatch_and_expiry() {
            let operation = operation();
            let (claims, provider, executor, roots) =
                signed_proof(&operation, "opaque-sre-1", "opaque-sec-2", "Security approver", 1_000, 3_000);
            let other = B054EpochAdminOperation::BootstrapE0 {
                tenant_id: "tenant-2".to_owned(),
                region: "weur".to_owned(),
            };
            assert!(b054_verify_admin_approval(&other, &claims, &provider, &executor, &roots, 2_000).is_err());
            assert!(b054_verify_admin_approval(&operation, &claims, &provider, &executor, &roots, 3_000).is_err());
        }

        #[test]
        fn rejects_invalid_provider_unknown_root_and_wrong_executor_key() {
            let operation = operation();
            let (claims, provider, executor, roots) =
                signed_proof(&operation, "opaque-sre-1", "opaque-sec-2", "Security approver", 1_000, 3_000);
            assert!(b054_verify_admin_approval(&operation, &claims, "AA==", &executor, &roots, 2_000).is_err());
            assert!(b054_verify_admin_approval(&operation, &claims, &provider, &executor, &std::collections::BTreeMap::new(), 2_000).is_err());
            assert!(b054_verify_admin_approval(&operation, &claims, &provider, &provider, &roots, 2_000).is_err());
        }
    }
