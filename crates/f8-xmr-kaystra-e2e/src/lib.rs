//! End-to-end tests over the actual Kaystra public types and outbox effect.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use adapter_dom_real::RevealedSecretSinkV1;
    use counterparty_api::RevealedSecretBytes;
    use curve25519_dalek::Scalar;
    use kaystra_core::{
        settlement_engine::EffectOutcome,
        state::{Effect, EvidenceRefV1},
        store_port::ClaimedEffectV1,
        terms::SettlementTermsV1,
        types::{
            AssetId, ChainId, EffectId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole,
            LegTermsV1, LockMechanism, ParticipantId, RecoveryPolicyV1, SessionId, SettlementId,
            SolverId, TimelockSpec,
        },
    };
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };
    use xmr_crypto::XmrSpendShare;
    use xmr_delivery_sqlite::SqliteDeliveryStore;
    use xmr_kaystra_bridge::XmrClaimToSpendSink;
    use xmr_live_sidecar_api::{BuildSweepRequestV2, BuildSweepResponseV2, API_VERSION_V2};
    use xmr_route_secret::XmrRouteSecret;
    use xmr_secret_store::{
        EncryptedSqliteSecretStore, SecretMaterialStore, SecretStoreMasterKey, XmrSecretMaterial,
    };
    use xmr_setup_profile::{
        proof_context_hash, validate_setup, V1MechanismAdmission, XmrAdapterProfileV1, XmrNetwork,
        XmrProofContextV1, XmrSetupBindingV1,
    };
    use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort, SpendPortError, SweepBuildPort};

    struct MockBuilder {
        calls: Arc<AtomicUsize>,
    }

    impl SweepBuildPort for MockBuilder {
        fn build_sweep(
            &mut self,
            request: BuildSweepRequestV2,
        ) -> Result<BuildSweepResponseV2, SpendPortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            request
                .validate_public_fields()
                .map_err(|_| SpendPortError::Rejected)?;
            Ok(BuildSweepResponseV2 {
                api_version: API_VERSION_V2,
                request_nonce: request.request_nonce,
                tx_hash: [0x77; 32],
                raw_tx: b"exact-signed-monero-transaction".to_vec(),
            })
        }
    }

    struct MockBroadcaster {
        calls: Arc<AtomicUsize>,
        outcomes: Arc<Mutex<VecDeque<Result<BroadcastAcceptance, SpendPortError>>>>,
    }

    impl ExactBroadcastPort for MockBroadcaster {
        fn submit_exact(
            &mut self,
            _tx_hash: [u8; 32],
            _raw_tx: &[u8],
        ) -> Result<BroadcastAcceptance, SpendPortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcomes
                .lock()
                .map_err(|_| SpendPortError::Retryable)?
                .pop_front()
                .unwrap_or(Ok(BroadcastAcceptance::AlreadyKnown))
        }
    }

    fn effect(evidence: EvidenceRefV1) -> ClaimedEffectV1 {
        ClaimedEffectV1 {
            settlement_id: SettlementId([1; 32]),
            effect_id: EffectId([0x42; 32]),
            kind: Effect::RequestClaimConsumption { evidence },
            payload: Vec::new(),
            payload_hash: [0x24; 32],
            attempts: 1,
        }
    }

    fn evidence() -> EvidenceRefV1 {
        EvidenceRefV1 {
            chain_id: ChainId([0xD0; 32]),
            tx_id: [0x33; 32],
            event_index: 0,
            block_height: 100,
            block_anchor: [0x44; 32],
        }
    }

    fn terms(adaptor_point: [u8; 33], profile_hash: [u8; 32]) -> SettlementTermsV1 {
        SettlementTermsV1 {
            settlement_id: SettlementId([1; 32]),
            session_id: SessionId([2; 32]),
            intent_hash: IntentHash([3; 32]),
            solver_id: SolverId([4; 32]),
            roster: [ParticipantId([5; 32]), ParticipantId([6; 32])],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([0xD0; 32]),
                asset_id: AssetId([0xD1; 32]),
                amount: 1_000,
                beneficiary: ParticipantId([5; 32]),
                refund_to: ParticipantId([6; 32]),
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 200 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 10,
                    max_reorg_depth: 20,
                },
                adapter_profile_hash: [0xD2; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([0xA0; 32]),
                asset_id: AssetId([0xA1; 32]),
                amount: 1_000,
                beneficiary: ParticipantId([6; 32]),
                refund_to: ParticipantId([5; 32]),
                // Frozen V1 has no CrossCurveSharedSpend tag; explicit lab alias.
                mechanism: LockMechanism::SchnorrAdaptor,
                deadline: TimelockSpec::BlockHeight { value: 150 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 10,
                    max_reorg_depth: 20,
                },
                adapter_profile_hash: profile_hash,
            },
            adaptor_point_sec1: adaptor_point,
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 10,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: Vec::new(),
        }
    }

    /// The proof context the setup will re-derive from the frozen terms, so a
    /// route can be generated bound to exactly it. Mirrors the counterparty
    /// leg of [`terms`].
    fn context_hash(profile: &XmrAdapterProfileV1) -> [u8; 32] {
        proof_context_hash(
            profile,
            &XmrProofContextV1 {
                settlement_id: [1; 32],
                chain_id: [0xA0; 32],
                asset_id: [0xA1; 32],
                amount_piconero: 1_000,
                min_confirmations: 10,
                max_reorg_depth: 20,
            },
        )
        .expect("fixed context is valid")
    }

    #[test]
    fn retry_reuses_exact_raw_transaction_without_rebuilding(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2)?;
        let route =
            XmrRouteSecret::generate([1; 32], context_hash(&profile), &mut rand::thread_rng())?;
        let terms = terms(route.dom_adaptor_point().0, profile.profile_hash());
        let terms_hash = terms.terms_hash()?;
        let remote_bytes = route.with_xmr_share(|bytes| *bytes);
        let local_bytes = Scalar::from(7_u64).to_bytes();
        let local = XmrSpendShare::from_canonical_bytes(local_bytes)?;
        let remote = XmrSpendShare::from_canonical_bytes(remote_bytes)?;
        let expected_public = local.combine(&remote)?.public_key()?;
        let setup = validate_setup(
            &terms,
            &profile,
            XmrSetupBindingV1 {
                settlement_id: [1; 32],
                terms_hash,
                dleq: route.proof().clone(),
                funding_tx_hash: [0x55; 32],
                expected_amount_piconero: 1_000,
                destination: "stagenet-destination".to_owned(),
                combined_spend_public_key: expected_public,
            },
            Some(V1MechanismAdmission::LaboratoryAlias),
        )?;

        let secrets_path = directory.path().join("secrets.sqlite");
        let delivery_path = directory.path().join("delivery.sqlite");
        let secrets = EncryptedSqliteSecretStore::open(
            &secrets_path,
            SecretStoreMasterKey::new([0x99; 32])?,
        )?;
        let material = XmrSecretMaterial::new(local_bytes, Scalar::from(13_u64).to_bytes())?;
        secrets.insert([1; 32], terms_hash, &material, &mut rand::thread_rng())?;
        let delivery = SqliteDeliveryStore::open(&delivery_path)?;
        let build_calls = Arc::new(AtomicUsize::new(0));
        let broadcast_calls = Arc::new(AtomicUsize::new(0));
        let outcomes = Arc::new(Mutex::new(VecDeque::from([
            Err(SpendPortError::Retryable),
            Ok(BroadcastAcceptance::Accepted),
        ])));
        let mut sink = XmrClaimToSpendSink::new(
            setup,
            secrets,
            delivery,
            MockBuilder {
                calls: Arc::clone(&build_calls),
            },
            MockBroadcaster {
                calls: Arc::clone(&broadcast_calls),
                outcomes,
            },
        );
        let evidence = evidence();
        let effect = effect(evidence);
        let first = route.with_revealed_dom_secret(|revealed| {
            sink.consume_revealed_secret(&effect, &evidence, revealed)
        });
        assert_eq!(first, EffectOutcome::RetryLater);
        let second = route.with_revealed_dom_secret(|revealed| {
            sink.consume_revealed_secret(&effect, &evidence, revealed)
        });
        assert_eq!(second, EffectOutcome::Completed);
        assert_eq!(build_calls.load(Ordering::SeqCst), 1);
        assert_eq!(broadcast_calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn wrong_revealed_witness_is_rejected_before_build() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let profile = XmrAdapterProfileV1::new(XmrNetwork::Stagenet, 3, 2)?;
        let route =
            XmrRouteSecret::generate([1; 32], context_hash(&profile), &mut rand::thread_rng())?;
        let wrong =
            XmrRouteSecret::generate([1; 32], context_hash(&profile), &mut rand::thread_rng())?;
        let terms = terms(route.dom_adaptor_point().0, profile.profile_hash());
        let terms_hash = terms.terms_hash()?;
        let remote = XmrSpendShare::from_canonical_bytes(route.with_xmr_share(|bytes| *bytes))?;
        let local_bytes = Scalar::from(7_u64).to_bytes();
        let local = XmrSpendShare::from_canonical_bytes(local_bytes)?;
        let setup = validate_setup(
            &terms,
            &profile,
            XmrSetupBindingV1 {
                settlement_id: [1; 32],
                terms_hash,
                dleq: route.proof().clone(),
                funding_tx_hash: [0x55; 32],
                expected_amount_piconero: 1_000,
                destination: "stagenet-destination".to_owned(),
                combined_spend_public_key: local.combine(&remote)?.public_key()?,
            },
            Some(V1MechanismAdmission::LaboratoryAlias),
        )?;
        let secrets = EncryptedSqliteSecretStore::open(
            directory.path().join("secrets.sqlite"),
            SecretStoreMasterKey::new([0x99; 32])?,
        )?;
        secrets.insert(
            [1; 32],
            terms_hash,
            &XmrSecretMaterial::new(local_bytes, Scalar::from(13_u64).to_bytes())?,
            &mut rand::thread_rng(),
        )?;
        let build_calls = Arc::new(AtomicUsize::new(0));
        let mut sink = XmrClaimToSpendSink::new(
            setup,
            secrets,
            SqliteDeliveryStore::open(directory.path().join("delivery.sqlite"))?,
            MockBuilder {
                calls: Arc::clone(&build_calls),
            },
            MockBroadcaster {
                calls: Arc::new(AtomicUsize::new(0)),
                outcomes: Arc::new(Mutex::new(VecDeque::new())),
            },
        );
        let evidence = evidence();
        let effect = effect(evidence);
        let outcome = wrong.with_revealed_dom_secret(|revealed: &RevealedSecretBytes| {
            sink.consume_revealed_secret(&effect, &evidence, revealed)
        });
        assert_eq!(outcome, EffectOutcome::Rejected);
        assert_eq!(build_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
