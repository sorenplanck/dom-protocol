//! End-to-end host-side tests for the DOM Solana condition-lock leg.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use f8_solana_model::{transition, Event, State};
    use kaystra_core::{
        settlement_engine::{ChainRecordV1, ChainSourceV1},
        state::EvidenceRefV1,
        terms::SettlementTermsV1,
        types::{
            AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
            LockMechanism, ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId,
            TimelockSpec,
        },
    };
    use solana_delivery::DeliveryStore;
    use solana_delivery_sqlite::SqliteSolanaDeliveryStore;
    use solana_escrow_wire::{AssetKind, EscrowInstructionV1, EscrowStateV1, EscrowStatus};
    use solana_kaystra_source::{
        SolanaKaystraSource, SolanaSlotAnchor, VerifiedSolanaEvent, VerifiedSolanaEventKind,
    };
    use solana_observation_store::SqliteVerifiedSolanaFeed;
    use solana_profile::{
        SolanaAdapterProfileV1, SolanaAssetV1, SolanaNetwork, SolanaProofContextV1,
    };
    use solana_session_init::{finalize_session, prepare_route_secret};
    use solana_setup_store::SolanaSetupStore;
    use solana_transaction_builder::{assemble_signed_transaction, build_legacy_message};
    use solana_types::{SolanaHash, SolanaPubkey, SolanaSignature};

    const PROGRAM: &str = "3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw";

    fn terms(adaptor: [u8; 33], profile_hash: [u8; 32], funder: SolanaPubkey) -> SettlementTermsV1 {
        let recipient = ParticipantId([0x31; 32]);
        let refund = ParticipantId([0x21; 32]);
        SettlementTermsV1 {
            settlement_id: SettlementId([1; 32]),
            session_id: SessionId([2; 32]),
            intent_hash: IntentHash([3; 32]),
            solver_id: SolverId([4; 32]),
            roster: [refund, recipient],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: ChainId([0xD0; 32]),
                asset_id: AssetId([0xD1; 32]),
                amount: 500,
                beneficiary: refund,
                refund_to: recipient,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 1_000 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 10,
                    max_reorg_depth: 20,
                },
                adapter_profile_hash: [0xD2; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([0x51; 32]),
                asset_id: AssetId([0x52; 32]),
                amount: 500,
                beneficiary: recipient,
                refund_to: refund,
                mechanism: LockMechanism::CrossCurveConditionLock,
                deadline: TimelockSpec::TimestampSeconds {
                    value: 2_000_000_000,
                },
                finality: FinalityPolicyV1 {
                    min_confirmations: 1,
                    max_reorg_depth: 32,
                },
                adapter_profile_hash: profile_hash,
            },
            adaptor_point_sec1: adaptor,
            fee_limit: FeeLimitV1 {
                dom_max: 50,
                counterparty_max: 50,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 1_000,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: funder.0.to_vec(),
        }
    }

    #[test]
    fn route_setup_instruction_and_signed_transaction_are_consistent(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let signing = SigningKey::from_bytes(&[7; 32]);
        let funder = SolanaPubkey(signing.verifying_key().to_bytes());
        let program = SolanaPubkey::from_base58(PROGRAM)?;
        let profile = SolanaAdapterProfileV1::new(SolanaNetwork::LocalValidator, program, 3, 2)?;
        let context = SolanaProofContextV1 {
            settlement_id: [1; 32],
            chain_id: [0x51; 32],
            asset_id: [0x52; 32],
            amount: 500,
            beneficiary: [0x31; 32],
            refund_to: [0x21; 32],
            refund_after_unix: 2_000_000_000,
            min_confirmations: 1,
            max_reorg_depth: 32,
            asset: SolanaAssetV1::NativeSol,
            funder,
        };
        let route = prepare_route_secret(&profile, &context, &mut rand::thread_rng())?;
        let frozen = terms(route.dom_adaptor_point().0, profile.profile_hash(), funder);
        let setup_store = SolanaSetupStore::open(directory.path().join("setup.sqlite"))?;
        let session = finalize_session(
            &profile,
            &frozen,
            SolanaAssetV1::NativeSol,
            funder,
            [0xA5; 32],
            route,
            &setup_store,
        )?;
        let instruction = solana_program_client::initialize(session.setup());
        let decoded = EscrowInstructionV1::decode(&instruction.data).map_err(|e| e.to_string())?;
        assert!(matches!(decoded, EscrowInstructionV1::InitializeNative(_)));

        let plan = build_legacy_message(funder, SolanaHash([0x61; 32]), &[instruction])?;
        let signature = SolanaSignature(signing.sign(&plan.message).to_bytes());
        let raw = assemble_signed_transaction(&plan, &[(funder, signature)])?;
        assert!(!raw.is_empty());

        let delivery = SqliteSolanaDeliveryStore::open(directory.path().join("delivery.sqlite"))?;
        let first = delivery.prepare_exact([1; 32], [0x44; 32], signature, &raw)?;
        let replay = delivery.prepare_exact([1; 32], [0x44; 32], signature, &raw)?;
        assert_eq!(first.raw_fingerprint, replay.raw_fingerprint);
        Ok(())
    }

    #[test]
    fn wire_state_has_mutually_exclusive_terminals() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            transition(State::Funded, Event::ClaimValidSecret)?,
            State::Claimed
        );
        assert!(transition(State::Claimed, Event::RefundAfterDeadline).is_err());
        let state = EscrowStateV1 {
            status: EscrowStatus::Funded,
            asset_kind: AssetKind::NativeSol,
            state_bump: 1,
            vault_bump: 2,
            authority_bump: 3,
            token_decimals: 0,
            settlement_id: [1; 32],
            terms_hash: [2; 32],
            setup_id: [3; 32],
            funder: [4; 32],
            recipient: [5; 32],
            refund_recipient: [6; 32],
            token_program: [0; 32],
            mint: [0; 32],
            vault: [7; 32],
            dom_adaptor_point: {
                let mut p = [8; 33];
                p[0] = 2;
                p
            },
            claim_point_ed25519: [9; 32],
            amount: 10,
            funded_amount: 10,
            refund_after_unix: 2_000_000_000,
            terminal_slot: 0,
            revealed_secret_be: [0; 32],
        };
        assert_eq!(
            EscrowStateV1::decode(&state.encode()).map_err(|e| e.to_string())?,
            state
        );
        Ok(())
    }

    #[test]
    fn finalized_feed_handles_skipped_slots_and_emits_kaystra_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let chain = ChainId([0x51; 32]);
        let feed = SqliteVerifiedSolanaFeed::open(
            directory.path().join("observations.sqlite"),
            chain,
            [1; 32],
            [2; 32],
        )?;
        feed.replace_canonical_suffix(
            100,
            103,
            &[
                SolanaSlotAnchor {
                    slot: 100,
                    blockhash: [0xA0; 32],
                },
                SolanaSlotAnchor {
                    slot: 103,
                    blockhash: [0xA3; 32],
                },
            ],
        )?;
        feed.insert_event(&VerifiedSolanaEvent {
            settlement_id: [1; 32],
            terms_hash: [2; 32],
            kind: VerifiedSolanaEventKind::Funding,
            evidence: EvidenceRefV1 {
                chain_id: chain,
                tx_id: [3; 32],
                event_index: 0,
                block_height: 103,
                block_anchor: [0xA3; 32],
            },
        })?;
        let source = SolanaKaystraSource::new_from_slot(feed, [1; 32], [2; 32], 100)?;
        let cursor = source.genesis_cursor()?;
        let (records, _) = source.scan(&cursor)?;
        assert!(matches!(
            records.as_slice(),
            [ChainRecordV1::Funding { .. }]
        ));
        Ok(())
    }
}
