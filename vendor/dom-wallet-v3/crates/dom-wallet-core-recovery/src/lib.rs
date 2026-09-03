//! Wallet-owned BIP-39 and frozen Recovery Capsule v1 construction boundary.

#![forbid(unsafe_code)]

use bip39::{Language, Mnemonic};
use dom_adaptor::{SessionBlindingShareCapabilityV1, SigningShareV1};
use dom_consensus::{
    validate_transaction, Transaction, TransactionInput, TransactionOutput, ValidationContext,
};
use dom_core::{BlockHeight, Timestamp};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    range_proof_verify_with_extra_commit,
    recovery::{
        derive_recovery_root, recover_output_from_capsule, OutputRecoveryDomain, PublicOutputKind,
        RecoveredOutput, RecoveryCapsule, RecoveryChainContext, RecoveryRoot,
        RECOVERY_CAPSULE_SIZE, RECOVERY_VERSION,
    },
    schnorr_add_public_keys, MAX_PROVABLE_VALUE, RANGE_PROOF_SERIALIZATION_VERSION,
    RANGE_PROOF_SIZE,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::{
    build_send_recoverable, finalize, respond_receive_recoverable, sender_excess_blinding,
    sender_phase_slate, slate_kernel_features, RecoveryBuildContext, SlateInput,
};
use dom_tx::{build_recoverable_output, slate::Slate};
use dom_wallet_core_api::ScanBlock;
use dom_wallet_core_protocol::{RecoverySlateBody, RecoverySlateSidecars};
use dom_wallet_core_sync::CoreChainIdentity;
use dom_wallet_domain::{
    RecoveryOutputClass, ReservedRecoveryCoordinate, WalletState, RECOVERY_SCHEME_BIP39_256_V1,
};
use dom_wallet_keys::{coinbase_blinding, ExtendedPrivKey};
use dom_wallet_recovery::{restore_from_canonical_scan, RestoreError, RestoredWalletState};
use rand::RngCore;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Frozen canonical serialized output size: commitment plus length and envelope.
pub const CANONICAL_TRANSACTION_OUTPUT_SIZE: usize = 33 + 4 + 835;
/// Frozen proof envelope size.
pub const RECOVERY_PROOF_ENVELOPE_SIZE: usize = RANGE_PROOF_SIZE + RECOVERY_CAPSULE_SIZE;

/// Canonical word count for every Wallet V3 recovery phrase.
pub const CANONICAL_PHRASE_WORDS: usize = 24;

/// Why a recovery phrase was rejected, precise enough for the UI to point at
/// the problem instead of saying "invalid phrase" and leaving the user to
/// re-read 24 words.
///
/// SECURITY: a diagnosis carries positions and counts, NEVER phrase content.
/// Command errors reach the log file, and a word the user typed — even a
/// misspelled one — is one keystroke away from real seed material. The caller
/// already holds the input and can highlight the word at `index` itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhraseProblem {
    /// Wrong number of words; `got` is what the user supplied.
    WrongWordCount { got: usize },
    /// The zero-based word at `index` is not in the BIP-39 English wordlist.
    UnknownWord { index: usize },
    /// Every word is real but the phrase's checksum does not verify — almost
    /// always two words swapped, or one word replaced by another valid word.
    ChecksumMismatch,
    /// Structurally unusable for reasons the user cannot act on individually.
    Malformed,
}

/// Canonical English 24-word BIP-39 seed boundary.
pub struct CanonicalWalletSeed {
    mnemonic: Mnemonic,
    seed: Zeroizing<[u8; 64]>,
    legacy_root: ExtendedPrivKey,
}

impl fmt::Debug for CanonicalWalletSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalWalletSeed([REDACTED])")
    }
}

impl CanonicalWalletSeed {
    /// Generate exactly 256 bits of operating-system entropy.
    pub fn generate() -> Result<Self, RecoveryMaterialError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|_| RecoveryMaterialError::RandomnessUnavailable)?;
        Self::from_entropy(&entropy)
    }

    /// Reconstruct the canonical boundary from encrypted 256-bit entropy.
    pub fn from_entropy(entropy: &[u8; 32]) -> Result<Self, RecoveryMaterialError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
            .map_err(|_| RecoveryMaterialError::InvalidMnemonic)?;
        Self::from_mnemonic(mnemonic)
    }

    /// Parse an English mnemonic, including BIP-39 Unicode normalization.
    pub fn parse(phrase: &str) -> Result<Self, RecoveryMaterialError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| RecoveryMaterialError::InvalidMnemonic)?;
        if mnemonic.word_count() != CANONICAL_PHRASE_WORDS || mnemonic.to_entropy().len() != 32 {
            return Err(RecoveryMaterialError::InvalidMnemonic);
        }
        Self::from_mnemonic(mnemonic)
    }

    /// Diagnose a phrase without constructing any seed material.
    ///
    /// Returns `Ok(())` exactly when [`CanonicalWalletSeed::parse`] would
    /// succeed, so the UI can rely on this as a pre-flight check that agrees
    /// with the real parser. Nothing derived from the phrase is retained.
    pub fn diagnose_phrase(phrase: &str) -> Result<(), PhraseProblem> {
        // The BIP-39 word count is checked first so a truncated phrase reports
        // its length instead of an unknown-word index the user cannot act on.
        let words = phrase.split_whitespace().count();
        if words != CANONICAL_PHRASE_WORDS {
            return Err(PhraseProblem::WrongWordCount { got: words });
        }
        match Mnemonic::parse_in(Language::English, phrase) {
            Ok(mnemonic) => {
                if mnemonic.word_count() != CANONICAL_PHRASE_WORDS
                    || mnemonic.to_entropy().len() != 32
                {
                    return Err(PhraseProblem::Malformed);
                }
                Ok(())
            }
            Err(bip39::Error::UnknownWord(index)) => Err(PhraseProblem::UnknownWord { index }),
            Err(bip39::Error::InvalidChecksum) => Err(PhraseProblem::ChecksumMismatch),
            Err(bip39::Error::BadWordCount(got)) => Err(PhraseProblem::WrongWordCount { got }),
            Err(_) => Err(PhraseProblem::Malformed),
        }
    }

    fn from_mnemonic(mnemonic: Mnemonic) -> Result<Self, RecoveryMaterialError> {
        if mnemonic.word_count() != 24 || mnemonic.to_entropy().len() != 32 {
            return Err(RecoveryMaterialError::InvalidMnemonic);
        }
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let legacy_root = ExtendedPrivKey::from_seed(seed.as_slice())
            .map_err(|_| RecoveryMaterialError::LegacyCoinbaseDerivation)?;
        Ok(Self {
            mnemonic,
            seed,
            legacy_root,
        })
    }

    /// Copy entropy into the caller's encrypted-state buffer.
    pub fn copy_entropy_to(&self, destination: &mut [u8; 32]) {
        let entropy = Zeroizing::new(self.mnemonic.to_entropy());
        destination.copy_from_slice(&entropy);
    }

    /// Return a one-time zeroizing phrase for the explicit creation ceremony.
    pub fn mnemonic_text(&self) -> Zeroizing<String> {
        Zeroizing::new(self.mnemonic.to_string())
    }

    fn recovery_root(
        &self,
        chain: RecoveryChainContext,
    ) -> Result<RecoveryRoot, RecoveryMaterialError> {
        derive_recovery_root(self.seed.as_slice(), chain)
            .map_err(|_| RecoveryMaterialError::RecoveryRootDerivation)
    }

    /// Run the frozen canonical ownership-recovery algorithm without exposing seed bytes.
    pub fn restore_canonical_scan(
        &self,
        chain: RecoveryChainContext,
        blocks: &[ScanBlock],
    ) -> Result<RestoredWalletState, RestoreError> {
        restore_from_canonical_scan(self.seed.as_slice(), chain, blocks)
    }

    /// Derive the historical DOM wallet coinbase blinding for `height`.
    ///
    /// Wallets released before Recovery Capsule v1 used the frozen
    /// `m/44'/330'/0'/1'/height'` path. Keeping this compatibility derivation
    /// here lets seed restore recognize old mining rewards without exposing the
    /// BIP-39 seed or changing the recovery-capable format used by new outputs.
    pub fn legacy_coinbase_blinding(
        &self,
        height: u64,
    ) -> Result<Zeroizing<[u8; 32]>, RecoveryMaterialError> {
        coinbase_blinding(&self.legacy_root, height)
            .map_err(|_| RecoveryMaterialError::LegacyCoinbaseDerivation)
    }
}

/// Public production-path declaration used to prevent proof-only additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionOutputPath {
    pub class: RecoveryOutputClass,
    pub constructor: &'static str,
    pub recovery_required: bool,
}

/// Every Wallet V3 output class has one frozen recoverable constructor.
pub const PRODUCTION_OUTPUT_PATHS: [ProductionOutputPath; 5] = [
    ProductionOutputPath {
        class: RecoveryOutputClass::ReceiveRequest,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::ReceiveSlate,
        constructor: "respond_receive_recoverable",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::Change,
        constructor: "build_send_recoverable",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::SelfTransfer,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::Coinbase,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
];

/// Wallet-owned result with public output data and an opaque spend secret.
pub struct RecoverableOutputResult {
    pub output: TransactionOutput,
    pub canonical_bytes: Vec<u8>,
    pub commitment: [u8; 33],
    pub range_proof: [u8; RANGE_PROOF_SIZE],
    pub recovery_capsule: [u8; RECOVERY_CAPSULE_SIZE],
    pub proof_envelope: [u8; RECOVERY_PROOF_ENVELOPE_SIZE],
    pub account: u32,
    pub derivation_index: u64,
    pub class: RecoveryOutputClass,
    secret: OutputSpendSecret,
}

impl RecoverableOutputResult {
    /// Compare encrypted-state spending evidence without exposing this blinding.
    pub fn matches_spend_blinding(&self, candidate: &[u8; 32]) -> bool {
        self.secret.0.as_bytes() == candidate
    }
}

impl fmt::Debug for RecoverableOutputResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOutputResult")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("class", &self.class)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

struct OutputSpendSecret(dom_crypto::BlindingFactor);

impl fmt::Debug for OutputSpendSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutputSpendSecret([REDACTED])")
    }
}

/// Authenticated recovery result with an opaque spend secret.
pub struct RecoveredWalletOutput {
    pub value: u64,
    pub account: u32,
    pub derivation_index: u64,
    pub class: RecoveryOutputClass,
    secret: OutputSpendSecret,
}

impl fmt::Debug for RecoveredWalletOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredWalletOutput")
            .field("value", &"[REDACTED]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("class", &self.class)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl RecoveredWalletOutput {
    /// Compare opaque spending evidence without exposing either blinding.
    pub fn matches_original(&self, original: &RecoverableOutputResult) -> bool {
        self.secret.0.as_bytes() == original.secret.0.as_bytes()
    }
}

/// Wallet orchestration around frozen Recovery Capsule and output APIs.
pub struct RecoverableOutputBuilder {
    root: RecoveryRoot,
    chain: RecoveryChainContext,
}

impl fmt::Debug for RecoverableOutputBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOutputBuilder")
            .field("root", &"[REDACTED]")
            .field("network_magic", &self.chain.network_magic)
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .finish()
    }
}

impl RecoverableOutputBuilder {
    pub fn new(
        seed: &CanonicalWalletSeed,
        identity: &CoreChainIdentity,
    ) -> Result<Self, RecoveryMaterialError> {
        validate_identity(identity)?;
        let chain = RecoveryChainContext {
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
        };
        Ok(Self {
            root: seed.recovery_root(chain)?,
            chain,
        })
    }

    /// Build, canonically decode, verify, and self-recover before exposure.
    pub fn build(
        &self,
        value: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableOutputResult, RecoveryMaterialError> {
        if value > MAX_PROVABLE_VALUE {
            return Err(RecoveryMaterialError::ValueOutOfRange);
        }
        let domain = domain_for_class(coordinate.class());
        let material = build_recoverable_output(
            &self.root,
            self.chain,
            value,
            coordinate.account(),
            coordinate.derivation_index(),
            domain,
        )
        .map_err(|_| RecoveryMaterialError::OutputConstruction)?;
        let output = material.output;
        let canonical_bytes = output
            .to_bytes()
            .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
        if canonical_bytes.len() != CANONICAL_TRANSACTION_OUTPUT_SIZE {
            return Err(RecoveryMaterialError::CanonicalSize);
        }
        let decoded = TransactionOutput::from_bytes(&canonical_bytes)
            .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
        if decoded != output {
            return Err(RecoveryMaterialError::CanonicalEncoding);
        }
        let range_proof: [u8; RANGE_PROOF_SIZE] = output
            .range_proof_bytes()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?
            .try_into()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?;
        let capsule = output
            .recovery_capsule()
            .map_err(|_| RecoveryMaterialError::InvalidCapsule)?
            .ok_or(RecoveryMaterialError::RecoveryRequired)?;
        let recovery_capsule = *capsule.as_bytes();
        let proof_envelope: [u8; RECOVERY_PROOF_ENVELOPE_SIZE] = output
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?;
        if !range_proof_verify_with_extra_commit(
            output.commitment.as_bytes(),
            &range_proof,
            &recovery_capsule,
        )
        .map_err(|_| RecoveryMaterialError::ProofVerification)?
        {
            return Err(RecoveryMaterialError::ProofVerification);
        }
        let recovered = recover_output_from_capsule(
            &self.root,
            self.chain,
            output.commitment.as_bytes(),
            RANGE_PROOF_SERIALIZATION_VERSION,
            domain.public_kind(),
            &capsule,
        )
        .map_err(|_| RecoveryMaterialError::CapsuleAuthentication)?
        .ok_or(RecoveryMaterialError::CapsuleAuthentication)?;
        validate_recovery(
            &recovered,
            value,
            coordinate.account(),
            coordinate.derivation_index(),
            domain,
            output.commitment.as_bytes(),
        )?;
        if recovered.blinding.as_bytes() != material.blinding.as_bytes() {
            return Err(RecoveryMaterialError::SelfRecoveryMismatch);
        }
        Ok(RecoverableOutputResult {
            commitment: *output.commitment.as_bytes(),
            output,
            canonical_bytes,
            range_proof,
            recovery_capsule,
            proof_envelope,
            account: coordinate.account(),
            derivation_index: coordinate.derivation_index(),
            class: coordinate.class(),
            secret: OutputSpendSecret(material.blinding),
        })
    }

    /// Build a spendable recovery-capable coinbase through the canonical DOM
    /// wallet-miner constructor. Only the public coinbase leaves this boundary.
    pub fn build_coinbase(
        &self,
        height: dom_core::BlockHeight,
        total_fees: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<dom_consensus::CoinbaseTransaction, RecoveryMaterialError> {
        if coordinate.class() != RecoveryOutputClass::Coinbase {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        dom_node::miner::build_seed_recoverable_coinbase(
            height,
            total_fees,
            &self.chain.chain_id,
            &self.root,
            self.chain,
            coordinate.account(),
            coordinate.derivation_index(),
        )
        .map_err(|_| RecoveryMaterialError::OutputConstruction)
    }

    /// Attempt authenticated ownership recovery without exposing secret bytes.
    pub fn try_recover(
        &self,
        output: &TransactionOutput,
        class: RecoveryOutputClass,
    ) -> Result<Option<RecoveredWalletOutput>, RecoveryMaterialError> {
        let domain = domain_for_class(class);
        let capsule = output
            .recovery_capsule()
            .map_err(|_| RecoveryMaterialError::InvalidCapsule)?
            .ok_or(RecoveryMaterialError::RecoveryRequired)?;
        let recovered = recover_output_from_capsule(
            &self.root,
            self.chain,
            output.commitment.as_bytes(),
            RANGE_PROOF_SERIALIZATION_VERSION,
            domain.public_kind(),
            &capsule,
        )
        .map_err(|_| RecoveryMaterialError::CapsuleAuthentication)?;
        match recovered {
            Some(value) if value.domain != domain => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            Some(value) => Ok(Some(recovered_wallet_output(value, class))),
            None => Ok(None),
        }
    }

    /// Create sender change through the frozen recovery-capable Slate builder.
    pub fn build_sender_offer(
        &self,
        inputs: &[WalletSlateInput],
        change_value: u64,
        amount: u64,
        fee: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableSlateMaterial, RecoveryMaterialError> {
        self.build_sender_offer_with_lock_height(inputs, change_value, amount, fee, 0, coordinate)
    }

    /// Build the ordinary-wallet contribution consumed by the authoritative
    /// Scriptless funding transaction composer.
    ///
    /// This performs no collaborative proof or signing. It delegates change
    /// construction to the same recovery-capable DOM output builder used by a
    /// normal wallet send, creates one public offset contribution, and derives
    /// exactly `e_i = change_i - inputs_i - offset_i` through the canonical
    /// Slate arithmetic. The opaque Scriptless layer later combines `e_i`
    /// only with this participant's shared-output share.
    pub fn build_scriptless_funding_contribution(
        &self,
        inputs: &[WalletSlateInput],
        change_value: u64,
        coordinate: Option<ReservedRecoveryCoordinate>,
    ) -> Result<PreparedScriptlessFundingContributionV1, RecoveryMaterialError> {
        if inputs.is_empty() && (change_value != 0 || coordinate.is_some()) {
            return Err(RecoveryMaterialError::ScriptlessFundingConstruction);
        }
        let change = match (change_value, coordinate) {
            (0, None) => None,
            (0, Some(_)) | (_, None) => {
                return Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            (_, Some(coordinate)) if coordinate.class() != RecoveryOutputClass::Change => {
                return Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            (_, Some(coordinate)) => {
                let RecoverableOutputResult {
                    output,
                    commitment,
                    secret,
                    ..
                } = self.build(change_value, coordinate)?;
                Some((
                    output,
                    RecoverableOwnedOutput {
                        commitment,
                        value: change_value,
                        blinding: Zeroizing::new(*secret.0.as_bytes()),
                    },
                ))
            }
        };

        let offset = BlindingFactor::random();
        let wallet_excess = Zeroizing::new(
            sender_excess_blinding(
                inputs.iter().map(|input| &input.blinding),
                change.as_ref().map(|(_, owned)| &*owned.blinding),
                offset.as_bytes(),
            )
            .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)?,
        );
        let opaque = SigningShareV1::from_be_bytes(*wallet_excess)
            .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)?;
        let wallet_excess_public_key = opaque.public_key().to_compressed_bytes();
        drop(opaque);

        let canonical_inputs = inputs
            .iter()
            .map(|input| {
                Ok(TransactionInput {
                    commitment: Commitment::from_compressed_bytes(&input.commitment)
                        .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)?,
                })
            })
            .collect::<Result<Vec<_>, RecoveryMaterialError>>()?;
        let (other_outputs, change) = match change {
            Some((output, owned)) => (vec![output], Some(owned)),
            None => (Vec::new(), None),
        };
        Ok(PreparedScriptlessFundingContributionV1 {
            public: ScriptlessFundingPublicComponentsV1 {
                inputs: canonical_inputs,
                other_outputs,
                offset_contribution: *offset.as_bytes(),
                wallet_excess_public_key,
            },
            change,
            wallet_excess,
        })
    }

    /// Build the wallet-owned output contribution for one real Scriptless
    /// claim or refund template.
    ///
    /// The output is constructed by the frozen Recovery Capsule path. The
    /// opaque local excess is exactly `e_i = payout_blinding_i - offset_i`;
    /// subtraction of this participant's shared-output share belongs only to
    /// the pinned `dom-adaptor` composition authority.
    pub fn build_scriptless_shared_output_spend_contribution(
        &self,
        payout_value: u64,
        coordinate: Option<ReservedRecoveryCoordinate>,
    ) -> Result<PreparedScriptlessPayoutContributionV1, RecoveryMaterialError> {
        let payout = match (payout_value, coordinate) {
            (0, None) => None,
            (0, Some(_)) | (_, None) => {
                return Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            (_, Some(coordinate)) if coordinate.class() != RecoveryOutputClass::SelfTransfer => {
                return Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            (_, Some(coordinate)) => {
                let RecoverableOutputResult {
                    output,
                    commitment,
                    secret,
                    ..
                } = self.build(payout_value, coordinate)?;
                Some((
                    output,
                    RecoverableOwnedOutput {
                        commitment,
                        value: payout_value,
                        blinding: Zeroizing::new(*secret.0.as_bytes()),
                    },
                ))
            }
        };
        let offset = BlindingFactor::random();
        let payout_excess = Zeroizing::new(
            sender_excess_blinding(
                std::iter::empty::<&[u8; 32]>(),
                payout.as_ref().map(|(_, owned)| &*owned.blinding),
                offset.as_bytes(),
            )
            .map_err(|_| RecoveryMaterialError::ScriptlessPayoutConstruction)?,
        );
        let opaque = SigningShareV1::from_be_bytes(*payout_excess)
            .map_err(|_| RecoveryMaterialError::ScriptlessPayoutConstruction)?;
        let payout_excess_public_key = opaque.public_key().to_compressed_bytes();
        drop(opaque);

        Ok(PreparedScriptlessPayoutContributionV1 {
            public: ScriptlessPayoutPublicComponentsV1 {
                outputs: payout
                    .as_ref()
                    .map(|(output, _)| vec![output.clone()])
                    .unwrap_or_default(),
                offset_contribution: *offset.as_bytes(),
                payout_excess_public_key,
            },
            owned_output: payout.map(|(_, owned)| owned),
            payout_excess,
        })
    }

    /// Create sender change through the frozen recovery-capable Slate builder
    /// while preserving an explicit canonical kernel lock height.
    ///
    /// `lock_height == 0` is byte-compatible with the historical PLAIN path.
    /// A non-zero value is written before the Slate is serialized or exported
    /// and before either participant signs. The canonical DOM responder and
    /// finalizer consequently derive `KERNEL_FEAT_HEIGHT_LOCKED` and bind the
    /// height into the kernel signature; no transaction bytes are edited.
    ///
    /// The satisfied-height policy and consensus preflight belong to the
    /// caller because this builder deliberately has no chain snapshot.
    pub fn build_sender_offer_with_lock_height(
        &self,
        inputs: &[WalletSlateInput],
        change_value: u64,
        amount: u64,
        fee: u64,
        lock_height: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableSlateMaterial, RecoveryMaterialError> {
        if coordinate.class() != RecoveryOutputClass::Change {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        let core_inputs: Vec<SlateInput> = inputs
            .iter()
            .map(|input| SlateInput {
                commitment: input.commitment,
                blinding: zeroize::Zeroizing::new(input.blinding),
            })
            .collect();
        let mut sender = build_send_recoverable(
            &core_inputs,
            change_value,
            amount,
            fee,
            self.chain.chain_id,
            RecoveryBuildContext {
                root: &self.root,
                chain: self.chain,
                account: coordinate.account(),
                derivation_index: coordinate.derivation_index(),
            },
        )
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        // The pinned DOM API exposes `build_send_with_lock_height` and
        // `build_send_recoverable`, but not their combined form. The only
        // semantic difference before signing is this public Slate field.
        // Setting it here, before `from_slate` freezes canonical bytes, keeps
        // the recovery-capable output path and delegates all feature/message
        // derivation to the canonical responder/finalizer.
        sender.slate.lock_height = lock_height;
        let private = SlatePrivateMaterial::Sender {
            excess_blinding: sender.excess_blinding,
            nonce: sender.nonce,
            change: sender
                .change
                .map(|change| (change.commitment, change.value, change.blinding)),
        };
        RecoverableSlateMaterial::from_slate(sender.slate, private)
    }

    /// Create a recipient output through the frozen recovery-capable responder.
    pub fn build_recipient_response(
        &self,
        offer: &RecoverySlateBody,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableSlateMaterial, RecoveryMaterialError> {
        if !matches!(
            coordinate.class(),
            RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate
        ) {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        let slate = Slate::from_bytes(offer.canonical_bytes())
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        let response = respond_receive_recoverable(
            slate,
            &self.chain.chain_id,
            RecoveryBuildContext {
                root: &self.root,
                chain: self.chain,
                account: coordinate.account(),
                derivation_index: coordinate.derivation_index(),
            },
        )
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        RecoverableSlateMaterial::from_slate(
            response.slate,
            SlatePrivateMaterial::Recipient {
                output_blinding: response.recipient_output_blinding,
            },
        )
    }
}

/// Exact public common-wallet components for one participant's funding input.
/// These are normal DOM transaction objects and contain no blinding, nonce,
/// seed, participant identity, or Scriptless marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptlessFundingPublicComponentsV1 {
    pub inputs: Vec<TransactionInput>,
    pub other_outputs: Vec<TransactionOutput>,
    pub offset_contribution: [u8; 32],
    pub wallet_excess_public_key: [u8; 33],
}

/// Exact public contribution for one participant's claim or refund payout.
/// It contains only a normal recoverable DOM output, a canonical transaction
/// offset contribution and the public point `e_i*G`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptlessPayoutPublicComponentsV1 {
    /// Empty for a non-beneficiary signer and exactly one official Wallet V3
    /// recoverable output for the beneficiary.
    pub outputs: Vec<TransactionOutput>,
    pub offset_contribution: [u8; 32],
    pub payout_excess_public_key: [u8; 33],
}

/// Prepared payout material whose secrets may only enter encrypted Wallet V3
/// state. It deliberately has no serialization, Clone or scalar accessor.
pub struct PreparedScriptlessPayoutContributionV1 {
    pub public: ScriptlessPayoutPublicComponentsV1,
    pub owned_output: Option<RecoverableOwnedOutput>,
    payout_excess: Zeroizing<[u8; 32]>,
}

/// Short-lived opaque payout excess used only to authenticate encrypted state
/// against its persisted public point before template binding. It exposes no
/// signing or composition operation and is not a signing capability.
pub struct OpaqueScriptlessPayoutExcessV1 {
    share: SigningShareV1,
}

impl OpaqueScriptlessPayoutExcessV1 {
    /// Rehydrate `e_i = payout_blinding_i - offset_i` from encrypted state.
    pub fn from_encrypted_context(
        payout_excess_contribution: [u8; 32],
    ) -> Result<Self, RecoveryMaterialError> {
        let share = SigningShareV1::from_be_bytes(payout_excess_contribution)
            .map_err(|_| RecoveryMaterialError::ScriptlessPayoutConstruction)?;
        Ok(Self { share })
    }

    /// Public point used to authenticate encrypted state against persisted and
    /// possibly exposed payout components.
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.share.public_key().to_compressed_bytes()
    }
}

impl fmt::Debug for PreparedScriptlessPayoutContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedScriptlessPayoutContributionV1(REDACTED)")
    }
}

impl PreparedScriptlessPayoutContributionV1 {
    /// Copy `e_i` only into the encrypted payout reservation context.
    pub fn copy_payout_excess_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(self.payout_excess.as_ref());
    }
}

/// Prepared public components plus secrets destined only for encrypted Wallet
/// V3 state. Debug output is intentionally fully redacted.
pub struct PreparedScriptlessFundingContributionV1 {
    pub public: ScriptlessFundingPublicComponentsV1,
    pub change: Option<RecoverableOwnedOutput>,
    wallet_excess: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PreparedScriptlessFundingContributionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedScriptlessFundingContributionV1(REDACTED)")
    }
}

impl PreparedScriptlessFundingContributionV1 {
    /// Copy the wallet excess only into the encrypted persistence context.
    pub fn copy_wallet_excess_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(self.wallet_excess.as_ref());
    }
}

/// Short-lived authentication view of an encrypted funding excess. It can
/// reproduce only the already-public `e_i*G`; it has no signing/composition
/// method and is never a substitute for the post-template capability.
pub struct OpaqueScriptlessFundingExcessV1 {
    share: SigningShareV1,
}

impl OpaqueScriptlessFundingExcessV1 {
    pub fn from_encrypted_context(
        wallet_excess_contribution: [u8; 32],
    ) -> Result<Self, RecoveryMaterialError> {
        let share = SigningShareV1::from_be_bytes(wallet_excess_contribution)
            .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)?;
        Ok(Self { share })
    }

    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.share.public_key().to_compressed_bytes()
    }
}

/// Durable public binding copied into a short-lived signing capability.
///
/// It contains no secret, but prevents a rehydrated wallet contribution from
/// being composed under another chain, session, participant or template.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BoundScriptlessSigningContextV1 {
    pub chain_id: [u8; 32],
    pub session_id: [u8; 32],
    pub session_share_binding_digest: [u8; 32],
    pub participant_position: u16,
    pub template_hash: [u8; 32],
}

impl BoundScriptlessSigningContextV1 {
    fn matches(&self, session_share: &SessionBlindingShareCapabilityV1) -> bool {
        let binding = session_share.binding();
        self.chain_id == *binding.chain_id()
            && self.session_id == *binding.session_id()
            && self.session_share_binding_digest == binding.binding_digest_v1()
            && self.participant_position == binding.participant_index()
            && binding.roster().len() == 2
            && binding.terms_hash() != &[0u8; 32]
            && binding.capsule_hash() != &[0u8; 32]
            && binding.roster().get(usize::from(self.participant_position))
                == Some(binding.participant_id())
            && session_share.public_key() == binding.share_point()
            && self.template_hash != [0u8; 32]
    }
}

impl fmt::Debug for BoundScriptlessSigningContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundScriptlessSigningContextV1")
            .field("participant_position", &self.participant_position)
            .field("binding", &"[REDACTED]")
            .finish()
    }
}

/// Short-lived, non-serializable funding handoff into `dom-adaptor`.
///
/// The wallet contribution remains opaque and zeroizes on drop. The only
/// secret-bearing operation accepts the exact authenticated shared-blinding
/// capability already bound to the real funding template and returns DOM's
/// opaque combined `r_i + e_i` share. There is no callback or byte accessor.
pub struct ScriptlessFundingSigningCapabilityV1 {
    share: SigningShareV1,
    context: BoundScriptlessSigningContextV1,
}

impl ScriptlessFundingSigningCapabilityV1 {
    /// Rehydrate an encrypted common-wallet excess only after template bind.
    pub fn from_template_bound_encrypted_context(
        wallet_excess_contribution: [u8; 32],
        context: BoundScriptlessSigningContextV1,
    ) -> Result<Self, RecoveryMaterialError> {
        let share = SigningShareV1::from_be_bytes(wallet_excess_contribution)
            .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)?;
        if context.chain_id == [0u8; 32]
            || context.session_id == [0u8; 32]
            || context.session_share_binding_digest == [0u8; 32]
            || context.participant_position >= 2
            || context.template_hash == [0u8; 32]
        {
            return Err(RecoveryMaterialError::ScriptlessSigningBinding);
        }
        Ok(Self { share, context })
    }

    /// Compose exactly `r_i + e_i` through the bound DOM authority.
    pub fn compose_local_funding_share_v1(
        &self,
        session_share: &SessionBlindingShareCapabilityV1,
    ) -> Result<SigningShareV1, RecoveryMaterialError> {
        if !self.context.matches(session_share) {
            return Err(RecoveryMaterialError::ScriptlessSigningBinding);
        }
        session_share
            .compose_funding_signing_share_v1(&self.share)
            .map_err(|_| RecoveryMaterialError::ScriptlessFundingConstruction)
    }

    /// Public key used to verify that encrypted restart state still matches
    /// the already-persisted public funding component.
    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.share.public_key().to_compressed_bytes()
    }
}

/// Short-lived, non-serializable Claim/Refund handoff into `dom-adaptor`.
/// Its sole operation returns the opaque `e_i - r_i` share for the exact
/// template-bound session; no wallet or shared-output scalar is exposed.
pub struct ScriptlessPayoutSigningCapabilityV1 {
    share: SigningShareV1,
    context: BoundScriptlessSigningContextV1,
}

impl ScriptlessPayoutSigningCapabilityV1 {
    pub fn from_template_bound_encrypted_context(
        payout_excess_contribution: [u8; 32],
        context: BoundScriptlessSigningContextV1,
    ) -> Result<Self, RecoveryMaterialError> {
        let share = SigningShareV1::from_be_bytes(payout_excess_contribution)
            .map_err(|_| RecoveryMaterialError::ScriptlessPayoutConstruction)?;
        if context.chain_id == [0u8; 32]
            || context.session_id == [0u8; 32]
            || context.session_share_binding_digest == [0u8; 32]
            || context.participant_position >= 2
            || context.template_hash == [0u8; 32]
        {
            return Err(RecoveryMaterialError::ScriptlessSigningBinding);
        }
        Ok(Self { share, context })
    }

    pub fn compose_local_shared_output_spend_share_v1(
        &self,
        session_share: &SessionBlindingShareCapabilityV1,
    ) -> Result<SigningShareV1, RecoveryMaterialError> {
        if !self.context.matches(session_share) {
            return Err(RecoveryMaterialError::ScriptlessSigningBinding);
        }
        session_share
            .compose_shared_output_spend_signing_share_v1(&self.share)
            .map_err(|_| RecoveryMaterialError::ScriptlessPayoutConstruction)
    }

    pub fn public_key_bytes(&self) -> [u8; 33] {
        self.share.public_key().to_compressed_bytes()
    }
}

/// Wallet input material with redacted blinding diagnostics.
#[derive(Clone)]
pub struct WalletSlateInput {
    pub commitment: [u8; 33],
    blinding: [u8; 32],
}

impl WalletSlateInput {
    pub fn new(commitment: [u8; 33], blinding: [u8; 32]) -> Self {
        Self {
            commitment,
            blinding,
        }
    }
}

impl fmt::Debug for WalletSlateInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSlateInput")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

/// Canonical Slate v4 body plus exact ordered sidecars.
pub struct RecoverableSlateMaterial {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    private: SlatePrivateMaterial,
}

impl RecoverableSlateMaterial {
    fn from_slate(
        slate: Slate,
        private: SlatePrivateMaterial,
    ) -> Result<Self, RecoveryMaterialError> {
        let sender_change = optional_capsule(&slate.sender_change_recovery_capsule)?;
        let recipient = optional_capsule(&slate.recipient_recovery_capsule)?;
        let canonical = slate
            .to_bytes()
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        Ok(Self {
            body: RecoverySlateBody::from_canonical_bytes(&canonical)
                .map_err(|_| RecoveryMaterialError::SlateConstruction)?,
            sidecars: RecoverySlateSidecars {
                sender_change,
                recipient,
            },
            private,
        })
    }

    /// Confirm that required private material remains retained without exposing it.
    pub fn retains_private_material(&self) -> bool {
        match &self.private {
            SlatePrivateMaterial::Sender {
                excess_blinding,
                nonce,
                change,
            } => {
                excess_blinding.iter().any(|byte| *byte != 0)
                    && nonce.iter().any(|byte| *byte != 0)
                    && change
                        .as_ref()
                        .is_none_or(|value| value.2.iter().any(|byte| *byte != 0))
            }
            SlatePrivateMaterial::Recipient { output_blinding } => {
                output_blinding.iter().any(|byte| *byte != 0)
            }
        }
    }

    /// Consume sender material into encrypted-state secrets and public change data.
    pub fn into_sender_parts(self) -> Result<RecoverableSenderParts, RecoveryMaterialError> {
        match self.private {
            SlatePrivateMaterial::Sender {
                excess_blinding,
                nonce,
                change,
            } => Ok(RecoverableSenderParts {
                body: self.body,
                sidecars: self.sidecars,
                excess_blinding,
                nonce,
                change: change.map(|(commitment, value, blinding)| RecoverableOwnedOutput {
                    commitment,
                    value,
                    blinding,
                }),
            }),
            SlatePrivateMaterial::Recipient { .. } => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
        }
    }

    /// Consume recipient material into encrypted-state secrets and public output data.
    pub fn into_recipient_parts(self) -> Result<RecoverableRecipientParts, RecoveryMaterialError> {
        let (commitment, value) = recipient_public(&self.body)?;
        match self.private {
            SlatePrivateMaterial::Recipient { output_blinding } => Ok(RecoverableRecipientParts {
                body: self.body,
                sidecars: self.sidecars,
                output: RecoverableOwnedOutput {
                    commitment,
                    value,
                    blinding: output_blinding,
                },
            }),
            SlatePrivateMaterial::Sender { .. } => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
        }
    }
}

/// Public output coordinates plus a secret intended only for encrypted Wallet state.
pub struct RecoverableOwnedOutput {
    pub commitment: [u8; 33],
    pub value: u64,
    blinding: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoverableOwnedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOwnedOutput")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("value", &"[REDACTED]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

impl RecoverableOwnedOutput {
    pub fn copy_blinding_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(self.blinding.as_ref());
    }
}

pub struct RecoverableSenderParts {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    pub change: Option<RecoverableOwnedOutput>,
    excess_blinding: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoverableSenderParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverableSenderParts([REDACTED])")
    }
}

impl RecoverableSenderParts {
    /// Rehydrate encrypted sender context after restart without changing Slate bytes.
    pub fn from_encrypted_context(
        body: RecoverySlateBody,
        excess_blinding: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<Self, RecoveryMaterialError> {
        let slate = Slate::from_bytes(body.canonical_bytes())
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        if slate.version != dom_tx::slate::RECOVERY_SLATE_VERSION
            || excess_blinding == [0u8; 32]
            || nonce == [0u8; 32]
        {
            return Err(RecoveryMaterialError::SlateConstruction);
        }
        Ok(Self {
            sidecars: RecoverySlateSidecars {
                sender_change: optional_capsule(&slate.sender_change_recovery_capsule)?,
                recipient: optional_capsule(&slate.recipient_recovery_capsule)?,
            },
            body,
            change: None,
            excess_blinding: Zeroizing::new(excess_blinding),
            nonce: Zeroizing::new(nonce),
        })
    }

    pub fn copy_signing_secrets_to(&self, excess: &mut [u8; 32], nonce: &mut [u8; 32]) {
        excess.copy_from_slice(self.excess_blinding.as_ref());
        nonce.copy_from_slice(self.nonce.as_ref());
    }
}

pub struct RecoverableRecipientParts {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    pub output: RecoverableOwnedOutput,
}

impl fmt::Debug for RecoverableRecipientParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverableRecipientParts([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRecoverableTransaction {
    pub canonical_bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
    pub kernel_excess: [u8; 33],
    pub fee: u64,
    pub weight: u32,
}

/// Public evidence returned after an independent participant verifies that
/// finalized canonical transaction bytes are exactly bound to its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecoverableTransaction {
    pub transaction_hash: [u8; 32],
    pub kernel_excess: [u8; 33],
    pub fee: u64,
    pub lock_height: u64,
    pub weight: u32,
}

/// Finalize only when the response strips exactly to the persisted recovery offer.
pub fn finalize_recoverable_transaction(
    response: &RecoverySlateBody,
    offer: &RecoverySlateBody,
    sender: &RecoverableSenderParts,
    chain_id: [u8; 32],
) -> Result<FinalizedRecoverableTransaction, RecoveryMaterialError> {
    let response_slate = Slate::from_bytes(response.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let offer_slate = Slate::from_bytes(offer.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let stripped = sender_phase_slate(&response_slate)
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let expected = offer_slate
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    if stripped != expected || sender.body.canonical_bytes() != offer.canonical_bytes() {
        return Err(RecoveryMaterialError::SlateBindingMismatch);
    }
    let transaction = finalize(
        &response_slate,
        &sender.excess_blinding,
        &sender.nonce,
        &chain_id,
    )
    .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let canonical_bytes = transaction
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
    let transaction_hash = *dom_crypto::blake2b_256(&canonical_bytes).as_bytes();
    let kernel = transaction
        .kernels
        .first()
        .ok_or(RecoveryMaterialError::SlateConstruction)?;
    Ok(FinalizedRecoverableTransaction {
        canonical_bytes,
        transaction_hash,
        kernel_excess: *kernel.excess.as_bytes(),
        fee: transaction
            .total_fee()
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?,
        weight: transaction.weight(),
    })
}

/// Independently verify finalized bytes against a recipient's exact Slate
/// response and the current validated DOM chain snapshot.
///
/// This is the receiver-side half of the G0 requirement that both wallets
/// validate the final transaction before broadcast. It performs canonical
/// decode/re-encode, exact input/output/order/offset/kernel binding, and the
/// full public DOM consensus transaction verifier. It never needs sender or
/// recipient secret material.
pub fn verify_recoverable_transaction_against_response(
    canonical_bytes: &[u8],
    response: &RecoverySlateBody,
    identity: &CoreChainIdentity,
) -> Result<VerifiedRecoverableTransaction, RecoveryMaterialError> {
    validate_identity(identity)?;
    let transaction = Transaction::from_bytes(canonical_bytes)
        .map_err(|_| RecoveryMaterialError::TransactionVerification)?;
    if transaction
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::TransactionVerification)?
        != canonical_bytes
    {
        return Err(RecoveryMaterialError::TransactionVerification);
    }

    let slate = Slate::from_bytes(response.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::TransactionVerification)?;
    if slate.chain_id != identity.chain_id
        || transaction.inputs.len() != slate.sender_inputs.len()
        || transaction
            .inputs
            .iter()
            .zip(&slate.sender_inputs)
            .any(|(input, expected)| input.commitment != *expected)
        || transaction.offset != slate.sender_offset_contribution
    {
        return Err(RecoveryMaterialError::SlateBindingMismatch);
    }

    let expected_outputs = response_transaction_outputs(&slate)?;
    if transaction.outputs != expected_outputs || transaction.kernels.len() != 1 {
        return Err(RecoveryMaterialError::SlateBindingMismatch);
    }

    let recipient_excess = slate
        .recipient_public_excess
        .clone()
        .ok_or(RecoveryMaterialError::TransactionVerification)?;
    let aggregate_excess =
        schnorr_add_public_keys(&[slate.sender_public_excess.clone(), recipient_excess])
            .map_err(|_| RecoveryMaterialError::TransactionVerification)?;
    let expected_excess =
        Commitment::from_compressed_bytes(&aggregate_excess.to_compressed_bytes())
            .map_err(|_| RecoveryMaterialError::TransactionVerification)?;
    let kernel = &transaction.kernels[0];
    if kernel.features != slate_kernel_features(slate.lock_height)
        || kernel.fee.noms() != slate.fee
        || kernel.lock_height != slate.lock_height
        || kernel.excess != expected_excess
    {
        return Err(RecoveryMaterialError::SlateBindingMismatch);
    }

    validate_transaction(
        &transaction,
        &ValidationContext {
            current_height: BlockHeight(identity.current_tip.height),
            chain_id: identity.chain_id,
            // Transaction validation currently has no wall-clock rule. Keep a
            // deterministic value instead of smuggling local time into G0.
            now: Timestamp(0),
        },
    )
    .map_err(|_| RecoveryMaterialError::TransactionVerification)?;

    Ok(VerifiedRecoverableTransaction {
        transaction_hash: *dom_crypto::blake2b_256(canonical_bytes).as_bytes(),
        kernel_excess: *kernel.excess.as_bytes(),
        fee: kernel.fee.noms(),
        lock_height: kernel.lock_height,
        weight: transaction.weight(),
    })
}

fn response_transaction_outputs(
    slate: &Slate,
) -> Result<Vec<TransactionOutput>, RecoveryMaterialError> {
    let recipient = slate
        .recipient_output
        .clone()
        .ok_or(RecoveryMaterialError::TransactionVerification)?;
    let mut outputs = Vec::with_capacity(usize::from(slate.sender_change_output.is_some()) + 1);
    if let Some(change) = &slate.sender_change_output {
        let capsule = RecoveryCapsule::from_bytes(&slate.sender_change_recovery_capsule)
            .map_err(|_| RecoveryMaterialError::InvalidCapsule)?;
        outputs.push(
            TransactionOutput::with_recovery_capsule(
                change.commitment.clone(),
                change.proof.bytes.clone(),
                &capsule,
            )
            .map_err(|_| RecoveryMaterialError::TransactionVerification)?,
        );
    }
    let capsule = RecoveryCapsule::from_bytes(&slate.recipient_recovery_capsule)
        .map_err(|_| RecoveryMaterialError::InvalidCapsule)?;
    outputs.push(
        TransactionOutput::with_recovery_capsule(
            recipient.commitment,
            recipient.proof.bytes,
            &capsule,
        )
        .map_err(|_| RecoveryMaterialError::TransactionVerification)?,
    );
    Ok(outputs)
}

fn recipient_public(body: &RecoverySlateBody) -> Result<([u8; 33], u64), RecoveryMaterialError> {
    let slate = Slate::from_bytes(body.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let output = slate
        .recipient_output
        .ok_or(RecoveryMaterialError::SlateConstruction)?;
    Ok((*output.commitment.as_bytes(), slate.amount))
}

enum SlatePrivateMaterial {
    Sender {
        excess_blinding: Zeroizing<[u8; 32]>,
        nonce: Zeroizing<[u8; 32]>,
        change: Option<([u8; 33], u64, Zeroizing<[u8; 32]>)>,
    },
    Recipient {
        output_blinding: Zeroizing<[u8; 32]>,
    },
}

fn optional_capsule(
    bytes: &[u8],
) -> Result<Option<[u8; RECOVERY_CAPSULE_SIZE]>, RecoveryMaterialError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let capsule =
        RecoveryCapsule::from_bytes(bytes).map_err(|_| RecoveryMaterialError::InvalidCapsule)?;
    Ok(Some(*capsule.as_bytes()))
}

fn validate_identity(identity: &CoreChainIdentity) -> Result<(), RecoveryMaterialError> {
    if identity.network_magic != identity.network.magic()
        || identity.chain_id == [0u8; 32]
        || identity.protocol_version != dom_core::PROTOCOL_VERSION
        || identity.range_proof_serialization_version != RANGE_PROOF_SERIALIZATION_VERSION
    {
        return Err(RecoveryMaterialError::ChainIdentityMismatch);
    }
    Ok(())
}

fn domain_for_class(class: RecoveryOutputClass) -> OutputRecoveryDomain {
    match class {
        RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate => {
            OutputRecoveryDomain::Received
        }
        RecoveryOutputClass::Change => OutputRecoveryDomain::Change,
        RecoveryOutputClass::SelfTransfer => OutputRecoveryDomain::SelfTransfer,
        RecoveryOutputClass::Coinbase => OutputRecoveryDomain::Coinbase,
    }
}

fn class_for_domain(domain: OutputRecoveryDomain) -> RecoveryOutputClass {
    match domain {
        OutputRecoveryDomain::Received => RecoveryOutputClass::ReceiveSlate,
        OutputRecoveryDomain::Change => RecoveryOutputClass::Change,
        OutputRecoveryDomain::SelfTransfer => RecoveryOutputClass::SelfTransfer,
        OutputRecoveryDomain::Coinbase => RecoveryOutputClass::Coinbase,
    }
}

fn recovered_wallet_output(
    recovered: RecoveredOutput,
    requested_class: RecoveryOutputClass,
) -> RecoveredWalletOutput {
    let class = if recovered.domain == OutputRecoveryDomain::Received {
        requested_class
    } else {
        class_for_domain(recovered.domain)
    };
    RecoveredWalletOutput {
        value: recovered.value,
        account: recovered.account,
        derivation_index: recovered.derivation_index,
        class,
        secret: OutputSpendSecret(recovered.blinding),
    }
}

fn validate_recovery(
    recovered: &RecoveredOutput,
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: OutputRecoveryDomain,
    commitment: &[u8; 33],
) -> Result<(), RecoveryMaterialError> {
    let recomputed = Commitment::commit(recovered.value, &recovered.blinding);
    if recovered.value != value
        || recovered.account != account
        || recovered.derivation_index != derivation_index
        || recovered.domain != domain
        || recomputed.as_bytes() != commitment
    {
        return Err(RecoveryMaterialError::SelfRecoveryMismatch);
    }
    Ok(())
}

/// Typed failures contain no mnemonic, seed, recovery root, value, or blinding.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMaterialError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("BIP-39 mnemonic is invalid")]
    InvalidMnemonic,
    #[error("recovery root derivation failed")]
    RecoveryRootDerivation,
    #[error("legacy coinbase derivation failed")]
    LegacyCoinbaseDerivation,
    #[error("Core chain identity is incompatible")]
    ChainIdentityMismatch,
    #[error("output value is outside the frozen proof range")]
    ValueOutOfRange,
    #[error("recovery coordinate has the wrong output domain")]
    CoordinateDomainMismatch,
    #[error("frozen output construction failed")]
    OutputConstruction,
    #[error("canonical output encoding failed")]
    CanonicalEncoding,
    #[error("canonical output size is invalid")]
    CanonicalSize,
    #[error("Recovery Capsule v1 is required")]
    RecoveryRequired,
    #[error("Recovery Capsule v1 framing is invalid")]
    InvalidCapsule,
    #[error("range-proof verification failed")]
    ProofVerification,
    #[error("capsule authentication failed")]
    CapsuleAuthentication,
    #[error("self-recovery did not match constructed material")]
    SelfRecoveryMismatch,
    #[error("recoverable Slate construction failed")]
    SlateConstruction,
    #[error("recoverable Slate response does not bind to the persisted offer")]
    SlateBindingMismatch,
    #[error("finalized transaction does not pass canonical DOM verification")]
    TransactionVerification,
    #[error("Scriptless funding wallet contribution construction failed")]
    ScriptlessFundingConstruction,
    #[error("Scriptless claim/refund payout contribution construction failed")]
    ScriptlessPayoutConstruction,
    #[error("Scriptless signing capability binding is invalid")]
    ScriptlessSigningBinding,
}

/// Whether encrypted state is eligible for the canonical BIP-39 boundary.
pub fn state_uses_canonical_seed(state: &WalletState) -> bool {
    state
        .recovery
        .as_ref()
        .is_some_and(|value| value.scheme == RECOVERY_SCHEME_BIP39_256_V1)
}

/// Frozen public constants used by the output boundary.
pub fn frozen_versions() -> (u16, u8) {
    (RECOVERY_VERSION, RANGE_PROOF_SERIALIZATION_VERSION)
}

/// Public kind for a Wallet output class.
pub fn public_output_kind(class: RecoveryOutputClass) -> PublicOutputKind {
    domain_for_class(class).public_kind()
}

#[cfg(test)]
mod compatibility_tests {
    use super::CanonicalWalletSeed;
    use dom_wallet_keys::{Bip39Seed, SeedAcceptance};

    #[test]
    fn shared_phrase_derives_byte_identical_bip39_seed_in_legacy_and_v3() {
        let canonical = CanonicalWalletSeed::from_entropy(&[0x2a; 32]).unwrap();
        let phrase = canonical.mnemonic_text();
        let legacy = Bip39Seed::from_phrase(&phrase, SeedAcceptance::NewWallet).unwrap();

        assert_eq!(
            canonical.seed.as_slice(),
            legacy.seed_bytes(),
            "the same test phrase must produce the same 64-byte BIP-39 secret"
        );
    }
}
