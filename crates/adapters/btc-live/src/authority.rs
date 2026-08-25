//! Secret-free authority values for Bitcoin funding integration.

use bitcoin::secp256k1::schnorr::Signature;

use crate::LiveBitcoinError;

/// Explicit BIP68 delay committed by the Bitcoin refund input.
///
/// This type deliberately represents only a relative delay. It does not
/// project an absolute block height or timestamp into BIP68; a higher-layer
/// timing authority must make and authenticate that decision before creating
/// a [`crate::BitcoinPrebroadcastPlanV1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinRefundDelayV1 {
    /// Relative delay measured in Bitcoin blocks.
    Blocks(u16),
    /// Relative delay measured in 512-second BIP68 intervals.
    Time512Seconds(u16),
}

impl BitcoinRefundDelayV1 {
    /// Strictly decodes one enabled, nonzero BIP68 sequence.
    pub fn from_sequence(sequence: u32) -> Result<Self, LiveBitcoinError> {
        const DISABLE_FLAG: u32 = 1 << 31;
        const TIME_FLAG: u32 = 1 << 22;
        const VALUE_MASK: u32 = 0xffff;
        if sequence & DISABLE_FLAG != 0 || sequence & !(TIME_FLAG | VALUE_MASK) != 0 {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let units =
            u16::try_from(sequence & VALUE_MASK).map_err(|_| LiveBitcoinError::InvalidRequest)?;
        if units == 0 {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        if sequence & TIME_FLAG == 0 {
            Ok(Self::Blocks(units))
        } else {
            Ok(Self::Time512Seconds(units))
        }
    }

    /// Exact consensus sequence encoding for this relative delay.
    #[must_use]
    pub const fn sequence(self) -> u32 {
        match self {
            Self::Blocks(units) => units as u32,
            Self::Time512Seconds(units) => (1 << 22) | units as u32,
        }
    }
}

/// Authenticated, secret-free summary of one wallet-selected funding plan.
///
/// The summary is persisted in its own owner-only immutable stage before a
/// refund can be armed. Its total input value comes from exact `gettxout`
/// responses while every selected input is still unspent; all other fields
/// are rederived from the authenticated Prepared transaction and plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinPreparedFundingSummaryV1 {
    pub(crate) route_binding: [u8; 32],
    pub(crate) plan_digest: [u8; 32],
    pub(crate) prepared_record_digest: [u8; 32],
    pub(crate) summary_record_digest: [u8; 32],
    pub(crate) funding_txid: [u8; 32],
    pub(crate) funding_wtxid: [u8; 32],
    pub(crate) contract_vout: u32,
    pub(crate) contract_amount_sat: u64,
    pub(crate) requested_fee_rate_sat_vb: u64,
    pub(crate) total_input_sat: u64,
    pub(crate) total_output_sat: u64,
    pub(crate) actual_fee_sat: u64,
    pub(crate) virtual_size_vb: u64,
    pub(crate) refund_delay: BitcoinRefundDelayV1,
}

impl BitcoinPreparedFundingSummaryV1 {
    /// Complete route binding accepted by the prebroadcast store.
    #[must_use]
    pub const fn route_binding(&self) -> [u8; 32] {
        self.route_binding
    }

    /// Digest of the complete canonical public plan.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Digest of the authenticated Prepared record containing funding bytes.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared_record_digest
    }

    /// Digest of this immutable summary record.
    #[must_use]
    pub const fn summary_record_digest(&self) -> [u8; 32] {
        self.summary_record_digest
    }

    /// Funding transaction identifier in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.funding_txid
    }

    /// Funding witness transaction identifier in internal byte order.
    #[must_use]
    pub const fn funding_wtxid(&self) -> [u8; 32] {
        self.funding_wtxid
    }

    /// Unique contract output index.
    #[must_use]
    pub const fn contract_vout(&self) -> u32 {
        self.contract_vout
    }

    /// Exact contract amount in satoshis.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// Fee rate requested from the wallet in satoshis per virtual byte.
    #[must_use]
    pub const fn requested_fee_rate_sat_vb(&self) -> u64 {
        self.requested_fee_rate_sat_vb
    }

    /// Sum of the exact selected input values in satoshis.
    #[must_use]
    pub const fn total_input_sat(&self) -> u64 {
        self.total_input_sat
    }

    /// Sum of every funding output in satoshis, including wallet change.
    #[must_use]
    pub const fn total_output_sat(&self) -> u64 {
        self.total_output_sat
    }

    /// Exact total funding fee in satoshis.
    #[must_use]
    pub const fn actual_fee_sat(&self) -> u64 {
        self.actual_fee_sat
    }

    /// Exact virtual size of the signed funding transaction.
    #[must_use]
    pub const fn virtual_size_vb(&self) -> u64 {
        self.virtual_size_vb
    }

    /// Explicit relative delay committed by the refund transaction.
    #[must_use]
    pub const fn refund_delay(&self) -> BitcoinRefundDelayV1 {
        self.refund_delay
    }
}

/// Public, raw-transaction-free request to a retained Bitcoin refund signer.
///
/// The request carries the exact BIP341 script-spend sighash and enough
/// authenticated public context for a retained signer to reject cross-route
/// or cross-plan reuse. It contains neither funding bytes nor a private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinRefundSigningRequestV1 {
    pub(crate) route_binding: [u8; 32],
    pub(crate) plan_digest: [u8; 32],
    pub(crate) prepared_record_digest: [u8; 32],
    pub(crate) summary_record_digest: [u8; 32],
    pub(crate) request_digest: [u8; 32],
    pub(crate) funding_txid: [u8; 32],
    pub(crate) contract_vout: u32,
    pub(crate) contract_amount_sat: u64,
    pub(crate) refund_key_xonly: [u8; 32],
    pub(crate) refund_delay: BitcoinRefundDelayV1,
    pub(crate) sighash: [u8; 32],
}

impl BitcoinRefundSigningRequestV1 {
    /// Complete route binding accepted by the prebroadcast store.
    #[must_use]
    pub const fn route_binding(&self) -> [u8; 32] {
        self.route_binding
    }

    /// Digest of the complete canonical public plan.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Digest of the exact authenticated Prepared record.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared_record_digest
    }

    /// Digest of the authenticated funding cost and plan summary.
    #[must_use]
    pub const fn summary_record_digest(&self) -> [u8; 32] {
        self.summary_record_digest
    }

    /// Domain-separated digest of every field in this signing request.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Funding transaction identifier in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.funding_txid
    }

    /// Unique contract output index.
    #[must_use]
    pub const fn contract_vout(&self) -> u32 {
        self.contract_vout
    }

    /// Exact contract amount in satoshis.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// BIP340 public key that must verify the returned signature.
    #[must_use]
    pub const fn refund_key_xonly(&self) -> [u8; 32] {
        self.refund_key_xonly
    }

    /// Explicit relative delay committed by the refund transaction.
    #[must_use]
    pub const fn refund_delay(&self) -> BitcoinRefundDelayV1 {
        self.refund_delay
    }

    /// Exact BIP341 Taproot script-spend signature hash.
    #[must_use]
    pub const fn sighash(&self) -> [u8; 32] {
        self.sighash
    }
}

/// One consuming BIP340 signature returned by a retained refund signer.
///
/// There is intentionally no byte getter, `Clone`, or `Debug` implementation.
/// The adapter consumes this value immediately, verifies it, constructs the
/// canonical refund internally, and persists that refund before returning.
pub struct BitcoinRefundSignatureV1 {
    pub(crate) bytes: [u8; 64],
}

impl BitcoinRefundSignatureV1 {
    /// Imports one exact default-sighash BIP340 signature from a signer.
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, LiveBitcoinError> {
        Signature::from_slice(&bytes).map_err(|_| LiveBitcoinError::RefundMismatch)?;
        Ok(Self { bytes })
    }
}

/// Retained, one-shot authority for the Bitcoin refund key.
///
/// Implementations must retain the private key outside `btc-live`, bind it to
/// the supplied request, and return only a signature. The adapter verifies
/// both the advertised public key and the returned signature. Consuming
/// `self` prevents this boundary from turning a retained signer into a
/// reusable raw-key or raw-transaction service.
pub trait RetainedBitcoinRefundSignerV1 {
    /// BIP340 public key controlled by this retained signer.
    fn refund_key_xonly(&self) -> [u8; 32];

    /// Consumes this authority to sign one exact refund request.
    fn sign_refund(
        self,
        request: BitcoinRefundSigningRequestV1,
    ) -> Result<BitcoinRefundSignatureV1, LiveBitcoinError>;
}

/// Payload-free identity of funding held and broadcast solely by `btc-live`.
///
/// A higher-layer durable runner can persist this descriptor before submit
/// and bind the later [`crate::BitcoinFundingBroadcastReceiptV1`] to it. The
/// descriptor contains no transaction bytes and therefore cannot create a
/// second broadcaster or a competing raw-funding outbox entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinExternalFundingCustodyV1 {
    pub(crate) route_binding: [u8; 32],
    pub(crate) plan_digest: [u8; 32],
    pub(crate) prepared_record_digest: [u8; 32],
    pub(crate) summary_record_digest: [u8; 32],
    pub(crate) refund_record_digest: [u8; 32],
    pub(crate) funding_txid: [u8; 32],
    pub(crate) refund_txid: [u8; 32],
    pub(crate) contract_vout: u32,
    pub(crate) contract_amount_sat: u64,
    pub(crate) actual_fee_sat: u64,
    pub(crate) virtual_size_vb: u64,
    pub(crate) custody_digest: [u8; 32],
}

impl BitcoinExternalFundingCustodyV1 {
    /// Complete route binding accepted by the prebroadcast store.
    #[must_use]
    pub const fn route_binding(&self) -> [u8; 32] {
        self.route_binding
    }

    /// Digest of the complete canonical public plan.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Digest of the exact authenticated Prepared record.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared_record_digest
    }

    /// Digest of the immutable funding summary record.
    #[must_use]
    pub const fn summary_record_digest(&self) -> [u8; 32] {
        self.summary_record_digest
    }

    /// Digest of the exact durable refund record.
    #[must_use]
    pub const fn refund_record_digest(&self) -> [u8; 32] {
        self.refund_record_digest
    }

    /// Funding transaction identifier in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.funding_txid
    }

    /// Refund transaction identifier in internal byte order.
    #[must_use]
    pub const fn refund_txid(&self) -> [u8; 32] {
        self.refund_txid
    }

    /// Unique contract output index.
    #[must_use]
    pub const fn contract_vout(&self) -> u32 {
        self.contract_vout
    }

    /// Exact contract amount in satoshis.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// Exact total funding fee in satoshis.
    #[must_use]
    pub const fn actual_fee_sat(&self) -> u64 {
        self.actual_fee_sat
    }

    /// Exact virtual size of the signed funding transaction.
    #[must_use]
    pub const fn virtual_size_vb(&self) -> u64 {
        self.virtual_size_vb
    }

    /// Domain-separated digest of this complete payload-free descriptor.
    #[must_use]
    pub const fn custody_digest(&self) -> [u8; 32] {
        self.custody_digest
    }

    /// Whether a sole-submit receipt names this exact retained funding.
    #[must_use]
    pub fn matches_broadcast_receipt(
        &self,
        receipt: &crate::BitcoinFundingBroadcastReceiptV1,
    ) -> bool {
        receipt.transaction_id() == self.funding_txid
    }
}
