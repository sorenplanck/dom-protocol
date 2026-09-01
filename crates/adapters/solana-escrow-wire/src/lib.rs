//! Shared, dependency-free wire format for the DOM Solana escrow program.
//!
//! This crate is consumed both by the host-side DOM adapters and by the
//! standalone Solana program. All integer fields are big-endian except where
//! the Solana/SPL protocol itself requires another encoding.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

/// State account magic.
pub const STATE_MAGIC: &[u8; 8] = b"DOMSOLV1";
/// Instruction magic.
pub const INSTRUCTION_MAGIC: &[u8; 8] = b"DOMSLIX1";
/// Frozen wire version.
pub const WIRE_VERSION: u16 = 1;
/// Exact state-account data size.
pub const STATE_LEN: usize = 464;
/// State PDA seed.
pub const STATE_SEED: &[u8] = b"dom-solana-state-v1";
/// Native SOL vault PDA seed.
pub const NATIVE_VAULT_SEED: &[u8] = b"dom-solana-native-v1";
/// SPL token-account PDA seed.
pub const TOKEN_VAULT_SEED: &[u8] = b"dom-solana-token-v1";
/// Vault-authority PDA seed.
pub const VAULT_AUTHORITY_SEED: &[u8] = b"dom-solana-authority-v1";

/// Asset secured by the escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetKind {
    /// Native SOL, amount measured in lamports.
    NativeSol = 1,
    /// Classic SPL Token Program account, amount in base units.
    LegacySpl = 2,
}

impl AssetKind {
    /// Strict tag decoder.
    pub fn from_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            1 => Ok(Self::NativeSol),
            2 => Ok(Self::LegacySpl),
            _ => Err(WireError::UnknownTag),
        }
    }
}

/// Monotonic escrow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EscrowStatus {
    /// PDA and vault exist, but the exact amount has not been deposited.
    Initialized = 1,
    /// Exact funding is present and either terminal path may execute.
    Funded = 2,
    /// Claim transferred the asset and revealed the scalar.
    Claimed = 3,
    /// Refund transferred the asset after the frozen deadline.
    Refunded = 4,
    /// Rent-bearing accounts were closed after a terminal state.
    Closed = 5,
}

impl EscrowStatus {
    /// Strict tag decoder.
    pub fn from_tag(tag: u8) -> Result<Self, WireError> {
        match tag {
            1 => Ok(Self::Initialized),
            2 => Ok(Self::Funded),
            3 => Ok(Self::Claimed),
            4 => Ok(Self::Refunded),
            5 => Ok(Self::Closed),
            _ => Err(WireError::UnknownTag),
        }
    }

    /// Whether the economic outcome is immutable.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Claimed | Self::Refunded | Self::Closed)
    }
}

/// Canonical state stored in the state PDA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowStateV1 {
    pub status: EscrowStatus,
    pub asset_kind: AssetKind,
    pub state_bump: u8,
    pub vault_bump: u8,
    pub authority_bump: u8,
    pub token_decimals: u8,
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub setup_id: [u8; 32],
    pub funder: [u8; 32],
    pub recipient: [u8; 32],
    pub refund_recipient: [u8; 32],
    pub token_program: [u8; 32],
    pub mint: [u8; 32],
    pub vault: [u8; 32],
    pub dom_adaptor_point: [u8; 33],
    pub claim_point_ed25519: [u8; 32],
    pub amount: u64,
    pub funded_amount: u64,
    pub refund_after_unix: i64,
    pub terminal_slot: u64,
    pub revealed_secret_be: [u8; 32],
}

impl EscrowStateV1 {
    /// Encode into the exact fixed-size account representation.
    pub fn encode(&self) -> [u8; STATE_LEN] {
        let mut out = [0u8; STATE_LEN];
        let mut offset = 0usize;
        put(&mut out, &mut offset, STATE_MAGIC);
        put(&mut out, &mut offset, &WIRE_VERSION.to_be_bytes());
        put(&mut out, &mut offset, &[self.status as u8]);
        put(&mut out, &mut offset, &[self.asset_kind as u8]);
        put(&mut out, &mut offset, &[self.state_bump]);
        put(&mut out, &mut offset, &[self.vault_bump]);
        put(&mut out, &mut offset, &[self.authority_bump]);
        put(&mut out, &mut offset, &[self.token_decimals]);
        put(&mut out, &mut offset, &self.settlement_id);
        put(&mut out, &mut offset, &self.terms_hash);
        put(&mut out, &mut offset, &self.setup_id);
        put(&mut out, &mut offset, &self.funder);
        put(&mut out, &mut offset, &self.recipient);
        put(&mut out, &mut offset, &self.refund_recipient);
        put(&mut out, &mut offset, &self.token_program);
        put(&mut out, &mut offset, &self.mint);
        put(&mut out, &mut offset, &self.vault);
        put(&mut out, &mut offset, &self.dom_adaptor_point);
        put(&mut out, &mut offset, &self.claim_point_ed25519);
        put(&mut out, &mut offset, &self.amount.to_be_bytes());
        put(&mut out, &mut offset, &self.funded_amount.to_be_bytes());
        put(&mut out, &mut offset, &self.refund_after_unix.to_be_bytes());
        put(&mut out, &mut offset, &self.terminal_slot.to_be_bytes());
        put(&mut out, &mut offset, &self.revealed_secret_be);
        debug_assert_eq!(offset, 433);
        out
    }

    /// Strictly decode the fixed-size representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != STATE_LEN {
            return Err(WireError::InvalidLength);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take_array::<8>()? != *STATE_MAGIC {
            return Err(WireError::InvalidMagic);
        }
        if cursor.take_u16()? != WIRE_VERSION {
            return Err(WireError::InvalidVersion);
        }
        let value = Self {
            status: EscrowStatus::from_tag(cursor.take_u8()?)?,
            asset_kind: AssetKind::from_tag(cursor.take_u8()?)?,
            state_bump: cursor.take_u8()?,
            vault_bump: cursor.take_u8()?,
            authority_bump: cursor.take_u8()?,
            token_decimals: cursor.take_u8()?,
            settlement_id: cursor.take_array()?,
            terms_hash: cursor.take_array()?,
            setup_id: cursor.take_array()?,
            funder: cursor.take_array()?,
            recipient: cursor.take_array()?,
            refund_recipient: cursor.take_array()?,
            token_program: cursor.take_array()?,
            mint: cursor.take_array()?,
            vault: cursor.take_array()?,
            dom_adaptor_point: cursor.take_array()?,
            claim_point_ed25519: cursor.take_array()?,
            amount: cursor.take_u64()?,
            funded_amount: cursor.take_u64()?,
            refund_after_unix: cursor.take_i64()?,
            terminal_slot: cursor.take_u64()?,
            revealed_secret_be: cursor.take_array()?,
        };
        if bytes[433..].iter().any(|byte| *byte != 0) {
            return Err(WireError::NonCanonical);
        }
        value.validate()?;
        Ok(value)
    }

    /// Validate invariants independent of account ownership/PDA checks.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.settlement_id == [0; 32]
            || self.terms_hash == [0; 32]
            || self.setup_id == [0; 32]
            || self.funder == [0; 32]
            || self.recipient == [0; 32]
            || self.refund_recipient == [0; 32]
            || self.vault == [0; 32]
            || self.claim_point_ed25519 == [0; 32]
            || self.amount == 0
            || !matches!(self.dom_adaptor_point[0], 0x02 | 0x03)
        {
            return Err(WireError::InvalidField);
        }
        match self.asset_kind {
            AssetKind::NativeSol => {
                if self.token_program != [0; 32] || self.mint != [0; 32] || self.token_decimals != 0
                {
                    return Err(WireError::InvalidField);
                }
            }
            AssetKind::LegacySpl => {
                if self.token_program == [0; 32] || self.mint == [0; 32] {
                    return Err(WireError::InvalidField);
                }
            }
        }
        match self.status {
            EscrowStatus::Initialized if self.funded_amount != 0 => {
                return Err(WireError::InvalidField)
            }
            EscrowStatus::Funded if self.funded_amount != self.amount => {
                return Err(WireError::InvalidField)
            }
            EscrowStatus::Claimed
                if self.funded_amount != 0
                    || self.terminal_slot == 0
                    || self.revealed_secret_be == [0; 32] =>
            {
                return Err(WireError::InvalidField)
            }
            EscrowStatus::Refunded
                if self.funded_amount != 0
                    || self.terminal_slot == 0
                    || self.revealed_secret_be != [0; 32] =>
            {
                return Err(WireError::InvalidField)
            }
            _ => {}
        }
        Ok(())
    }
}

/// Parameters shared by native and SPL initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitializeParamsV1 {
    pub settlement_id: [u8; 32],
    pub terms_hash: [u8; 32],
    pub setup_id: [u8; 32],
    pub recipient: [u8; 32],
    pub refund_recipient: [u8; 32],
    pub dom_adaptor_point: [u8; 33],
    pub claim_point_ed25519: [u8; 32],
    pub amount: u64,
    pub refund_after_unix: i64,
}

impl InitializeParamsV1 {
    fn validate(&self) -> Result<(), WireError> {
        if self.settlement_id == [0; 32]
            || self.terms_hash == [0; 32]
            || self.setup_id == [0; 32]
            || self.recipient == [0; 32]
            || self.refund_recipient == [0; 32]
            || self.claim_point_ed25519 == [0; 32]
            || self.amount == 0
            || self.refund_after_unix <= 0
            || !matches!(self.dom_adaptor_point[0], 0x02 | 0x03)
        {
            return Err(WireError::InvalidField);
        }
        Ok(())
    }
}

/// Program instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowInstructionV1 {
    InitializeNative(InitializeParamsV1),
    InitializeSpl(InitializeParamsV1),
    Fund,
    Claim { revealed_secret_be: [u8; 32] },
    Refund,
    Close,
}

impl EscrowInstructionV1 {
    /// Encode into the program's canonical instruction data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(252);
        out.extend_from_slice(INSTRUCTION_MAGIC);
        out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
        match self {
            Self::InitializeNative(params) => {
                out.push(1);
                put_initialize(&mut out, params);
            }
            Self::InitializeSpl(params) => {
                out.push(2);
                put_initialize(&mut out, params);
            }
            Self::Fund => out.push(3),
            Self::Claim { revealed_secret_be } => {
                out.push(4);
                out.extend_from_slice(revealed_secret_be);
            }
            Self::Refund => out.push(5),
            Self::Close => out.push(6),
        }
        out
    }

    /// Decode with version, bounds, field and trailing-byte checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 11 || bytes.len() > 252 {
            return Err(WireError::InvalidLength);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take_array::<8>()? != *INSTRUCTION_MAGIC {
            return Err(WireError::InvalidMagic);
        }
        if cursor.take_u16()? != WIRE_VERSION {
            return Err(WireError::InvalidVersion);
        }
        let instruction = match cursor.take_u8()? {
            1 => Self::InitializeNative(take_initialize(&mut cursor)?),
            2 => Self::InitializeSpl(take_initialize(&mut cursor)?),
            3 => Self::Fund,
            4 => Self::Claim {
                revealed_secret_be: cursor.take_array()?,
            },
            5 => Self::Refund,
            6 => Self::Close,
            _ => return Err(WireError::UnknownTag),
        };
        if !cursor.finished() {
            return Err(WireError::TrailingBytes);
        }
        match instruction {
            Self::InitializeNative(params) | Self::InitializeSpl(params) => params.validate()?,
            Self::Claim { revealed_secret_be } if revealed_secret_be == [0; 32] => {
                return Err(WireError::InvalidField)
            }
            _ => {}
        }
        Ok(instruction)
    }
}

/// Wire-format error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidLength,
    InvalidMagic,
    InvalidVersion,
    UnknownTag,
    TrailingBytes,
    InvalidField,
    NonCanonical,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "escrow wire: wrong byte length",
            Self::InvalidMagic => "escrow wire: wrong magic",
            Self::InvalidVersion => "escrow wire: unknown version",
            Self::UnknownTag => "escrow wire: unknown tag",
            Self::TrailingBytes => "escrow wire: trailing bytes",
            Self::InvalidField => "escrow wire: invalid field",
            Self::NonCanonical => "escrow wire: non-canonical encoding",
        })
    }
}

// No `Error` impl on purpose. `core::error::Error` requires Rust 1.81 and this
// crate is pinned to the workspace MSRV because the on-chain program links it;
// `Display` gives callers the message without moving that floor.

fn put_initialize(out: &mut Vec<u8>, params: &InitializeParamsV1) {
    out.extend_from_slice(&params.settlement_id);
    out.extend_from_slice(&params.terms_hash);
    out.extend_from_slice(&params.setup_id);
    out.extend_from_slice(&params.recipient);
    out.extend_from_slice(&params.refund_recipient);
    out.extend_from_slice(&params.dom_adaptor_point);
    out.extend_from_slice(&params.claim_point_ed25519);
    out.extend_from_slice(&params.amount.to_be_bytes());
    out.extend_from_slice(&params.refund_after_unix.to_be_bytes());
}

fn take_initialize(cursor: &mut Cursor<'_>) -> Result<InitializeParamsV1, WireError> {
    let value = InitializeParamsV1 {
        settlement_id: cursor.take_array()?,
        terms_hash: cursor.take_array()?,
        setup_id: cursor.take_array()?,
        recipient: cursor.take_array()?,
        refund_recipient: cursor.take_array()?,
        dom_adaptor_point: cursor.take_array()?,
        claim_point_ed25519: cursor.take_array()?,
        amount: cursor.take_u64()?,
        refund_after_unix: cursor.take_i64()?,
    };
    value.validate()?;
    Ok(value)
}

fn put<const N: usize>(out: &mut [u8; STATE_LEN], offset: &mut usize, bytes: &[u8; N]) {
    let end = *offset + N;
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.offset.checked_add(N).ok_or(WireError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(WireError::InvalidLength);
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_be_bytes(self.take_array()?))
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> InitializeParamsV1 {
        InitializeParamsV1 {
            settlement_id: [1; 32],
            terms_hash: [2; 32],
            setup_id: [3; 32],
            recipient: [4; 32],
            refund_recipient: [5; 32],
            dom_adaptor_point: {
                let mut point = [6; 33];
                point[0] = 2;
                point
            },
            claim_point_ed25519: [7; 32],
            amount: 1_000_000,
            refund_after_unix: 1_900_000_000,
        }
    }

    #[test]
    fn instruction_roundtrip() {
        for value in [
            EscrowInstructionV1::InitializeNative(params()),
            EscrowInstructionV1::InitializeSpl(params()),
            EscrowInstructionV1::Fund,
            EscrowInstructionV1::Claim {
                revealed_secret_be: [8; 32],
            },
            EscrowInstructionV1::Refund,
            EscrowInstructionV1::Close,
        ] {
            let encoded = value.encode();
            assert_eq!(EscrowInstructionV1::decode(&encoded), Ok(value));
        }
    }

    #[test]
    fn state_roundtrip() {
        let value = EscrowStateV1 {
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
                let mut point = [8; 33];
                point[0] = 3;
                point
            },
            claim_point_ed25519: [9; 32],
            amount: 10,
            funded_amount: 10,
            refund_after_unix: 1_900_000_000,
            terminal_slot: 0,
            revealed_secret_be: [0; 32],
        };
        assert_eq!(EscrowStateV1::decode(&value.encode()), Ok(value));
    }
}
