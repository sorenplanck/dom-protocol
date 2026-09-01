//! Route-scoped local EIP-1559 signing authority.
//!
//! The signer accepts only the typed request produced by `evm-actuator` and
//! rechecks every public route, deployment, account and role binding before
//! touching the key. It deliberately exposes no generic `sign(bytes)` API.

use blake2::{digest::Update, digest::VariableOutput, Blake2bVar};
use evm_actuator::{
    Eip1559SignatureV1, Eip1559SigningRequestV1, EvmAddressV1, EvmOperationKindV1, EvmSignerRoleV1,
    ScopedEip1559SignerV1, SignerRefusalV1,
};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

type Digest32 = [u8; 32];

const ZERO_DIGEST: Digest32 = [0; 32];
const ZERO_ADDRESS: EvmAddressV1 = [0; 20];

/// Immutable public policy for one local EVM signing account and route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionEvmSignerBindingV1 {
    route_id: Digest32,
    registry_digest: Digest32,
    profile_digest: Digest32,
    asset_binding_digest: Digest32,
    deployment_digest: Digest32,
    terms_digest: Digest32,
    chain_id: u64,
    contract: EvmAddressV1,
    account: EvmAddressV1,
    role: EvmSignerRoleV1,
}

/// Grouped constructor input, kept separate to make accidental cross-route
/// assembly visible at the composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionEvmSignerPinsV1 {
    pub(crate) route_id: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) asset_binding_digest: Digest32,
    pub(crate) deployment_digest: Digest32,
    pub(crate) terms_digest: Digest32,
    pub(crate) chain_id: u64,
    pub(crate) contract: EvmAddressV1,
    pub(crate) account: EvmAddressV1,
    pub(crate) role: EvmSignerRoleV1,
}

impl ProductionEvmSignerBindingV1 {
    pub(crate) fn new(
        pins: ProductionEvmSignerPinsV1,
    ) -> Result<Self, ProductionEvmSignerOpenErrorV1> {
        if [
            pins.route_id,
            pins.registry_digest,
            pins.profile_digest,
            pins.asset_binding_digest,
            pins.deployment_digest,
            pins.terms_digest,
        ]
        .contains(&ZERO_DIGEST)
            || pins.chain_id == 0
            || pins.contract == ZERO_ADDRESS
            || pins.account == ZERO_ADDRESS
        {
            return Err(ProductionEvmSignerOpenErrorV1::InvalidBinding);
        }
        Ok(Self {
            route_id: pins.route_id,
            registry_digest: pins.registry_digest,
            profile_digest: pins.profile_digest,
            asset_binding_digest: pins.asset_binding_digest,
            deployment_digest: pins.deployment_digest,
            terms_digest: pins.terms_digest,
            chain_id: pins.chain_id,
            contract: pins.contract,
            account: pins.account,
            role: pins.role,
        })
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn route_id(self) -> Digest32 {
        self.route_id
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn account(self) -> EvmAddressV1 {
        self.account
    }

    pub(crate) const fn role(self) -> EvmSignerRoleV1 {
        self.role
    }
}

/// Redacted constructor failure. Secret material is never included.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionEvmSignerOpenErrorV1 {
    #[error("production EVM signer binding is invalid")]
    InvalidBinding,
    #[error("production EVM signing key is invalid or belongs to another account")]
    InvalidCredential,
}

/// Imported local credential before it is assigned to one authenticated
/// route role.
///
/// The only observable property is the public EVM account derived from the
/// key.  Keeping import and route binding separate lets the composition root
/// prove that the credential matches exactly one admitted role without ever
/// copying or exposing the scalar.
pub(crate) struct ProductionEvmLocalCredentialV1 {
    account: EvmAddressV1,
    key: SigningKey,
}

impl core::fmt::Debug for ProductionEvmLocalCredentialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionEvmLocalCredentialV1([credential redacted])")
    }
}

impl ProductionEvmLocalCredentialV1 {
    pub(crate) fn import(
        secret: Zeroizing<Digest32>,
    ) -> Result<Self, ProductionEvmSignerOpenErrorV1> {
        let key = SigningKey::from_slice(secret.as_ref())
            .map_err(|_| ProductionEvmSignerOpenErrorV1::InvalidCredential)?;
        Ok(Self {
            account: evm_address(&key),
            key,
        })
    }

    pub(crate) const fn account(&self) -> EvmAddressV1 {
        self.account
    }

    pub(crate) fn bind(
        self,
        binding: ProductionEvmSignerBindingV1,
    ) -> Result<ProductionScopedEip1559SignerV1, ProductionEvmSignerOpenErrorV1> {
        if self.account != binding.account {
            return Err(ProductionEvmSignerOpenErrorV1::InvalidCredential);
        }
        Ok(ProductionScopedEip1559SignerV1 {
            binding,
            key: self.key,
        })
    }
}

/// Sole local owner of one EVM signing key.
///
/// This authority is intentionally stateless. The durable one-shot owner is
/// `DurableEvmActuatorV1`: it persists the immutable prepared operation before
/// this method can be called, derives the attempt id from that operation and
/// the exact signing hash, and persists the verified low-s signature before
/// any broadcast. `Eip1559SigningRequestV1` has no public constructor or public
/// fields, so no other crate can manufacture a competing request. If the
/// process dies between deterministic signing and the actuator commit, restart
/// derives and signs the same request again; no signature has left custody.
/// Adding a second journal here would create two authorities for the same
/// one-shot decision and introduce an unrecoverable cross-store commit gap.
pub(crate) struct ProductionScopedEip1559SignerV1 {
    binding: ProductionEvmSignerBindingV1,
    key: SigningKey,
}

impl core::fmt::Debug for ProductionScopedEip1559SignerV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionScopedEip1559SignerV1([credential redacted])")
    }
}

impl ProductionScopedEip1559SignerV1 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn new(
        binding: ProductionEvmSignerBindingV1,
        secret: Zeroizing<Digest32>,
    ) -> Result<Self, ProductionEvmSignerOpenErrorV1> {
        ProductionEvmLocalCredentialV1::import(secret)?.bind(binding)
    }

    pub(crate) const fn binding(&self) -> ProductionEvmSignerBindingV1 {
        self.binding
    }

    fn validate_request(&self, request: &Eip1559SigningRequestV1) -> Result<(), SignerRefusalV1> {
        let role_matches_operation = matches!(
            (request.signer_role(), request.operation_kind()),
            (
                EvmSignerRoleV1::Funder,
                EvmOperationKindV1::Open | EvmOperationKindV1::Refund
            ) | (EvmSignerRoleV1::Beneficiary, EvmOperationKindV1::Claim)
        );
        let role_account = match request.signer_role() {
            EvmSignerRoleV1::Funder => request.funder(),
            EvmSignerRoleV1::Beneficiary => request.beneficiary(),
        };
        if !role_matches_operation
            || request.route_id() != self.binding.route_id
            || request.registry_digest() != self.binding.registry_digest
            || request.profile_digest() != self.binding.profile_digest
            || request.asset_binding_digest() != self.binding.asset_binding_digest
            || request.deployment_digest() != self.binding.deployment_digest
            || request.terms_digest() != self.binding.terms_digest
            || request.chain_id() != self.binding.chain_id
            || request.to() != self.binding.contract
            || request.account() != self.binding.account
            || role_account != self.binding.account
            || request.signer_role() != self.binding.role
            || request.operation_id() == ZERO_DIGEST
            || request.effect_id() == ZERO_DIGEST
            || request.semantic_digest() == ZERO_DIGEST
            || request.lock_id() == ZERO_DIGEST
            || request.binding() == ZERO_DIGEST
            || request.calldata_digest() == ZERO_DIGEST
            || request.signing_hash() == ZERO_DIGEST
            || request.one_shot_attempt_id() == ZERO_DIGEST
            || request.gas_limit() == 0
            || request.attempt() == 0
        {
            return Err(SignerRefusalV1::Refused);
        }
        if derive_attempt_id(request)? != request.one_shot_attempt_id() {
            return Err(SignerRefusalV1::Refused);
        }
        Ok(())
    }
}

impl ScopedEip1559SignerV1 for ProductionScopedEip1559SignerV1 {
    fn sign_eip1559(
        &mut self,
        request: Eip1559SigningRequestV1,
    ) -> Result<Eip1559SignatureV1, SignerRefusalV1> {
        self.validate_request(&request)?;
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&request.signing_hash())
            .map_err(|_| SignerRefusalV1::Refused)?;
        let bytes = signature.to_bytes();
        let mut r = ZERO_DIGEST;
        let mut s = ZERO_DIGEST;
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(Eip1559SignatureV1 {
            y_parity: recovery.to_byte(),
            r,
            s,
        })
    }
}

fn evm_address(key: &SigningKey) -> EvmAddressV1 {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = adapter_evm::keccak256(&point.as_bytes()[1..]);
    let mut address = ZERO_ADDRESS;
    address.copy_from_slice(&digest[12..]);
    address
}

fn derive_attempt_id(request: &Eip1559SigningRequestV1) -> Result<Digest32, SignerRefusalV1> {
    const ACTUATOR_ATTEMPT_DOMAIN_V1: &[u8] = b"DOM-INTEROP/EVM-ACTUATOR/SIGNING-ATTEMPT/V1\0";
    let mut hasher = Blake2bVar::new(32).map_err(|_| SignerRefusalV1::Unavailable)?;
    hasher.update(ACTUATOR_ATTEMPT_DOMAIN_V1);
    hasher.update(&request.operation_id());
    hasher.update(&request.route_id());
    hasher.update(&request.effect_id());
    hasher.update(&request.fencing_epoch().to_be_bytes());
    hasher.update(&request.attempt().to_be_bytes());
    hasher.update(&request.signing_hash());
    let mut digest = ZERO_DIGEST;
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| SignerRefusalV1::Unavailable)?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Digest32 {
        [value; 32]
    }

    fn address(value: u8) -> EvmAddressV1 {
        [value; 20]
    }

    #[test]
    fn binding_refuses_zero_public_scope() {
        let mut pins = ProductionEvmSignerPinsV1 {
            route_id: digest(1),
            registry_digest: digest(2),
            profile_digest: digest(3),
            asset_binding_digest: digest(4),
            deployment_digest: digest(5),
            terms_digest: digest(6),
            chain_id: 1,
            contract: address(7),
            account: address(8),
            role: EvmSignerRoleV1::Funder,
        };
        pins.deployment_digest = ZERO_DIGEST;
        assert_eq!(
            ProductionEvmSignerBindingV1::new(pins),
            Err(ProductionEvmSignerOpenErrorV1::InvalidBinding)
        );
    }

    #[test]
    fn credential_must_derive_the_pinned_account_and_debug_is_redacted() {
        let secret = Zeroizing::new(digest(9));
        let credential = ProductionEvmLocalCredentialV1::import(secret).unwrap();
        let account = credential.account();
        assert_eq!(
            format!("{credential:?}"),
            "ProductionEvmLocalCredentialV1([credential redacted])"
        );
        let binding = ProductionEvmSignerBindingV1::new(ProductionEvmSignerPinsV1 {
            route_id: digest(1),
            registry_digest: digest(2),
            profile_digest: digest(3),
            asset_binding_digest: digest(4),
            deployment_digest: digest(5),
            terms_digest: digest(6),
            chain_id: 1,
            contract: address(7),
            account,
            role: EvmSignerRoleV1::Funder,
        })
        .unwrap();
        let signer = credential.bind(binding).unwrap();
        assert_eq!(
            format!("{signer:?}"),
            "ProductionScopedEip1559SignerV1([credential redacted])"
        );
        assert_eq!(
            ProductionScopedEip1559SignerV1::new(binding, Zeroizing::new(digest(10))).unwrap_err(),
            ProductionEvmSignerOpenErrorV1::InvalidCredential
        );
    }
}
