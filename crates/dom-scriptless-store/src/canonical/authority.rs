//! Structural codecs for store identities and vault-generation records.

use super::{
    exact, is_zero, read_u16, read_u64, storage_hash, CanonicalCodecError, StorageHashDomainV1,
};

const ROOT_MAGIC: &[u8; 8] = b"DOMNVRI1";
const LOCK_MAGIC: &[u8; 8] = b"DOMNVLK1";
const GENERATION_CORE_MAGIC: &[u8; 8] = b"DOMNVGC1";
const ACTIVE_GENERATION_MAGIC: &[u8; 8] = b"DOMNVAG1";

/// Exact encoded size shared by root and lock identity records.
pub const STORE_IDENTITY_LEN: usize = 122;
/// Exact encoded size of `VaultGenerationCoreV1`.
pub const VAULT_GENERATION_CORE_LEN: usize = 186;
/// Exact encoded size of `ActiveVaultGenerationV1`.
pub const ACTIVE_VAULT_GENERATION_LEN: usize = 226;

/// Authenticated immutable store-root identity.
#[derive(Clone, Eq, PartialEq)]
pub struct StoreRootIdentityV1 {
    bytes: [u8; STORE_IDENTITY_LEN],
    digest: [u8; 32],
}

impl StoreRootIdentityV1 {
    /// Constructs the exact root-identity bytes from independent nonzero IDs.
    pub fn new(
        contract_wallet_id: [u8; 32],
        store_root_id: [u8; 32],
        lock_instance_id: [u8; 16],
    ) -> Result<Self, CanonicalCodecError> {
        Self::construct(
            ROOT_MAGIC,
            StorageHashDomainV1::StoreRootIdentity,
            contract_wallet_id,
            store_root_id,
            lock_instance_id,
        )
    }

    fn construct(
        magic: &[u8; 8],
        domain: StorageHashDomainV1,
        contract_wallet_id: [u8; 32],
        store_root_id: [u8; 32],
        lock_instance_id: [u8; 16],
    ) -> Result<Self, CanonicalCodecError> {
        if is_zero(&contract_wallet_id) || is_zero(&store_root_id) || is_zero(&lock_instance_id) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let mut bytes = [0_u8; STORE_IDENTITY_LEN];
        bytes[..8].copy_from_slice(magic);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&contract_wallet_id);
        bytes[42..74].copy_from_slice(&store_root_id);
        bytes[74..90].copy_from_slice(&lock_instance_id);
        let digest = storage_hash(domain, &bytes[..90]);
        bytes[90..122].copy_from_slice(&digest);
        Ok(Self { bytes, digest })
    }

    /// Parses exact root bytes and authenticates the digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedStoreRootIdentityV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::StoreRootIdentity, &input[..90]);
        if structural.identity_digest() != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    pub const fn as_bytes(&self) -> &[u8; STORE_IDENTITY_LEN] {
        &self.bytes
    }

    /// Returns the stable independent Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the retained store-root identifier.
    pub fn store_root_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the retained lock-instance identifier.
    pub fn lock_instance_id(&self) -> &[u8] {
        &self.bytes[74..90]
    }

    /// Returns the authenticated root-identity digest.
    pub const fn identity_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Authenticated immutable store-lock identity.
#[derive(Clone, Eq, PartialEq)]
pub struct StoreLockIdentityV1 {
    bytes: [u8; STORE_IDENTITY_LEN],
    digest: [u8; 32],
}

impl StoreLockIdentityV1 {
    /// Constructs a lock identity matching one exact root identity.
    pub fn from_root(root: &StoreRootIdentityV1) -> Result<Self, CanonicalCodecError> {
        let mut contract_wallet_id = [0_u8; 32];
        contract_wallet_id.copy_from_slice(root.contract_wallet_id());
        let mut store_root_id = [0_u8; 32];
        store_root_id.copy_from_slice(root.store_root_id());
        let mut lock_instance_id = [0_u8; 16];
        lock_instance_id.copy_from_slice(root.lock_instance_id());
        let constructed = StoreRootIdentityV1::construct(
            LOCK_MAGIC,
            StorageHashDomainV1::StoreLockIdentity,
            contract_wallet_id,
            store_root_id,
            lock_instance_id,
        )?;
        Ok(Self {
            bytes: constructed.bytes,
            digest: constructed.digest,
        })
    }

    /// Parses and authenticates a lock identity against the retained root.
    pub fn from_bytes_with_root(
        input: &[u8],
        root: &StoreRootIdentityV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedStoreLockIdentityV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::StoreLockIdentity, &input[..90]);
        if structural.identity_digest() != digest
            || structural.contract_wallet_id() != root.contract_wallet_id()
            || structural.store_root_id() != root.store_root_id()
            || structural.lock_instance_id() != root.lock_instance_id()
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated lock bytes.
    pub const fn as_bytes(&self) -> &[u8; STORE_IDENTITY_LEN] {
        &self.bytes
    }

    /// Returns the authenticated lock-identity digest.
    pub const fn identity_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Authenticated immutable vault-generation core.
#[derive(Clone, Eq, PartialEq)]
pub struct VaultGenerationCoreV1 {
    bytes: [u8; VAULT_GENERATION_CORE_LEN],
    digest: [u8; 32],
}

impl VaultGenerationCoreV1 {
    /// Constructs an exact generation core from authorized public inputs.
    pub fn new(
        contract_wallet_id: [u8; 32],
        store_root_id: [u8; 32],
        vault_id: [u8; 32],
        nonce_epoch: u64,
        vault_generation: u64,
        master_envelope_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        if is_zero(&contract_wallet_id)
            || is_zero(&store_root_id)
            || is_zero(&vault_id)
            || contract_wallet_id == vault_id
            || nonce_epoch == 0
            || vault_generation == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let mut bytes = [0_u8; VAULT_GENERATION_CORE_LEN];
        bytes[..8].copy_from_slice(GENERATION_CORE_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].copy_from_slice(&contract_wallet_id);
        bytes[42..74].copy_from_slice(&store_root_id);
        bytes[74..106].copy_from_slice(&vault_id);
        bytes[106..114].copy_from_slice(&nonce_epoch.to_le_bytes());
        bytes[114..122].copy_from_slice(&vault_generation.to_le_bytes());
        bytes[122..154].copy_from_slice(&master_envelope_digest);
        let digest = storage_hash(StorageHashDomainV1::VaultGenerationCore, &bytes[..154]);
        bytes[154..186].copy_from_slice(&digest);
        Ok(Self { bytes, digest })
    }

    /// Parses exact core bytes and authenticates its digest.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedVaultGenerationCoreV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::VaultGenerationCore, &input[..154]);
        if structural.generation_core_digest() != digest {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    pub const fn as_bytes(&self) -> &[u8; VAULT_GENERATION_CORE_LEN] {
        &self.bytes
    }

    /// Returns the active nonce epoch.
    pub fn nonce_epoch(&self) -> u64 {
        read_u64(&self.bytes[106..114])
    }

    /// Returns the active generation counter.
    pub fn vault_generation(&self) -> u64 {
        read_u64(&self.bytes[114..122])
    }

    /// Returns the vault identifier.
    pub fn vault_id(&self) -> &[u8] {
        &self.bytes[74..106]
    }

    /// Returns the complete master-envelope digest.
    pub fn master_envelope_digest(&self) -> &[u8] {
        &self.bytes[122..154]
    }

    /// Returns the generation-core digest.
    pub const fn generation_core_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Authenticated active-generation projection.
#[derive(Clone, Eq, PartialEq)]
pub struct ActiveVaultGenerationV1 {
    bytes: [u8; ACTIVE_VAULT_GENERATION_LEN],
    digest: [u8; 32],
}

impl ActiveVaultGenerationV1 {
    /// Constructs an active projection after the exact journal head is known.
    pub fn new(
        core: &VaultGenerationCoreV1,
        journal_sequence: u64,
        journal_head_digest: [u8; 32],
    ) -> Result<Self, CanonicalCodecError> {
        let mut bytes = [0_u8; ACTIVE_VAULT_GENERATION_LEN];
        bytes[..8].copy_from_slice(ACTIVE_GENERATION_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..154].copy_from_slice(&core.as_bytes()[10..154]);
        bytes[154..162].copy_from_slice(&journal_sequence.to_le_bytes());
        bytes[162..194].copy_from_slice(&journal_head_digest);
        let digest = storage_hash(StorageHashDomainV1::ActiveVaultGeneration, &bytes[..194]);
        bytes[194..226].copy_from_slice(&digest);
        Ok(Self { bytes, digest })
    }

    /// Authenticates an active record and its generation-core relation.
    pub fn from_bytes_with_core(
        input: &[u8],
        core: &VaultGenerationCoreV1,
    ) -> Result<Self, CanonicalCodecError> {
        let structural = UnauthenticatedActiveVaultGenerationV1::parse_structural(input)?;
        let digest = storage_hash(StorageHashDomainV1::ActiveVaultGeneration, &input[..194]);
        if structural.active_generation_digest() != digest
            || input[10..154] != core.as_bytes()[10..154]
        {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }
        Ok(Self {
            bytes: *structural.as_bytes(),
            digest,
        })
    }

    /// Returns the exact authenticated bytes.
    pub const fn as_bytes(&self) -> &[u8; ACTIVE_VAULT_GENERATION_LEN] {
        &self.bytes
    }

    /// Returns the active journal sequence.
    pub fn journal_sequence(&self) -> u64 {
        read_u64(&self.bytes[154..162])
    }

    /// Returns the active journal head digest.
    pub fn journal_head_digest(&self) -> &[u8] {
        &self.bytes[162..194]
    }

    /// Returns the active-generation digest.
    pub const fn active_generation_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Structurally parsed immutable store-root identity.
pub struct UnauthenticatedStoreRootIdentityV1 {
    bytes: [u8; STORE_IDENTITY_LEN],
}

impl UnauthenticatedStoreRootIdentityV1 {
    /// Parses exact fields without authenticating the root-identity digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = parse_store_identity(input, ROOT_MAGIC)?;
        Ok(Self { bytes })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; STORE_IDENTITY_LEN] {
        &self.bytes
    }

    /// Returns the nonzero Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the nonzero store-root identifier.
    pub fn store_root_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the nonzero lock-instance identifier.
    pub fn lock_instance_id(&self) -> &[u8] {
        &self.bytes[74..90]
    }

    /// Returns the unauthenticated root-identity digest.
    pub fn identity_digest(&self) -> &[u8] {
        &self.bytes[90..122]
    }
}

/// Structurally parsed immutable store-lock identity.
pub struct UnauthenticatedStoreLockIdentityV1 {
    bytes: [u8; STORE_IDENTITY_LEN],
}

impl UnauthenticatedStoreLockIdentityV1 {
    /// Parses exact fields without authenticating the lock-identity digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = parse_store_identity(input, LOCK_MAGIC)?;
        Ok(Self { bytes })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; STORE_IDENTITY_LEN] {
        &self.bytes
    }

    /// Returns the nonzero Contracts wallet identifier.
    pub fn contract_wallet_id(&self) -> &[u8] {
        &self.bytes[10..42]
    }

    /// Returns the nonzero store-root identifier.
    pub fn store_root_id(&self) -> &[u8] {
        &self.bytes[42..74]
    }

    /// Returns the nonzero lock-instance identifier.
    pub fn lock_instance_id(&self) -> &[u8] {
        &self.bytes[74..90]
    }

    /// Returns the unauthenticated lock-identity digest.
    pub fn identity_digest(&self) -> &[u8] {
        &self.bytes[90..122]
    }
}

/// Structurally parsed immutable successor-generation core.
pub struct UnauthenticatedVaultGenerationCoreV1 {
    bytes: [u8; VAULT_GENERATION_CORE_LEN],
    nonce_epoch: u64,
    vault_generation: u64,
}

impl UnauthenticatedVaultGenerationCoreV1 {
    /// Parses exact fields without authenticating either embedded digest.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<VAULT_GENERATION_CORE_LEN>(input)?;
        let nonce_epoch = read_u64(&bytes[106..114]);
        let vault_generation = read_u64(&bytes[114..122]);
        if &bytes[..8] != GENERATION_CORE_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..42])
            || is_zero(&bytes[42..74])
            || is_zero(&bytes[74..106])
            || bytes[10..42] == bytes[74..106]
            || nonce_epoch == 0
            || vault_generation == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            nonce_epoch,
            vault_generation,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; VAULT_GENERATION_CORE_LEN] {
        &self.bytes
    }

    /// Returns the nonzero successor nonce epoch.
    pub const fn nonce_epoch(&self) -> u64 {
        self.nonce_epoch
    }

    /// Returns the nonzero successor vault generation.
    pub const fn vault_generation(&self) -> u64 {
        self.vault_generation
    }

    /// Returns the nonzero successor vault identifier.
    pub fn vault_id(&self) -> &[u8] {
        &self.bytes[74..106]
    }

    /// Returns the unauthenticated successor master-envelope digest.
    pub fn master_envelope_digest(&self) -> &[u8] {
        &self.bytes[122..154]
    }

    /// Returns the unauthenticated generation-core digest.
    pub fn generation_core_digest(&self) -> &[u8] {
        &self.bytes[154..186]
    }
}

/// Structurally parsed active vault-generation record.
pub struct UnauthenticatedActiveVaultGenerationV1 {
    bytes: [u8; ACTIVE_VAULT_GENERATION_LEN],
    nonce_epoch: u64,
    vault_generation: u64,
    journal_sequence: u64,
}

impl UnauthenticatedActiveVaultGenerationV1 {
    /// Parses exact fields without authenticating the digest DAG.
    pub fn parse_structural(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        let bytes = exact::<ACTIVE_VAULT_GENERATION_LEN>(input)?;
        let nonce_epoch = read_u64(&bytes[106..114]);
        let vault_generation = read_u64(&bytes[114..122]);
        let journal_sequence = read_u64(&bytes[154..162]);
        if &bytes[..8] != ACTIVE_GENERATION_MAGIC
            || read_u16(&bytes[8..10]) != 1
            || is_zero(&bytes[10..42])
            || is_zero(&bytes[42..74])
            || is_zero(&bytes[74..106])
            || bytes[10..42] == bytes[74..106]
            || nonce_epoch == 0
            || vault_generation == 0
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            nonce_epoch,
            vault_generation,
            journal_sequence,
        })
    }

    /// Returns the exact unauthenticated canonical bytes.
    pub const fn as_bytes(&self) -> &[u8; ACTIVE_VAULT_GENERATION_LEN] {
        &self.bytes
    }

    /// Returns the nonzero active nonce epoch.
    pub const fn nonce_epoch(&self) -> u64 {
        self.nonce_epoch
    }

    /// Returns the nonzero active vault generation.
    pub const fn vault_generation(&self) -> u64 {
        self.vault_generation
    }

    /// Returns the active journal sequence.
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns the unauthenticated active journal-head digest.
    pub fn journal_head_digest(&self) -> &[u8] {
        &self.bytes[162..194]
    }

    /// Returns the unauthenticated active-generation digest.
    pub fn active_generation_digest(&self) -> &[u8] {
        &self.bytes[194..226]
    }
}

fn parse_store_identity(
    input: &[u8],
    magic: &[u8; 8],
) -> Result<[u8; STORE_IDENTITY_LEN], CanonicalCodecError> {
    let bytes = exact::<STORE_IDENTITY_LEN>(input)?;
    if &bytes[..8] != magic
        || read_u16(&bytes[8..10]) != 1
        || is_zero(&bytes[10..42])
        || is_zero(&bytes[42..74])
        || is_zero(&bytes[74..90])
    {
        return Err(CanonicalCodecError::InvalidEncoding);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_identity(magic: &[u8; 8]) -> [u8; STORE_IDENTITY_LEN] {
        let mut bytes = [0_u8; STORE_IDENTITY_LEN];
        bytes[..8].copy_from_slice(magic);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(0x11);
        bytes[42..74].fill(0x22);
        bytes[74..90].fill(0x33);
        bytes
    }

    fn generation(magic: &[u8; 8], length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; length];
        bytes[..8].copy_from_slice(magic);
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10..42].fill(0x11);
        bytes[42..74].fill(0x22);
        bytes[74..106].fill(0x33);
        bytes[106..114].copy_from_slice(&7_u64.to_le_bytes());
        bytes[114..122].copy_from_slice(&1_u64.to_le_bytes());
        bytes
    }

    #[test]
    fn root_and_lock_parse_exact_nonzero_identities() -> Result<(), CanonicalCodecError> {
        let root_bytes = store_identity(ROOT_MAGIC);
        let root = UnauthenticatedStoreRootIdentityV1::parse_structural(&root_bytes)?;
        assert_eq!(root.as_bytes(), &root_bytes);
        assert_eq!(root.contract_wallet_id(), &[0x11; 32]);
        assert_eq!(root.store_root_id(), &[0x22; 32]);
        assert_eq!(root.lock_instance_id(), &[0x33; 16]);

        let lock_bytes = store_identity(LOCK_MAGIC);
        let lock = UnauthenticatedStoreLockIdentityV1::parse_structural(&lock_bytes)?;
        assert_eq!(lock.as_bytes(), &lock_bytes);
        assert_eq!(lock.contract_wallet_id(), root.contract_wallet_id());
        assert_eq!(lock.store_root_id(), root.store_root_id());
        assert_eq!(lock.lock_instance_id(), root.lock_instance_id());
        Ok(())
    }

    #[test]
    fn store_identities_reject_zero_ids_and_wrong_framing() {
        let canonical = store_identity(ROOT_MAGIC);
        for range in [10..42, 42..74, 74..90] {
            let mut bytes = canonical;
            bytes[range].fill(0);
            assert!(UnauthenticatedStoreRootIdentityV1::parse_structural(&bytes).is_err());
        }
        let mut wrong_magic = canonical;
        wrong_magic[0] ^= 1;
        assert!(UnauthenticatedStoreRootIdentityV1::parse_structural(&wrong_magic).is_err());
        assert!(UnauthenticatedStoreRootIdentityV1::parse_structural(&canonical[..121]).is_err());
    }

    #[test]
    fn generation_core_enforces_nonzero_identity_and_counters() -> Result<(), CanonicalCodecError> {
        let bytes = generation(GENERATION_CORE_MAGIC, VAULT_GENERATION_CORE_LEN);
        let core = UnauthenticatedVaultGenerationCoreV1::parse_structural(&bytes)?;
        assert_eq!(core.nonce_epoch(), 7);
        assert_eq!(core.vault_generation(), 1);
        assert_eq!(core.master_envelope_digest(), &[0; 32]);
        assert_eq!(core.generation_core_digest(), &[0; 32]);

        for range in [10..42, 42..74, 74..106, 106..114, 114..122] {
            let mut invalid = bytes.clone();
            invalid[range].fill(0);
            assert!(UnauthenticatedVaultGenerationCoreV1::parse_structural(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn active_generation_retains_structural_zero_digest_outputs() -> Result<(), CanonicalCodecError>
    {
        let mut bytes = generation(ACTIVE_GENERATION_MAGIC, ACTIVE_VAULT_GENERATION_LEN);
        bytes[154..162].copy_from_slice(&5_u64.to_le_bytes());
        let active = UnauthenticatedActiveVaultGenerationV1::parse_structural(&bytes)?;
        assert_eq!(&active.as_bytes()[..], bytes.as_slice());
        assert_eq!(active.nonce_epoch(), 7);
        assert_eq!(active.vault_generation(), 1);
        assert_eq!(active.journal_sequence(), 5);
        assert_eq!(active.journal_head_digest(), &[0; 32]);
        assert_eq!(active.active_generation_digest(), &[0; 32]);
        Ok(())
    }

    #[test]
    fn generation_rejects_contract_wallet_vault_collision() {
        let mut core = generation(GENERATION_CORE_MAGIC, VAULT_GENERATION_CORE_LEN);
        core[74..106].fill(0x11);
        assert!(UnauthenticatedVaultGenerationCoreV1::parse_structural(&core).is_err());

        let mut active = generation(ACTIVE_GENERATION_MAGIC, ACTIVE_VAULT_GENERATION_LEN);
        active[74..106].fill(0x11);
        assert!(UnauthenticatedActiveVaultGenerationV1::parse_structural(&active).is_err());
    }

    #[test]
    fn authenticated_root_lock_core_and_active_roundtrip() -> Result<(), CanonicalCodecError> {
        let root = StoreRootIdentityV1::new([0x11; 32], [0x22; 32], [0x33; 16])?;
        let lock = StoreLockIdentityV1::from_root(&root)?;
        assert!(StoreRootIdentityV1::from_bytes(root.as_bytes())? == root);
        assert!(StoreLockIdentityV1::from_bytes_with_root(lock.as_bytes(), &root)? == lock);

        let core =
            VaultGenerationCoreV1::new([0x11; 32], [0x22; 32], [0x44; 32], 1, 1, [0x55; 32])?;
        assert!(VaultGenerationCoreV1::from_bytes(core.as_bytes())? == core);
        let active = ActiveVaultGenerationV1::new(&core, 7, [0x66; 32])?;
        assert!(ActiveVaultGenerationV1::from_bytes_with_core(active.as_bytes(), &core)? == active);
        assert_eq!(active.journal_sequence(), 7);
        Ok(())
    }

    #[test]
    fn authenticated_authority_records_reject_every_mutation() -> Result<(), CanonicalCodecError> {
        let root = StoreRootIdentityV1::new([0x11; 32], [0x22; 32], [0x33; 16])?;
        let lock = StoreLockIdentityV1::from_root(&root)?;
        for index in 0..STORE_IDENTITY_LEN {
            let mut mutated_root = *root.as_bytes();
            mutated_root[index] ^= 1;
            assert!(StoreRootIdentityV1::from_bytes(&mutated_root).is_err());

            let mut mutated_lock = *lock.as_bytes();
            mutated_lock[index] ^= 1;
            assert!(StoreLockIdentityV1::from_bytes_with_root(&mutated_lock, &root).is_err());
        }

        let core =
            VaultGenerationCoreV1::new([0x11; 32], [0x22; 32], [0x44; 32], 1, 1, [0x55; 32])?;
        for index in 0..VAULT_GENERATION_CORE_LEN {
            let mut mutated = *core.as_bytes();
            mutated[index] ^= 1;
            assert!(VaultGenerationCoreV1::from_bytes(&mutated).is_err());
        }
        let active = ActiveVaultGenerationV1::new(&core, 7, [0x66; 32])?;
        for index in 0..ACTIVE_VAULT_GENERATION_LEN {
            let mut mutated = *active.as_bytes();
            mutated[index] ^= 1;
            assert!(ActiveVaultGenerationV1::from_bytes_with_core(&mutated, &core).is_err());
        }
        Ok(())
    }

    #[test]
    fn authority_records_reject_every_truncation_and_trailing_byte() {
        let records = [
            store_identity(ROOT_MAGIC).to_vec(),
            store_identity(LOCK_MAGIC).to_vec(),
            generation(GENERATION_CORE_MAGIC, VAULT_GENERATION_CORE_LEN),
            generation(ACTIVE_GENERATION_MAGIC, ACTIVE_VAULT_GENERATION_LEN),
        ];
        for (record_index, bytes) in records.into_iter().enumerate() {
            for end in 0..bytes.len() {
                let rejected = match record_index {
                    0 => {
                        UnauthenticatedStoreRootIdentityV1::parse_structural(&bytes[..end]).is_err()
                    }
                    1 => {
                        UnauthenticatedStoreLockIdentityV1::parse_structural(&bytes[..end]).is_err()
                    }
                    2 => UnauthenticatedVaultGenerationCoreV1::parse_structural(&bytes[..end])
                        .is_err(),
                    3 => UnauthenticatedActiveVaultGenerationV1::parse_structural(&bytes[..end])
                        .is_err(),
                    _ => false,
                };
                assert!(rejected, "record {record_index}, prefix {end}");
            }
            let mut trailing = bytes;
            trailing.push(0);
            let rejected = match record_index {
                0 => UnauthenticatedStoreRootIdentityV1::parse_structural(&trailing).is_err(),
                1 => UnauthenticatedStoreLockIdentityV1::parse_structural(&trailing).is_err(),
                2 => UnauthenticatedVaultGenerationCoreV1::parse_structural(&trailing).is_err(),
                3 => UnauthenticatedActiveVaultGenerationV1::parse_structural(&trailing).is_err(),
                _ => false,
            };
            assert!(rejected, "record {record_index}, trailing");
        }
    }
}
