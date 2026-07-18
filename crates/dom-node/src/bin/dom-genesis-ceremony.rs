//! Offline, single-worker deterministic DOM genesis ceremony reproducer.
//!
//! This executable constructs only height-zero identities. It never opens a
//! chain database, listener, peer connection, wallet, or normal mining loop.

#![recursion_limit = "512"]

use anyhow::{anyhow, Context, Result};
use dom_chain::{build_canonical_genesis, GenesisInscriptionV1, MainnetGenesisIdentityV1};
use dom_consensus::{
    derive_chain_id, BlockHeader, CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
};
use dom_core::{
    configured_genesis_hash_for_network_magic, BlockHeight, Hash256, KERNEL_FEAT_COINBASE,
    NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, TAG_CHAIN_ID,
    TAG_GENESIS_BLINDING, TAG_GENESIS_INSCRIPTION, TAG_KERNEL_MSG_COINBASE,
    TAG_MAINNET_GENESIS_IDENTITY, TAG_PMMR_EMPTY,
};
use dom_crypto::hash::{blake2b_256, blake2b_256_tagged};
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::{fast_pow_hash, hash_meets_target, target_to_difficulty, CompactTarget};
use dom_serialization::{DomDeserialize, DomSerialize};
use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
use serde_json::json;
use std::time::Instant;

const GENESIS_POW_SEED: [u8; 32] = [0u8; 32];
const CEREMONY_UTC: &str = "2026-07-14T23:23:49Z";

fn json_string<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {key}"))
}

fn decode_hex(value: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    hex::decode(json_string(value, key)?).with_context(|| format!("decode {key}"))
}

fn manual_header_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&header.version.to_le_bytes());
    bytes.extend_from_slice(&header.height.0.to_le_bytes());
    bytes.extend_from_slice(header.prev_hash.as_bytes());
    bytes.extend_from_slice(&header.timestamp.0.to_le_bytes());
    bytes.extend_from_slice(header.output_root.as_bytes());
    bytes.extend_from_slice(header.kernel_root.as_bytes());
    bytes.extend_from_slice(header.rangeproof_root.as_bytes());
    bytes.extend_from_slice(&header.total_kernel_offset);
    bytes.extend_from_slice(&header.target.0.to_le_bytes());
    let mut difficulty = [0u8; 32];
    header.total_difficulty.to_big_endian(&mut difficulty);
    bytes.extend_from_slice(&difficulty);
    bytes.extend_from_slice(&header.pow.nonce.to_le_bytes());
    bytes.extend_from_slice(header.pow.randomx_hash.as_bytes());
    bytes
}

fn independent_chain_id(network_magic: u32, genesis_identifier: &[u8]) -> Result<Hash256> {
    let identifier: [u8; 32] = genesis_identifier
        .try_into()
        .map_err(|_| anyhow!("genesis identifier must be 32 bytes"))?;
    let mut preimage = Vec::with_capacity(36);
    preimage.extend_from_slice(&network_magic.to_be_bytes());
    preimage.extend_from_slice(&identifier);
    Ok(blake2b_256_tagged(TAG_CHAIN_ID, &preimage))
}

fn independent_legacy_coinbase(signing_context: &[u8; 32]) -> Result<CoinbaseTransaction> {
    let blinding_hash = blake2b_256_tagged(TAG_GENESIS_BLINDING, b"");
    let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())?;
    let nonce = *blake2b_256_tagged(TAG_GENESIS_BLINDING, b"bulletproof-nonce").as_bytes();
    let explicit_value = dom_core::block_reward(BlockHeight::GENESIS).noms();
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, proof_commitment) =
        dom_crypto::range_proof_prove_bytes_with_nonce(explicit_value, &blinding, &nonce)?;
    if proof_commitment != *commitment.as_bytes() {
        return Err(anyhow!("independent genesis proof commitment mismatch"));
    }
    let excess = Commitment::commit(0, &blinding);
    let mut message_data = Vec::with_capacity(9);
    message_data.push(KERNEL_FEAT_COINBASE);
    message_data.extend_from_slice(&explicit_value.to_le_bytes());
    let message = blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &message_data);
    let key = SecretKey::from_bytes(blinding.as_bytes())?;
    let signature = dom_crypto::schnorr_sign(&key, message.as_bytes(), signing_context)?;
    Ok(CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: signature.to_bytes(),
        },
        offset: [0u8; 32],
    })
}

fn verify_mainnet_vector(value: &serde_json::Value) -> Result<()> {
    let header_bytes = decode_hex(value, "rooted_header_hex")?;
    let header = BlockHeader::from_bytes(&header_bytes)?;
    if manual_header_bytes(&header) != header_bytes || header_bytes.len() != 256 {
        return Err(anyhow!("Mainnet manual rooted-header reproduction failed"));
    }
    let target = CompactTarget(header.target.0).to_target()?;
    if hex::encode(target) != json_string(value, "expanded_target_hex")?
        || target_to_difficulty(&target).to_string() != json_string(value, "derived_difficulty")?
    {
        return Err(anyhow!("Mainnet target or difficulty mismatch"));
    }
    let payload = b"Not a store of value. A means of exchange.";
    let mut inscription = Vec::with_capacity(45);
    inscription.push(1);
    inscription.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    inscription.extend_from_slice(payload);
    if hex::encode(payload) != json_string(value, "inscription_utf8_hex")?
        || hex::encode(&inscription) != json_string(value, "inscription_encoding_hex")?
    {
        return Err(anyhow!("Mainnet inscription bytes mismatch"));
    }
    let commitment = blake2b_256_tagged(TAG_GENESIS_INSCRIPTION, &inscription);
    if commitment.to_hex() != json_string(value, "inscription_commitment_hex")? {
        return Err(anyhow!("Mainnet inscription commitment mismatch"));
    }
    let empty_root = blake2b_256_tagged(TAG_PMMR_EMPTY, &[]);
    if header.output_root != empty_root
        || header.kernel_root != empty_root
        || header.rangeproof_root != empty_root
    {
        return Err(anyhow!("Mainnet empty PMMR roots mismatch"));
    }
    let body = [0u8; 16];
    let mut envelope = Vec::with_capacity(357);
    envelope.push(1);
    envelope.extend_from_slice(&(header_bytes.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&header_bytes);
    envelope.extend_from_slice(&(body.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&body);
    envelope.push(1);
    envelope.extend_from_slice(&(inscription.len() as u16).to_be_bytes());
    envelope.extend_from_slice(&inscription);
    envelope.extend_from_slice(commitment.as_bytes());
    if envelope != decode_hex(value, "identity_envelope_hex")? || envelope.len() != 357 {
        return Err(anyhow!("Mainnet identity-envelope reproduction failed"));
    }
    let pow_digest =
        dom_pow::randomx_pool::randomx_hash(&GENESIS_POW_SEED, &header.pow_preimage())?;
    if pow_digest != *header.pow.randomx_hash.as_bytes() || !hash_meets_target(&pow_digest, &target)
    {
        return Err(anyhow!("Mainnet independent PoW verification failed"));
    }
    let identifier = blake2b_256_tagged(TAG_MAINNET_GENESIS_IDENTITY, &envelope);
    if identifier.to_hex() != json_string(value, "genesis_identifier_hex")? {
        return Err(anyhow!("Mainnet genesis identifier mismatch"));
    }
    let chain_id = independent_chain_id(NETWORK_MAGIC_MAINNET, identifier.as_bytes())?;
    if chain_id.to_hex() != json_string(value, "chain_id_hex")? {
        return Err(anyhow!("Mainnet chain ID mismatch"));
    }
    Ok(())
}

fn verify_legacy_vector(value: &serde_json::Value, network_magic: u32) -> Result<()> {
    let header_bytes = decode_hex(value, "rooted_header_hex")?;
    let complete_bytes = decode_hex(value, "complete_genesis_hex")?;
    let block = dom_consensus::Block::from_bytes(&complete_bytes)?;
    let signing_context: [u8; 32] = decode_hex(value, "genesis_coinbase_signing_context_hex")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("signing context has {} bytes", bytes.len()))?;
    let independent_coinbase = independent_legacy_coinbase(&signing_context)?;
    if independent_coinbase.to_bytes()? != block.coinbase.to_bytes()? {
        return Err(anyhow!("legacy low-level coinbase reproduction failed"));
    }
    if manual_header_bytes(&block.header) != header_bytes || header_bytes.len() != 256 {
        return Err(anyhow!("legacy manual rooted-header reproduction failed"));
    }
    let mut reconstructed = header_bytes.clone();
    reconstructed.extend_from_slice(&block.coinbase.to_bytes()?);
    reconstructed.extend_from_slice(&(block.transactions.len() as u32).to_le_bytes());
    for transaction in &block.transactions {
        reconstructed.extend_from_slice(&transaction.to_bytes()?);
    }
    if reconstructed != complete_bytes {
        return Err(anyhow!("legacy complete-block reproduction failed"));
    }
    let body = complete_bytes
        .get(header_bytes.len()..)
        .ok_or_else(|| anyhow!("legacy body boundary is invalid"))?;
    if body != decode_hex(value, "economic_body_hex")? {
        return Err(anyhow!("legacy economic-body reproduction failed"));
    }
    let (output_root, kernel_root, rangeproof_root) = dom_consensus::compute_block_pmmr_roots(
        block.header.height,
        &block.coinbase,
        &block.transactions,
    )?;
    if output_root != block.header.output_root
        || kernel_root != block.header.kernel_root
        || rangeproof_root != block.header.rangeproof_root
    {
        return Err(anyhow!("legacy PMMR root reproduction failed"));
    }
    let target = CompactTarget(block.header.target.0).to_target()?;
    if hex::encode(target) != json_string(value, "expanded_target_hex")?
        || target_to_difficulty(&target).to_string() != json_string(value, "derived_difficulty")?
    {
        return Err(anyhow!("legacy target or difficulty mismatch"));
    }
    if network_magic == NETWORK_MAGIC_REGTEST {
        let digest = fast_pow_hash(&GENESIS_POW_SEED, &block.header.pow_preimage());
        if digest != *block.header.pow.randomx_hash.as_bytes()
            || !hash_meets_target(&digest, &target)
        {
            return Err(anyhow!("Regtest independent PoW verification failed"));
        }
    }
    let identifier = blake2b_256(&header_bytes);
    if identifier.to_hex() != json_string(value, "genesis_identifier_hex")? {
        return Err(anyhow!("legacy genesis identifier mismatch"));
    }
    let chain_id = independent_chain_id(network_magic, identifier.as_bytes())?;
    if chain_id.to_hex() != json_string(value, "chain_id_hex")? {
        return Err(anyhow!("legacy chain ID mismatch"));
    }
    Ok(())
}

fn verify_vectors() -> Result<()> {
    let mainnet: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        "test-vectors/genesis/mainnet-v1.json",
    )?)?;
    let regtest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        "test-vectors/genesis/regtest-v1.json",
    )?)?;
    let testnet: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
        "test-vectors/genesis/testnet-v1.json",
    )?)?;
    for _ in 0..100 {
        verify_mainnet_vector(&mainnet)?;
        verify_legacy_vector(&regtest, NETWORK_MAGIC_REGTEST)?;
        verify_legacy_vector(&testnet, NETWORK_MAGIC_TESTNET)?;
    }
    // Re-encoding JSON changes formatting but cannot change any protocol byte.
    let reformatted: serde_json::Value = serde_json::from_str(&serde_json::to_string(&mainnet)?)?;
    verify_mainnet_vector(&reformatted)?;
    println!(
        "verified_repetitions=100 mainnet={} regtest={} testnet={}",
        json_string(&mainnet, "genesis_identifier_hex")?,
        json_string(&regtest, "genesis_identifier_hex")?,
        json_string(&testnet, "genesis_identifier_hex")?
    );
    Ok(())
}

fn legacy_vector(
    network: &str,
    network_magic: u32,
    timestamp_utc: &str,
    nonce_attempts: u64,
    pow_algorithm: &str,
) -> Result<serde_json::Value> {
    let configured = configured_genesis_hash_for_network_magic(network_magic)?;
    let chain_id = derive_chain_id(network_magic, &configured);
    let canonical = build_canonical_genesis(network_magic, chain_id.as_bytes())?;
    let block = canonical
        .block
        .as_ref()
        .ok_or_else(|| anyhow!("{network} has no legacy canonical block"))?;
    let header = &block.header;
    let body_bytes = canonical
        .block_bytes
        .get(canonical.header_bytes.len()..)
        .ok_or_else(|| anyhow!("{network} block is shorter than its header"))?;
    let transaction_input_count: usize = block
        .transactions
        .iter()
        .map(|transaction| transaction.inputs.len())
        .sum();
    let transaction_output_count: usize = block
        .transactions
        .iter()
        .map(|transaction| transaction.outputs.len())
        .sum();
    let transaction_kernel_count: usize = block
        .transactions
        .iter()
        .map(|transaction| transaction.kernels.len())
        .sum();
    let signing_context_hex = if network_magic == NETWORK_MAGIC_REGTEST {
        "473d3be0c797556bee04a1ddc77f13bbd43e92daeccadc34d4a5a9f2d3e61beb".to_owned()
    } else {
        chain_id.to_hex()
    };
    Ok(json!({
        "schema_version": 1,
        "vector_version": 1,
        "network": network,
        "network_magic_hex": format!("{network_magic:08x}"),
        "protocol_version": header.version,
        "timestamp_utc": timestamp_utc,
        "timestamp_unix": header.timestamp.0,
        "height": header.height.0,
        "previous_identifier_hex": header.prev_hash.to_hex(),
        "compact_target_hex": format!("{:08x}", header.target.0),
        "expanded_target_hex": hex::encode(CompactTarget(header.target.0).to_target()?),
        "derived_difficulty": header.total_difficulty.to_string(),
        "nonce": header.pow.nonce,
        "nonce_attempts": nonce_attempts,
        "body_input_count": transaction_input_count,
        "body_output_count": 1 + transaction_output_count,
        "body_kernel_count": 1 + transaction_kernel_count,
        "body_transaction_count": block.transactions.len(),
        "body_fee_noms": block.total_fees()?,
        "test_only_coinbase": true,
        "genesis_coinbase_signing_context_hex": signing_context_hex,
        "spendable_issuance_noms": block.coinbase.kernel.explicit_value,
        "output_root_hex": header.output_root.to_hex(),
        "kernel_root_hex": header.kernel_root.to_hex(),
        "range_proof_root_hex": header.rangeproof_root.to_hex(),
        "rooted_header_length": canonical.header_bytes.len(),
        "rooted_header_hex": hex::encode(&canonical.header_bytes),
        "economic_body_length": body_bytes.len(),
        "economic_body_hex": hex::encode(body_bytes),
        "identity_format": "LegacyCanonicalBlockV1",
        "complete_genesis_length": canonical.block_bytes.len(),
        "complete_genesis_hex": hex::encode(&canonical.block_bytes),
        "pow_algorithm": pow_algorithm,
        "pow_seed_hex": hex::encode(GENESIS_POW_SEED),
        "pow_digest_hex": header.pow.randomx_hash.to_hex(),
        "genesis_identifier_algorithm": "Blake2b-256",
        "genesis_identifier_domain": null,
        "genesis_identifier_hex": canonical.hash.to_hex(),
        "chain_id_algorithm": "Blake2b-256 tagged with a little-endian u16 domain-length prefix",
        "chain_id_domain": "DOM:chain-id:v1",
        "chain_id_hex": chain_id.to_hex(),
        "endianness": {
            "network_magic": "big-endian in chain-ID preimage",
            "header_scalars": "little-endian except total_difficulty",
            "total_difficulty": "32-byte big-endian",
            "hashes": "canonical byte order as displayed"
        }
    }))
}

fn write_vectors() -> Result<()> {
    let mainnet = build_canonical_genesis(NETWORK_MAGIC_MAINNET, &[0u8; 32])?;
    let header = BlockHeader::from_bytes(&mainnet.header_bytes)?;
    let identity = MainnetGenesisIdentityV1::from_canonical_bytes(&mainnet.block_bytes)?;
    let chain_id = derive_chain_id(NETWORK_MAGIC_MAINNET, &mainnet.hash);
    let inscription = identity.inscription();
    let mainnet_vector = json!({
        "schema_version": 1,
        "vector_version": 1,
        "network": "mainnet",
        "network_magic_hex": format!("{NETWORK_MAGIC_MAINNET:08x}"),
        "protocol_version": header.version,
        "timestamp_utc": CEREMONY_UTC,
        "timestamp_unix": header.timestamp.0,
        "height": header.height.0,
        "previous_identifier_hex": header.prev_hash.to_hex(),
        "compact_target_hex": format!("{:08x}", header.target.0),
        "expanded_target_hex": hex::encode(CompactTarget(header.target.0).to_target()?),
        "derived_difficulty": header.total_difficulty.to_string(),
        "nonce": header.pow.nonce,
        "nonce_attempts": 7_151,
        "body_input_count": 0,
        "body_output_count": 0,
        "body_kernel_count": 0,
        "body_transaction_count": 0,
        "body_fee_noms": 0,
        "spendable_issuance_noms": 0,
        "coinbase_present": false,
        "range_proof_present": false,
        "recovery_capsule_present": false,
        "output_root_hex": header.output_root.to_hex(),
        "kernel_root_hex": header.kernel_root.to_hex(),
        "range_proof_root_hex": header.rangeproof_root.to_hex(),
        "rooted_header_length": mainnet.header_bytes.len(),
        "rooted_header_hex": hex::encode(&mainnet.header_bytes),
        "economic_body_length": identity.body_bytes().len(),
        "economic_body_hex": hex::encode(identity.body_bytes()),
        "identity_format": "MainnetGenesisIdentityV1",
        "identity_envelope_length": mainnet.block_bytes.len(),
        "identity_envelope_hex": hex::encode(&mainnet.block_bytes),
        "inscription_version": 1,
        "inscription_utf8_hex": hex::encode(inscription.payload()),
        "inscription_encoding_hex": hex::encode(inscription.to_canonical_bytes()?),
        "inscription_commitment_domain": "DOM:genesis-inscription:v1",
        "inscription_commitment_hex": inscription.commitment()?.to_hex(),
        "pow_algorithm": "RandomX",
        "pow_seed_hex": hex::encode(GENESIS_POW_SEED),
        "pow_digest_hex": header.pow.randomx_hash.to_hex(),
        "genesis_identifier_algorithm": "Blake2b-256 tagged with a little-endian u16 domain-length prefix",
        "genesis_identifier_domain": "DOM:mainnet-genesis-identity:v1",
        "genesis_identifier_hex": mainnet.hash.to_hex(),
        "chain_id_algorithm": "Blake2b-256 tagged with a little-endian u16 domain-length prefix",
        "chain_id_domain": "DOM:chain-id:v1",
        "chain_id_hex": chain_id.to_hex(),
        "endianness": {
            "network_magic": "big-endian in chain-ID preimage",
            "header_scalars": "little-endian except total_difficulty",
            "total_difficulty": "32-byte big-endian",
            "identity_lengths": "unsigned 16-bit big-endian",
            "hashes": "canonical byte order as displayed"
        }
    });
    let regtest_vector = legacy_vector(
        "regtest",
        NETWORK_MAGIC_REGTEST,
        CEREMONY_UTC,
        1,
        "DOM_FAST_POW_V1",
    )?;
    let testnet_vector = legacy_vector(
        "testnet",
        NETWORK_MAGIC_TESTNET,
        "2026-05-13T03:23:53Z",
        0,
        "Frozen legacy proof-only Testnet header",
    )?;
    for (path, value) in [
        ("test-vectors/genesis/mainnet-v1.json", mainnet_vector),
        ("test-vectors/genesis/regtest-v1.json", regtest_vector),
        ("test-vectors/genesis/testnet-v1.json", testnet_vector),
    ] {
        let mut encoded = serde_json::to_string_pretty(&value)?;
        encoded.push('\n');
        std::fs::write(path, encoded).with_context(|| format!("write {path}"))?;
    }
    Ok(())
}

fn randomx_hash(vm: &RandomXVM, preimage: &[u8]) -> Result<[u8; 32]> {
    let bytes = vm
        .calculate_hash(preimage)
        .map_err(|error| anyhow!("RandomX calculation failed: {error}"))?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|value: Vec<u8>| anyhow!("RandomX returned {} bytes", value.len()))?;
    Ok(hash)
}

fn search_mainnet(mut header: BlockHeader) -> Result<(BlockHeader, u64, u128)> {
    let target = CompactTarget(header.target.0).to_target()?;
    let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    let cache = RandomXCache::new(flags, &GENESIS_POW_SEED)
        .map_err(|error| anyhow!("RandomX cache initialization failed: {error}"))?;
    let dataset = RandomXDataset::new(flags, cache.clone(), 0)
        .map_err(|error| anyhow!("RandomX dataset initialization failed: {error}"))?;
    let vm = RandomXVM::new(flags, Some(cache), Some(dataset))
        .map_err(|error| anyhow!("RandomX VM initialization failed: {error}"))?;
    let started = Instant::now();
    let mut nonce = 0u64;
    let mut attempts = 0u64;
    loop {
        header.pow.nonce = nonce;
        let digest = randomx_hash(&vm, &header.pow_preimage())?;
        attempts = attempts
            .checked_add(1)
            .ok_or_else(|| anyhow!("Mainnet nonce-attempt counter overflow"))?;
        if hash_meets_target(&digest, &target) {
            header.pow.randomx_hash = Hash256::from_bytes(digest);
            return Ok((header, attempts, started.elapsed().as_millis()));
        }
        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("Mainnet nonce space exhausted"))?;
        if attempts.is_multiple_of(100_000) {
            eprintln!(
                "Mainnet ceremony search: attempts={attempts} nonce={nonce} elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
    }
}

fn finalize_regtest(mut header: BlockHeader) -> Result<(BlockHeader, u64)> {
    let target = CompactTarget(header.target.0).to_target()?;
    let mut nonce = 0u64;
    let mut attempts = 0u64;
    loop {
        header.pow.nonce = nonce;
        let digest = fast_pow_hash(&GENESIS_POW_SEED, &header.pow_preimage());
        attempts = attempts
            .checked_add(1)
            .ok_or_else(|| anyhow!("Regtest nonce-attempt counter overflow"))?;
        if hash_meets_target(&digest, &target) {
            header.pow.randomx_hash = Hash256::from_bytes(digest);
            return Ok((header, attempts));
        }
        nonce = nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("Regtest nonce space exhausted"))?;
    }
}

fn main() -> Result<()> {
    if std::env::args().any(|argument| argument == "--verify-vectors") {
        return verify_vectors();
    }
    if std::env::args().any(|argument| argument == "--write-vectors") {
        return write_vectors();
    }
    let mainnet_candidate =
        build_canonical_genesis(NETWORK_MAGIC_MAINNET, &[0u8; 32]).context("Mainnet candidate")?;
    let mainnet_header = BlockHeader::from_bytes(&mainnet_candidate.header_bytes)?;
    let (mainnet_header, mainnet_attempts, mainnet_elapsed_ms) = search_mainnet(mainnet_header)?;
    let mainnet_header_bytes = mainnet_header.to_bytes()?;
    let mainnet_identity = MainnetGenesisIdentityV1::new(
        mainnet_header_bytes.clone(),
        GenesisInscriptionV1::mainnet(),
    )?;
    let mainnet_bytes = mainnet_identity.to_canonical_bytes()?;
    let mainnet_identifier = mainnet_identity.identity_hash()?;
    let mainnet_chain_id = derive_chain_id(NETWORK_MAGIC_MAINNET, &mainnet_identifier);

    let configured_regtest = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_REGTEST)?;
    let configured_regtest_chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &configured_regtest);
    let regtest_candidate = build_canonical_genesis(
        NETWORK_MAGIC_REGTEST,
        configured_regtest_chain_id.as_bytes(),
    )
    .context("Regtest candidate")?;
    let mut regtest_block = regtest_candidate
        .block
        .ok_or_else(|| anyhow!("Regtest candidate has no legacy block"))?;
    let (regtest_header, regtest_attempts) = finalize_regtest(regtest_block.header)?;
    regtest_block.header = regtest_header;
    let regtest_header_bytes = regtest_block.header.to_bytes()?;
    let regtest_bytes = regtest_block.to_bytes()?;
    let regtest_identifier = blake2b_256(&regtest_header_bytes);
    let regtest_chain_id = derive_chain_id(NETWORK_MAGIC_REGTEST, &regtest_identifier);

    let configured_testnet = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_TESTNET)?;
    let testnet_chain_id = derive_chain_id(NETWORK_MAGIC_TESTNET, &configured_testnet);
    let testnet = build_canonical_genesis(NETWORK_MAGIC_TESTNET, testnet_chain_id.as_bytes())?;
    let testnet_block = testnet
        .block
        .as_ref()
        .ok_or_else(|| anyhow!("Testnet candidate has no legacy block"))?;

    let output = json!({
        "mainnet": {
            "attempts": mainnet_attempts,
            "elapsed_ms": mainnet_elapsed_ms,
            "nonce": mainnet_header.pow.nonce,
            "pow_digest_hex": mainnet_header.pow.randomx_hash.to_hex(),
            "header_hex": hex::encode(&mainnet_header_bytes),
            "identity_envelope_hex": hex::encode(&mainnet_bytes),
            "genesis_identifier_hex": mainnet_identifier.to_hex(),
            "chain_id_hex": mainnet_chain_id.to_hex(),
            "target_hex": hex::encode(CompactTarget(mainnet_header.target.0).to_target()?),
            "difficulty": mainnet_header.total_difficulty.to_string(),
            "output_root_hex": mainnet_header.output_root.to_hex(),
            "kernel_root_hex": mainnet_header.kernel_root.to_hex(),
            "range_proof_root_hex": mainnet_header.rangeproof_root.to_hex()
        },
        "regtest": {
            "caller_chain_id_hex": configured_regtest_chain_id.to_hex(),
            "attempts": regtest_attempts,
            "nonce": regtest_block.header.pow.nonce,
            "pow_digest_hex": regtest_block.header.pow.randomx_hash.to_hex(),
            "header_hex": hex::encode(&regtest_header_bytes),
            "block_hex": hex::encode(&regtest_bytes),
            "genesis_identifier_hex": regtest_identifier.to_hex(),
            "chain_id_hex": regtest_chain_id.to_hex(),
            "target_hex": hex::encode(CompactTarget(regtest_block.header.target.0).to_target()?),
            "difficulty": regtest_block.header.total_difficulty.to_string(),
            "output_root_hex": regtest_block.header.output_root.to_hex(),
            "kernel_root_hex": regtest_block.header.kernel_root.to_hex(),
            "range_proof_root_hex": regtest_block.header.rangeproof_root.to_hex(),
            "block_length": regtest_bytes.len()
        },
        "testnet": {
            "nonce": testnet_block.header.pow.nonce,
            "pow_digest_hex": testnet_block.header.pow.randomx_hash.to_hex(),
            "header_hex": hex::encode(&testnet.header_bytes),
            "block_hex": hex::encode(&testnet.block_bytes),
            "genesis_identifier_hex": testnet.hash.to_hex(),
            "chain_id_hex": testnet_chain_id.to_hex(),
            "target_hex": hex::encode(CompactTarget(testnet_block.header.target.0).to_target()?),
            "difficulty": testnet_block.header.total_difficulty.to_string(),
            "output_root_hex": testnet_block.header.output_root.to_hex(),
            "kernel_root_hex": testnet_block.header.kernel_root.to_hex(),
            "range_proof_root_hex": testnet_block.header.rangeproof_root.to_hex(),
            "block_length": testnet.block_bytes.len()
        }
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
