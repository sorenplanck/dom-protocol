use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use chain_profile::{
    ChainKindV1, ChainProfileV1, MoneroNetworkV1, SolanaNetworkV1, MAX_ALLOWED_ASSETS,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};

use crate::types::{
    AssetBindingV1, AssetRepresentationV1, BitcoinDeploymentV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, MoneroDeploymentV1,
    RegistryChainProfileV1, RegistryManifestV1, SolanaDeploymentV1, MAX_ASSET_BINDINGS, MAX_CHAINS,
    MAX_MANIFEST_BYTES, MAX_SIGNET_CHALLENGE_BYTES,
};
use crate::{RegistryError, Result, REGISTRY_VERSION};

const MANIFEST_MAGIC: &[u8; 8] = b"DOMREG1\0";

pub(crate) fn encode_manifest(manifest: &RegistryManifestV1) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1_024);
    out.extend_from_slice(MANIFEST_MAGIC);
    put_u16(&mut out, REGISTRY_VERSION);
    put_u16(&mut out, 0);
    out.extend_from_slice(&manifest.network_id);
    put_u64(&mut out, manifest.epoch);
    put_u64(&mut out, manifest.valid_from);
    put_u64(&mut out, manifest.expires_at);
    encode_dom(&mut out, manifest.dom);
    put_u16(
        &mut out,
        u16::try_from(manifest.chains.len()).map_err(|_| RegistryError::BoundExceeded)?,
    );
    for chain in &manifest.chains {
        encode_chain(&mut out, chain)?;
    }
    put_u16(
        &mut out,
        u16::try_from(manifest.assets.len()).map_err(|_| RegistryError::BoundExceeded)?,
    );
    for asset in &manifest.assets {
        out.extend_from_slice(&asset.chain_id.0);
        out.extend_from_slice(&asset.asset_id.0);
        out.push(asset.decimals);
        match asset.representation {
            AssetRepresentationV1::Native => out.push(0x01),
            AssetRepresentationV1::EvmErc20 {
                token,
                token_code_hash,
            } => {
                out.push(0x02);
                out.extend_from_slice(&token);
                out.extend_from_slice(&token_code_hash);
            }
        }
    }
    if out.len() > MAX_MANIFEST_BYTES {
        return Err(RegistryError::BoundExceeded);
    }
    Ok(out)
}

pub(crate) fn decode_manifest(bytes: &[u8]) -> Result<RegistryManifestV1> {
    let mut reader = Reader::new(bytes);
    if reader.take::<8>()? != *MANIFEST_MAGIC {
        return Err(RegistryError::NonCanonicalEncoding);
    }
    if reader.u16()? != REGISTRY_VERSION {
        return Err(RegistryError::UnsupportedVersion);
    }
    if reader.u16()? != 0 {
        return Err(RegistryError::NonCanonicalEncoding);
    }
    let network_id = reader.take::<32>()?;
    let epoch = reader.u64()?;
    let valid_from = reader.u64()?;
    let expires_at = reader.u64()?;
    let dom = decode_dom(&mut reader)?;
    let chain_count = usize::from(reader.u16()?);
    if chain_count == 0 || chain_count > MAX_CHAINS {
        return Err(RegistryError::BoundExceeded);
    }
    let mut chains = Vec::with_capacity(chain_count);
    for _ in 0..chain_count {
        chains.push(decode_chain(&mut reader)?);
    }
    let asset_count = usize::from(reader.u16()?);
    if asset_count == 0 || asset_count > MAX_ASSET_BINDINGS {
        return Err(RegistryError::BoundExceeded);
    }
    let mut assets = Vec::with_capacity(asset_count);
    for _ in 0..asset_count {
        let chain_id = ChainId(reader.take::<32>()?);
        let asset_id = AssetId(reader.take::<32>()?);
        let decimals = reader.u8()?;
        let representation = match reader.u8()? {
            0x01 => AssetRepresentationV1::Native,
            0x02 => AssetRepresentationV1::EvmErc20 {
                token: reader.take::<20>()?,
                token_code_hash: reader.take::<32>()?,
            },
            _ => return Err(RegistryError::NonCanonicalEncoding),
        };
        assets.push(AssetBindingV1 {
            chain_id,
            asset_id,
            decimals,
            representation,
        });
    }
    reader.finish()?;
    Ok(RegistryManifestV1 {
        network_id,
        epoch,
        valid_from,
        expires_at,
        dom,
        chains,
        assets,
    })
}

fn encode_dom(out: &mut Vec<u8>, dom: DomDeploymentV1) {
    out.extend_from_slice(&dom.chain_id.0);
    out.extend_from_slice(&dom.genesis_hash);
    out.push(dom.runtime_identity.network as u8);
    put_u32(out, dom.runtime_identity.network_magic);
    put_u32(out, dom.runtime_identity.protocol_version);
    out.push(dom.runtime_identity.range_proof_serialization_version);
    out.extend_from_slice(&dom.consensus_rules_digest);
    put_u32(out, dom.scriptless_api_version);
    encode_timing(out, dom.timing);
    encode_finality(out, dom.finality);
    out.extend_from_slice(&dom.native_asset.0);
}

fn decode_dom(reader: &mut Reader<'_>) -> Result<DomDeploymentV1> {
    let chain_id = ChainId(reader.take::<32>()?);
    let genesis_hash = reader.take::<32>()?;
    let network = match reader.u8()? {
        1 => DomNetworkV1::Mainnet,
        2 => DomNetworkV1::Testnet,
        3 => DomNetworkV1::Regtest,
        _ => return Err(RegistryError::NonCanonicalEncoding),
    };
    Ok(DomDeploymentV1 {
        chain_id,
        genesis_hash,
        runtime_identity: DomRuntimeIdentityV1 {
            network,
            network_magic: reader.u32()?,
            protocol_version: reader.u32()?,
            range_proof_serialization_version: reader.u8()?,
        },
        consensus_rules_digest: reader.take::<32>()?,
        scriptless_api_version: reader.u32()?,
        timing: decode_timing(reader)?,
        finality: decode_finality(reader)?,
        native_asset: AssetId(reader.take::<32>()?),
    })
}

fn encode_chain(out: &mut Vec<u8>, chain: &RegistryChainProfileV1) -> Result<()> {
    let profile = &chain.profile;
    out.extend_from_slice(&profile.chain_id.0);
    match profile.kind {
        ChainKindV1::Evm {
            evm_chain_id,
            native_lock_contract,
            native_code_hash,
            erc20_lock_contract,
        } => {
            out.push(0x01);
            put_u64(out, evm_chain_id);
            out.extend_from_slice(&native_lock_contract);
            out.extend_from_slice(&native_code_hash);
            match erc20_lock_contract {
                None => out.push(0),
                Some((contract, hash)) => {
                    out.push(1);
                    out.extend_from_slice(&contract);
                    out.extend_from_slice(&hash);
                }
            }
        }
        ChainKindV1::Bitcoin { network } => {
            out.push(0x02);
            out.push(network as u8);
        }
        ChainKindV1::Monero { network } => {
            out.push(0x03);
            out.push(network as u8);
        }
        ChainKindV1::Solana {
            network,
            escrow_program,
            program_data_hash,
        } => {
            out.push(0x04);
            out.push(network as u8);
            out.extend_from_slice(&escrow_program);
            out.extend_from_slice(&program_data_hash);
        }
    }
    encode_timing(out, profile.timing);
    encode_finality(out, profile.finality);
    out.extend_from_slice(&profile.native_asset.0);
    put_u16(
        out,
        u16::try_from(profile.allowed_assets.len()).map_err(|_| RegistryError::BoundExceeded)?,
    );
    for asset in &profile.allowed_assets {
        out.extend_from_slice(&asset.0);
    }
    match &chain.deployment {
        ChainDeploymentV1::Evm(deployment) => {
            out.push(0x01);
            out.extend_from_slice(&deployment.genesis_hash);
            put_u64(out, deployment.native_start_block);
            match deployment.erc20_start_block {
                None => out.push(0),
                Some(value) => {
                    out.push(1);
                    put_u64(out, value);
                }
            }
            out.extend_from_slice(&deployment.abi_digest);
            out.extend_from_slice(&deployment.compiler_digest);
            out.extend_from_slice(&deployment.source_digest);
            out.extend_from_slice(&deployment.deployment_digest);
            out.push(u8::from(deployment.finalized_tag_required));
            put_u64(out, deployment.page_size);
            put_u64(out, deployment.gas_limit_hint);
            put_u128(out, deployment.max_fee_per_gas);
            put_u128(out, deployment.max_priority_fee_per_gas);
        }
        ChainDeploymentV1::Monero(deployment) => {
            out.push(0x03);
            out.extend_from_slice(&deployment.genesis_hash);
            put_u64(out, deployment.max_fee_piconero);
        }
        ChainDeploymentV1::Solana(deployment) => {
            out.push(0x04);
            out.extend_from_slice(&deployment.genesis_hash);
            put_u64(out, deployment.max_fee_lamports);
        }
        ChainDeploymentV1::Bitcoin(deployment) => {
            out.push(0x02);
            out.extend_from_slice(&deployment.genesis_hash);
            put_u16(
                out,
                u16::try_from(deployment.signet_challenge.len())
                    .map_err(|_| RegistryError::BoundExceeded)?,
            );
            out.extend_from_slice(&deployment.signet_challenge);
            put_u64(out, deployment.max_fee_rate_sat_vbyte);
            put_u64(out, deployment.min_relay_fee_sat_kvb);
        }
    }
    Ok(())
}

fn decode_chain(reader: &mut Reader<'_>) -> Result<RegistryChainProfileV1> {
    let chain_id = ChainId(reader.take::<32>()?);
    let kind = match reader.u8()? {
        0x01 => {
            let evm_chain_id = reader.u64()?;
            let native_lock_contract = reader.take::<20>()?;
            let native_code_hash = reader.take::<32>()?;
            let erc20_lock_contract = match reader.u8()? {
                0 => None,
                1 => Some((reader.take::<20>()?, reader.take::<32>()?)),
                _ => return Err(RegistryError::NonCanonicalEncoding),
            };
            ChainKindV1::Evm {
                evm_chain_id,
                native_lock_contract,
                native_code_hash,
                erc20_lock_contract,
            }
        }
        0x02 => ChainKindV1::Bitcoin {
            network: decode_bitcoin_network(reader.u8()?)?,
        },
        0x03 => ChainKindV1::Monero {
            network: MoneroNetworkV1::from_u8(reader.u8()?)
                .ok_or(RegistryError::NonCanonicalEncoding)?,
        },
        0x04 => ChainKindV1::Solana {
            network: SolanaNetworkV1::from_u8(reader.u8()?)
                .ok_or(RegistryError::NonCanonicalEncoding)?,
            escrow_program: reader.take::<32>()?,
            program_data_hash: reader.take::<32>()?,
        },
        _ => return Err(RegistryError::NonCanonicalEncoding),
    };
    let timing = decode_timing(reader)?;
    let finality = decode_finality(reader)?;
    let native_asset = AssetId(reader.take::<32>()?);
    let allowed_count = usize::from(reader.u16()?);
    if allowed_count > MAX_ALLOWED_ASSETS {
        return Err(RegistryError::BoundExceeded);
    }
    let mut allowed_assets = Vec::with_capacity(allowed_count);
    for _ in 0..allowed_count {
        allowed_assets.push(AssetId(reader.take::<32>()?));
    }
    let deployment = match reader.u8()? {
        0x01 => {
            let genesis_hash = reader.take::<32>()?;
            let native_start_block = reader.u64()?;
            let erc20_start_block = match reader.u8()? {
                0 => None,
                1 => Some(reader.u64()?),
                _ => return Err(RegistryError::NonCanonicalEncoding),
            };
            let abi_digest = reader.take::<32>()?;
            let compiler_digest = reader.take::<32>()?;
            let source_digest = reader.take::<32>()?;
            let deployment_digest = reader.take::<32>()?;
            let finalized_tag_required = reader.bool()?;
            let page_size = reader.u64()?;
            let gas_limit_hint = reader.u64()?;
            let max_fee_per_gas = reader.u128()?;
            let max_priority_fee_per_gas = reader.u128()?;
            ChainDeploymentV1::Evm(EvmDeploymentV1 {
                genesis_hash,
                native_start_block,
                erc20_start_block,
                abi_digest,
                compiler_digest,
                source_digest,
                deployment_digest,
                finalized_tag_required,
                page_size,
                gas_limit_hint,
                max_fee_per_gas,
                max_priority_fee_per_gas,
            })
        }
        0x02 => {
            let genesis_hash = reader.take::<32>()?;
            let challenge_len = usize::from(reader.u16()?);
            if challenge_len > MAX_SIGNET_CHALLENGE_BYTES {
                return Err(RegistryError::BoundExceeded);
            }
            let signet_challenge = reader.bytes(challenge_len)?.to_vec();
            let max_fee_rate_sat_vbyte = reader.u64()?;
            let min_relay_fee_sat_kvb = reader.u64()?;
            ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                genesis_hash,
                signet_challenge,
                max_fee_rate_sat_vbyte,
                min_relay_fee_sat_kvb,
            })
        }
        0x03 => {
            let genesis_hash = reader.take::<32>()?;
            let max_fee_piconero = reader.u64()?;
            ChainDeploymentV1::Monero(MoneroDeploymentV1 {
                genesis_hash,
                max_fee_piconero,
            })
        }
        0x04 => {
            let genesis_hash = reader.take::<32>()?;
            let max_fee_lamports = reader.u64()?;
            ChainDeploymentV1::Solana(SolanaDeploymentV1 {
                genesis_hash,
                max_fee_lamports,
            })
        }
        _ => return Err(RegistryError::NonCanonicalEncoding),
    };
    Ok(RegistryChainProfileV1 {
        profile: ChainProfileV1 {
            chain_id,
            kind,
            timing,
            finality,
            native_asset,
            allowed_assets,
        },
        deployment,
    })
}

fn encode_timing(out: &mut Vec<u8>, timing: ChainTimingBoundsV1) {
    put_u32(out, timing.min_block_seconds);
    put_u32(out, timing.max_block_seconds);
    put_u32(out, timing.max_reorg_seconds);
    put_u32(out, timing.observation_seconds);
    put_u32(out, timing.broadcast_seconds);
}

fn decode_timing(reader: &mut Reader<'_>) -> Result<ChainTimingBoundsV1> {
    Ok(ChainTimingBoundsV1 {
        min_block_seconds: reader.u32()?,
        max_block_seconds: reader.u32()?,
        max_reorg_seconds: reader.u32()?,
        observation_seconds: reader.u32()?,
        broadcast_seconds: reader.u32()?,
    })
}

fn encode_finality(out: &mut Vec<u8>, finality: FinalityPolicyV1) {
    put_u32(out, finality.min_confirmations);
    put_u32(out, finality.max_reorg_depth);
}

fn decode_finality(reader: &mut Reader<'_>) -> Result<FinalityPolicyV1> {
    Ok(FinalityPolicyV1 {
        min_confirmations: reader.u32()?,
        max_reorg_depth: reader.u32()?,
    })
}

fn decode_bitcoin_network(value: u8) -> Result<BitcoinNetworkV1> {
    match value {
        0x01 => Ok(BitcoinNetworkV1::Regtest),
        0x02 => Ok(BitcoinNetworkV1::CustomSignet),
        0x03 => Ok(BitcoinNetworkV1::PublicSignet),
        _ => Err(RegistryError::NonCanonicalEncoding),
    }
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, value: u128) {
    out.extend_from_slice(&value.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RegistryError::Overflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RegistryError::NonCanonicalEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| RegistryError::NonCanonicalEncoding)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(RegistryError::NonCanonicalEncoding),
        }
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }

    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.take::<16>()?))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RegistryError::NonCanonicalEncoding)
        }
    }
}
