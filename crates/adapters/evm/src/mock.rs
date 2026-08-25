//! Deterministic in-crate EVM mock.
//!
//! This is the only "chain" the test suite ever talks to. It implements
//! [`JsonRpc`] over an in-memory block list, so `cargo test -p adapter-evm`
//! performs zero network I/O and produces the same bytes on every machine.
//!
//! It is a *test double*, not a simulator: it does not execute EVM bytecode and
//! it does not enforce the contract's rules. It reproduces exactly the surface
//! the adapter reads — `eth_chainId`, `eth_getCode`, `eth_getBlockByNumber`,
//! `eth_getBlockByHash`, `eth_getLogs`, `eth_getTransactionReceipt`,
//! `eth_getTransactionByHash` — plus a set of deliberate [`Faults`] so that
//! every fail-closed path in the adapter can be exercised against a hostile
//! endpoint rather than against a stub.
//!
//! Each mock log is its own transaction, and the receipt the mock serves
//! carries that log, so [`crate::attest`]'s "is the log really in its own
//! receipt?" check has something real to verify — and the faults can take it
//! away one property at a time.
//!
//! Block hashes are `keccak256(parent_hash ‖ height ‖ salt)`. The salt is what
//! [`MockChain::reorg`] changes, so a re-mined segment gets different hashes
//! while sharing every block below the fork point — which is precisely the
//! shape [`crate::reorg`] has to cope with.

use counterparty_api::AdapterError;
use serde_json::{json, Value};

use crate::abi::{
    concat_words, event_topic0, keccak256, word_address, word_bytes32, word_u256, word_u64,
    SIG_CLAIMED, SIG_LOCK_OPENED, SIG_REFUNDED,
};
use crate::error::Result;
use crate::rpc::{hex_of, JsonRpc};

/// Deliberate misbehaviours the mock can be asked to exhibit.
#[derive(Clone, Copy, Default, Debug)]
pub struct Faults {
    /// Every call fails at the transport level.
    pub break_transport: bool,
    /// `eth_getLogs` returns its page in descending order.
    pub logs_out_of_order: bool,
    /// `eth_getLogs` returns every log twice.
    pub duplicate_logs: bool,
    /// Logs omit the `removed` member.
    pub drop_removed_field: bool,
    /// Logs carry `removed: true`.
    pub mark_logs_removed: bool,
    /// Logs claim an emitter other than the configured contract.
    pub wrong_emitter: bool,
    /// Logs carry a `topic0` that belongs to no known event.
    pub wrong_topic0: bool,
    /// Logs carry two topics instead of four.
    pub wrong_topic_arity: bool,
    /// Log `data` is one word shorter than the event declares.
    pub truncate_log_data: bool,
    /// Log `data` carries an extra trailing word.
    pub extra_log_data: bool,
    /// Receipts report `status: 0`.
    pub receipt_reverted: bool,
    /// Receipts are `null`.
    pub receipt_missing: bool,
    /// Receipts point at a different block than the log does.
    pub receipt_block_mismatch: bool,
    /// Receipts carry an empty `logs` array: the transaction succeeded but
    /// never emitted the log `eth_getLogs` advertised.
    pub receipt_logs_empty: bool,
    /// The receipt carries the log, but at a different `logIndex`.
    pub receipt_log_index_shifted: bool,
    /// The receipt carries a log at the right index whose payload differs from
    /// the one `eth_getLogs` served.
    pub receipt_log_tampered: bool,
    /// `eth_getTransactionByHash` answers `null`.
    pub transaction_missing: bool,
    /// The transaction claims a different block than its own receipt.
    pub transaction_block_mismatch: bool,
    /// The transaction was sent to some other address than the contract.
    pub transaction_to_foreign: bool,
    /// The transaction is still pending: no block hash, no block number.
    pub transaction_pending: bool,
    /// Height-addressed block lookups answer with a different hash than the one
    /// the logs carry: the log's block is not the canonical block there.
    pub divergent_canonical_block_hash: bool,
    /// Every header reports a parent that does not exist, so no chain of
    /// parent hashes reaches anything.
    pub orphan_parent_linkage: bool,
    /// The `finalized` tag answers `null`.
    pub finalized_null: bool,
    /// `eth_chainId` answers with a different chain.
    pub wrong_chain_id: bool,
    /// `eth_getCode` answers with different bytecode.
    pub wrong_code: bool,
    /// Every result is replaced by a structurally invalid value.
    pub garbage_results: bool,
}

/// One log record held by the mock.
#[derive(Clone, Debug)]
struct MockLogRec {
    topics: Vec<[u8; 32]>,
    data: Vec<u8>,
    tx_hash: [u8; 32],
}

/// One block held by the mock.
#[derive(Clone, Debug)]
struct MockBlock {
    hash: [u8; 32],
    parent_hash: [u8; 32],
    logs: Vec<MockLogRec>,
}

/// A deterministic, in-memory EVM endpoint.
#[derive(Clone, Debug)]
pub struct MockChain {
    chain_id: u64,
    contract: [u8; 20],
    code: Vec<u8>,
    blocks: Vec<MockBlock>,
    finalized: Option<u64>,
    salt: u8,
    faults: Faults,
}

fn block_hash_of(parent: &[u8; 32], height: u64, salt: u8) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 8 + 1);
    pre.extend_from_slice(parent);
    pre.extend_from_slice(&height.to_be_bytes());
    pre.push(salt);
    keccak256(&pre)
}

fn tx_hash_of(height: u64, index: usize, salt: u8) -> [u8; 32] {
    let mut pre = Vec::with_capacity(1 + 8 + 8 + 1);
    pre.push(0x54); // 'T'
    pre.extend_from_slice(&height.to_be_bytes());
    pre.extend_from_slice(&(index as u64).to_be_bytes());
    pre.push(salt);
    keccak256(&pre)
}

impl MockChain {
    /// A chain with only the genesis block (height 0) and default bytecode.
    pub fn new(chain_id: u64, contract: [u8; 20]) -> Self {
        let genesis = MockBlock {
            hash: block_hash_of(&[0u8; 32], 0, 0),
            parent_hash: [0u8; 32],
            logs: Vec::new(),
        };
        Self {
            chain_id,
            contract,
            code: b"ConditionLockV2-mock-bytecode".to_vec(),
            blocks: vec![genesis],
            finalized: None,
            salt: 0,
            faults: Faults::default(),
        }
    }

    /// Appends `n` empty blocks.
    pub fn with_blocks(mut self, n: u64) -> Self {
        for _ in 0..n {
            self.push_block();
        }
        self
    }

    /// Marks height `h` as the finalized checkpoint (clamped to the tip).
    pub fn finalize(mut self, h: u64) -> Self {
        self.finalized = Some(h.min(self.height()));
        self
    }

    /// Installs a fault profile.
    pub fn with_faults(mut self, faults: Faults) -> Self {
        self.faults = faults;
        self
    }

    /// Shorthand for a transport that always fails.
    pub fn breaking_transport(mut self) -> Self {
        self.faults.break_transport = true;
        self
    }

    /// Replaces the deployed bytecode.
    pub fn with_code(mut self, code: Vec<u8>) -> Self {
        self.code = code;
        self
    }

    /// keccak256 of the deployed bytecode — the value to pin in the config.
    pub fn code_hash(&self) -> [u8; 32] {
        keccak256(&self.code)
    }

    /// Configured chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Configured contract address.
    pub fn contract(&self) -> [u8; 20] {
        self.contract
    }

    /// Tip height.
    pub fn height(&self) -> u64 {
        (self.blocks.len() as u64).saturating_sub(1)
    }

    /// Hash of the block at `h`, if it exists.
    pub fn block_hash(&self, h: u64) -> Option<[u8; 32]> {
        self.blocks.get(usize::try_from(h).ok()?).map(|b| b.hash)
    }

    /// Currently finalized height, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.finalized
    }

    /// Appends one empty block and returns its height.
    pub fn push_block(&mut self) -> u64 {
        let height = self.blocks.len() as u64;
        let parent = self.blocks.last().map(|b| b.hash).unwrap_or([0u8; 32]);
        self.blocks.push(MockBlock {
            hash: block_hash_of(&parent, height, self.salt),
            parent_hash: parent,
            logs: Vec::new(),
        });
        height
    }

    /// Sets the finalized checkpoint in place (clamped to the tip).
    pub fn set_finalized(&mut self, h: u64) {
        self.finalized = Some(h.min(self.height()));
    }

    /// Drops `depth` blocks from the tip and re-mines the same number of empty
    /// blocks under a fresh salt, so the re-mined segment has different hashes
    /// while everything below the fork point is untouched.
    pub fn reorg(&mut self, depth: u64) {
        let depth = depth.min(self.height());
        for _ in 0..depth {
            self.blocks.pop();
        }
        self.salt = self.salt.wrapping_add(1);
        for _ in 0..depth {
            self.push_block();
        }
        if let Some(f) = self.finalized {
            self.finalized = Some(f.min(self.height()));
        }
    }

    fn append_log(&mut self, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<(u64, u32)> {
        let height = self.height();
        let salt = self.salt;
        let block = self.blocks.last_mut().ok_or(AdapterError::InvalidState)?;
        let index = block.logs.len();
        block.logs.push(MockLogRec {
            topics,
            data,
            tx_hash: tx_hash_of(height, index, salt),
        });
        u32::try_from(index)
            .map(|i| (height, i))
            .map_err(|_| AdapterError::BoundsExceeded)
    }

    /// Appends a `LockOpened` log to the tip block.
    #[allow(clippy::too_many_arguments)]
    pub fn push_lock_opened(
        &mut self,
        lock_id: [u8; 32],
        binding: [u8; 32],
        funder: [u8; 20],
        beneficiary: [u8; 20],
        asset: [u8; 20],
        amount: [u8; 32],
        adaptor_address: [u8; 20],
        deadline: u64,
    ) -> Result<(u64, u32)> {
        let topics = vec![
            event_topic0(SIG_LOCK_OPENED),
            word_bytes32(lock_id),
            word_bytes32(binding),
            word_address(funder),
        ];
        let data = concat_words(&[
            word_address(beneficiary),
            word_address(asset),
            word_u256(amount),
            word_address(adaptor_address),
            word_u64(deadline),
        ])?;
        self.append_log(topics, data)
    }

    /// Appends a `Claimed` log to the tip block.
    pub fn push_claimed(
        &mut self,
        lock_id: [u8; 32],
        binding: [u8; 32],
        beneficiary: [u8; 20],
        t: [u8; 32],
    ) -> Result<(u64, u32)> {
        let topics = vec![
            event_topic0(SIG_CLAIMED),
            word_bytes32(lock_id),
            word_bytes32(binding),
            word_address(beneficiary),
        ];
        let data = concat_words(&[word_u256(t)])?;
        self.append_log(topics, data)
    }

    /// Appends a `Refunded` log to the tip block.
    pub fn push_refunded(
        &mut self,
        lock_id: [u8; 32],
        binding: [u8; 32],
        funder: [u8; 20],
        amount: [u8; 32],
    ) -> Result<(u64, u32)> {
        let topics = vec![
            event_topic0(SIG_REFUNDED),
            word_bytes32(lock_id),
            word_bytes32(binding),
            word_address(funder),
        ];
        let data = concat_words(&[word_u256(amount)])?;
        self.append_log(topics, data)
    }

    /// Transaction hash of a log, for building evidence in tests.
    pub fn tx_hash_at(&self, height: u64, index: usize) -> Option<[u8; 32]> {
        self.blocks
            .get(usize::try_from(height).ok()?)?
            .logs
            .get(index)
            .map(|l| l.tx_hash)
    }

    // -- JSON rendering -----------------------------------------------------

    fn header_json(&self, h: u64) -> Value {
        self.header_json_inner(h, false)
    }

    /// Header as answered by a *height-addressed* lookup. This is the only
    /// rendering [`Faults::divergent_canonical_block_hash`] touches, because
    /// the fault it models is "the canonical index disagrees with the log",
    /// which a hash-addressed lookup cannot exhibit.
    fn header_json_by_number(&self, h: u64) -> Value {
        self.header_json_inner(h, self.faults.divergent_canonical_block_hash)
    }

    fn header_json_inner(&self, h: u64, divergent_hash: bool) -> Value {
        match usize::try_from(h).ok().and_then(|i| self.blocks.get(i)) {
            Some(b) => {
                let mut hash = b.hash;
                if divergent_hash {
                    hash[0] ^= 0xFF;
                }
                let parent = if self.faults.orphan_parent_linkage {
                    [0xEE; 32]
                } else {
                    b.parent_hash
                };
                json!({
                    "number": crate::rpc::quantity(h),
                    "hash": hex_of(&hash),
                    "parentHash": hex_of(&parent),
                })
            }
            None => Value::Null,
        }
    }

    fn log_json(&self, height: u64, index: usize, rec: &MockLogRec) -> Value {
        let f = &self.faults;
        let mut topics: Vec<[u8; 32]> = rec.topics.clone();
        if f.wrong_topic0 && !topics.is_empty() {
            topics[0] = [0xEE; 32];
        }
        if f.wrong_topic_arity {
            topics.truncate(2);
        }
        let mut data = rec.data.clone();
        if f.truncate_log_data && data.len() >= 32 {
            data.truncate(data.len() - 32);
        }
        if f.extra_log_data {
            data.extend_from_slice(&[0u8; 32]);
        }
        let address = if f.wrong_emitter {
            [0xDE; 20]
        } else {
            self.contract
        };
        let block_hash = self.block_hash(height).unwrap_or([0u8; 32]);
        let mut obj = json!({
            "address": hex_of(&address),
            "topics": topics.iter().map(|t| json!(hex_of(t))).collect::<Vec<_>>(),
            "data": hex_of(&data),
            "blockNumber": crate::rpc::quantity(height),
            "blockHash": hex_of(&block_hash),
            "transactionHash": hex_of(&rec.tx_hash),
            "logIndex": crate::rpc::quantity(index as u64),
            "removed": f.mark_logs_removed,
        });
        if f.drop_removed_field {
            if let Some(m) = obj.as_object_mut() {
                m.remove("removed");
            }
        }
        obj
    }

    fn logs_in_range(&self, from: u64, to: u64, topic0s: &[[u8; 32]]) -> Vec<Value> {
        let mut out = Vec::new();
        for h in from..=to {
            let Some(block) = usize::try_from(h).ok().and_then(|i| self.blocks.get(i)) else {
                continue;
            };
            for (i, rec) in block.logs.iter().enumerate() {
                let matches =
                    topic0s.is_empty() || rec.topics.first().is_some_and(|t| topic0s.contains(t));
                if matches {
                    out.push(self.log_json(h, i, rec));
                }
            }
        }
        if self.faults.duplicate_logs {
            let dup = out.clone();
            out.extend(dup);
        }
        if self.faults.logs_out_of_order {
            out.reverse();
        }
        out
    }

    /// Locates the log a transaction hash belongs to. Each mock log is its own
    /// transaction, so this is a one-to-one mapping.
    fn find_tx(&self, tx_hash: &[u8; 32]) -> Option<(u64, usize)> {
        for (h, block) in self.blocks.iter().enumerate() {
            for (i, rec) in block.logs.iter().enumerate() {
                if &rec.tx_hash == tx_hash {
                    return Some((h as u64, i));
                }
            }
        }
        None
    }

    fn receipt_json(&self, tx_hash: &[u8; 32]) -> Value {
        if self.faults.receipt_missing {
            return Value::Null;
        }
        let Some((h, index)) = self.find_tx(tx_hash) else {
            return Value::Null;
        };
        let Some(block) = usize::try_from(h).ok().and_then(|i| self.blocks.get(i)) else {
            return Value::Null;
        };
        let Some(rec) = block.logs.get(index) else {
            return Value::Null;
        };
        let status = if self.faults.receipt_reverted { 0 } else { 1 };
        let (bn, bh) = if self.faults.receipt_block_mismatch {
            (h + 1, [0x99u8; 32])
        } else {
            (h, block.hash)
        };
        // A real receipt carries the logs its own transaction produced. The
        // mock reproduces that faithfully, because "is this log in its own
        // receipt?" is one of the checks the adapter must be able to make.
        let logs: Vec<Value> = if self.faults.receipt_logs_empty {
            Vec::new()
        } else {
            let rendered_index = if self.faults.receipt_log_index_shifted {
                index.saturating_add(7)
            } else {
                index
            };
            let mut entry = self.log_json(h, rendered_index, rec);
            if self.faults.receipt_log_tampered {
                if let Some(m) = entry.as_object_mut() {
                    m.insert("data".into(), json!(hex_of(&[0xA5u8; 32])));
                }
            }
            vec![entry]
        };
        json!({
            "status": crate::rpc::quantity(status),
            "blockNumber": crate::rpc::quantity(bn),
            "blockHash": hex_of(&bh),
            "transactionHash": hex_of(tx_hash),
            "logs": logs,
        })
    }

    fn transaction_json(&self, tx_hash: &[u8; 32]) -> Value {
        if self.faults.transaction_missing {
            return Value::Null;
        }
        let Some((h, _)) = self.find_tx(tx_hash) else {
            return Value::Null;
        };
        let Some(block) = usize::try_from(h).ok().and_then(|i| self.blocks.get(i)) else {
            return Value::Null;
        };
        if self.faults.transaction_pending {
            return json!({
                "hash": hex_of(tx_hash),
                "blockNumber": Value::Null,
                "blockHash": Value::Null,
                "to": hex_of(&self.contract),
            });
        }
        let (bn, bh) = if self.faults.transaction_block_mismatch {
            (h.saturating_add(1), [0x88u8; 32])
        } else {
            (h, block.hash)
        };
        let to = if self.faults.transaction_to_foreign {
            [0xDA; 20]
        } else {
            self.contract
        };
        json!({
            "hash": hex_of(tx_hash),
            "blockNumber": crate::rpc::quantity(bn),
            "blockHash": hex_of(&bh),
            "to": hex_of(&to),
        })
    }
}

fn parse_tag(v: Option<&Value>) -> Option<String> {
    v.and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn parse_quantity(s: &str) -> Option<u64> {
    let body = s.strip_prefix("0x")?;
    u64::from_str_radix(body, 16).ok()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let body = s.strip_prefix("0x")?;
    if body.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in body.as_bytes().chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        *out.get_mut(i)? = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

impl JsonRpc for MockChain {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        if self.faults.break_transport {
            return Err(AdapterError::AdapterUnavailable);
        }
        if self.faults.garbage_results {
            return Ok(json!("not-a-valid-result"));
        }
        match method {
            "eth_chainId" => {
                let id = if self.faults.wrong_chain_id {
                    self.chain_id.wrapping_add(1)
                } else {
                    self.chain_id
                };
                Ok(json!(crate::rpc::quantity(id)))
            }
            "eth_getCode" => {
                let code: &[u8] = if self.faults.wrong_code {
                    b"different-bytecode"
                } else {
                    &self.code
                };
                Ok(json!(hex_of(code)))
            }
            "eth_getBlockByNumber" => {
                let tag = parse_tag(params.get(0)).ok_or(AdapterError::AdapterUnavailable)?;
                match tag.as_str() {
                    "finalized" => {
                        if self.faults.finalized_null {
                            return Ok(Value::Null);
                        }
                        match self.finalized {
                            Some(h) => Ok(self.header_json(h)),
                            None => Ok(Value::Null),
                        }
                    }
                    "latest" => Ok(self.header_json(self.height())),
                    other => {
                        let h = parse_quantity(other).ok_or(AdapterError::AdapterUnavailable)?;
                        Ok(self.header_json_by_number(h))
                    }
                }
            }
            "eth_getBlockByHash" => {
                let want = parse_tag(params.get(0))
                    .as_deref()
                    .and_then(parse_hex32)
                    .ok_or(AdapterError::AdapterUnavailable)?;
                for (h, b) in self.blocks.iter().enumerate() {
                    if b.hash == want {
                        return Ok(self.header_json(h as u64));
                    }
                }
                Ok(Value::Null)
            }
            "eth_getTransactionReceipt" => {
                let want = parse_tag(params.get(0))
                    .as_deref()
                    .and_then(parse_hex32)
                    .ok_or(AdapterError::AdapterUnavailable)?;
                Ok(self.receipt_json(&want))
            }
            "eth_getTransactionByHash" => {
                let want = parse_tag(params.get(0))
                    .as_deref()
                    .and_then(parse_hex32)
                    .ok_or(AdapterError::AdapterUnavailable)?;
                Ok(self.transaction_json(&want))
            }
            "eth_getLogs" => {
                let filter = params.get(0).ok_or(AdapterError::AdapterUnavailable)?;
                let from = parse_tag(filter.get("fromBlock"))
                    .as_deref()
                    .and_then(parse_quantity)
                    .ok_or(AdapterError::AdapterUnavailable)?;
                let to = parse_tag(filter.get("toBlock"))
                    .as_deref()
                    .and_then(parse_quantity)
                    .ok_or(AdapterError::AdapterUnavailable)?;
                let mut topic0s: Vec<[u8; 32]> = Vec::new();
                if let Some(list) = filter.get("topics").and_then(|t| t.as_array()) {
                    if let Some(first) = list.first().and_then(|t| t.as_array()) {
                        for t in first {
                            if let Some(h) = t.as_str().and_then(parse_hex32) {
                                topic0s.push(h);
                            }
                        }
                    }
                }
                Ok(Value::Array(self.logs_in_range(
                    from,
                    to.min(self.height()),
                    &topic0s,
                )))
            }
            _ => Err(AdapterError::AdapterUnavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{EthClient, RpcBlockHeader};

    #[test]
    fn chain_is_linked_and_deterministic() {
        let a = MockChain::new(31337, [0xC0; 20]).with_blocks(5);
        let b = MockChain::new(31337, [0xC0; 20]).with_blocks(5);
        assert_eq!(a.height(), 5);
        for h in 0..=5 {
            assert_eq!(
                a.block_hash(h),
                b.block_hash(h),
                "mock must be reproducible"
            );
        }
        let client = EthClient::new(&a);
        for h in 1..=5u64 {
            let this = client.block_by_number(h).expect("rpc").expect("block");
            let prev = client.block_by_number(h - 1).expect("rpc").expect("block");
            assert_eq!(this.parent_hash, prev.hash, "parent linkage broken at {h}");
        }
        assert_eq!(client.block_by_number(6), Ok(None));
    }

    #[test]
    fn reorg_changes_only_the_top_segment() {
        let mut c = MockChain::new(31337, [0xC0; 20]).with_blocks(10);
        let before: Vec<Option<[u8; 32]>> = (0..=10).map(|h| c.block_hash(h)).collect();
        c.reorg(3);
        assert_eq!(c.height(), 10);
        for h in 0..=7u64 {
            assert_eq!(
                c.block_hash(h),
                before[h as usize],
                "block {h} must be untouched"
            );
        }
        for h in 8..=10u64 {
            assert_ne!(
                c.block_hash(h),
                before[h as usize],
                "block {h} must be re-mined"
            );
        }
    }

    #[test]
    fn logs_are_served_in_range_and_receipts_line_up() {
        let mut c = MockChain::new(31337, [0xC0; 20]).with_blocks(2);
        c.push_claimed([1u8; 32], [2u8; 32], [3u8; 20], [4u8; 32])
            .expect("log appended");
        c.set_finalized(2);
        let client = EthClient::new(&c);
        let logs = client
            .logs(0, 2, &[0xC0; 20], &[event_topic0(SIG_CLAIMED)])
            .expect("logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_number, 2);
        assert!(!logs[0].removed);
        let r = client
            .receipt(&logs[0].tx_hash)
            .expect("rpc")
            .expect("receipt");
        assert_eq!(r.status, 1);
        assert_eq!(r.block_hash, logs[0].block_hash);
        // The receipt carries the very log the query returned.
        assert_eq!(r.log_at(logs[0].log_index), Some(&logs[0]));

        let tx = client
            .transaction(&logs[0].tx_hash)
            .expect("rpc")
            .expect("transaction");
        assert_eq!(tx.hash, logs[0].tx_hash);
        assert_eq!(tx.block_hash, Some(logs[0].block_hash));
        assert_eq!(tx.block_number, Some(logs[0].block_number));
        assert_eq!(tx.to, Some([0xC0; 20]));
    }

    #[test]
    fn the_corroboration_faults_are_actually_injected() {
        let mut base = MockChain::new(31337, [0xC0; 20]).with_blocks(1);
        base.push_claimed([1u8; 32], [2u8; 32], [3u8; 20], [4u8; 32])
            .expect("log");
        base.set_finalized(1);
        let tx = base.tx_hash_at(1, 0).expect("tx hash");

        let empty = base.clone().with_faults(Faults {
            receipt_logs_empty: true,
            ..Faults::default()
        });
        assert_eq!(
            EthClient::new(&empty)
                .receipt(&tx)
                .expect("rpc")
                .expect("receipt")
                .logs
                .len(),
            0
        );

        let shifted = base.clone().with_faults(Faults {
            receipt_log_index_shifted: true,
            ..Faults::default()
        });
        assert!(EthClient::new(&shifted)
            .receipt(&tx)
            .expect("rpc")
            .expect("receipt")
            .log_at(0)
            .is_none());

        let gone = base.clone().with_faults(Faults {
            transaction_missing: true,
            ..Faults::default()
        });
        assert_eq!(EthClient::new(&gone).transaction(&tx), Ok(None));

        let foreign = base.clone().with_faults(Faults {
            transaction_to_foreign: true,
            ..Faults::default()
        });
        assert_eq!(
            EthClient::new(&foreign)
                .transaction(&tx)
                .expect("rpc")
                .expect("tx")
                .to,
            Some([0xDA; 20])
        );

        let pending = base.clone().with_faults(Faults {
            transaction_pending: true,
            ..Faults::default()
        });
        assert_eq!(
            EthClient::new(&pending)
                .transaction(&tx)
                .expect("rpc")
                .expect("tx")
                .block_hash,
            None
        );

        // A height-addressed lookup diverges; a hash-addressed one does not.
        let true_hash = base.block_hash(1).expect("block");
        let divergent = base.with_faults(Faults {
            divergent_canonical_block_hash: true,
            ..Faults::default()
        });
        let by_number = EthClient::new(&divergent)
            .block_by_number(1)
            .expect("rpc")
            .expect("header");
        assert_ne!(by_number.hash, true_hash);
        assert_eq!(
            EthClient::new(&divergent)
                .block_by_hash(&true_hash)
                .expect("rpc")
                .map(|h| h.hash),
            Some(true_hash)
        );
    }

    #[test]
    fn faults_are_actually_injected() {
        let mut base = MockChain::new(31337, [0xC0; 20]).with_blocks(1);
        base.push_claimed([1u8; 32], [2u8; 32], [3u8; 20], [4u8; 32])
            .expect("log");
        base.set_finalized(1);

        let hostile = base.clone().with_faults(Faults {
            wrong_emitter: true,
            ..Faults::default()
        });
        let logs = EthClient::new(&hostile)
            .logs(0, 1, &[0xC0; 20], &[])
            .expect("logs");
        assert_eq!(logs[0].address, [0xDE; 20]);

        let dup = base.clone().with_faults(Faults {
            duplicate_logs: true,
            logs_out_of_order: true,
            ..Faults::default()
        });
        assert_eq!(
            EthClient::new(&dup)
                .logs(0, 1, &[0xC0; 20], &[])
                .map(|l| l.len()),
            Ok(2)
        );

        let noremoved = base.clone().with_faults(Faults {
            drop_removed_field: true,
            ..Faults::default()
        });
        assert_eq!(
            EthClient::new(&noremoved).logs(0, 1, &[0xC0; 20], &[]),
            Err(AdapterError::EvidenceInvalid)
        );

        let garbage = base.with_faults(Faults {
            garbage_results: true,
            ..Faults::default()
        });
        assert!(EthClient::new(&garbage).chain_id().is_err());
    }

    #[test]
    fn finalized_tag_is_absent_until_configured() {
        let c = MockChain::new(31337, [0xC0; 20]).with_blocks(4);
        assert_eq!(
            RpcBlockHeader::parse(
                &c.call("eth_getBlockByNumber", json!(["finalized", false]))
                    .expect("call")
            ),
            Ok(None)
        );
        let c = c.finalize(3);
        let head = RpcBlockHeader::parse(
            &c.call("eth_getBlockByNumber", json!(["finalized", false]))
                .expect("call"),
        )
        .expect("parse")
        .expect("header");
        assert_eq!(head.number, 3);
    }

    #[test]
    fn code_hash_is_stable_and_pinnable() {
        let c = MockChain::new(1337, [0xC0; 20]);
        assert_eq!(EthClient::new(&c).code_hash(&[0xC0; 20]), Ok(c.code_hash()));
        let other = c.clone().with_faults(Faults {
            wrong_code: true,
            ..Faults::default()
        });
        assert_ne!(
            EthClient::new(&other).code_hash(&[0xC0; 20]),
            Ok(c.code_hash())
        );
    }
}
