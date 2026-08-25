//! Shared scaffolding for the `adapter-evm` integration tests.
//!
//! Everything here drives the deterministic in-crate mock; no test in this
//! crate touches a network.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use adapter_evm::adapter::test_support::{
    sample_config, sample_terms, FIXTURE_BENEFICIARY, FIXTURE_CHAIN_ID, FIXTURE_CONTRACT,
    FIXTURE_FUNDER,
};
use adapter_evm::binding::{
    adaptor_address_of_scalar, adaptor_point_of_scalar, derive_binding, derive_lock_id,
};
use adapter_evm::mock::{Faults, MockChain};
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{EvmAdapter, EvmAdapterConfig, LockTerms};
use counterparty_api::{AdapterError, AdaptorPointBytes};
use serde_json::Value;

/// A [`MockChain`] that can be mutated while an adapter holds it.
#[derive(Clone)]
pub struct SharedChain(Arc<Mutex<MockChain>>);

impl SharedChain {
    pub fn new(chain: MockChain) -> Self {
        Self(Arc::new(Mutex::new(chain)))
    }

    pub fn with_mut<T>(&self, f: impl FnOnce(&mut MockChain) -> T) -> T {
        let mut g = self.0.lock().expect("mock chain lock");
        f(&mut g)
    }

    pub fn with<T>(&self, f: impl FnOnce(&MockChain) -> T) -> T {
        let g = self.0.lock().expect("mock chain lock");
        f(&g)
    }

    pub fn set_faults(&self, faults: Faults) {
        self.with_mut(|c| {
            let replaced = c.clone().with_faults(faults);
            *c = replaced;
        });
    }
}

impl JsonRpc for SharedChain {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        let g = self
            .0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?;
        g.call(method, params)
    }
}

/// A JSON-RPC endpoint that answers honestly and then rewrites the answer.
///
/// `Faults` can only produce the shapes the mock was written for. This
/// interposer produces arbitrary ones, which is what makes it possible to
/// remove exactly one field from exactly one answer — the precision a
/// mutation-killing test needs.
pub struct Rewrite<F> {
    inner: SharedChain,
    rewrite: F,
}

impl<F> Rewrite<F>
where
    F: Fn(&str, &Value, Value) -> Value + Send + Sync,
{
    pub fn new(inner: SharedChain, rewrite: F) -> Self {
        Self { inner, rewrite }
    }
}

impl<F> JsonRpc for Rewrite<F>
where
    F: Fn(&str, &Value, Value) -> Value + Send + Sync,
{
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        let v = self.inner.call(method, params.clone())?;
        Ok((self.rewrite)(method, &params, v))
    }
}

/// Counts the JSON-RPC calls made through it.
///
/// Some properties are only observable as work *not* done: "the finality gate
/// runs before a single round trip is spent", or "the walk stops at the first
/// link the endpoint cannot produce". Those are the properties a hostile
/// endpoint attacks, and a counter is the only way to assert them.
pub struct Counted<R: JsonRpc> {
    inner: R,
    calls: Arc<AtomicUsize>,
}

impl<R: JsonRpc> Counted<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn counter(&self) -> Arc<AtomicUsize> {
        self.calls.clone()
    }

    pub fn count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl<R: JsonRpc> JsonRpc for Counted<R> {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.call(method, params)
    }
}

/// Rewrites one member of every `eth_getBlockByHash` answer.
pub fn block_by_hash_field(
    chain: SharedChain,
    key: &'static str,
    value: Option<Value>,
) -> Rewrite<impl Fn(&str, &Value, Value) -> Value + Send + Sync> {
    Rewrite::new(chain, move |method, _, mut v| {
        if method == "eth_getBlockByHash" {
            if let Some(o) = v.as_object_mut() {
                match &value {
                    Some(x) => {
                        o.insert(key.to_string(), x.clone());
                    }
                    None => {
                        o.remove(key);
                    }
                }
            }
        }
        v
    })
}

/// Rewrites one member of every `eth_getTransactionReceipt` answer.
pub fn receipt_field(
    chain: SharedChain,
    key: &'static str,
    value: Option<Value>,
) -> Rewrite<impl Fn(&str, &Value, Value) -> Value + Send + Sync> {
    Rewrite::new(chain, move |method, _, mut v| {
        if method == "eth_getTransactionReceipt" {
            if let Some(o) = v.as_object_mut() {
                match &value {
                    Some(x) => {
                        o.insert(key.to_string(), x.clone());
                    }
                    None => {
                        o.remove(key);
                    }
                }
            }
        }
        v
    })
}

/// Rewrites one member of every log entry inside every receipt.
pub fn receipt_log_field(
    chain: SharedChain,
    key: &'static str,
    value: Option<Value>,
) -> Rewrite<impl Fn(&str, &Value, Value) -> Value + Send + Sync> {
    Rewrite::new(chain, move |method, _, mut v| {
        if method == "eth_getTransactionReceipt" {
            if let Some(logs) = v.get_mut("logs").and_then(|l| l.as_array_mut()) {
                for entry in logs.iter_mut() {
                    if let Some(o) = entry.as_object_mut() {
                        match &value {
                            Some(x) => {
                                o.insert(key.to_string(), x.clone());
                            }
                            None => {
                                o.remove(key);
                            }
                        }
                    }
                }
            }
        }
        v
    })
}

/// Rewrites one member of every `eth_getTransactionByHash` answer.
pub fn transaction_field(
    chain: SharedChain,
    key: &'static str,
    value: Option<Value>,
) -> Rewrite<impl Fn(&str, &Value, Value) -> Value + Send + Sync> {
    Rewrite::new(chain, move |method, _, mut v| {
        if method == "eth_getTransactionByHash" {
            if let Some(o) = v.as_object_mut() {
                match &value {
                    Some(x) => {
                        o.insert(key.to_string(), x.clone());
                    }
                    None => {
                        o.remove(key);
                    }
                }
            }
        }
        v
    })
}

/// A 32-byte hex word that is not any real hash in a fixture.
pub fn alien_word(tag: u8) -> Value {
    Value::String(format!("0x{}", format!("{tag:02x}").repeat(32)))
}

/// A 20-byte hex address that is not any real address in a fixture.
pub fn alien_address(tag: u8) -> Value {
    Value::String(format!("0x{}", format!("{tag:02x}").repeat(20)))
}

/// A complete, self-consistent fixture: configuration, chain, terms and the
/// identifiers the contract would derive.
pub struct Scenario {
    pub cfg: EvmAdapterConfig,
    pub chain: SharedChain,
    pub terms: LockTerms,
    pub binding: [u8; 32],
    pub lock_id: [u8; 32],
    pub secret: [u8; 32],
    pub adaptor_point: AdaptorPointBytes,
    pub amount: [u8; 32],
    pub deadline: u64,
}

pub const AMOUNT: u128 = 1_000_000_000_000_000_000;
pub const DEADLINE: u64 = 1_900_000_000;

/// Builds a scenario whose chain is empty (genesis only).
pub fn scenario(secret_seed: u8) -> Scenario {
    let mut secret = [0u8; 32];
    secret[31] = secret_seed.max(1);
    secret[11] = secret_seed;

    let chain = MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT);
    let mut cfg = sample_config();
    cfg.expected_code_hash = chain.code_hash();

    let mut terms = sample_terms(&cfg);
    terms.adaptor_address = adaptor_address_of_scalar(&secret).expect("canonical scalar");
    terms.amount = adapter_evm::evidence::amount_word(AMOUNT);
    terms.deadline = DEADLINE;

    let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).expect("binding");
    let lock_id = derive_lock_id(&binding, &cfg.funder).expect("lock id");

    Scenario {
        cfg,
        chain: SharedChain::new(chain),
        terms,
        binding,
        lock_id,
        secret,
        adaptor_point: AdaptorPointBytes(adaptor_point_of_scalar(&secret).expect("point")),
        amount: terms.amount,
        deadline: DEADLINE,
    }
}

impl Scenario {
    pub fn adapter(&self) -> EvmAdapter<SharedChain> {
        EvmAdapter::new(self.cfg, self.chain.clone()).expect("valid configuration")
    }

    /// Mines `n` empty blocks.
    pub fn mine(&self, n: u64) {
        self.chain.with_mut(|c| {
            for _ in 0..n {
                c.push_block();
            }
        });
    }

    /// Mines a block containing this scenario's `LockOpened`.
    pub fn mine_open(&self) -> u64 {
        self.chain.with_mut(|c| {
            let h = c.push_block();
            c.push_lock_opened(
                self.lock_id,
                self.binding,
                FIXTURE_FUNDER,
                FIXTURE_BENEFICIARY,
                self.cfg.asset,
                self.amount,
                self.terms.adaptor_address,
                self.deadline,
            )
            .expect("log appended");
            h
        })
    }

    /// Mines a block containing this scenario's `Claimed`.
    pub fn mine_claim(&self) -> u64 {
        self.chain.with_mut(|c| {
            let h = c.push_block();
            c.push_claimed(self.lock_id, self.binding, FIXTURE_BENEFICIARY, self.secret)
                .expect("log appended");
            h
        })
    }

    /// Mines a block containing this scenario's `Refunded`.
    pub fn mine_refund(&self) -> u64 {
        self.chain.with_mut(|c| {
            let h = c.push_block();
            c.push_refunded(self.lock_id, self.binding, FIXTURE_FUNDER, self.amount)
                .expect("log appended");
            h
        })
    }

    /// Mines a block carrying a `LockOpened` for a *different* session on the
    /// same deployment.
    pub fn mine_foreign_open(&self) -> u64 {
        let mut foreign_terms = self.terms;
        foreign_terms.session_id = [0x99; 32];
        let foreign_binding =
            derive_binding(self.cfg.chain_id, &self.cfg.contract, &foreign_terms).expect("binding");
        let foreign_lock = derive_lock_id(&foreign_binding, &self.cfg.funder).expect("lock id");
        self.chain.with_mut(|c| {
            let h = c.push_block();
            c.push_lock_opened(
                foreign_lock,
                foreign_binding,
                FIXTURE_FUNDER,
                FIXTURE_BENEFICIARY,
                self.cfg.asset,
                self.amount,
                foreign_terms.adaptor_address,
                self.deadline,
            )
            .expect("log appended");
            h
        })
    }

    pub fn finalize(&self, h: u64) {
        self.chain.with_mut(|c| c.set_finalized(h));
    }

    pub fn finalize_tip(&self) {
        self.chain.with_mut(|c| {
            let tip = c.height();
            c.set_finalized(tip);
        });
    }

    pub fn height(&self) -> u64 {
        self.chain.with(|c| c.height())
    }

    pub fn reorg(&self, depth: u64) {
        self.chain.with_mut(|c| c.reorg(depth));
    }
}

/// Runs a future to completion without an async runtime.
pub fn block_on<F: core::future::Future>(f: F) -> F::Output {
    pollster::block_on(f)
}
