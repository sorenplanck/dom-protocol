//! Sharing one transport between the adapter, the port and the test that
//! drives the world.
//!
//! `EvmAdapter` takes its transport by value, and the EVM-leg driver
//! ([`crate::port::EvmChainPort`]) needs the finalized height, which is another
//! read against the same endpoint. A test additionally needs to *mutate* the
//! deterministic
//! [`adapter_evm::mock::MockChain`] between ticks — mine a block, append a log,
//! inject a reorg — exactly as `f2-harness` mutates its `SimChain` through an
//! `Rc<RefCell<_>>`.
//!
//! `JsonRpc` is `Send + Sync`, so the F2 pattern is spelled here with
//! `Arc<Mutex<_>>` instead of `Rc<RefCell<_>>`. Everything else is the same
//! shape: one shared world, several holders, the test in charge of time.

use std::sync::{Arc, Mutex};

use adapter_evm::rpc::JsonRpc;
use counterparty_api::AdapterError;
use serde_json::Value;

/// A [`JsonRpc`] transport shared by several holders, with mutable access for
/// whoever is simulating the world.
pub struct SharedRpc<R: JsonRpc>(Arc<Mutex<R>>);

impl<R: JsonRpc> Clone for SharedRpc<R> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<R: JsonRpc> SharedRpc<R> {
    /// Wraps a transport.
    pub fn new(inner: R) -> Self {
        Self(Arc::new(Mutex::new(inner)))
    }

    /// Mutable access to the underlying endpoint.
    ///
    /// Only meaningful for a simulated one; a real HTTP transport has nothing
    /// worth mutating. A poisoned lock is reported as unavailability rather
    /// than panicking (I14).
    pub fn with_mut<T>(&self, f: impl FnOnce(&mut R) -> T) -> Result<T, AdapterError> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?;
        Ok(f(&mut guard))
    }

    /// Read-only access to the underlying endpoint.
    pub fn with<T>(&self, f: impl FnOnce(&R) -> T) -> Result<T, AdapterError> {
        let guard = self
            .0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?;
        Ok(f(&guard))
    }
}

impl<R: JsonRpc> JsonRpc for SharedRpc<R> {
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        let guard = self
            .0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?;
        guard.call(method, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_evm::mock::MockChain;
    use serde_json::json;

    #[test]
    fn clones_observe_the_same_world() {
        let a = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        let b = a.clone();
        assert_eq!(a.with(|c| c.height()), Ok(0));
        b.with_mut(|c| {
            c.push_block();
        })
        .expect("lock");
        assert_eq!(a.with(|c| c.height()), Ok(1), "the world is shared");
    }

    #[test]
    fn the_transport_still_answers_json_rpc() {
        let s = SharedRpc::new(MockChain::new(31337, [0xC0; 20]));
        assert_eq!(
            s.call("eth_chainId", json!([])),
            Ok(json!("0x7a69")),
            "31337 == 0x7a69"
        );
    }
}
