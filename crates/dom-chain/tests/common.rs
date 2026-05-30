use dom_chain::ChainState;
use dom_core::{DomError, Hash256};
use dom_store::DomStore;
use std::path::Path;

pub const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

#[allow(dead_code)]
pub fn open_test_store(data_dir: &Path) -> DomStore {
    // Windows CI reserves LMDB map size more strictly than Linux/macOS.
    // These fixtures are tiny, so tests use a small map size explicitly.
    // Production callers still use DomStore::open() and keep the 16 GiB map.
    DomStore::open_with_map_size(data_dir, TEST_LMDB_MAP_SIZE).expect("store open")
}

#[allow(dead_code)]
pub fn open_test_chain(
    data_dir: &Path,
    genesis_hash: Hash256,
    network_magic: u32,
) -> Result<ChainState, DomError> {
    ChainState::open(open_test_store(data_dir), genesis_hash, network_magic)
}
