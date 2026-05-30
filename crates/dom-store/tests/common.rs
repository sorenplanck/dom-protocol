use dom_store::DomStore;
use std::path::Path;

pub const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

#[allow(dead_code)]
pub fn open_test_store(path: &Path) -> DomStore {
    // Windows CI reserves LMDB map size more strictly than Linux/macOS.
    // These storage fixtures are tiny, so tests use a small explicit map
    // size while production callers still use `DomStore::open()` and keep
    // the 16 GiB default. Consensus, reopen, and fail-closed semantics are
    // unchanged because only the fixture allocation size differs.
    DomStore::open_with_map_size(path, TEST_LMDB_MAP_SIZE).expect("open")
}
