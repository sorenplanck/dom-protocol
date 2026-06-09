//! Test-only temp-dir cleanup that tolerates Windows file locking.

/// Remove a test data directory, tolerating Windows sharing violations.
///
/// Several tests intentionally still hold a `DomNode`/`DomStore` (and thus a
/// memory-mapped LMDB environment) when they clean up. POSIX allows deleting
/// files with open handles; Windows reports ERROR_SHARING_VIOLATION instead.
/// The removal is test hygiene, not behavior under test, so on Windows a
/// failed removal is ignored (ephemeral CI runners reap the temp dir), while
/// other platforms still panic to surface real cleanup regressions.
pub(crate) fn remove_test_dir(dir: &std::path::Path) {
    if let Err(err) = std::fs::remove_dir_all(dir) {
        if !cfg!(windows) {
            panic!("cleanup test dir {}: {err}", dir.display());
        }
    }
}
