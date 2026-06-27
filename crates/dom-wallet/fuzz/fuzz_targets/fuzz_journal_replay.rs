#![no_main]
//! Fuzz target: dom_wallet::TxJournal::replay over arbitrary on-disk bytes.
//!
//! Subfamily: fuzz-panic / directed-corruption (Lens A — panic/crash + DoS).
//!
//! Invariant: replaying an ARBITRARY journal file must NEVER panic. Replay is
//! documented as "total": malformed lines, truncated tails, unknown event
//! types, and invalid state transitions are logged and skipped, not fatal.
//! This target writes the fuzz bytes verbatim as `journal.log` and replays it.
//!
//! It also exercises the unbounded `BufReader::lines()` read path (the
//! amplification candidate): a single giant line allocates O(line length).
//! libFuzzer's default max_len bounds the input so this is a panic probe, not
//! an unbounded-memory campaign; the absence of a length cap is recorded as an
//! analysis finding in the dom-shield report rather than asserted here.

use libfuzzer_sys::fuzz_target;
use dom_wallet::TxJournal;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let path = dir.path().join("journal.log");
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let journal = match TxJournal::open(dir.path()) {
        Ok(j) => j,
        Err(_) => return,
    };
    // Must not panic on any input; Ok/Err are both acceptable.
    let _ = journal.replay();
});
