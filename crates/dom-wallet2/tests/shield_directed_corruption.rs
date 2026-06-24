//! dom-shield — directed corruption / poisoned-cursor probes for dom-wallet2.
//!
//! Vectors:
//! - Poisoned cursor (hostile node): `WalletV2State::sync` advances
//!   `meta.last_reconciled_tip` from the TIP REPORTED BY THE SOURCE, and
//!   `sync_if_behind` short-circuits (skips the resync) when
//!   `source_tip - last_reconciled_tip < threshold`. A node that UNDER-reports
//!   the tip can therefore stall the wallet's reconciliation indefinitely, and a
//!   node that OVER-reports advances the cursor past blocks it never served.
//!   These probes document that behavior.
//! - Persisted-state directed corruption complements the src tests: here we
//!   tamper the ENCRYPTED FILE in ways the src suite does not (truncation,
//!   header-byte flips) and assert no panic.
//!
//! These are behavioral probes over the public API; production logic is not
//! modified, and a surprising outcome is REPORTED, not patched.

use dom_wallet2::{
    load_wallet_state, save_wallet_state, BlockRef, ChainSource, Network, OutputOrigin,
    OutputStatus, PersistError, ScanBlock, StoredOutput, SyncError, WalletV2State,
};

const C_R: [u8; 33] = [0xC7u8; 33];

/// A hostile chain source: it reports an arbitrary `tip` (which the wallet
/// trusts) but serves a separately-chosen set of scan blocks. Models a node that
/// lies about the tip and/or withholds blocks.
struct HostileSource {
    reported_tip: BlockRef,
    served: Vec<ScanBlock>,
}

#[derive(Debug, thiserror::Error)]
#[error("hostile")]
struct Never;

impl ChainSource for HostileSource {
    type Error = Never;
    fn tip(&self) -> Result<BlockRef, Never> {
        Ok(self.reported_tip)
    }
    fn scan_range(&self, _from: u64, _to: u64) -> Result<Vec<ScanBlock>, Never> {
        Ok(self.served.clone())
    }
}

fn state_with_receive(tip_cursor: u64) -> WalletV2State {
    let mut state = WalletV2State::new(Network::Regtest, [0u8; 32]);
    state.meta.last_reconciled_tip = tip_cursor;
    state
        .outputs
        .insert(StoredOutput::new_unconfirmed(
            C_R,
            500,
            [0x9au8; 32],
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        ))
        .unwrap();
    state
}

#[test]
fn poisoned_cursor_under_reported_tip_stalls_resync() {
    // The wallet has reconciled to height 100. A real new block 101 confirms the
    // pending receive. A hostile node under-reports the tip as 100 (== cursor),
    // so `sync_if_behind(threshold=1)` sees gap 0 and SKIPS the scan — the wallet
    // never sees the confirming block. This is the stall the probe documents.
    let mut state = state_with_receive(100);
    let hostile = HostileSource {
        reported_tip: BlockRef {
            height: 100,
            hash: [0x64; 32],
        },
        // The node WOULD serve block 101 confirming C_R if asked — but it won't be.
        served: vec![ScanBlock {
            height: 101,
            hash: [101u8; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }],
    };

    let ran = state
        .sync_if_behind(&hostile, 1, 2000)
        .expect("tip reachable");
    assert!(
        ran.is_none(),
        "precondition: under-reported tip skips the scan"
    );
    // The output is NOT confirmed — the wallet was stalled by the lie.
    assert_eq!(
        state.outputs.get(&C_R).unwrap().status,
        OutputStatus::Unconfirmed,
        "DOCUMENTED: under-reported tip leaves a confirmable output unconfirmed \
         (hostile node can stall reconciliation; sync_if_behind trusts source.tip)"
    );
    // Cursor unchanged — still 100.
    assert_eq!(state.meta.last_reconciled_tip, 100);
}

#[test]
fn poisoned_cursor_sync_advances_to_source_reported_tip() {
    // `sync` advances the cursor to `report.tip` (the tip of the SERVED blocks,
    // not an independently-verified height). A node that serves a block at a
    // forged height pushes the cursor to that height. Documents that the cursor
    // is only as trustworthy as the served scan.
    let mut state = state_with_receive(0);
    let forged_height = 5_000_000u64;
    let hostile = HostileSource {
        reported_tip: BlockRef {
            height: forged_height,
            hash: [0xAB; 32],
        },
        served: vec![ScanBlock {
            height: forged_height,
            hash: [0xAB; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }],
    };

    let report = state.sync(&hostile, 0, 2000).expect("sync ok");
    assert_eq!(report.tip.unwrap().height, forged_height);
    assert_eq!(
        state.meta.last_reconciled_tip, forged_height,
        "DOCUMENTED: cursor advanced to the source-reported (forged) tip height"
    );
    // The confirm itself is legitimate IF the block were real (status-only path).
    assert_eq!(
        state.outputs.get(&C_R).unwrap().status,
        OutputStatus::Confirmed
    );
}

#[test]
fn poisoned_cursor_does_not_corrupt_inv_ret() {
    // Even under a hostile source, the INV-RET cardinality guarantee must hold:
    // sync never drops the persisted output regardless of what the node serves.
    let mut state = state_with_receive(0);
    let before = state.outputs.len();
    let hostile = HostileSource {
        reported_tip: BlockRef {
            height: 9,
            hash: [9; 32],
        },
        served: vec![], // node serves NOTHING despite claiming tip 9
    };
    let report = state.sync(&hostile, 0, 2000).expect("sync ok");
    assert_eq!(report.outputs_before, report.outputs_after);
    assert_eq!(
        state.outputs.len(),
        before,
        "INV-RET held under hostile source"
    );
    // Empty view -> the unconfirmed output stays unconfirmed (no false reorg of U).
    assert_eq!(
        state.outputs.get(&C_R).unwrap().status,
        OutputStatus::Unconfirmed
    );
}

// ── Directed corruption of the encrypted persisted state (no panic) ──────────

fn saved_state(path: &std::path::Path) {
    let mut state = WalletV2State::new(Network::Regtest, [0x7e; 32]);
    state
        .outputs
        .insert(StoredOutput::new_unconfirmed(
            C_R,
            500,
            [0x9a; 32],
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1,
        ))
        .unwrap();
    save_wallet_state(&state, path, "pw").unwrap();
}

#[test]
fn truncated_wallet_file_is_rejected_without_panic() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("wallet.dat");
    saved_state(&path);

    let full = std::fs::read(&path).unwrap();
    // Truncate to various lengths: 0, mid-header, just-past-header, mid-body.
    for cut in [0usize, 8, 32, 64, full.len() / 2] {
        let cut = cut.min(full.len());
        std::fs::write(&path, &full[..cut]).unwrap();
        let res = load_wallet_state(&path, "pw");
        assert!(
            res.is_err(),
            "truncated-to-{cut} file must be rejected, not loaded"
        );
        // Must be a typed PersistError, never a panic (catch_unwind would have
        // unwound before this assert if it panicked).
        match res {
            Err(PersistError::Envelope(_))
            | Err(PersistError::UnsupportedSchema(_))
            | Err(PersistError::Store(_)) => {}
            Ok(_) => panic!("truncated file unexpectedly loaded"),
        }
    }
}

#[test]
fn header_byte_flips_are_rejected_without_panic() {
    // The 64-byte envelope header is: magic[0..14], version[14..16],
    // salt[16..48], nonce[48..60], padding[60..64]. The loader validates
    // magic+version, then reads salt+nonce for the KDF/AEAD; the 4 padding bytes
    // are NOT validated and are not AEAD-bound, so flipping them yields a still-
    // loadable file (documented below). Every flip must, regardless, be
    // PANIC-FREE. One representative byte per region keeps the Argon2id KDF cost
    // to ~6 derivations (seconds), not 64.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("wallet.dat");

    // (byte index, must-be-rejected?) — padding bytes are NOT rejected.
    let cases: [(usize, bool); 6] = [
        (0, true),   // magic
        (13, true),  // magic (last)
        (14, true),  // version
        (20, true),  // salt -> wrong KDF key -> Decryption error
        (50, true),  // nonce -> AEAD failure -> Decryption error
        (61, false), // padding -> ignored, file still loads (documented)
    ];

    for (i, must_reject) in cases {
        saved_state(&path);
        let mut data = std::fs::read(&path).unwrap();
        data[i] ^= 0xFF;
        std::fs::write(&path, &data).unwrap();

        let res = std::panic::catch_unwind(|| load_wallet_state(&path, "pw"));
        assert!(
            res.is_ok(),
            "PANIC: loading a wallet with header byte {i} flipped panicked"
        );
        let loaded = res.unwrap();
        if must_reject {
            assert!(
                loaded.is_err(),
                "corrupted header byte {i} (validated region) must be rejected"
            );
        } else {
            // DOCUMENTED: padding bytes 60..64 are not validated nor AEAD-bound,
            // so a flip there is silently accepted. Not a panic surface; recorded
            // as a (benign) integrity gap — the AEAD still protects the payload.
            assert!(
                loaded.is_ok(),
                "padding byte {i} flip unexpectedly changed load outcome"
            );
        }
    }
}

#[test]
fn random_garbage_file_is_rejected_without_panic() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("garbage.dat");
    for len in [0usize, 1, 63, 64, 65, 200] {
        let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
        std::fs::write(&path, &bytes).unwrap();
        let res = std::panic::catch_unwind(|| load_wallet_state(&path, "pw"));
        assert!(
            res.is_ok(),
            "PANIC: garbage file of len {len} panicked the loader"
        );
        assert!(res.unwrap().is_err());
    }
    let _ = SyncError::<Never>::Source(Never); // keep the import meaningful
}
