//! Fast-mode ↔ light-mode equivalence — consensus-critical.
//!
//! The mining path (`MinerVm`, `FLAG_FULL_MEM`, precomputed ~2 GB dataset)
//! MUST produce byte-identical hashes to the validation path (`randomx_hash`,
//! light mode, on-the-fly dataset items) for every (seed, preimage). RandomX
//! defines fast/light as two evaluation strategies of the same function; this
//! test pins that equivalence against upstream drift, wrong flags on the
//! mining path, or dataset init bugs.
//!
//! Runtime note: the first `MinerVm::new` per seed builds the full dataset
//! single-threaded (randomx-rs 1.4.1 exposes no parallel init) — expect this
//! binary to take on the order of minutes. It is kept as a separate test file
//! so `cargo test -p dom-pow` still runs it, but other suites don't wait on
//! the dataset build.

use dom_pow::randomx_pool::{miner_dataset_id_for_seed, randomx_hash};
use dom_pow::MinerVm;

/// One shared seed for the whole binary: the dataset pool holds a single
/// ~2 GB entry, so every test targets the same seed and pays the build once.
const SEED: [u8; 32] = [7u8; 32];

#[test]
fn fast_mode_equals_light_mode_and_dataset_is_reused() {
    // Note: empty input is rejected by randomx-rs (`ParameterError`) on BOTH
    // paths, and pow_preimage is never empty — so no empty vector here.
    let preimages: &[&[u8]] = &[
        b"DOM/randomx/v1/vector/genesis",
        &[0u8],
        b"a",
        &[0u8; 76], // pow_preimage-sized: header bytes minus randomx_hash
        &[0xFFu8; 128],
        b"DOM fast-mode equivalence vector 2026",
    ];

    let miner = MinerVm::new(&SEED).expect("fast-mode miner VM");
    let dataset_id_after_first = miner_dataset_id_for_seed(&SEED)
        .expect("dataset must be pooled after MinerVm::new");

    for preimage in preimages {
        let fast = miner.hash(preimage).expect("fast-mode hash");
        let light = randomx_hash(&SEED, preimage).expect("light-mode hash");
        assert_eq!(
            fast, light,
            "fast/light divergence for preimage {preimage:02x?} — consensus break"
        );
    }

    // Acceptance criterion: the dataset is built once per seed and reused.
    // A second VM (as a second mining worker would create) must attach to the
    // exact same pooled dataset, and hashing must still agree.
    let second_worker = MinerVm::new(&SEED).expect("second fast-mode miner VM");
    let dataset_id_after_second =
        miner_dataset_id_for_seed(&SEED).expect("dataset still pooled");
    assert_eq!(
        dataset_id_after_first, dataset_id_after_second,
        "second MinerVm must reuse the pooled dataset, not rebuild it"
    );
    let fast2 = second_worker
        .hash(preimages[0])
        .expect("second worker hash");
    let light2 = randomx_hash(&SEED, preimages[0]).expect("light-mode hash");
    assert_eq!(fast2, light2);
}

/// The persistent-VM light constructor must also match the validation path —
/// it is the regtest mining path.
#[test]
fn light_miner_vm_equals_validation_hash() {
    let preimage = b"DOM light MinerVm equivalence";
    let vm = MinerVm::new_light(&SEED).expect("light miner VM");
    let via_vm = vm.hash(preimage).expect("light vm hash");
    let via_validation = randomx_hash(&SEED, preimage).expect("validation hash");
    assert_eq!(via_vm, via_validation);
}

/// Frozen cross-check: the fast-mode path must reproduce the frozen consensus
/// vector from `randomx_vectors.rs` (seed = [0;32]). This intentionally uses
/// a second seed: it exercises dataset rotation (pool capacity is 1) and pins
/// fast mode directly to the frozen bytes, not just to light mode.
#[test]
#[ignore = "builds a second ~2 GB dataset (minutes); run explicitly: cargo test -p dom-pow --test miner_light_equivalence -- --ignored"]
fn fast_mode_reproduces_frozen_vector() {
    let seed = [0u8; 32];
    let preimage = b"DOM/randomx/v1/vector/genesis";
    let expected: [u8; 32] = {
        let mut out = [0u8; 32];
        let hex = "5fb8aaf461cbbaf36d5e702afd2ecdda110777bf5b8481739f4dd07764401c9f";
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };
    let miner = MinerVm::new(&seed).expect("fast-mode miner VM");
    assert_eq!(miner.hash(preimage).expect("hash"), expected);
}
