//! Regression coverage for `read_list` allocation bounds.
//!
//! `Reader::read_list::<T>(max_count)` rejects a declared count that cannot fit
//! in the remaining input budget before calling `Vec::with_capacity(count)`.
//! These directed cases verify that a tiny count-only buffer cannot force an
//! allocation proportional to an attacker-controlled count.
//!
//! METHOD: a counting global allocator records the peak bytes allocated during a
//! single `read_list` call. We feed a 4-byte buffer (count only, no item bytes)
//! and assert the peak allocation is bounded relative to the input size. A large
//! allocation proportional to the declared count makes the regression test fail.
//!
//! No production change. This test only OBSERVES allocation behavior.

use dom_core::BlockHeight;
use dom_serialization::{DomDeserialize, Reader};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ── Counting allocator ──────────────────────────────────────────────────────────
//
// We track the LARGEST SINGLE allocation request made while armed. This is
// exactly the signal we want: an eager `Vec::with_capacity(count)` asks the
// allocator for one contiguous block proportional to the attacker-controlled
// count. Tracking only the per-call max (never a running total) sidesteps any
// underflow from deallocations of pre-armed allocations.

struct CountingAlloc;

static MAX_SINGLE: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            let sz = layout.size();
            let mut cur = MAX_SINGLE.load(Ordering::Relaxed);
            while sz > cur {
                match MAX_SINGLE.compare_exchange_weak(
                    cur,
                    sz,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(p) => cur = p,
                }
            }
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

/// Run `f`, returning the largest single allocation (bytes) requested while it ran.
fn measure_peak<R>(f: impl FnOnce() -> R) -> (R, usize) {
    MAX_SINGLE.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let r = f();
    ARMED.store(false, Ordering::SeqCst);
    let peak = MAX_SINGLE.load(Ordering::SeqCst);
    (r, peak)
}

#[derive(Debug, PartialEq, Eq)]
struct HeapItem(Vec<u8>);

impl DomDeserialize for HeapItem {
    const MIN_SERIALIZED_SIZE: usize = 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        Ok(Self(r.read_vec(16)?))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Fixed4([u8; 4]);

impl DomDeserialize for Fixed4 {
    const MIN_SERIALIZED_SIZE: usize = 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        Ok(Self(r.read_array::<4>()?))
    }
}

struct ZeroMinimum;

impl DomDeserialize for ZeroMinimum {
    const MIN_SERIALIZED_SIZE: usize = 0;

    fn deserialize(_r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        Ok(Self)
    }
}

struct MaxMinimum;

impl DomDeserialize for MaxMinimum {
    const MIN_SERIALIZED_SIZE: usize = usize::MAX;

    fn deserialize(_r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        Ok(Self)
    }
}

// ── The directed amplification probe ────────────────────────────────────────────
//
// STATUS: GREEN regression — `read_list` now rejects impossible counts before
// any eager allocation proportional to the attacker-controlled count.

#[test]
fn read_list_tiny_buffer_huge_count_bounded_alloc() {
    // 4-byte input: declares 100_000_000 items, ZERO item bytes follow.
    // max_count is large (mirrors a caller that trusts a generous bound).
    const DECLARED: u32 = 100_000_000; // 1e8
    const MAX_COUNT: usize = 200_000_000; // attacker's count is <= max_count
    let input = DECLARED.to_le_bytes(); // exactly 4 bytes

    // Sanity: accepting this declared count would require 800 MB of canonical
    // BlockHeight bytes before any per-item decoding work.
    let would_be = (DECLARED as usize)
        .checked_mul(BlockHeight::MIN_SERIALIZED_SIZE)
        .unwrap();

    let (res, peak) = measure_peak(|| {
        let mut r = Reader::new(&input);
        r.read_list::<BlockHeight>(MAX_COUNT)
    });

    // read_list MUST fail (no item bytes present) — confirm it does not succeed.
    assert!(
        res.is_err(),
        "read_list with no item bytes must error (EOF), not succeed"
    );

    // RESOURCE-LIMIT ASSERT: peak allocation must be bounded by a small multiple
    // of the INPUT size (4 bytes), NOT by the declared count. We allow a generous
    // 64 KiB slack for incidental allocations (error strings, etc.).
    const BOUND: usize = 64 * 1024;
    assert!(
        peak < BOUND,
        "AMPLIFICATION (FIX-QUEUE): read_list eagerly allocated peak={peak} bytes \
         from a 4-byte input declaring count={DECLARED} \
         (would-be with_capacity = {would_be} bytes). \
         Expected < {BOUND} bytes. read_list must validate count against remaining \
         bytes BEFORE with_capacity (e.g. cap capacity at remaining/min_item_size)."
    );
}

#[test]
fn heap_owning_item_uses_wire_minimum_not_rust_layout() {
    let mut input = 2u32.to_le_bytes().to_vec();
    input.extend_from_slice(&0u32.to_le_bytes());
    input.extend_from_slice(&0u32.to_le_bytes());

    let mut r = Reader::new(&input);
    let decoded = r
        .read_list::<HeapItem>(2)
        .expect("two empty heap-owning items fit the serialized byte budget");
    r.finish().expect("all heap item bytes consumed");

    assert_eq!(decoded, vec![HeapItem(Vec::new()), HeapItem(Vec::new())]);
}

#[test]
fn exact_minimum_serialized_budget_is_accepted() {
    let mut input = 2u32.to_le_bytes().to_vec();
    input.extend_from_slice(&[1, 2, 3, 4]);
    input.extend_from_slice(&[5, 6, 7, 8]);

    let mut r = Reader::new(&input);
    let decoded = r
        .read_list::<Fixed4>(2)
        .expect("count times minimum serialized size equals remaining budget");

    assert_eq!(decoded, vec![Fixed4([1, 2, 3, 4]), Fixed4([5, 6, 7, 8])]);
}

#[test]
fn minimum_serialized_budget_overrun_is_rejected_before_allocation() {
    let mut input = 3u32.to_le_bytes().to_vec();
    input.extend_from_slice(&[1, 2, 3, 4]);
    input.extend_from_slice(&[5, 6, 7, 8]);

    let (res, peak) = measure_peak(|| {
        let mut r = Reader::new(&input);
        r.read_list::<Fixed4>(3)
    });

    assert!(
        res.is_err(),
        "three Fixed4 items require 12 serialized bytes after the count prefix"
    );
    assert!(
        peak < 64 * 1024,
        "budget rejection must happen before count-proportional allocation, peak={peak}"
    );
}

#[test]
fn minimum_serialized_budget_multiplication_overflow_is_rejected() {
    let input = 2u32.to_le_bytes();
    let mut r = Reader::new(&input);
    let res = r.read_list::<MaxMinimum>(2);

    assert!(
        res.is_err(),
        "count times minimum serialized size overflow must be rejected"
    );
}

#[test]
fn zero_minimum_serialized_size_is_rejected() {
    let input = 0u32.to_le_bytes();
    let mut r = Reader::new(&input);
    let res = r.read_list::<ZeroMinimum>(0);

    assert!(res.is_err(), "zero minimum serialized size is invalid");
}

#[test]
fn empty_list_is_valid_for_nonzero_minimum_item_type() {
    let input = 0u32.to_le_bytes();
    let mut r = Reader::new(&input);
    let decoded = r
        .read_list::<BlockHeight>(10)
        .expect("empty list is valid when the item type has a nonzero minimum");
    r.finish()
        .expect("empty list consumes only its count prefix");

    assert!(decoded.is_empty());
}

#[test]
fn oversized_count_is_rejected_before_allocation() {
    let input = 11u32.to_le_bytes();
    let (res, peak) = measure_peak(|| {
        let mut r = Reader::new(&input);
        r.read_list::<BlockHeight>(10)
    });

    assert!(res.is_err(), "count over caller cap must be rejected");
    assert!(
        peak < 64 * 1024,
        "caller-cap rejection must happen before count-proportional allocation, peak={peak}"
    );
}

#[test]
fn truncated_item_payload_is_rejected() {
    let mut input = 1u32.to_le_bytes().to_vec();
    input.extend_from_slice(&[1, 2, 3]);
    let mut r = Reader::new(&input);

    assert!(
        r.read_list::<Fixed4>(1).is_err(),
        "declared Fixed4 item with only three payload bytes must be rejected"
    );
}

#[test]
fn existing_valid_blockheight_vector_remains_accepted() {
    let mut input = 2u32.to_le_bytes().to_vec();
    input.extend_from_slice(&7u64.to_le_bytes());
    input.extend_from_slice(&9u64.to_le_bytes());

    let mut r = Reader::new(&input);
    let decoded = r
        .read_list::<BlockHeight>(2)
        .expect("valid BlockHeight list remains accepted");
    r.finish()
        .expect("valid BlockHeight list consumes all bytes");

    assert_eq!(decoded, vec![BlockHeight(7), BlockHeight(9)]);
}

#[test]
fn read_list_count_exceeding_remaining_bytes_must_not_overalloc() {
    // Tighter case: 8-byte input. 4-byte count = 1_000_000, then 4 stray bytes.
    // Even one full BlockHeight (8 bytes) is not present after the count.
    const DECLARED: u32 = 1_000_000;
    let mut input = DECLARED.to_le_bytes().to_vec();
    input.extend_from_slice(&[0u8; 4]); // not even one 8-byte item

    let (res, peak) = measure_peak(|| {
        let mut r = Reader::new(&input);
        r.read_list::<BlockHeight>(usize::MAX) // worst case: no caller bound
    });

    assert!(res.is_err(), "insufficient item bytes must error");

    const BOUND: usize = 64 * 1024;
    assert!(
        peak < BOUND,
        "AMPLIFICATION (FIX-QUEUE): peak={peak} bytes for input of {} bytes \
         declaring count={DECLARED}. read_list pre-allocates with_capacity(count) \
         before bounds-checking item bytes.",
        input.len()
    );
}
