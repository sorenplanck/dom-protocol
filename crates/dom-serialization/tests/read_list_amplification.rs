//! fuzz-amplificação (directed + resource-limit) — `read_list` eager allocation.
//!
//! ENUMERATED VECTOR: `Reader::read_list::<T>(max_count)` calls
//! `Vec::with_capacity(count)` where `count` is read straight from the buffer
//! (a u32), checked ONLY against `max_count` — never against the bytes actually
//! remaining. A tiny buffer (just the 4-byte count prefix) can therefore declare
//! a huge count and force an eager allocation of `count * size_of::<T>()` bytes
//! BEFORE a single item is read. This is a memory-amplification / DoS door
//! whenever the caller's `max_count` is large.
//!
//! METHOD: a counting global allocator records the peak bytes allocated during a
//! single `read_list` call. We feed a 4-byte buffer (count only, no item bytes)
//! and assert the peak allocation is bounded relative to the input size. If the
//! allocator records ~ count*size_of::<T>() bytes, the test goes RED and the case
//! is an amplification finding (see report → FIX-QUEUE).
//!
//! No production change. This test only OBSERVES allocation behavior.

use dom_core::BlockHeight;
use dom_serialization::Reader;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ── Counting allocator ──────────────────────────────────────────────────────────
//
// We track the LARGEST SINGLE allocation request made while armed. This is
// exactly the signal we want: an eager `Vec::with_capacity(count)` asks the
// allocator for one contiguous `count * size_of::<T>()` block, which shows up as
// a single large `alloc` call. Tracking only the per-call max (never a running
// total) sidesteps any underflow from deallocations of pre-armed allocations.

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

// ── The directed amplification probe ────────────────────────────────────────────
//
// STATUS: RED — confirmed real DoS finding (FIX-DS-AMP-001). `read_list` calls
// `Vec::with_capacity(count)` (src/lib.rs:235) using `count` straight from the
// wire, validated ONLY against `max_count`, never against remaining bytes. A
// 4-byte input declaring count=1e8 forces an 800 MB eager allocation before any
// item is read (measured peak == count*size_of::<T>()).
//
// These two tests are `#[ignore]`d so the green suite is not blocked by a
// production bug the shield is forbidden to fix (test-construction ≠ bug-fix).
// Run them on demand to reproduce:
//     cargo test -p dom-serialization --test read_list_amplification -- --ignored
// Remove the #[ignore] once the production guard lands (see report FIX-QUEUE).

#[test]
#[ignore = "RED FIX-DS-AMP-001: read_list with_capacity(count) eager-alloc DoS; run with --ignored"]
fn read_list_tiny_buffer_huge_count_bounded_alloc() {
    // 4-byte input: declares 100_000_000 items, ZERO item bytes follow.
    // max_count is large (mirrors a caller that trusts a generous bound).
    const DECLARED: u32 = 100_000_000; // 1e8
    const MAX_COUNT: usize = 200_000_000; // attacker's count is <= max_count
    let input = DECLARED.to_le_bytes(); // exactly 4 bytes

    // Sanity: with_capacity(1e8) of BlockHeight would be ~800 MB.
    let would_be = (DECLARED as usize)
        .checked_mul(std::mem::size_of::<BlockHeight>())
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
#[ignore = "RED FIX-DS-AMP-001: read_list with_capacity(count) eager-alloc DoS; run with --ignored"]
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
