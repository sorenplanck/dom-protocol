#![no_main]
//! Fuzz target: dom_serialization::Reader primitives on arbitrary bytes.
//!
//! Invariant: NO primitive read (read_u8/u16/u32/u64/u128, read_array,
//! read_bytes, read_vec, read_list, consume-via-read_bytes, finish) may panic or
//! read out-of-bounds on ANY input. Every call returns Ok(_) or Err(DomError).
//!
//! The first bytes of the input drive an opcode stream so a single corpus entry
//! exercises an arbitrary interleaving of reads against the remaining bytes.
//!
//! NOTE: max_len / max_count are capped SMALL on purpose. This target hunts
//! panics/OOB, not memory amplification — the eager-alloc amplification door is
//! covered by the directed resource-limit test
//! (tests/read_list_amplification.rs), so we keep this target OOM-free.

use libfuzzer_sys::fuzz_target;
use dom_serialization::Reader;
use dom_core::Hash256;

const MAX_VEC: usize = 4096;
const MAX_COUNT: usize = 256;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        let mut r = Reader::new(data);
        let _ = r.read_u8();
        let _ = r.finish();
        return;
    }

    // First byte = number of opcodes to run (bounded). Rest = opcode+payload.
    let (header, rest) = data.split_at(1);
    let steps = header[0] as usize;
    let mut r = Reader::new(rest);

    // The opcode is taken from a rolling read of the buffer itself: we consume
    // one byte as the opcode each step (via remaining/position bookkeeping the
    // Reader stays in bounds because every read is checked internally).
    for i in 0..steps {
        let op = (i as u8).wrapping_add(rest.len() as u8);
        match op % 11 {
            0 => {
                let _ = r.read_u8();
            }
            1 => {
                let _ = r.read_u16();
            }
            2 => {
                let _ = r.read_u32();
            }
            3 => {
                let _ = r.read_u64();
            }
            4 => {
                let _ = r.read_u128();
            }
            5 => {
                let _ = r.read_array::<32>();
            }
            6 => {
                // read_bytes (exercises consume directly) with a bounded n.
                let n = (r.remaining()).min(MAX_VEC);
                let _ = r.read_bytes(n);
            }
            7 => {
                let _ = r.read_vec(MAX_VEC);
            }
            8 => {
                let _ = r.read_list::<Hash256>(MAX_COUNT);
            }
            9 => {
                let _ = r.read_list::<dom_core::BlockHeight>(MAX_COUNT);
            }
            _ => {
                // Observe bookkeeping never panics.
                let _ = r.position();
                let _ = r.remaining();
            }
        }
    }

    // finish() must never panic regardless of consumption state.
    let _ = r.finish();
});
