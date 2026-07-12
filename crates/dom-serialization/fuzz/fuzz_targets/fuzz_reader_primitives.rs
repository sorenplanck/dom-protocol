#![no_main]
//! Fuzz target: dom_serialization::Reader primitives on arbitrary bytes.
//!
//! Invariant: NO primitive read (read_u8/u16/u32/u64/u128, read_array,
//! read_bytes, read_vec, read_list, consume-via-read_bytes, finish) may panic or
//! read out-of-bounds on ANY input. Every call returns Ok(_) or Err(DomError).
//!
//! The first byte selects the number of operations. Each operation code is
//! deterministically derived from its index and the remaining-input length, so a
//! corpus entry exercises a repeatable interleaving of reads against its suffix.
//!
//! NOTE: max_len / max_count are capped SMALL on purpose. This target hunts
//! panics/OOB, not memory amplification — the eager-alloc amplification door is
//! covered by the directed resource-limit test
//! (tests/read_list_amplification.rs), so we keep this target OOM-free.

use dom_core::Hash256;
use dom_serialization::{DomDeserialize, Reader};
use libfuzzer_sys::fuzz_target;

const MAX_VEC: usize = 4096;
const MAX_COUNT: usize = 256;

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

struct NestedVecItem;

impl DomDeserialize for NestedVecItem {
    const MIN_SERIALIZED_SIZE: usize = 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, dom_core::DomError> {
        let _ = r.read_vec(MAX_VEC)?;
        Ok(Self)
    }
}

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

    // Operation selection is deterministic from the loop index and input length;
    // it does not consume opcode bytes from the Reader.
    for i in 0..steps {
        let op = (i as u8).wrapping_add(rest.len() as u8);
        match op % 14 {
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
            10 => {
                let _ = r.read_list::<ZeroMinimum>(MAX_COUNT);
            }
            11 => {
                let _ = r.read_list::<MaxMinimum>(MAX_COUNT);
            }
            12 => {
                let _ = r.read_list::<NestedVecItem>(MAX_COUNT);
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
