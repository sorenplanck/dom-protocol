//! KAV-drift — byte-freeze of the canonical plain-kernel signing message.
//!
//! `plain_kernel_message(fee, lock_height)` is the message both participants
//! sign; if its byte layout silently drifts (tag, field order, endianness), old
//! and new wallets would compute different challenges and every cross-version
//! aggregate signature would fail (or, worse, a malleated layout could collide).
//! These vectors pin the exact 32-byte digest for fixed inputs so any change to
//! the construction (TAG_KERNEL_MSG, KERNEL_FEAT_PLAIN, LE encoding, ordering)
//! turns RED.
//!
//! The frozen values were produced by executing the current implementation; if
//! they ever need updating, that update is a deliberate, reviewed protocol
//! change — never a silent edit.

use dom_slate::plain_kernel_message;

#[test]
fn plain_kernel_message_fee0_lock0_is_frozen() {
    let h = plain_kernel_message(0, 0).expect("kernel message");
    assert_eq!(
        hex::encode(h.as_bytes()),
        "10d43a5ac3160fdbc67a1f8a293f9750558e53c18fa37f58d340df3fdd41aa34",
        "kernel message layout drifted for (fee=0, lock_height=0)"
    );
}

#[test]
fn plain_kernel_message_fee10_lock0_is_frozen() {
    let h = plain_kernel_message(10, 0).expect("kernel message");
    assert_eq!(
        hex::encode(h.as_bytes()),
        "b7c8cad8ef18dd731dbf65a530a68db21d7860b2e3c2957a72d1e90334547719",
        "kernel message layout drifted for (fee=10, lock_height=0)"
    );
}

#[test]
fn plain_kernel_message_fee10_lock144_is_frozen() {
    let h = plain_kernel_message(10, 144).expect("kernel message");
    assert_eq!(
        hex::encode(h.as_bytes()),
        "141ae0b0cf166b400dd6e73994a44bcd3b7eab6c8ef86177fc28f48ebb49f47d",
        "kernel message layout drifted for (fee=10, lock_height=144)"
    );
}

/// Drift sentinel: fee and lock_height must be encoded as DISTINCT fields and
/// little-endian, so swapping the two yields a different digest.
#[test]
fn plain_kernel_message_fee_and_lock_are_not_symmetric() {
    let a = plain_kernel_message(10, 144).expect("a");
    let b = plain_kernel_message(144, 10).expect("b");
    assert_ne!(
        a.as_bytes(),
        b.as_bytes(),
        "fee/lock_height must not be interchangeable in the kernel message"
    );
}
