# ADR-0002: Argon2 Memory Zeroization Boundary

Status: Accepted for the isolated storage-cryptography implementation; production object activation remains blocked
Date: 2026-08-05

## Context

The master-key envelope derives its key-encryption key with Argon2id 0.5.3.
The crate's `hash_password_into` convenience method allocates its memory matrix
as an ordinary `Vec<Block>` (`argon2-0.5.3/src/lib.rs:229-231`). Enabling the
dependency's optional `zeroize` feature clears selected internal temporaries
(`argon2-0.5.3/src/lib.rs:322-323,501-504`) and implements `Zeroize` for each
`Block` (`argon2-0.5.3/src/block.rs:151-155`), but the convenience method does
not wrap the complete allocated matrix in a drop guard.

## Decision

Enable the Argon2 `alloc` and `zeroize` features. Do not call
`hash_password_into`. Allocate the exact `Params::block_count()` matrix with a
fallible `try_reserve_exact`, initialize it without further growth, wrap the
owned `Vec<argon2::Block>` immediately in `zeroize::Zeroizing`, and pass its
mutable slice to `hash_password_into_with_memory`.

Allocation failure maps to `CryptoError::KeyDerivationFailed`. The RAII guard
invokes the `Zeroize` implementation for the vector on normal return, error
return, and Rust panic unwinding. The passphrase, Argon output, HKDF output, and
decrypted master key retain their existing owned zeroizing guards.

## Alternatives considered

- Retaining `hash_password_into` was rejected because its allocated matrix has
  no zeroizing owner.
- Enabling only Argon2's `zeroize` feature was rejected because that clears
  selected temporaries but not the convenience method's complete matrix.
- Reducing Argon2 parameters in tests was rejected because it would cease to
  exercise the frozen production profile.
- Claiming that ordinary allocator release erases memory was rejected.

## Residual risk

This is best-effort process-memory zeroization, not an OS remanence guarantee.
It does not prove erasure of compiler-created copies, CPU registers, allocator
metadata, swap, hibernation images, core dumps, hypervisor snapshots, or RAM
after abrupt power loss or process abort. Platform hardening and independent
review remain required before production activation. No claim of complete
system-level memory erasure is made.

## Compatibility

The change does not alter the Argon2id parameters, derived bytes, envelope
format, consensus, or wire data. It changes only ownership of the KDF working
memory and preserves fail-closed behavior.
