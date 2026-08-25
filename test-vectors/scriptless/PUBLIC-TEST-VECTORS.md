# Public test-vector safety notice

> [!CAUTION]
> TEST VECTOR ONLY — PUBLIC AND INSECURE
>
> NEVER USE THIS SEED, KEY, NONCE, SCALAR, OR MNEMONIC ON MAINNET

Every value below this directory is public test material. It may include fixed
secret scalars, auxiliary randomness, nonce material, signing shares, and
adaptor secrets. These values exist solely for deterministic conformance and
must never control funds or assets of value.

The two signed input JSON files retain their immutable conditional status text.
Their detached Minisign signatures bind the exact input bytes supplied and
ratified by the operator; the files were not edited during publication
preparation. The independent reference programs and outputs remain frozen at
their pre-comparison hashes. The adjacent manifest records the complete public
evidence set without changing any signed or frozen file.

Running a generator does not make its outputs independent. The committed
reference outputs are independent evidence only because their implementation
and expected bytes were frozen before comparison with the Rust production
implementation.

## Frozen historical instructions

The immutable independent-set README records the feature names and report path
used by the original post-barrier comparison environment. Those historical
instructions are not commands for this publication branch: `dom-adaptor`
intentionally exposes no `fuzzing` or `test-helpers` feature, and the
machine-specific comparison report is deliberately excluded. The committed
crate-local comparison adapter is compiled only under `cfg(test)`, reads the
unchanged frozen output, and asserts all 311 checkpoints through the public
production boundary. The current Cargo manifests, not the frozen historical
instructions, define the supported build graph.
