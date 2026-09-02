# Architecture Foundation

The final crate architecture will be approved only after the foundational specifications are complete.

The design must separate domain state, key management, storage, chain access, synchronization, transaction lifecycle, backup and recovery, APIs, transports, command-line interfaces, and test infrastructure.

Higher-level interfaces may depend on domain contracts. Domain rules must not depend on CLI, HTTP, UI, or concrete node implementations.
