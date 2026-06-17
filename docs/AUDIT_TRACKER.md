# DOM Protocol Audit Tracker

**Phase 1 Started:** 2026-05-19  
**Current Phase:** In Progress  
**Status:** 🔄 Consensus + Crypto Review

---

## PHASE 1: Consensus Layer + Cryptographic Primitives

### Consensus Validators (V1-V18) — RFC-0007 + RFC-0010

**Location:** `crates/dom-consensus/src/`

#### Transaction Validation Steps

| # | Step | File | Status | Notes |
|---|------|------|--------|-------|
| 1 | Canonical decode | `transaction.rs` | ✅ | DomDeserialize implemented |
| 2 | Primitive validation | `transaction.rs` | ✅ | Structure + limits check |
| 2b | Lock height check | `transaction.rs` | ✅ | Temporal validation |
| 3 | Scalar validation | `validate_transaction_structure` | ✅ | Inside structure check |
| 4 | Point validation | `validate_transaction_structure` | ✅ | Commitment parsing |
| 5 | Duplicate detection | `validate_transaction_structure` | ✅ | Input dedup |
| 6 | Range proof validation | `validate_range_proofs` | ✅ | Bulletproofs+ per output |
| 7 | Kernel signature | `validate_kernel_signatures` | ✅ | Schnorr + chain_id |
| 8 | Fee calculation | `validate_transaction` | ✅ | Checked arithmetic |
| 9 | Weight calculation | `validate_transaction` | ✅ | Per RFC-0010 |
| 10 | Balance equation | `validate_balance_equation` | ✅ | Full cryptographic check |

#### Block Validation Steps

| # | Step | File | Status | Notes |
|---|------|------|--------|-------|
| 1 | Canonical decode | `block_full.rs` | ✅ | DomDeserialize |
| 2 | Header syntax | `block.rs` | ✅ | Version, prev_hash validation |
| 3 | Parent lookup | `chain_state.rs` | ✅ | Via LMDB store |
| 4 | Median-time-past | `block.rs` | ✅ | 11-block window |
| 5 | Future timestamp | `block.rs` | ✅ | MAX_FUTURE_BLOCK_TIME=120s |
| 6 | PoW validation | `block.rs` | ✅ | RandomX + target check |
| 7 | Total difficulty | `block.rs` | ✅ | U256 accumulation |
| 8 | TX validation | `block_full.rs` | ✅ | Each TX, all 10 steps |
| 9a | Duplicate detection (pre-cut) | `block_full.rs` | ✅ | Input dedup |
| 9b | Deterministic cut-through | `cutthrough.rs` | ✅ | RFC-0008 §2.3 |
| 9c | Duplicate detection (post-cut) | `block_full.rs` | ✅ | Output dedup |
| 10 | PMMR update | `validate_pmmr_roots` | ✅ | Three MMRs (output/kernel/proof) |
| 11 | PMMR root verification | `validate_pmmr_roots` | ✅ | Header roots match computed |
| 12 | Aggregate balance equation | `block_full.rs` | ✅ | Block-level balance |
| 13 | Weight validation | `block_full.rs` | ✅ | MAX_BLOCK_WEIGHT check |
| 14 | Atomic state commit | `chain_state.rs` | ✅ | LMDB transaction |

---

### Cryptographic Primitives — RFC-0001 + RFC-0009

**Location:** `crates/dom-crypto/src/`

#### Schnorr Signatures (secp256k1, BIP-340)

| Aspect | File | Test Coverage | Status |
|--------|------|----------------|--------|
| **Key Types** | `keys.rs` | `test_secret_key_derives_public_key` | ✅ |
| **Scalar Validation** | `keys.rs` | `test_zero_scalar_rejected` | ✅ |
| **Public Key Parsing** | `keys.rs` | `test_uncompressed_key_rejected` | ✅ |
| **Signature Structure** | `schnorr.rs` | `test_signature_fields_private` | ✅ |
| **Deterministic Signing** | `schnorr.rs` | `test_deterministic_signing` | ✅ |
| **Sign-Verify Roundtrip** | `schnorr.rs` | `test_sign_verify_roundtrip` | ✅ |
| **Wrong Chain ID Fails** | `schnorr.rs` | `test_wrong_chain_id_fails_verify` | ✅ |
| **Cross-Chain Replay Prevention** | `schnorr.rs` | `test_cross_chain_replay_prevented` | ✅ |
| **Invalid s (Zero)** | `schnorr.rs` | `test_invalid_s_zero_rejected` | ✅ |
| **RFC6979 Nonce** | `schnorr.rs` | Implicit (deterministic signing) | ✅ |
| **Challenge Function** | `schnorr.rs` | `test_sign_verify_roundtrip` | ✅ |

#### Pedersen Commitments (secp256k1)

| Aspect | File | Test Coverage | Status |
|--------|------|----------------|--------|
| **Commitment Calculation** | `pedersen.rs` | `test_commitment_deterministic` | ✅ |
| **Different Values → Different Commits** | `pedersen.rs` | `test_different_values_different_commitments` | ✅ |
| **Different Blindings** | `pedersen.rs` | `test_different_blindings_different_commitments` | ✅ |
| **Verify Function** | `pedersen.rs` | `test_commitment_verify` | ✅ |
| **Homomorphic Addition** | `pedersen.rs` | `test_homomorphic_addition` | ✅ |
| **Homomorphic Subtraction** | `pedersen.rs` | `test_homomorphic_subtraction` | ✅ |
| **Point on Curve** | `pedersen.rs` | `test_commitment_roundtrip_bytes` | ✅ |
| **Blinding Zero Rejected** | `pedersen.rs` | `test_zero_blinding_rejected` | ✅ |
| **Balance Equation** | `pedersen.rs` | `test_balance_equation_*` (5 tests) | ✅ |

#### H Generator (RFC9380)

| Aspect | File | Test Coverage | Status |
|--------|------|----------------|--------|
| **Derivation Deterministic** | `h_generator.rs` | `test_h_derivation_is_deterministic` | ✅ |
| **Final Matches Derivation** | `h_generator.rs` | `test_h_final_matches_derivation` | ✅ |
| **Properties Satisfied** | `h_generator.rs` | `test_h_satisfies_all_properties` | ✅ |
| **Not Equal to G** | `h_generator.rs` | `test_h_not_equal_to_g` | ✅ |
| **Binding with Bulletproofs** | `bulletproof.rs` | `test_h_dom_binding_verified` | ✅ |

#### Bulletproofs+ Range Proofs

| Aspect | File | Test Coverage | Status |
|--------|------|----------------|--------|
| **Generator Deterministic** | `bulletproof.rs` | `test_generator_is_deterministic` | ✅ |
| **Prove-Verify Roundtrip** | `bulletproof.rs` | `test_prove_verify_roundtrip_small` | ✅ |
| **Zero Value** | `bulletproof.rs` | `test_prove_verify_zero` | ✅ |
| **Max Supply Value** | `bulletproof.rs` | `test_prove_verify_max_supply` | ✅ |
| **Wrong Commitment Fails** | `bulletproof.rs` | `test_wrong_commitment_fails_verify` | ✅ |
| **Empty Proof Rejected** | `bulletproof.rs` | `test_empty_proof_rejected` | ✅ |
| **Size Limit** | `bulletproof.rs` | `test_proof_size_within_limit` | ✅ |
| **Value Above Max Rejected** | `bulletproof.rs` | `test_value_above_max_rejected` | ✅ |
| **SEC1 ↔ ZKP Format** | `bulletproof.rs` | `test_roundtrip_sec1_zkp_sec1_100_samples` | ✅ |
| **Deterministic Nonce** | `bulletproof.rs` | `prove_with_nonce` function | ✅ |

#### Blake2b-256 Tagged Hashing

| Aspect | File | Test Coverage | Status |
|--------|------|----------------|--------|
| **Deterministic** | `hash.rs` | `test_blake2b_256_is_deterministic` | ✅ |
| **Tagged ≠ Untagged** | `hash.rs` | `test_tagged_hash_differs_from_untagged` | ✅ |
| **Different Tags** | `hash.rs` | `test_different_tags_produce_different_hashes` | ✅ |
| **Incremental = Oneshot** | `hash.rs` | `test_incremental_matches_oneshot` | ✅ |
| **Domain Separation** | `hash.rs` | `test_kernel_sig_tag_vector` | ✅ |

---

## Known Fixes Applied (v5)

### Pedersen/Bulletproof Format Consistency

**Issue:** SEC1 (0x02/0x03) vs ZKP (0x08/0x09) format inconsistency in commitment encoding.

**Status:** ✅ RESOLVED (2026-05-15)

**Solution Implemented:**
- `sec1_to_zkp()`: Convert SEC1 prefix to ZKP by checking `is_square(y)`
- `zkp_to_sec1()`: Convert ZKP back to SEC1 by trying both prefixes
- 200/200 roundtrip tests passing
- 203/203 workspace tests passing
- Phase 2 (full unification) deferred to v1.1

**Files Modified:**
- `crates/dom-crypto/src/bulletproof.rs`
- `Cargo.toml` (expose-field feature for k256)

---

## Test Summary

### Current Test Count

```
Total Passing:    238
Total Failures:   0
Total Ignored:    0

By Crate:
├── dom-consensus:      31 ✅
├── dom-crypto:         17 ✅
├── dom-serialization:  48 ✅
├── dom-rpc:            26 ✅
├── dom-wire:           20 ✅
├── dom-wallet:         11 ✅
├── dom-chain:          15 ✅
├── dom-tx:             15 ✅  (multi-kernel fee tests)
├── dom-pmmr:           12 ✅
├── dom-pow:            8 ✅
├── dom-store:          6 ✅
├── dom-mempool:        5 ✅
├── dom-node:           8 ✅
├── dom-config:         3 ✅
└── Others:             12 ✅
```

### Clippy Status

```
$ cargo clippy --all -- -D warnings
0 warnings
```

### Code Style

```
$ cargo fmt --check
All files properly formatted
```

---

## Audit Findings Tracker

### Phase 1 Findings (To Be Filled By Auditor)

| ID | Severity | Component | Issue | Status | Fix |
|----|-----------| ----------|-------|--------|-----|
| A1-001 | [pending] | consensus | [pending] | ⏳ | ⏳ |
| A1-002 | [pending] | crypto | [pending] | ⏳ | ⏳ |
| ... | ... | ... | ... | ⏳ | ⏳ |

### Phase 2 Findings (Queued)

| ID | Severity | Component | Issue | Status | Fix |
|----|-----------| ----------|-------|--------|-----|
| A2-001 | [pending] | storage | [pending] | ⏳ | ⏳ |
| A2-002 | [pending] | p2p | [pending] | ⏳ | ⏳ |
| ... | ... | ... | ... | ⏳ | ⏳ |

### Wallet v2 Hardening Notes (docs/audits/)

| ID | Severity | Component | Issue | Status | Note |
|----|----------|-----------|-------|--------|------|
| R-31 / R-19 | baixa-média (correção/UX; não-consenso) | dom-wallet2 / coin selection | `create_send` confia no estado persistido e em `meta.last_reconciled_tip`; sem checagem do UTXO ao vivo nem reconcile como pré-condição → pode reservar/montar sobre input não-canônico (rejeitado só no submit; input fica preso) | ✅ (c) implementada (release da reserva no reject do submit); 📝 (b) aberta (frescura antes do send) | [R-31-R-19-coin-selection-freshness.md](audits/R-31-R-19-coin-selection-freshness.md) |
| R-32 | baixa (defensivo; não-consenso) | dom-wallet2 / dom-rpc | wallet não reconcilia `network`/`chain_id` contra o nó antes de scan/submit; `/status` não expõe `chain_id`/genesis | 📝 documentado, não corrigido | [R-32-wallet-node-chain-reconciliation.md](audits/R-32-wallet-node-chain-reconciliation.md) |

---

## Testnet Burn-In Metrics

### Stability

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Uptime** | 99.9% | 18h 38m (100% so far) | ✅ |
| **Block Production** | 156+ | 156 | ✅ |
| **Consensus Failures** | 0 | 0 | ✅ |
| **Critical Errors** | 0 | 0 | ✅ |

### Performance

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| **Block Validation** | <1s | ~200ms (est.) | ✅ |
| **TX Validation** | <100ms | ~50ms per (est.) | ✅ |
| **Sig Verification** | <50ms per kernel | ~30ms (est.) | ✅ |

---

## Next Steps

### Immediate (This Week)

- [ ] **Complete Phase 1 Audit Review**
  - Auditor delivers findings (consensus + crypto)
  - Categorize by severity (CRITICAL / HIGH / MEDIUM / LOW)
  - Developer reviews each finding

- [ ] **Begin Phase 1 Fixes**
  - Prioritize CRITICAL findings
  - Implement patches
  - Add regression tests

### Short-term (Next 2 Weeks)

- [ ] **Phase 1 Re-audit**
  - Auditor verifies fixes
  - Sign-off on consensus + crypto

- [ ] **Phase 2 Audit Start**
  - Storage layer review begins
  - P2P protocol review begins
  - PoW/ASERT review begins

### Medium-term (3-4 Weeks)

- [ ] **Phase 2 Complete**
  - All findings addressed
  - Testnet public announced

- [ ] **Public Testnet Launch**
  - 3+ months burn-in period
  - Community monitoring
  - Block explorer + faucet

---

## Contact & Escalation

| Role | Contact | Escalation |
|------|---------|-----------|
| **Lead Dev** | sorenplanck@tutamail.com | High-severity findings |
| **Security Auditor** | [TBD] | CRITICAL findings only |
| **Community Lead** | [TBD] | Testnet coordination |

---

**Document Owner:** Soren Planck  
**Last Updated:** 2026-05-19  
**Next Update:** Post-Phase 1 Audit Complete
