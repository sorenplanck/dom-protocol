# DOM Protocol Audit Report Template

## 1. Executive Summary

State the audit objective, scope, and overall risk assessment.

## 2. Scope Reviewed

List crates, modules, files, and subsystems reviewed.

## 3. Methodology

Describe:

- Static review.
- Test execution.
- Negative testing.
- Threat-model-based review.
- Diff review.
- Any limitations.

## 4. Findings Summary

| ID | Severity | Area | Title | Status |
|----|----------|------|-------|--------|
| DOM-AUDIT-001 | Critical | Consensus | Example | Open |

## 5. Detailed Findings

### DOM-AUDIT-001 — Title

Severity: Critical | High | Medium | Low | Informational  
Area: Consensus | Crypto | Mempool | P2P | Wallet | Storage | CI  
Status: Open | Fixed | Mitigated | Accepted | Needs Review

#### Affected Files

- `path/to/file.rs`

#### Description

Explain the issue clearly.

#### Impact

Explain what an attacker or failure mode could cause.

#### Exploitability

Explain how realistic exploitation is.

#### Evidence

Include code references, tests, command output, or reasoning.

#### Recommended Fix

Explain the safest remediation.

#### Validation Required

List required tests and commands.

## 6. Consensus Impact Assessment

State whether any reviewed or changed logic affects consensus.

## 7. Cryptography Impact Assessment

State whether any reviewed or changed logic affects cryptographic assumptions.

## 8. Mempool/Reorg/Double-Spend Assessment

State whether mempool, reorg, or double-spend behavior was reviewed and what was found.

## 9. Wallet Safety Assessment

State whether wallet behavior was reviewed and what was found.

## 10. P2P/DoS Assessment

State whether P2P and DoS resistance was reviewed and what was found.

## 11. Validation Evidence

Commands run:

```bash
# paste commands here
```

Results:

```text
# paste summarized results here
```

## 12. Files Changed

List all changed files and explain why each was changed.

## 13. Forbidden File Compliance

State whether any forbidden files were touched. If yes, include explicit authorization.

## 14. Remaining Risks

List unresolved risks and recommended next steps.

## 15. Final Recommendation

Choose one:

- Ready for next audit phase.
- Not ready for mainnet.
- Blocked pending critical fixes.
- Requires human cryptography/consensus review.

