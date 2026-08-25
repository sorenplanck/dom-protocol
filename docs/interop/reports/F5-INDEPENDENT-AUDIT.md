# F5 Independent Audit Record

```text
Date:          2026-08-12
Authority:     Foundation v0.18 (v0.17 closure incorporated); Annex M v3.3; D-027
Scope:         governance; BIP-325; cryptography; evidence/USPE; reproducibility
Method:        five execution-independent review passes over frozen inputs and
               content-addressed outputs; no claim of an external third party
Result:        PASS — no open P0/P1; P2 corrected or adjudicated
```

## 1. Governance

PASS. D-027 is RATIFIED by the operator's explicit decision, D-014 is retained
only as SUPERSEDED history, and the active formula requires regtest plus custom
Signet. Public Signet is optional and has no gate, roadmap or release operand.
Mainnet remains excluded. Current v0.18, the incorporated v0.17 F5 text,
Annex M v3.3, reports, runbook, workflow and guards agree. Historical v0.16/
v3.2 text is preserved and marked superseded; v0.17 is preserved as the F5
closure version and is superseded only by the later D-028 consolidation.

## 2. BIP-325 and network identity

PASS. The network runs unmodified official Bitcoin Core v31.0.0 with the
official Signet miner. The fixed challenge is non-trivial P2PK/1-of-1; its key
is ephemeral, mode 0600 and outside Git. Miner/signer and observer use separate
processes, datadirs, RPC and P2P ports. Genesis, magic, challenge/hash, Core and
miner hashes, peers, CSV and finality policy are frozen. Every recorded miner
command returned 0 and advanced the chain height exactly one block. No
OP_TRUE, fork, mock, btcmock or regtest mining RPC is present in the custom
Signet path.

## 3. Cryptography

PASS. C1a official BIP-327, C1b instrumented semantics, all 24 C2 cells, C3
byte equality and C4 adversarial cases pass. E01-E04 are P2TR key-path claims
using the real MuSig2/adaptor implementation and BIP340 verifier. Each public
extraction record has identical `adaptor_point_T` and
`extracted_t_times_g_point`, with `extracted_t_times_g_equals_t=true`. E05/E06
are Core-validated CSV script-path refunds. CSV=17 is conformance-only and
production CSV=144 passed regtest unchanged.

## 4. Evidence, observer and USPE

PASS. Full blocks validate their Merkle root and witness commitment; linked
headers prove depth 2. The durable observer accepts each event once and labels
the identical redelivery a duplicate. The verifier emits
`VerifiedBitcoinOutcomeV1`, USPE consumes it into `EvidenceVerification`, and
dom-sim proves one economic terminal. Wrong outpoint, mutated witness,
claim/refund race and conflicting funding all fail closed. E07-E09 create
distinct alternate tips and reconfirm every disconnected transaction.

## 5. Reproducibility and secret handling

PASS. The final `manifest.json` covers 82 evidence files; its SHA-256
`39b8dd8ffe0029074a259ab09bd3e90705d1364d600be447aaa92fee3fb129eb`
and every listed file hash were recomputed successfully. Commands, exit codes, durations,
versions, txids/wtxids, raw transactions, outpoints, witnesses, blocks,
headers, network/terms/policy, journals and state receipts are retained. The
final package additionally retains the public deterministic inputs, C1a seed,
invocation contract and explicit entropy boundaries. The corpus-aware scanner
passed over 82 evidence files, and a second extracted-package scan
proved the exact WIF absent; no WIF, scalar, nonce secret or credential is in
Git or evidence.
Configs contain no static RPC credentials. Author and committer for every
closure commit are Soren Planck, with no coauthor trailer.
The complete custom-Signet, regtest and validation sets are published under
`docs/evidence/F5-2026-08-12/` as deterministic archives with external
SHA-256 files and extraction/verification instructions. The validation archive
contains a 46-file manifest, all 19 final zero-exit commands and two successful
10,000-run parser fuzz targets. It also preserves the initial incompatible-
nightly failure and the full from-zero corrected rerun.

## Findings and disposition

No P0 finding was opened. P1 findings found and corrected before closure:

- partial mempool reconstruction during reorg was replaced by explicit,
  ordered, outpoint-checked suffix replay;
- wallet rebroadcast and mempool persistence were disabled and frozen;
- an official-miner zero exit without block acceptance is now rejected by an
  exact height-increment check and replacement branches rotate coinbase payout;
- the frozen Signet genesis internal byte order was corrected and regression
  tested;
- confirmation policy now proves two successor headers rather than relying on
  Core's inclusive confirmation count;
- observer redelivery, E14 witness mutation, logger sealing and secret/public
  evidence separation were corrected before the clean run;
- the missing evidence-decoder and witness-parser fuzz targets were added, and
  zero-input verifier paths were made explicitly fail-closed.

Operational P2 findings (Core v31 `send` response parsing, datadir release
wait, spend-block isolation and shell quoting) were corrected. One global
shellcheck informational warning remains in the unrelated Sepolia runner at
`scripts/sepolia_e2e.sh:717`; it predates and is outside F5, does not affect an
F5 executable path, and was adjudicated as non-blocking rather than changing an
unrelated subsystem. All F5 scripts pass shellcheck and `bash -n`.

There are no open P0 or P1 findings. The five audit tracks are GREEN.
