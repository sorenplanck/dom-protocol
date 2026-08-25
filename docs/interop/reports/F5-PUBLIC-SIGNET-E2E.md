# Optional Public Signet — Historical Pre-Spend Execution Record

Date: 2026-08-11  
Historical basis: Foundation v0.16; Annex M v3.2; D-014 (SUPERSEDED)
Current authority: Foundation v0.17; Annex M v3.3; D-027
Network: Bitcoin Public Signet  
Result: **OPTIONAL UTILITY NOT EXECUTED BEFORE FUNDING**

This is an observed execution record, not a substitute for on-chain
evidence and not a gate adjudication. Under D-027, Public Signet is outside
the gate, roadmap and release and never blocks F5-F8. No funding transaction
or F5 spend was built, signed, broadcast, or claimed as confirmed. The
operator-provided funding address below is preserved as historical data.

## 1. Commit binding

| Item | Observed value |
|---|---|
| Repository | `https://github.com/sorenplanck/Dom-interop.git` |
| Branch | `main` |
| Technical commit tested and published | `a8981c459e39a43c080b7a77b60163b5c77fdc3a` |
| Technical tree | `4be51370ed3771147a4d82abba8ea84c1a58f762` |
| Technical parent | `e100d1b96596acfbb734f9856af5bd2762f37947` |
| Author and committer | `Soren Planck <sorenplanck@tutamail.com>` |
| Worktree before node preflight | clean; `HEAD == origin/main` |

The technical commit completes the public runner before any chain action:

- E01–E04 use four independent Public-Signet Taproot key-path claim
  sessions and durable two-party nonce vaults;
- E05–E06 use two independent CSV=1 Taproot script-path refunds;
- E12 reopens the E04 vault in a new process and resends the persisted
  partial bytes without recomputation;
- E13/E14 mutate evidence copies only;
- one non-RBF PSBT funds exactly six row-specific P2TR outputs;
- the runner recovers each accepted terms hash from two agreeing F6
  journals and refuses a caller-supplied free hash;
- full blocks returned by Bitcoin Core are checked for their Merkle root
  and witness commitment before `KeystoneBitcoinEvidenceV1` verification;
- only `VerifiedBitcoinOutcomeV1` crosses
  `verified_outcome_to_uspe_event` into USPE;
- every pre-broadcast raw transaction and state transition uses an
  fsync-backed atomic checkpoint; a process lock admits one broadcaster.

## 2. Pre-chain verification

No regtest or custom-Signet node was started. C1–C4 integration suites
were not executed. The requested focused and non-chain checks produced:

| Command | Exit | Observed result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | PASS |
| `cargo build --workspace --locked` | 0 | PASS |
| `cargo test -p f5-e2e --locked` | 0 | PASS, 8 passed, 0 failed |
| `cargo test -p btc-crypto --lib --locked` | 0 | PASS, no library tests |
| `cargo test -p btc-crypto --test backend_pipeline --locked` | 0 | PASS, 3 passed, 0 failed |
| `cargo test -p btc-evidence --locked` | 0 | PASS, 7 passed, 0 failed |
| `cargo test -p uspe --locked` | 0 | PASS, 34 passed, 0 failed |
| `cargo test --workspace --lib --locked` | 0 | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | PASS |
| `shellcheck scripts/f5-signet-public-e2e.sh` | 0 | PASS |
| forbidden network/mining/free-hash guards | 0 | PASS |
| `git diff --check` | 0 | PASS |

The new Public-Signet-only unit coverage separately proved six distinct
contracts, Public-Signet template selection, CSV=1, claim/refund BIP340
verification, exact adaptor-secret extraction (`extracted_t·G = T`),
durable partial persistence, process-style reopen, and byte-identical
resend. No scalar was printed.

## 3. Bitcoin Core observation

The existing datadir was preserved and restarted without reindex,
rescan, deletion, network substitution, mining, or reorg injection:

| Item | Observed value/status |
|---|---|
| Datadir | `/home/leonardov/.bitcoin-f5-signet` |
| Bitcoin Core | `v31.0.0` |
| Configuration | `signet=1`, `server=1`, `txindex=1`, `dbcache=1500` |
| RPC | authenticated and responsive for `getrpcinfo` on `127.0.0.1:38332` |
| Public Signet genesis | configured runner pin `00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6` |
| Public Signet challenge | configured runner pin `512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae` |
| P2P | connected to a Public Signet peer; peer advertised height 317278 |
| Local active height on reopen | 267540 |
| Latest observed active height | 267542 |
| Latest observed verification progress | approximately 0.879255 |
| Initial block download | active |
| Headers vs blocks | approximately 317278 vs 267542; not equal |
| txindex | enabled and synchronized to the local active height |
| Pruning | disabled |
| Free disk | approximately 333 GiB |

The node took approximately four minutes to validate block 267541 and a
further two and a half minutes to reach 267542. It remained about 49,736
blocks behind the observed header tip. Therefore the then-required condition
`initialblockdownload == false && blocks == headers` was not met.

Wallet `f5pub` did not previously exist. The authorized creation request
created its descriptor wallet files. It is now loaded and returned this
fresh Public-Signet funding receive address:

`tb1pdtz7tc5c0qz9n9ln9tecw3e9cg7vm5xx2fydh7r4cl9edevdal3szm4mz8`

The balance and spendable-UTXO query remained blocked by the node's
pending synchronization RPCs and is therefore not asserted here. No
wallet secret or private descriptor was read or logged.

## 4. Accepted-terms observation

No `F5_SIGNET_TERMS_MANIFEST`, accepted-terms file, or pair of persistent
F6 binding journals was found in either repository/worktree, their F5
artifacts, or the operator command history. Consequently there is no
legitimate `rfq_id` from which `f5-e2e recover-terms` can replay both
parties and recover an `accepted_terms_hash`.

The runner deliberately cannot synthesize this input. A JSON assertion
or environment hash is insufficient. This is an independent pre-spend
blocker even after the node completes IBD.

## 5. Published executor contracts

These are deterministic outputs of the published technical commit with
`network=PublicSignet` and `csv_delay=1`. They prove executor publication,
but MUST NOT be funded until a real manifest and both journals bind the
corresponding sessions and accepted terms.

| Row | Address | scriptPubKey |
|---|---|---|
| E01 | `tb1phdrzz85r7wu5r3fw87rhpyuqnzpa4qgdvceehkc8sf6az5n8x5cqs34vqp` | `5120bb46211e83f3b941c52e3f877093809883da810d66339bdb078275d152673530` |
| E02 | `tb1p8wsnvu57fm4yyv34ph4jdjrze5c0xlhxy2c9flyhw42hfrd7edxqq4vpr4` | `51203ba136729e4eea4232350deb26c862cd30f37ee622b054fc977555748dbecb4c` |
| E03 | `tb1p2nqw8vfvengvx2rwtxs92jvu39vcy4xhnjxs5fn7kvag3sntu3rq2k2hrr` | `512054c0e3b12cccd0c3286e59a055499c89598254d79c8d0a267eb33a88c26be446` |
| E04 | `tb1pw0v82d6ckrhdade86akwrykzwp2kj0gc5vdult7acs5lrve59nds9wnmwh` | `512073d8753758b0eedeb727d76ce192c27055693d18a31bcfafddc429f1b3342cdb` |
| E05 | `tb1pt9ng00j98s8ggu7pvup4cp9f7elpu2vq0zthaxg8n9lvwqk78jdslhn3nl` | `5120596687be453c0e8473c167035c04a9f67e1e298078977e9907997ec702de3c9b` |
| E06 | `tb1pnwq46kvzfm42rsdhrwpp9jqfl9m4nnf6xsfkaeuyz87vsru0fdhq3wwqd2` | `51209b815d59824eeaa1c1b71b8212c809f97759cd3a34136ee78411fcc80f8f4b6e` |

| Row | Refund leaf | Control block |
|---|---|---|
| E01 | `0101b275208914ea8a6998f28f46da15dee37006302de835b2bd881fb00c4b64a986b4abc9ac` | `c16ea9d2c09175889fb77bc721fcf740d01f1ccea21ac9f5755ffb043ca9ee5019` |
| E02 | `0101b27520a9b4e3fa397ce2bfcdc7b512ecef65cdda86cad8b9fd1a4015bc3e52aca42a40ac` | `c1e3499a4dac8f12bd8a09390e2c2fb24c0001e018bb7cc17c09878f876de849da` |
| E03 | `0101b2752081f2ba11fcd32bf696f8a182be91045d0d0ffd6f3efc8f4ddff7b7a2d6bf3463ac` | `c1d87a2b8f51fb304e1f066d08a51ce6c9759af8c9f7f1e39dceca106796ad5846` |
| E04 | `0101b275203ea591bcc41f0533840df2988412eceb52a59454520554e03397a4f288963aa5ac` | `c1c955a0b049d388dc6c595f79cca7f43734ce9d5e96bb5d00e570705e05fa0a4a` |
| E05 | `0101b275200be71186dfdaf6bc4530c1697bb61c5369027684f77646e9ed23a8ee65d9ae36ac` | `c01ed9147b2ee778d984d707a72cbc36ef11591d8faa3c204a6f9bb77c9a78a7e2` |
| E06 | `0101b275202a2546babe6ed577cc03584e083982e4ec8a7e7d625d5a3dd430c49138adf3eaac` | `c18e106615e902727b85e06e1dbdb940c02901969dc171ee01d9f563d676c9d062` |

These values are not asserted as accepted terms in this blocked record.

## 6. Optional utility inputs

If the operator independently chooses to resume this optional utility:

1. allow the existing node/datadir to reach the current Public Signet
   tip so `IBD=false`, `blocks=headers`, txindex is current, and `f5pub`
   loads;
2. supply `F5_SIGNET_TERMS_MANIFEST` for exactly E01–E06, with a real
   RFQ and two existing, agreeing F6 journal paths for each row.

The current `f5pub` receive address is
`tb1pdtz7tc5c0qz9n9ln9tecw3e9cg7vm5xx2fydh7r4cl9edevdal3szm4mz8`.
Run `status` after synchronization to obtain the confirmed balance,
spendable UTXO count, and exact funding need. Those values are not
observable yet and are not fabricated here.
The executor's default minimum is 63,000 sat (six 10,000-sat outputs plus
an initial 3,000-sat funding-fee allowance); 73,000 sat is the provisional
recommended wallet balance. The final request remains subject to actual
wallet coin selection and node fee policy.

## 7. Historical optional matrix

| Optional Public-Signet row | Evidence | Utility status |
|---|---|---|
| Public Signet preflight | Correct persistent node and network configuration observed; IBD active and blocks behind headers | BLOCKED |
| E01 DOM→BTC / Bitcoin-first / claim | Published executor contract only; no funding or tx | BLOCKED |
| E02 DOM→BTC / DOM-first / claim | Published executor contract only; no funding or tx | BLOCKED |
| E03 BTC→DOM / Bitcoin-first / claim | Published executor contract only; no funding or tx | BLOCKED |
| E04 BTC→DOM / DOM-first / claim | Published executor contract only; no funding or tx | BLOCKED |
| E05 DOM→BTC / CSV refund | Published CSV=1 executor contract only; no funding or tx | BLOCKED |
| E06 BTC→DOM / CSV refund | Published CSV=1 executor contract only; no funding or tx | BLOCKED |
| E12 resend after partial | Local Public-profile vault reopen regression passed; optional Public-Signet row was not funded | NOT RUN |
| E13 invalid evidence refused | Verifier regression exists; no copied public on-chain evidence exists | BLOCKED |
| E14 tampered witness refused | Verifier regression exists; no copied public on-chain witness exists | BLOCKED |
| Keystone verification | Implementation and btc-evidence tests pass; no public transaction proof exists | BLOCKED |
| USPE consumption | Bridge and USPE tests pass; no verified public outcome exists | BLOCKED |
| Secret scan | Source/build guard passed; no public runtime artifact set exists | BLOCKED |

```text
Public Signet network ........ BLOCKED
DOM→BTC ...................... BLOCKED
BTC→DOM ...................... BLOCKED
BIP340 claim ................. BLOCKED
CSV=1 refund ................. BLOCKED
Keystone verification ........ BLOCKED
USPE consumption ............. BLOCKED
Crash/restore ................ BLOCKED
Byte-identical resend ........ BLOCKED
Secret scan .................. BLOCKED
G-F5 gate effect .............. NONE (D-027)
```

`optional_public_signet_complete` is false. This value has no effect on F5,
G-F5 or any later gate.
