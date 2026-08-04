# Wallet V3 v0.3.2 rebaseline record

Date: 2026-08-04

## Provenance

| Property | Recorded value |
|---|---|
| Read-only source | `/home/leonardov/dom-wallet-v3` |
| Source branch | `redesign/restore-remote-scan` |
| Source commit | `1868e61bc39eca223d794348d70e48668ad06708` |
| Source tree | `5c572e4b5d083dbb7caa0ca608c0d2864add9f6c` |
| Workspace version | `0.3.2` |
| Previous isolated commit | `abb573168be75b23269343559e4e94e28e9d33e7` |
| Isolated branch | `feat/scriptless-integration` |
| New annotated tag | `baseline/scriptless-wallet-v0.3.2-2026-08-04` |

The official source had no tracked working-tree changes. Its only untracked
entries were the three previously recorded reports. They were not opened for
implementation use and were not imported into the isolated clone.

## Update method and evidence

The isolated clone fetched through its existing `source-local` fetch-only
remote. `git merge-base --is-ancestor` proved that the v0.3.2 commit descends
from the previous baseline. The isolated branch then advanced exclusively with
`git merge --ff-only`; no merge commit, rebase, reset, or checkout-based discard
was used.

After the fast-forward:

- isolated HEAD equals the source commit;
- isolated tree ID equals the source tree ID;
- the previous baseline tag still resolves to `abb573168…`;
- the new baseline tag resolves to `1868e61…`;
- `.githooks/pre-push` retains SHA-256
  `07e168fa9713045f3dd5180393663607023671f884da3535a0188d1aa517c29b`;
- all configured push URLs remain `no_push://push-disabled`;
- none of the three untracked official reports appeared in the clone.

Validation results are recorded in the mission's consolidated report. This
record changes no Wallet source code and authorizes no production use.
