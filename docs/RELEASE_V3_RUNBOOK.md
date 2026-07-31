# DOM Protocol 0.2.0 — publication and rollout runbook

This runbook publishes the Mainnet v3 release and updates the infrastructure in
the required order. It is intentionally fail-closed: do not continue after a
failed checksum, service preflight, restart, or health check.

## 1. Operator variables

Run from the clean `release/mainnet` checkout on the release notebook:

```bash
cd /home/leonardov/dom-release

export RELEASE_BRANCH=release/mainnet
export RELEASE_TAG=v0.2.0
export RELEASE_NAME=dom-node-0.2.0-linux-x86_64
export RELEASE_ASSET="$PWD/dist/$RELEASE_NAME"
export RELEASE_SHA256_FILE="$RELEASE_ASSET.sha256"
export RELEASE_SIGNATURE="$RELEASE_ASSET.minisig"
export RELEASE_NOTES="$PWD/docs/RELEASE_V3.md"

export SEED1_SSH=root@66.42.127.141
export SEED2_SSH=root@64.177.121.62

# No observer SSH destination is declared in this repository or in the
# notebook SSH configuration. Set the real destination before continuing.
export OBSERVER_SSH='root@REPLACE_WITH_OBSERVER_HOST'

# These names and paths match deploy/dom-mainnet.service. If the preflight
# below shows a different installed unit or ExecStart, stop and set the real
# values before changing any server.
export SEED1_UNIT=dom-mainnet.service
export SEED2_UNIT=dom-mainnet.service
export OBSERVER_UNIT=dom-mainnet.service
export REMOTE_BINARY=/usr/local/bin/dom-node
export REMOTE_ASSET=/tmp/dom-node-0.2.0-linux-x86_64

export MINISIGN_SECRET_KEY="${MINISIGN_SECRET_KEY:?export the notebook Minisign secret-key path}"

test "$OBSERVER_SSH" != 'root@REPLACE_WITH_OBSERVER_HOST'
test "$(git branch --show-current)" = "$RELEASE_BRANCH"
test -z "$(git status --porcelain=v1)"
```

The seed addresses above resolve as:

```text
seed1.dom-protocol.org -> 66.42.127.141
seed2.dom-protocol.org -> 64.177.121.62
```

## 2. Final local build and assets

```bash
cd /home/leonardov/dom-release

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
export DOM_BUILD_COMMIT="$(git rev-parse HEAD)"
test "${#DOM_BUILD_COMMIT}" -eq 40
DOM_BUILD_COMMIT="$DOM_BUILD_COMMIT" cargo build --release -p dom-node --bin dom-node

mkdir -p dist
install -m 0755 target/release/dom-node "$RELEASE_ASSET"
"$RELEASE_ASSET" --version

sha256sum "$RELEASE_ASSET" | tee "$RELEASE_SHA256_FILE"
minisign -Sm "$RELEASE_ASSET" \
  -s "$MINISIGN_SECRET_KEY" \
  -t "DOM Protocol 0.2.0 Mainnet hard fork v3"

test -s "$RELEASE_ASSET"
test -s "$RELEASE_SHA256_FILE"
test -s "$RELEASE_SIGNATURE"
test -s "$RELEASE_NOTES"
```

Expected version:

```text
dom-node 0.2.0
```

## 3. Push the release branch

Review exactly what will be published:

```bash
cd /home/leonardov/dom-release
git status --short
git log --oneline origin/release/mainnet..HEAD
git diff --check origin/release/mainnet..HEAD
```

Push only the release branch:

```bash
git push origin release/mainnet
```

Do not use `--force`.

## 4. Create and push the tag

Proposed tag: **`v0.2.0`**.

```bash
cd /home/leonardov/dom-release
test -z "$(git status --porcelain=v1)"
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/release/mainnet)"
test -z "$(git tag --list v0.2.0)"

git tag -a v0.2.0 \
  -m "DOM Protocol 0.2.0 — Mainnet hard fork v3 at height 12500"
git show --no-patch --decorate v0.2.0
git push origin v0.2.0
```

## 5. Create the GitHub release

Attach all four release artifacts:

1. `dom-node-0.2.0-linux-x86_64`
2. `dom-node-0.2.0-linux-x86_64.minisig`
3. `dom-node-0.2.0-linux-x86_64.sha256`
4. `docs/RELEASE_V3.md`

Use the same release notes as the GitHub release body:

```bash
cd /home/leonardov/dom-release

gh release create v0.2.0 \
  "$RELEASE_ASSET" \
  "$RELEASE_SIGNATURE" \
  "$RELEASE_SHA256_FILE" \
  "$RELEASE_NOTES" \
  --title "DOM Protocol 0.2.0 — Mainnet hard fork v3" \
  --notes-file "$RELEASE_NOTES" \
  --verify-tag
```

Record the published URL:

```bash
gh release view v0.2.0 --json url,tagName,name,assets
```

## 6. Remote preflight — no changes

Confirm the installed service and binary path on all three hosts before
uploading anything:

```bash
ssh "$SEED1_SSH" \
  "sudo systemctl cat '$SEED1_UNIT'; sudo systemctl show '$SEED1_UNIT' -p ExecStart -p ActiveState"
ssh "$SEED2_SSH" \
  "sudo systemctl cat '$SEED2_UNIT'; sudo systemctl show '$SEED2_UNIT' -p ExecStart -p ActiveState"
ssh "$OBSERVER_SSH" \
  "sudo systemctl cat '$OBSERVER_UNIT'; sudo systemctl show '$OBSERVER_UNIT' -p ExecStart -p ActiveState"
```

Each unit must be active and its `ExecStart` must resolve to
`/usr/local/bin/dom-node`. If not, stop and correct the corresponding variable;
do not adapt the deployment command while a rollout is in progress.

Load the expected checksum from the signed release asset:

```bash
export RELEASE_SHA256="$(cut -d ' ' -f1 "$RELEASE_SHA256_FILE")"
test "${#RELEASE_SHA256}" -eq 64
```

## 7. Update seed1

Upload, verify, back up, install, restart, and verify:

```bash
scp "$RELEASE_ASSET" "$SEED1_SSH:$REMOTE_ASSET"

ssh "$SEED1_SSH" \
  "set -euo pipefail
   printf '%s  %s\n' '$RELEASE_SHA256' '$REMOTE_ASSET' | sha256sum -c -
   sudo systemctl stop '$SEED1_UNIT'
   if sudo test -e '$REMOTE_BINARY.bak'; then
     sudo mv '$REMOTE_BINARY.bak' '$REMOTE_BINARY.bak.'\"\$(date -u +%Y%m%dT%H%M%SZ)\"
   fi
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY' '$REMOTE_BINARY.bak'
   sudo install -m 0755 '$REMOTE_ASSET' '$REMOTE_BINARY'
   sudo systemctl start '$SEED1_UNIT'
   sudo systemctl is-active '$SEED1_UNIT'
   '$REMOTE_BINARY' --version
   sha256sum '$REMOTE_BINARY'
   curl -fsS http://127.0.0.1:18080/status"
```

Observe seed1 before touching seed2:

```bash
ssh "$SEED1_SSH" \
  "sudo journalctl -u '$SEED1_UNIT' --since '5 minutes ago' --no-pager |
   tail -n 200"
```

Required: active service, `dom-node 0.2.0`, matching SHA-256, increasing height,
connected peers, and no unexpected reputation/finality WARN.

## 8. Update seed2

Only continue after seed1 is healthy:

```bash
scp "$RELEASE_ASSET" "$SEED2_SSH:$REMOTE_ASSET"

ssh "$SEED2_SSH" \
  "set -euo pipefail
   printf '%s  %s\n' '$RELEASE_SHA256' '$REMOTE_ASSET' | sha256sum -c -
   sudo systemctl stop '$SEED2_UNIT'
   if sudo test -e '$REMOTE_BINARY.bak'; then
     sudo mv '$REMOTE_BINARY.bak' '$REMOTE_BINARY.bak.'\"\$(date -u +%Y%m%dT%H%M%SZ)\"
   fi
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY' '$REMOTE_BINARY.bak'
   sudo install -m 0755 '$REMOTE_ASSET' '$REMOTE_BINARY'
   sudo systemctl start '$SEED2_UNIT'
   sudo systemctl is-active '$SEED2_UNIT'
   '$REMOTE_BINARY' --version
   sha256sum '$REMOTE_BINARY'
   curl -fsS http://127.0.0.1:18080/status"
```

Observe seed2 before touching the observer:

```bash
ssh "$SEED2_SSH" \
  "sudo journalctl -u '$SEED2_UNIT' --since '5 minutes ago' --no-pager |
   tail -n 200"
```

Apply the same acceptance criteria used for seed1.

## 9. Update the observer

Only continue after both seeds are healthy:

```bash
scp "$RELEASE_ASSET" "$OBSERVER_SSH:$REMOTE_ASSET"

ssh "$OBSERVER_SSH" \
  "set -euo pipefail
   printf '%s  %s\n' '$RELEASE_SHA256' '$REMOTE_ASSET' | sha256sum -c -
   sudo systemctl stop '$OBSERVER_UNIT'
   if sudo test -e '$REMOTE_BINARY.bak'; then
     sudo mv '$REMOTE_BINARY.bak' '$REMOTE_BINARY.bak.'\"\$(date -u +%Y%m%dT%H%M%SZ)\"
   fi
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY' '$REMOTE_BINARY.bak'
   sudo install -m 0755 '$REMOTE_ASSET' '$REMOTE_BINARY'
   sudo systemctl start '$OBSERVER_UNIT'
   sudo systemctl is-active '$OBSERVER_UNIT'
   '$REMOTE_BINARY' --version
   sha256sum '$REMOTE_BINARY'
   curl -fsS http://127.0.0.1:18080/status"
```

Observe the observer:

```bash
ssh "$OBSERVER_SSH" \
  "sudo journalctl -u '$OBSERVER_UNIT' --since '5 minutes ago' --no-pager |
   tail -n 200"
```

Confirm that its height agrees with both seeds.

## 10. Rollback

Rollback one host at a time. Do not roll back after Mainnet reaches height
12,500, because the legacy binary cannot follow valid v3 blocks.

For a host and unit selected explicitly:

```bash
export ROLLBACK_SSH="$SEED1_SSH"
export ROLLBACK_UNIT="$SEED1_UNIT"

ssh "$ROLLBACK_SSH" \
  "set -euo pipefail
   sudo test -x '$REMOTE_BINARY.bak'
   sudo systemctl stop '$ROLLBACK_UNIT'
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY.bak' '$REMOTE_BINARY'
   sudo systemctl start '$ROLLBACK_UNIT'
   sudo systemctl is-active '$ROLLBACK_UNIT'
   '$REMOTE_BINARY' --version"
```

## 11. Activation monitoring

At height 12,500:

```bash
curl -fsS http://66.42.127.141/status
ssh "$SEED1_SSH" "sudo journalctl -u '$SEED1_UNIT' -f"
ssh "$SEED2_SSH" "sudo journalctl -u '$SEED2_UNIT' -f"
ssh "$OBSERVER_SSH" "sudo journalctl -u '$OBSERVER_UNIT' -f"
```

Monitor:

- block 12,499 is v2 and block 12,500 is v3;
- observer and seeds agree on height and tip;
- normal block cadence continues;
- upgraded peer user-agents advertise `dom-node/0.2.0`;
- no unexpected rolling-finality or reputation-threshold WARN occurs.
