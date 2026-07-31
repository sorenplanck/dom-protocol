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
export RELEASE_ASSET="$PWD/target/release/dom-node"
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
export REMOTE_ASSET=/tmp/dom-node-v0.2.0

test "$OBSERVER_SSH" != 'root@REPLACE_WITH_OBSERVER_HOST'
test "$(git branch --show-current)" = "$RELEASE_BRANCH"
test -z "$(git status --porcelain=v1)"
```

The seed addresses above resolve as:

```text
seed1.dom-protocol.org -> 66.42.127.141
seed2.dom-protocol.org -> 64.177.121.62
```

## 2. Final compatible build and unsigned assets

The release binary must run on the Ubuntu 22.04 infrastructure
(`GLIBC 2.35`). Do not publish a binary built directly on a newer workstation:
that artifact may acquire a `GLIBC_2.38` dependency and fail before `main`.
Build in the pinned Debian Bullseye container, then test the result in an
Ubuntu 22.04 container.

```bash
cd /home/leonardov/dom-release

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
export DOM_BUILD_COMMIT="$(git rev-parse HEAD)"
test "${#DOM_BUILD_COMMIT}" -eq 40

docker run --rm \
  -e DOM_BUILD_COMMIT="$DOM_BUILD_COMMIT" \
  -v "$PWD:/src:ro" \
  -v "$PWD/target/release-compatible:/out" \
  rust:1.82-bullseye \
  bash -lc '
    apt-get update
    apt-get install -y --no-install-recommends build-essential cmake pkg-config libclang-dev clang
    cp -a /src /build
    cd /build
    CARGO_TARGET_DIR=/cargo-target cargo build --locked --release -p dom-node --bin dom-node
    install -m 0755 /cargo-target/release/dom-node /out/dom-node
  '

install -m 0755 target/release-compatible/dom-node "$RELEASE_ASSET"
"$RELEASE_ASSET" --version

docker run --rm \
  -v "$RELEASE_ASSET:/usr/local/bin/dom-node:ro" \
  ubuntu:22.04 \
  /usr/local/bin/dom-node --version

sha256sum "$RELEASE_ASSET" | tee "$RELEASE_SHA256_FILE"

test -s "$RELEASE_ASSET"
test -s "$RELEASE_SHA256_FILE"
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
  -m "DOM Protocol 0.2.0 — hard fork v3 + correções de rede"
git show --no-patch --decorate v0.2.0
git push origin refs/tags/v0.2.0
```

Confirm that the branch and tag both resolve to the intended commit:

```bash
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/release/mainnet)"
test "$(git rev-list -n 1 v0.2.0)" = "$(git rev-parse HEAD)"
git rev-parse HEAD
```

The final command prints the exact revision that Wallet V3 must pin.

## 5. Create the unsigned draft GitHub release

Create the draft with these two unsigned artifacts:

1. `dom-node`
2. `dom-node.sha256`

Use the same release notes as the GitHub release body:

```bash
cd /home/leonardov/dom-release

gh release create v0.2.0 \
  --draft \
  --title "DOM Protocol 0.2.0" \
  --notes-file "$RELEASE_NOTES" \
  "$RELEASE_ASSET" \
  "$RELEASE_SHA256_FILE"
```

Record the draft URL:

```bash
gh release view v0.2.0 --json url,isDraft,tagName,name,assets
```

The operator signs the exact uploaded `dom-node` file. Codex must neither
request nor handle the Minisign private key. After signing, the operator adds
the detached signature without replacing the binary:

```bash
minisign -Sm "$RELEASE_ASSET"
test -s "$RELEASE_SIGNATURE"
gh release upload v0.2.0 "$RELEASE_SIGNATURE"
```

Verify all three assets, then publish the draft in the GitHub UI. The expected
final asset set is `dom-node`, `dom-node.sha256`, and `dom-node.minisig`.

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
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
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
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
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
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
```

Observe the observer:

```bash
ssh "$OBSERVER_SSH" \
  "sudo journalctl -u '$OBSERVER_UNIT' --since '5 minutes ago' --no-pager |
   tail -n 200"
```

Confirm that its height agrees with both seeds.

## 10. Explicit rollback per machine

Rollback one host at a time. Do not roll back after Mainnet reaches height
12,500, because the legacy binary cannot follow valid v3 blocks.

### Seed1 rollback

```bash
ssh "$SEED1_SSH" \
  "set -euo pipefail
   sudo test -x '$REMOTE_BINARY.bak'
   sudo systemctl stop '$SEED1_UNIT'
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY.bak' '$REMOTE_BINARY'
   sudo systemctl start '$SEED1_UNIT'
   sudo systemctl is-active '$SEED1_UNIT'
   '$REMOTE_BINARY' --version
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
```

### Seed2 rollback

```bash
ssh "$SEED2_SSH" \
  "set -euo pipefail
   sudo test -x '$REMOTE_BINARY.bak'
   sudo systemctl stop '$SEED2_UNIT'
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY.bak' '$REMOTE_BINARY'
   sudo systemctl start '$SEED2_UNIT'
   sudo systemctl is-active '$SEED2_UNIT'
   '$REMOTE_BINARY' --version
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
```

### Observer rollback

```bash
ssh "$OBSERVER_SSH" \
  "set -euo pipefail
   sudo test -x '$REMOTE_BINARY.bak'
   sudo systemctl stop '$OBSERVER_UNIT'
   sudo cp --preserve=mode,timestamps '$REMOTE_BINARY.bak' '$REMOTE_BINARY'
   sudo systemctl start '$OBSERVER_UNIT'
   sudo systemctl is-active '$OBSERVER_UNIT'
   '$REMOTE_BINARY' --version
   curl -fsS http://127.0.0.1:3371/metrics |
     grep -E '^(dom_chain_height|dom_best_known_peer_height|dom_peer_count) '"
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
