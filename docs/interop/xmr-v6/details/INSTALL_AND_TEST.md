# Installation and testing

## Requirements

- target checkout at the source-locked DOM commit, unless drift is explicitly accepted;
- Python 3.11+;
- Rust stable 1.85+ for the Monero-oxide raw verifier and GPL sidecar;
- a local Monero regtest/stagenet daemon for live tests.

## Commands

```bash
python3 scripts/apply-v6.py /home/leonardov/dom-protocol
cd /home/leonardov/dom-protocol
bash scripts/xmr-v6/run-v6-gates.sh
```

Build the GPL sidecar separately:

```bash
bash scripts/xmr-v6/build-sidecar.sh
```

The installer applies `patches/dom-real-xmr-secret-forwarding.patch`. It does not
apply `patches/kaystra-terms-v2-cross-curve.patch`.
