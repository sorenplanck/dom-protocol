# DOM Protocol — Deployment Guide

**Version:** 0.1.0

This document covers current Testnet deployment and the planned
operational path for Mainnet once readiness gates and genesis freeze
are satisfied. For local
development on a laptop / WSL / single CI machine, see
[`REGTEST.md`](./REGTEST.md) — `Network::Regtest` runs the entire
consensus stack with a trivial PoW target, 1-block coinbase maturity,
and a cache-only RandomX VM (~300 MB per node). It is **never** for
production: its magic byte (`DOMR`) and port (33371) are mutually
disjoint from Mainnet (`DOM1` / 33369) and Testnet (`DOMT` / 33370),
so a Regtest node cannot peer with a real network.

---

## Hardware Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 2 GB
- Disk: 50 GB SSD

**Recommended:**
- CPU: 4 cores
- RAM: 4 GB
- Disk: 100 GB NVMe

---

## Installation

```bash
# Build from source
git clone https://github.com/sorenplanck/dom-protocol.git
cd dom-protocol
cargo build --release
```

---

## Configuration

```toml
# testnet.toml
network = "Testnet"
data_dir = "/var/lib/dom"
p2p_listen_addr = "0.0.0.0:33370"
mine = false
```

---

## Systemd Service

For the current devnet/testnet VPS backbone service template, environment
file, install script, health checks, journal logs, update flow, and firewall
commands, see [`BACKBONE_SYSTEMD.md`](./BACKBONE_SYSTEMD.md).

```bash
sudo systemctl enable dom-node
sudo systemctl start dom-node
```

---

## Firewall

```bash
sudo ufw allow 33370/tcp  # Testnet
sudo ufw allow 33369/tcp  # Mainnet
```

---

**Maintained by:** Soren Planck
