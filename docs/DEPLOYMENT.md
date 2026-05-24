# DOM Protocol — Deployment Guide

**Version:** 0.1.0

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

**Note:** For local development and integration tests, use `network = "Regtest"` instead. See [REGTEST.md](./REGTEST.md) for details.

---

## Systemd Service

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
