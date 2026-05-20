# DOM Protocol Deployment

Quick deployment guide for DOM Protocol nodes.

---

## Quick Start (Testnet)

```bash
# 1. Build binaries
cargo build --release

# 2. Create user and directories
sudo useradd -r -s /bin/false dom
sudo mkdir -p /var/lib/dom-testnet
sudo chown dom:dom /var/lib/dom-testnet

# 3. Copy config
sudo cp deploy/testnet.toml /etc/dom/testnet.toml

# 4. Install binary
sudo cp target/release/dom-node /usr/local/bin/

# 5. Install systemd service
sudo cp deploy/dom-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dom-testnet
sudo systemctl start dom-testnet

# 6. Check status
sudo systemctl status dom-testnet
sudo journalctl -u dom-testnet -f
```

---

## Firewall

```bash
# Testnet
sudo ufw allow 33370/tcp

# Mainnet
sudo ufw allow 33369/tcp
```

---

## Monitoring

```bash
# Check node status
dom-cli node status

# View logs
sudo journalctl -u dom-testnet -n 100

# Check peers
dom-cli node peers
```

---

## Wallet Setup (Miners)

```bash
# Create wallet
dom-cli wallet create \
  --path /var/lib/dom-testnet/miner.wallet \
  --password "YOUR_PASSWORD"

# Update config
sudo nano /etc/dom/testnet.toml
# Set: wallet_path and wallet_password

# Restart node
sudo systemctl restart dom-testnet
```

---

## Troubleshooting

### No peers connecting
```bash
# Check firewall
sudo ufw status
sudo netstat -an | grep 33370

# Check logs
sudo journalctl -u dom-testnet | grep ERROR
```

### Sync stuck
```bash
# Compare with explorer
curl https://explorer.dom-protocol.org/api/height

# Check disk space
df -h /var/lib/dom-testnet
```

---

## Support

- Docs: https://docs.dom-protocol.org
- GitHub: https://github.com/sorenplanck/dom-protocol/issues
- Email: sorenplanck@tutamail.com

---

For full documentation, see `docs/DEPLOYMENT.md`
