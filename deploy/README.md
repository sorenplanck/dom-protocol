# DOM Protocol Deployment

Two deployment paths: systemd (recommended for VPS/bare-metal) and Docker Compose (recommended for cloud/orchestration). Pick one.

## Path 1 — systemd

### Testnet

    cargo build --release
    sudo useradd -r -s /bin/false dom
    sudo mkdir -p /var/lib/dom-testnet
    sudo chown dom:dom /var/lib/dom-testnet
    sudo cp target/release/dom-node /usr/local/bin/
    sudo mkdir -p /etc/dom
    sudo cp deploy/testnet.toml /etc/dom/testnet.toml
    sudo cp deploy/dom-testnet.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now dom-testnet
    sudo systemctl status dom-testnet
    sudo journalctl -u dom-testnet -f

### Mainnet

Same as testnet but replace every testnet with mainnet:

    sudo mkdir -p /var/lib/dom-mainnet
    sudo chown dom:dom /var/lib/dom-mainnet
    sudo cp deploy/mainnet.toml /etc/dom/mainnet.toml
    sudo cp deploy/dom-mainnet.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now dom-mainnet

The mainnet service ships with stricter hardening than the testnet one (ProtectKernelModules, RestrictRealtime, LimitNOFILE=65536, etc.).

## Path 2 — Docker Compose

    docker compose -f deploy/docker-compose.testnet.yml up -d
    docker compose -f deploy/docker-compose.testnet.yml logs -f dom-node

Data persists in the named volume dom-testnet-data. To wipe:

    docker compose -f deploy/docker-compose.testnet.yml down -v

For mainnet, copy docker-compose.testnet.yml to docker-compose.mainnet.yml, change the port (33370 to 33369), data dir, and seed peers.

## Firewall

    sudo ufw allow 33370/tcp   # Testnet
    sudo ufw allow 33369/tcp   # Mainnet

## Monitoring

    sudo systemctl status dom-testnet
    sudo journalctl -u dom-testnet -n 200 --no-pager
    sudo journalctl -u dom-testnet -f
    docker compose -f deploy/docker-compose.testnet.yml logs -f
    docker exec -it dom-testnet ls -la /var/lib/dom-testnet

## Wallet Setup (Miners)

Set environment variables before start:

    DOM_WALLET_PATH=/var/lib/dom-testnet/miner.wallet
    DOM_WALLET_PASSWORD=<from secrets manager — never in this file>

Then enable mining in the config file:

    mine = true

Restart the service after editing.

Security: wallet password MUST come from a secrets manager (systemd-creds, Docker secrets, Vault, etc.). Never commit it to config files or environment-file plaintext.

## Troubleshooting

### No peers connecting

    sudo ufw status
    sudo netstat -tlnp | grep -E '33369|33370'
    sudo journalctl -u dom-testnet | grep -E 'ERROR|WARN' | head -20

### DNS seeds failing

DNS seeds (testnet-seed1.dom-protocol.org, etc.) are not live yet. Fall back to manual seed_peers:

    seed_peers = ["64.111.92.205:33370"]

Or as env var on the Docker compose file (already pre-configured).

### Sync stuck

    curl -s http://64.111.92.205:33370/health
    df -h /var/lib/dom-testnet

For full hardening, security policy, and operational checklists see docs/DEPLOYMENT.md and docs/SECURITY_AUDIT.md.

Maintained by: Soren Planck — sorenplanck@tutamail.com
