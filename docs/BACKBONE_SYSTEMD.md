# DOM Backbone systemd service

This runbook installs and operates a DOM devnet/testnet backbone node on a
Linux VPS using systemd. It does not define consensus behavior and does not
store wallet secrets.

The current `dom-node` binary defaults to `Network::Testnet`. Use this backbone
profile for devnet/testnet infrastructure. Mainnet operation remains gated by
mainnet readiness, genesis finalization, and release-blocker policy.

## Files

- `deploy/dom-backbone.service` -> `/etc/systemd/system/dom-backbone.service`
- `deploy/dom-backbone.env.example` -> `/etc/dom/backbone.env`
- `docs/BACKBONE_SYSTEMD.md` -> `/usr/local/share/doc/dom/BACKBONE_SYSTEMD.md`
- Node data: `/var/lib/dom-backbone`
- Binary: `/usr/local/bin/dom-node`

`/etc/dom/backbone.env` is local process configuration only. Do not place
wallet passwords, seed phrases, private keys, API tokens, or bearer tokens in
the unit file or environment file.

## Install

Build or obtain the release binary, then copy it into place:

```bash
cargo build --release -p dom-node
sudo install -m 0755 target/release/dom-node /usr/local/bin/dom-node
```

Install the service files:

```bash
sudo scripts/install_dom_backbone_systemd.sh
```

Review `/etc/dom/backbone.env` before starting:

```bash
sudoedit /etc/dom/backbone.env
```

Default environment values:

```ini
DOM_DATA_DIR=/var/lib/dom-backbone
DOM_P2P_LISTEN_ADDR=0.0.0.0:33370
DOM_LOG=info
```

Optional private devnet/testnet bootstrap peers can be set as a comma-separated
list:

```ini
DOM_SEED_PEERS=198.51.100.10:33370,198.51.100.11:33370
```

## Operate

Start:

```bash
sudo systemctl start dom-backbone
```

Stop:

```bash
sudo systemctl stop dom-backbone
```

Restart:

```bash
sudo systemctl restart dom-backbone
```

Enable at boot:

```bash
sudo systemctl enable dom-backbone
```

Status and health:

```bash
sudo systemctl status dom-backbone --no-pager
systemctl is-active dom-backbone
journalctl -u dom-backbone -n 100 --no-pager
```

The service uses `Restart=always` with `RestartSec=10`, so repeated crashes are
visible in `systemctl status` and `journalctl`.

## Logs

Logs go to journald:

```bash
journalctl -u dom-backbone -f
journalctl -u dom-backbone --since "1 hour ago"
```

Do not paste secrets into logs or issue reports. The backbone unit and env
example intentionally contain no wallet password, seed, private key, or token
fields.

## Update binary

```bash
sudo systemctl stop dom-backbone
cargo build --release -p dom-node
sudo install -m 0755 target/release/dom-node /usr/local/bin/dom-node
sudo systemctl start dom-backbone
sudo systemctl status dom-backbone --no-pager
```

The data directory is not replaced by the update command.

## Firewall

Open the configured P2P port. The default devnet/testnet backbone port is
`33370/tcp`:

```bash
sudo ufw allow 33370/tcp
```

For a private deployment, restrict the source addresses where possible.

## Troubleshooting

Check that the binary exists and is executable:

```bash
test -x /usr/local/bin/dom-node
```

Check that the environment file is readable by the service:

```bash
sudo systemctl cat dom-backbone
sudo ls -l /etc/dom/backbone.env
```

Check recent restarts:

```bash
systemctl show dom-backbone -p NRestarts -p ExecMainStatus -p ExecMainCode
```
