# DOM Protocol Troubleshooting

Quick diagnostic commands and common issue resolutions.

## Quick Checks

```bash
cargo build --all 2>&1 | tail -10
cargo test --all 2>&1 | grep "test result:" | tail -10
ps aux | grep dom-node
```

## Common Issues

### "unresolved import"
```bash
python3 scripts/integrate_modules.py
```

### "address already in use"
```bash
pkill -f dom-node
rm -f *.pid
```

See compilation-errors.md and runtime-debugging.md for more.

## Incident Notes

- [chain-persistence-latency-rca.md](./chain-persistence-latency-rca.md) — RCA for the long-running `chain_persistence` integration test
