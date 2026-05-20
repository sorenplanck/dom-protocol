# Runtime Debugging

## Logging
```bash
RUST_LOG=debug ./dom-node
RUST_LOG=dom_node=trace ./dom-node
```

## Common Issues

### Node wont start
```bash
sudo lsof -i :33370
```

### Sync stuck
```bash
~/dom/target/release/dom-cli node peers
```

### High memory
```bash
ps aux | grep dom-node
```
