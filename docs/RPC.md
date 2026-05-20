# DOM Protocol — JSON-RPC 2.0 API Reference

**Version:** 0.1.0  
**Endpoint:** http://127.0.0.1:33369  
**Protocol:** JSON-RPC 2.0

---

## Methods

### get_info
Get node status and chain tip.

### get_block
Get block by height or hash.

### submit_transaction
Submit transaction to mempool.

### get_peers
List connected peers.

### start_mining / stop_mining
Control mining operations.

---

## Error Codes
- -32700: Parse error
- -32600: Invalid request
- -32601: Method not found
- -32000: Block not found

---

**Maintained by:** Soren Planck
