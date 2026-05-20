#!/usr/bin/env python3
"""
DOM Protocol — Library Integration Script
Adds pub mod xxx; declarations to lib.rs based on existing modules.

Usage:
    python3 scripts/integrate_modules.py [--dry-run]
"""

import os
import sys
from pathlib import Path

DRY_RUN = "--dry-run" in sys.argv

CRATE_MODULES = {
    "dom-wallet": [
        "backup", "coin_selection", "utxo_tracker",
        "transaction_builder", "transaction_flow",
        "hardware", "atomic_swap", "multisig", "coinjoin",
    ],
    "dom-node": [
        "metrics", "time_sync", "checkpoints",
        "peer_discovery", "peer_scoring",
        "rpc_server", "rpc_server_complete", "relay",
    ],
    "dom-crypto": [
        "subgroup", "infinity", "musig2",
    ],
    "dom-consensus": [
        "maturity", "pmmr_validation", "invariants",
    ],
    "dom-chain": [
        "reorg_depth", "kernel_offset",
    ],
    "dom-store": [
        "block_undo", "crash_recovery_tests",
    ],
    "dom-mempool": [
        "pool", "mempool_manager",
    ],
    "dom-wire": [
        "versioning",
    ],
    "dom-pow": [
        "difficulty_tuning",
    ],
}

def integrate_crate(crate_name, modules):
    lib_rs = Path(f"crates/{crate_name}/src/lib.rs")
    
    if not lib_rs.exists():
        print(f"  WARN  {lib_rs} doesnt exist, skipping")
        return False
    
    content = lib_rs.read_text()
    added = []
    
    for module in modules:
        module_file = Path(f"crates/{crate_name}/src/{module}.rs")
        module_dir = Path(f"crates/{crate_name}/src/{module}/mod.rs")
        
        if not module_file.exists() and not module_dir.exists():
            continue
        
        if f"pub mod {module};" in content:
            continue
        
        added.append(module)
    
    if not added:
        print(f"  SKIP  {crate_name}: nothing to add")
        return True
    
    lines = content.split("\n")
    insert_idx = 0
    while insert_idx < len(lines) and (
        lines[insert_idx].startswith("//!") or
        lines[insert_idx].strip() == ""
    ):
        insert_idx += 1
    
    new_declarations = [f"pub mod {m};" for m in added]
    new_declarations.append("")
    
    new_lines = lines[:insert_idx] + new_declarations + lines[insert_idx:]
    new_content = "\n".join(new_lines)
    
    if DRY_RUN:
        print(f"  DRY   {crate_name}: would add {len(added)}: {', '.join(added)}")
    else:
        lib_rs.write_text(new_content)
        print(f"  ADD   {crate_name}: added {len(added)}: {', '.join(added)}")
    
    return True

def main():
    print("DOM Protocol Module Integration")
    print(f"Mode: {'DRY RUN' if DRY_RUN else 'APPLY CHANGES'}")
    print()
    
    if not Path("crates").exists():
        print("ERROR: crates directory not found.")
        sys.exit(1)
    
    for crate_name, modules in CRATE_MODULES.items():
        integrate_crate(crate_name, modules)
    
    print()
    print("Done.")

if __name__ == "__main__":
    main()
