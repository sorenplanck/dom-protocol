//! Offline maintenance tool for clearing persisted peer reputation.

use dom_node::node::clear_persisted_peer_reputation;
use dom_store::DomStore;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "dom-peer-reputation-clear".into());
    let Some(data_dir) = args.next() else {
        return Err(format!("usage: {program} <node-data-dir>").into());
    };
    if args.next().is_some() {
        return Err(format!("usage: {program} <node-data-dir>").into());
    }

    let path = Path::new(&data_dir);
    if !path.is_dir() {
        return Err(format!("node data directory does not exist: {}", path.display()).into());
    }

    let store = DomStore::open(path)?;
    clear_persisted_peer_reputation(&store)?;
    println!("cleared persisted peer reputation from {}", path.display());
    Ok(())
}
