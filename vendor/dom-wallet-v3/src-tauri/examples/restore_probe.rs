//! Headless end-to-end probe for the production seed-restore mechanism.
//!
//! Starts the real embedded Mainnet node and immediately restores a seed
//! WITHOUT waiting for any synchronization, then reports how the background
//! canonical scan advances (cursor, tip, progress, partial balance) until the
//! restore completes.
//!
//! This probe is the regression harness for the v0.2.4 restore gate: the
//! restore call must return in well under a second on a node that has not
//! synchronized a single block.

use dom_wallet_tauri_shell::DesktopApplication;
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn main() {
    let node_directory = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/dom-restore-probe/node".into());
    std::fs::create_dir_all(&node_directory).expect("node directory");
    let wallet_parent = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/tmp/dom-restore-probe/wallets".into());
    std::fs::create_dir_all(&wallet_parent).expect("wallet parent");

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
    let address = listener.local_addr().expect("local address");
    drop(listener);

    let app = DesktopApplication::default();
    println!("[probe] starting embedded Mainnet node at {address} (data: {node_directory})");
    let status = app
        .embedded_node_start_mainnet(&node_directory, address)
        .expect("Mainnet node starts");
    println!(
        "[probe] node start requested: network={:?} lifecycle={:?}",
        status.network, status.lifecycle
    );

    // BIP-39 24-word test vector (zero entropy); owns no outputs on Mainnet.
    let phrase = format!("{}art", "abandon ".repeat(23));
    let destination = std::path::Path::new(&wallet_parent).join("probe-restored");
    let password = "probe-password-123";

    // The restore runs against a node that is still starting and has scanned
    // nothing: it must succeed anyway, immediately and offline.
    let restore_started = Instant::now();
    match app.wallet_restore_from_mnemonic(&destination, password, phrase.as_str()) {
        Ok(result) => {
            println!(
                "[probe] RESTORE RETURNED in {}ms: scanning={} cursor={:?} tip={:?}",
                restore_started.elapsed().as_millis(),
                result.scanning,
                result.wallet.cursor_height,
                result.wallet.tip_height
            );
        }
        Err(error) => {
            println!(
                "[probe] RESTORE FAILED in {}ms: {error}",
                restore_started.elapsed().as_millis()
            );
            println!(
                "[probe] staging left behind: {}",
                std::path::Path::new(&wallet_parent)
                    .join(".probe-restored.seed-restore")
                    .exists()
            );
            let _ = app.application_shutdown();
            std::process::exit(1);
        }
    };
    if restore_started.elapsed() > Duration::from_secs(5) {
        println!("[probe] REGRESSION: the restore blocked on a chain source");
        let _ = app.application_shutdown();
        std::process::exit(2);
    }

    // Unlocking starts the self-healing background scan.
    app.wallet_open_managed(std::path::Path::new(&wallet_parent), "probe-restored")
        .expect("restored wallet opens");
    app.wallet_unlock(password)
        .expect("restored wallet unlocks");

    let scan_started = Instant::now();
    let deadline = scan_started + Duration::from_secs(60 * 60);
    let mut last_line = String::new();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let sync = match app.wallet_sync_status() {
            Ok(sync) => sync,
            Err(error) => {
                println!("[probe] sync status error: {error}");
                continue;
            }
        };
        let line = format!(
            "state={} cursor={:?} tip={:?} progress={:?}% restoring={} partial={:?} error={:?}",
            sync.state,
            sync.cursor_height,
            sync.tip_height,
            sync.scan_progress_percent,
            sync.seed_restore_in_progress,
            sync.partial_balance
                .as_ref()
                .map(|balance| balance.spendable),
            sync.last_error
        );
        if line != last_line {
            println!("[probe] +{:>5}s {line}", scan_started.elapsed().as_secs());
            last_line = line;
        }
        if sync.synchronized && !sync.seed_restore_in_progress {
            println!(
                "[probe] RESTORE SCAN COMPLETE after {}s at height {:?}",
                scan_started.elapsed().as_secs(),
                sync.cursor_height
            );
            break;
        }
        if Instant::now() >= deadline {
            println!("[probe] TIMEOUT waiting for the restore scan after 1h; aborting");
            let _ = app.application_shutdown();
            std::process::exit(3);
        }
    }

    println!(
        "[probe] destination exists: {} | staging left behind: {}",
        destination.exists(),
        std::path::Path::new(&wallet_parent)
            .join(".probe-restored.seed-restore")
            .exists()
    );
    let _ = app.application_shutdown();
}
