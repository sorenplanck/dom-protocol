//! Gate G0 — Phase-2 entry reality check (Master Specification §15.7).
//!
//! This is the STOP-SHIP baseline: before any Scriptless/DL2P work may enter
//! Phase 2, the protocol must prove that an ORDINARY 1→1 payment still works
//! end-to-end, through the CURRENT wallet engine and the CURRENT slate version,
//! on a clean regtest with TWO independent nodes and TWO independent wallets.
//!
//! ## What "current" means in this repository
//!
//! `dom-wallet` (v1) is **frozen and deprecated** — see
//! `crates/dom-wallet/src/lib.rs:5-19` ("DEPRECATED — wallet v1 … New user-wallet
//! work goes to `dom-wallet2`"). The current user-wallet engine is
//! **`dom-wallet2`**, which is what the shipping desktop wallet embeds
//! (`wallet-desktop/src-tauri/Cargo.toml:64`,
//! `wallet-desktop/src-tauri/src/wallet_manager.rs:1`). So G0 drives
//! `dom_wallet2::{create_send, receive, finalize_tracked, submit_finalized}` and
//! `CURRENT_SLATE_VERSION` — NOT v1, NOT `dom_tx::SpendBuilder`, NOT any miner
//! helper, NOT any Scriptless type.
//!
//! v1 appears in exactly one place and only as the node's own coinbase builder:
//! `dom-node` still mines into a v1 `WalletDir` (`crates/dom-node/src/miner.rs:995`),
//! and `NodeConfig::miner_address` is dead config (its only repo-wide read is the
//! `Debug` impl at `crates/dom-config/src/lib.rs:217`), so pointing the node at a
//! v1 wallet dir is the ONLY way to choose who earns the coinbase. Alice's v2
//! wallet then claims those coinbases through the production restore path,
//! because v1 and v2 derive the coinbase blinding from the SAME audited source:
//!   * v1: `crates/dom-wallet/src/wallet.rs:886` + `:888`
//!   * v2: `crates/dom-wallet2/src/keychain.rs:73` + `:82`
//!   * both → `dom_wallet_keys::seed::coinbase_blinding` (`m/44'/330'/0'/1'/h'`)
//! This is byte-identity already frozen by
//! `crates/dom-wallet2/tests/shield_xdiff_blinding_byte_identity.rs:52`.
//!
//! ## PoW mode
//!
//! `Network::Regtest` is a pure function to `FastDevOnly`
//! (`crates/dom-pow/src/lib.rs:611-613`), and the miner allocates **no RandomX VM
//! at all** in that mode (`crates/dom-node/src/miner.rs:1229` returns `Ok(None)`).
//! Regtest coinbase maturity is 1 (`crates/dom-core/src/constants.rs:420`). This
//! is the repository's own supported development mode — the same one
//! `spend_e2e.rs` and `transfer_slate_e2e.rs` already run unignored on every CI
//! invocation — not a bespoke shortcut. Consensus validation is unchanged.
//!
//! ## Forbidden shortcuts NOT taken
//!
//! No transaction bytes are edited, no miner-internal transaction builder is
//! called, the slate is never skipped, nothing is inserted into a wallet store or
//! the chain DB by hand, and no verification is disabled. Every value that lands
//! in a wallet arrives through `reconcile`/`restore` over canonical chain data.

use std::time::Duration;

use dom_consensus::transaction::Transaction;
use dom_core::{Hash256, GENESIS_HASH_REGTEST, INITIAL_BLOCK_REWARD};
use dom_integration_tests::helpers::*;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::{Slate, CURRENT_SLATE_VERSION};
use dom_wallet::{Network as V1Network, WalletDir};
use dom_wallet_keys::seed::Bip39Seed;
use dom_wallet2::{
    create_send, finalize_tracked, load_wallet_state, receive, restore_coinbase_from_seed,
    save_wallet_state, submit_finalized, ChainSource, KeychainV2, Network as V2Network,
    OutputStatus, RpcChainSource, RpcSourceError, StoredOutput, WalletV2State,
};

/// The chain id the NODE validates kernel signatures against:
/// `derive_chain_id(network_magic, genesis_hash)` — see
/// `crates/dom-node/src/node.rs:369` (`snapshot_tx_chain_view`) feeding
/// `Mempool::accept_tx_with_chain_view`.
///
/// **G0-BLOCKER-002.** The CURRENT wallet does not use this value. Wallet v1
/// derives it correctly and internally (`crates/dom-wallet/src/wallet.rs:170`,
/// `:210`, `:272` — `dom_consensus::derive_chain_id(network.magic(),
/// genesis_hash)`), which is why the v1 end-to-end test `transfer_slate_e2e.rs`
/// passes. Wallet v2 takes `chain_id` verbatim in
/// `WalletV2State::new(network, chain_id)`
/// (`crates/dom-wallet2/src/wallet_state.rs:58`) and the shipping desktop wallet
/// hands it the **underived genesis hash**
/// (`wallet-desktop/src-tauri/src/wallet_manager.rs:1206-1210`,
/// `genesis_chain_id` → `dom_core::startup_genesis_hash_for_network_magic`).
/// Since the aggregate kernel Schnorr signature binds the chain id, every
/// transaction the current wallet builds is rejected by every node.
/// `g0_current_wallet_chain_id_is_rejected_by_consensus` pins that empirically.
///
/// The canonical §15.7 scenario below therefore uses the CORRECT (node-agreeing)
/// chain id, so the remaining §15.7 criteria can actually be measured instead of
/// all collapsing behind the same single blocker.
fn node_chain_id() -> [u8; 32] {
    *dom_consensus::derive_chain_id(
        dom_core::NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(GENESIS_HASH_REGTEST),
    )
    .as_bytes()
}

/// What the shipping desktop wallet actually configures today.
const DESKTOP_CHAIN_ID: [u8; 32] = GENESIS_HASH_REGTEST;

/// A deliberately non-boundary amount: not zero, not the whole balance, not a
/// power of two, not equal to the reward or the fee.
const G0_AMOUNT: u64 = 1_234_567_890;
/// Non-boundary fee.
const G0_FEE: u64 = 1_234_567;

/// Funding blocks mined for Alice. With regtest maturity 1, at tip K the
/// coinbases from heights 1..=K-1 are mature.
const K_FUNDING: u64 = 4;

const RPC_TIMEOUT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// G0-BLOCKER-001 shim: inject the bearer token `RpcChainSource` cannot send.
// ---------------------------------------------------------------------------

/// A transparent HTTP forwarder that adds `Authorization: Bearer <token>` to
/// every request before passing it to the node.
///
/// **Why this exists is itself a G0 finding.** The current wallet's only chain
/// source, `dom_wallet2::RpcChainSource`, builds a bare
/// `reqwest::blocking::Client` with nothing but a timeout
/// (`crates/dom-wallet2/src/rpc_source.rs:113-116`), keeps that client PRIVATE
/// (`:102-107`), and takes only `(base_url, timeout)` in `new` (`:112`). It never
/// sets an `Authorization` header. But the node mounts `GET /chain/scan` inside
/// the bearer-protected router (`crates/dom-rpc/src/lib.rs:380` → `:387` →
/// `:392-395`), and `require_bearer_token`
/// (`crates/dom-rpc/src/middleware.rs:139-173`) has no loopback exemption and
/// 401s an empty configured token outright (`:144-146`). So the wallet's read
/// half CANNOT talk to any node this repository builds.
///
/// `g0_current_wallet_rpc_scanner_is_locked_out_of_the_node` measures that
/// directly. This shim then supplies the token the wallet cannot, so the REST of
/// §15.7 can still be measured over the real HTTP path (real `RpcChainSource`
/// code: real paging, real DTO decoding, real retry/status mapping) instead of
/// being reported as unknown.
async fn spawn_bearer_shim(upstream: String, token: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("shim bind");
    let addr = listener.local_addr().expect("shim addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let upstream = upstream.clone();
            let token = token.clone();
            tokio::spawn(async move {
                // 1. Read the request head (everything up to the blank line).
                let mut buf = Vec::new();
                let head_end = loop {
                    let mut chunk = [0u8; 4096];
                    let n = match client.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                    if buf.len() > 64 * 1024 {
                        return;
                    }
                };

                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_string();

                // 2. Rebuild the headers: drop Connection/Authorization, add ours.
                let mut content_length = 0usize;
                let mut kept = Vec::new();
                for line in lines {
                    if line.is_empty() {
                        continue;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if lower.starts_with("connection:") || lower.starts_with("authorization:") {
                        continue;
                    }
                    kept.push(line.to_string());
                }
                kept.push(format!("Authorization: Bearer {token}"));
                // Force one request per connection so the response framing is a
                // plain "copy until EOF" on both sides.
                kept.push("Connection: close".to_string());

                let mut out = format!("{request_line}\r\n");
                for h in kept {
                    out.push_str(&h);
                    out.push_str("\r\n");
                }
                out.push_str("\r\n");
                let mut wire = out.into_bytes();

                // 3. Body: whatever already arrived, plus the rest.
                let mut body = buf[head_end..].to_vec();
                while body.len() < content_length {
                    let mut chunk = [0u8; 4096];
                    match client.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                wire.extend_from_slice(&body);

                // 4. Forward, then stream the response straight back.
                let Ok(mut up) = TcpStream::connect(&upstream).await else {
                    return;
                };
                if up.write_all(&wire).await.is_err() {
                    return;
                }
                let _ = up.flush().await;
                let _ = tokio::io::copy(&mut up, &mut client).await;
                let _ = client.shutdown().await;
            });
        }
    });

    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Wallet helpers — production APIs only.
// ---------------------------------------------------------------------------

/// Build a fresh v2 wallet state from a BIP-39 seed, exactly as the shipping
/// desktop wallet does in `new_state_from_seed`
/// (`wallet-desktop/src-tauri/src/wallet_manager.rs:1198-1203`).
fn v2_wallet_from_seed(seed: &Bip39Seed) -> WalletV2State {
    v2_wallet_from_seed_with_chain_id(seed, node_chain_id())
}

/// Same, with an explicit chain id (used to reproduce the desktop's configuration).
fn v2_wallet_from_seed_with_chain_id(seed: &Bip39Seed, chain_id: [u8; 32]) -> WalletV2State {
    let mut state = WalletV2State::new(V2Network::Regtest, chain_id);
    state.keychain = KeychainV2 {
        seed_bytes: Some(zeroize::Zeroizing::new(*seed.seed_bytes())),
        seed_word_count: Some(seed.word_count() as u8),
        ..Default::default()
    };
    state
}

/// Pre-create the node's v1 `WalletDir` from a chosen seed, exactly like the
/// CLI/desktop do (the node refuses to create wallets — DOM-SEC-004). This is
/// what decides WHO earns the coinbase; the value is claimed by the v2 wallet.
fn node_wallet_dir_from_seed(path: &std::path::Path, password: &str, seed: &Bip39Seed) {
    let _ = std::fs::remove_dir_all(path);
    WalletDir::create_from_seed(
        path,
        password,
        V1Network::Regtest,
        &Hash256::from_bytes(GENESIS_HASH_REGTEST),
        seed,
    )
    .expect("create node wallet dir from seed");
}

/// Confirmed, maturity-aware spendable total — the same predicate
/// `dom_wallet2::payment` uses for coin selection
/// (`crates/dom-wallet2/src/payment.rs:74-82`).
fn confirmed_total(state: &WalletV2State, tip: u64) -> u64 {
    let maturity = state.network.coinbase_maturity();
    state
        .outputs
        .iter()
        .filter(|o| o.status == OutputStatus::Confirmed)
        .filter(|o| {
            !o.is_coinbase
                || o.origin_block
                    .map(|b| tip.saturating_sub(b.height) >= maturity)
                    .unwrap_or(false)
        })
        .map(|o| o.value)
        .sum()
}

/// Every confirmed output regardless of maturity (used for the change assertion,
/// which must not be confused by an immature coinbase).
fn confirmed_outputs(state: &WalletV2State) -> Vec<&StoredOutput> {
    state
        .outputs
        .iter()
        .filter(|o| o.status == OutputStatus::Confirmed)
        .collect()
}

/// Drive the production restore + reconcile cycle for a v2 wallet against a node,
/// exactly as the desktop's `recover_from_seed` does
/// (`wallet-desktop/src-tauri/src/wallet_manager.rs:1076-1110`).
///
/// `RpcChainSource` uses `reqwest::blocking`, which panics if driven from inside
/// a Tokio worker, so it runs on a blocking thread.
async fn wallet_rescan(state: &mut WalletV2State, base_url: &str, now: u64) -> u64 {
    let url = base_url.to_string();
    let keychain = state.keychain.clone();
    let (blocks, tip_height) = tokio::task::spawn_blocking(move || {
        let src = RpcChainSource::new(url, RPC_TIMEOUT).expect("rpc source");
        let tip = src.tip().expect("node tip over /chain/scan");
        let blocks = src
            .scan_for_restore(0, tip.height)
            .expect("chain scan for restore");
        (blocks, tip.height)
    })
    .await
    .expect("blocking rescan task");

    let recovered = restore_coinbase_from_seed(&keychain, &blocks, now).expect("restore coinbase");
    for out in recovered {
        // Insert only what the store does not already track; `insert` is the
        // store's own API and rejects duplicates.
        if state.outputs.get(&out.commitment).is_none() {
            state.outputs.insert(out).expect("insert recovered coinbase");
        }
    }
    state.reconcile_from_restore_blocks(&blocks, now);
    tip_height
}

/// Serialize → deserialize a slate, so every hop between Alice and Bob crosses
/// the real wire format rather than passing a live Rust value.
fn over_the_wire(slate: &Slate) -> Slate {
    let bytes = slate.to_bytes().expect("slate serialize");
    let back = Slate::from_bytes(&bytes).expect("slate deserialize");
    assert_eq!(
        back.to_bytes().expect("reserialize"),
        bytes,
        "slate must round-trip byte-identically"
    );
    back
}

/// Independent verification of a finalized transaction by a party that did not
/// build it: canonical-byte round trip plus the consensus validator itself.
fn verify_final_tx(tx: &Transaction, tip: u64, label: &str) -> Vec<u8> {
    verify_final_tx_with_chain_id(tx, tip, label, node_chain_id())
}

fn verify_final_tx_with_chain_id(
    tx: &Transaction,
    tip: u64,
    label: &str,
    chain_id: [u8; 32],
) -> Vec<u8> {
    let bytes = tx.to_bytes().expect("tx serialize");
    let decoded = Transaction::from_bytes(&bytes).expect("tx deserialize");
    let rebytes = decoded.to_bytes().expect("tx reserialize");
    assert_eq!(
        rebytes, bytes,
        "{label}: canonical tx bytes must round-trip byte-identically"
    );

    let ctx = dom_consensus::ValidationContext {
        current_height: dom_core::BlockHeight(tip),
        chain_id,
        now: dom_core::Timestamp(now_secs()),
    };
    dom_consensus::validate_transaction(&decoded, &ctx)
        .unwrap_or_else(|e| panic!("{label}: consensus rejected the finalized tx: {e:?}"));
    bytes
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

// ---------------------------------------------------------------------------
// G0-BLOCKER-001 — measured in isolation.
// ---------------------------------------------------------------------------

/// The current wallet's chain scanner, unmodified, against a node this
/// repository builds. §15.7 requires the receiver to detect its output "via the
/// normal scanner"; this measures whether the normal scanner can reach a node at
/// all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g0_current_wallet_rpc_scanner_is_locked_out_of_the_node() {
    init_tracing();

    let rpc_port = free_local_port();
    let rpc_addr = format!("127.0.0.1:{rpc_port}");
    let mut config = test_config("g0-authprobe", free_local_port(), false);
    config.rpc_listen_addr = Some(rpc_addr.clone());
    config.rpc_bearer_token = Some("g0-probe-token".into());

    let node = spawn_node(config).await;
    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&rpc_addr, 15)
        .await
        .expect("RPC listener");
    mine_blocks(&node, 2).await.expect("mine");

    let base = format!("http://{rpc_addr}");
    let err = tokio::task::spawn_blocking(move || {
        let src = RpcChainSource::new(base, RPC_TIMEOUT).expect("rpc source");
        src.tip()
    })
    .await
    .expect("blocking probe");

    match err {
        Ok(tip) => panic!(
            "G0-BLOCKER-001 appears fixed: RpcChainSource reached /chain/scan and got tip {tip:?}. \
             Re-adjudicate Gate G0 — the criterion this test pins has changed."
        ),
        Err(RpcSourceError::Status(401)) => {
            eprintln!(
                "[G0-BLOCKER-001 CONFIRMED] dom_wallet2::RpcChainSource::tip() -> 401 Unauthorized.\n\
                 The node mounts GET /chain/scan behind require_bearer_token \
                 (crates/dom-rpc/src/lib.rs:380 -> :392-395; \
                 crates/dom-rpc/src/middleware.rs:139-173), while RpcChainSource sends no \
                 Authorization header and exposes no way to set one \
                 (crates/dom-wallet2/src/rpc_source.rs:102-122).\n\
                 Impact: WalletV2State::sync, sync_if_behind, scan_for_restore and therefore the \
                 desktop wallet's recover_from_seed (wallet-desktop/src-tauri/src/wallet_manager.rs:1076) \
                 cannot read the chain from ANY node this repo builds. The two comments asserting \
                 /chain/scan is public are wrong: wallet-desktop/src-tauri/src/lib.rs:92 and \
                 wallet-desktop/src-tauri/src/wallet_manager.rs:16-20."
            );
        }
        Err(other) => panic!("expected 401 from /chain/scan, got {other:?}"),
    }

    // The write half is genuinely public and must keep working.
    let base = format!("http://{rpc_addr}");
    let submit_reachable = tokio::task::spawn_blocking(move || {
        // An empty body is rejected by the handler, but a 4xx from the HANDLER
        // (not 401 from the auth layer) proves the route is unauthenticated.
        reqwest::blocking::Client::new()
            .post(format!("{base}/tx/submit"))
            .json(&serde_json::json!({ "tx_hex": "00" }))
            .send()
            .map(|r| r.status().as_u16())
    })
    .await
    .expect("blocking submit probe")
    .expect("submit request");
    assert_ne!(
        submit_reachable, 401,
        "POST /tx/submit must remain public (crates/dom-rpc/src/lib.rs:375)"
    );
    eprintln!("[G0] POST /tx/submit is public (status {submit_reachable}) — broadcast half is fine");

    node.request_shutdown().await;
}

// ---------------------------------------------------------------------------
// §15.7 canonical scenario.
// ---------------------------------------------------------------------------

/// The §15.7 canonical scenario, with the placeholder API names substituted by
/// the real ones in this repository.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g0_plain_send_1_to_1_regtest_current_slate() {
    init_tracing();
    let started = std::time::Instant::now();

    // ── 0. Clean regtest, two independent nodes, two independent wallets. ────
    let alice_seed = Bip39Seed::generate_new().expect("alice seed");
    let bob_seed = Bip39Seed::generate_new().expect("bob seed");
    assert_ne!(
        alice_seed.seed_bytes(),
        bob_seed.seed_bytes(),
        "Alice and Bob must be independent wallets"
    );

    let tmp = tempfile::tempdir().expect("tmp");
    let alice_nodewallet = tmp.path().join("alice-node-wallet.dom");
    let alice_v2_path = tmp.path().join("alice-v2.wallet");
    let bob_v2_path = tmp.path().join("bob-v2.wallet");
    node_wallet_dir_from_seed(&alice_nodewallet, "pw-alice", &alice_seed);

    let data_dir_a = tmp.path().join("node-a");
    let data_dir_b = tmp.path().join("node-b");
    let p2p_a = free_local_port();
    let p2p_b = free_local_port();
    let rpc_a = format!("127.0.0.1:{}", free_local_port());
    let rpc_b = format!("127.0.0.1:{}", free_local_port());
    let p2p_a_addr = format!("127.0.0.1:{p2p_a}");
    let p2p_b_addr = format!("127.0.0.1:{p2p_b}");

    let mut cfg_a = test_config("g0-alice", p2p_a, false);
    cfg_a.data_dir = data_dir_a.to_string_lossy().into_owned();
    cfg_a.wallet_path = Some(alice_nodewallet.to_string_lossy().into_owned());
    cfg_a.wallet_password = Some("pw-alice".into());
    cfg_a.rpc_listen_addr = Some(rpc_a.clone());
    cfg_a.rpc_bearer_token = Some("g0-token-a".into());

    let mut cfg_b = test_config("g0-bob", p2p_b, false);
    cfg_b.data_dir = data_dir_b.to_string_lossy().into_owned();
    cfg_b.seed_peers = vec![p2p_a_addr.clone()];
    cfg_b.rpc_listen_addr = Some(rpc_b.clone());
    cfg_b.rpc_bearer_token = Some("g0-token-b".into());
    // Bob's node has NO wallet: Bob must start at zero and every nom he ends up
    // with has to arrive from Alice.

    let node_a = spawn_node(cfg_a).await;
    let node_b = spawn_node(cfg_b).await;
    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready(&p2p_a_addr, 15).await.expect("A p2p");
    wait_for_listener_ready(&rpc_a, 15).await.expect("A rpc");
    tokio::spawn(node_b.clone().run());
    wait_for_listener_ready(&p2p_b_addr, 15).await.expect("B p2p");
    wait_for_listener_ready(&rpc_b, 15).await.expect("B rpc");
    wait_for_peer_count(&node_b, 1, Duration::from_secs(45))
        .await
        .expect("B must connect to A");

    let shim_a = spawn_bearer_shim(rpc_a.clone(), "g0-token-a".into()).await;
    let shim_b = spawn_bearer_shim(rpc_b.clone(), "g0-token-b".into()).await;

    let mut alice = v2_wallet_from_seed(&alice_seed);
    let mut bob = v2_wallet_from_seed(&bob_seed);
    assert_eq!(alice.chain_id, bob.chain_id, "same regtest chain id");

    eprintln!(
        "[G0] commit-under-test worktree; slate version = {CURRENT_SLATE_VERSION}; \
         network = Regtest (FastDevOnly PoW, no RandomX VM); maturity = {}",
        alice.network.coinbase_maturity()
    );

    // ── 1. Mine ONLY to fund Alice. Bob starts at zero. ─────────────────────
    mine_blocks(&node_a, K_FUNDING).await.expect("funding mine");
    wait_for_height(&node_b, K_FUNDING, Duration::from_secs(60))
        .await
        .expect("funding blocks must propagate A -> B");

    let now = now_secs();
    let tip = wallet_rescan(&mut alice, &shim_a, now).await;
    assert_eq!(tip, K_FUNDING, "Alice's node must be at the funding tip");
    let alice_funded = confirmed_total(&alice, tip);
    assert_eq!(
        alice_funded,
        (K_FUNDING - 1) * INITIAL_BLOCK_REWARD,
        "Alice must hold exactly the matured coinbases (regtest maturity 1)"
    );

    let _ = wallet_rescan(&mut bob, &shim_b, now).await;
    assert_eq!(
        confirmed_total(&bob, tip),
        0,
        "Bob must start with zero balance"
    );
    assert_eq!(bob.outputs.len(), 0, "Bob must own no outputs at the start");

    // ── 2. Bob generates a receive request through the current normal flow. ──
    let request = bob
        .keychain
        .create_receive_request(G0_AMOUNT)
        .expect("bob receive request");
    assert_eq!(request.amount, G0_AMOUNT);
    assert_eq!(request.index, 0, "first request uses index 0");
    assert_eq!(
        bob.keychain.next_receive_index, 1,
        "the receive cursor must advance (it is persisted state)"
    );

    // ── 3. Alice builds the send with the wallet's PUBLIC API. ──────────────
    // Real coin selection, real change, current slate version. No lock height:
    // `create_send` does not expose one (see the height-locked cover test).
    let sent = create_send(&mut alice, request.amount, G0_FEE, now).expect("alice create_send");
    assert_eq!(
        sent.slate.version, CURRENT_SLATE_VERSION,
        "G0 requires the CURRENT slate version"
    );
    assert_eq!(sent.slate.amount, G0_AMOUNT);
    assert_eq!(sent.slate.fee, G0_FEE);
    assert_eq!(sent.slate.lock_height, 0, "plain send");
    assert!(
        !sent.slate.sender_inputs.is_empty(),
        "real coin selection must pick real inputs"
    );
    let change = sent
        .slate
        .sender_change_output
        .as_ref()
        .expect("a 1->1 send from a large coinbase must produce real change");
    let change_commitment = *change.commitment.as_bytes();
    let selected_sum: u64 = INITIAL_BLOCK_REWARD * sent.slate.sender_inputs.len() as u64;
    let expected_change = selected_sum - G0_AMOUNT - G0_FEE;
    assert!(expected_change > 0, "the scenario must exercise change");

    // No Scriptless / DL2P / recovery-extension fields on the wire.
    assert!(
        sent.slate.sender_change_recovery_capsule.is_empty()
            && sent.slate.recipient_recovery_capsule.is_empty(),
        "G0 is a plain send: no recovery-capsule extension fields"
    );

    // ── 4. Exchange exactly the messages production uses. ───────────────────
    let to_bob = over_the_wire(&sent.slate);
    let answered = receive(&mut bob, to_bob, now).expect("bob receive");
    assert_eq!(answered.version, CURRENT_SLATE_VERSION);
    let recipient_commitment = *answered
        .recipient_output
        .as_ref()
        .expect("bob must create his own output")
        .commitment
        .as_bytes();

    let back_to_alice = over_the_wire(&answered);
    let (tx, slate_hash) =
        finalize_tracked(&mut alice, back_to_alice, now).expect("alice finalize");

    // ── 5. BOTH wallets verify the final tx and its canonical bytes. ────────
    let alice_bytes = verify_final_tx(&tx, tip, "alice");
    let bob_view = Transaction::from_bytes(&alice_bytes).expect("bob decodes the finalized tx");
    let bob_bytes = verify_final_tx(&bob_view, tip, "bob");
    assert_eq!(
        alice_bytes, bob_bytes,
        "both wallets must agree on the canonical bytes"
    );
    assert_eq!(
        tx.kernels.len(),
        1,
        "a plain 1->1 send carries exactly one kernel"
    );
    assert_eq!(
        tx.kernels[0].features,
        dom_core::KERNEL_FEAT_PLAIN,
        "plain send => PLAIN kernel"
    );
    assert_eq!(tx.kernels[0].lock_height, 0);
    assert!(
        tx.outputs
            .iter()
            .any(|o| *o.commitment.as_bytes() == recipient_commitment),
        "bob must find HIS output in the finalized tx"
    );
    assert!(
        tx.outputs
            .iter()
            .any(|o| *o.commitment.as_bytes() == change_commitment),
        "alice's change output must be in the finalized tx"
    );
    let tx_hash = *dom_crypto::blake2b_256(&alice_bytes).as_bytes();

    // ── 6. Alice broadcasts via the normal RPC. ─────────────────────────────
    // POST /tx/submit is the node's public route; this is the unmodified
    // production sink, NOT a shim.
    let direct_a = format!("http://{rpc_a}");
    let (alice_after_submit, outcome) = {
        let mut state = alice;
        let url = direct_a.clone();
        let res = tokio::task::spawn_blocking(move || {
            let sink = RpcChainSource::new(url, RPC_TIMEOUT).expect("rpc sink");
            let out = submit_finalized(&mut state, &sink, slate_hash, now);
            (state, out)
        })
        .await
        .expect("blocking submit");
        res
    };
    alice = alice_after_submit;
    let outcome = outcome.expect("node must accept Alice's plain send");
    assert_eq!(outcome.tx_hash, tx_hash, "admission hash mismatch");
    eprintln!("[G0] mempool_accept: node A admitted {}", hex::encode(tx_hash));

    // Mempool acceptance on A, and real P2P relay to Bob's node.
    {
        let mp = node_a.mempool.lock().await;
        assert!(mp.get_tx(&tx_hash).is_some(), "tx must be in A's mempool");
    }
    wait_for_mempool_count(&node_b, 1, Duration::from_secs(120))
        .await
        .expect("tx must reach B's mempool via real P2P relay");
    {
        let mp = node_b.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_some(),
            "B's mempool must hold Alice's tx"
        );
    }

    // ── 7. A block confirms it. Bob's own node mines it. ────────────────────
    // Node B has no wallet, so the inclusion block's coinbase belongs to nobody
    // and cannot contaminate either balance assertion.
    mine_blocks(&node_b, 1).await.expect("inclusion mine on B");
    let conf_tip = K_FUNDING + 1;
    wait_for_height(&node_a, conf_tip, Duration::from_secs(60))
        .await
        .expect("inclusion block must propagate B -> A");
    {
        let mp = node_a.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_none(),
            "block_accept: the tx must drain from A's mempool once mined"
        );
        let chain = node_a.chain.lock().await;
        assert!(
            chain
                .store
                .get_utxo(&recipient_commitment)
                .ok()
                .flatten()
                .is_some(),
            "block_accept: Bob's output must be a live canonical UTXO"
        );
        assert!(
            chain
                .store
                .get_utxo(&change_commitment)
                .ok()
                .flatten()
                .is_some(),
            "block_accept: Alice's change must be a live canonical UTXO"
        );
    }
    eprintln!("[G0] block_accept: confirmed at height {conf_tip}");

    // ── 8. Bob detects the output via the normal scanner. ───────────────────
    let now = now_secs();
    let bob_tip = wallet_rescan(&mut bob, &shim_b, now).await;
    assert_eq!(bob_tip, conf_tip);
    assert_eq!(
        confirmed_total(&bob, bob_tip),
        G0_AMOUNT,
        "receiver_detected_value must equal sent_value"
    );
    let bob_out = confirmed_outputs(&bob);
    assert_eq!(bob_out.len(), 1, "Bob owns exactly the one received output");
    assert_eq!(bob_out[0].commitment, recipient_commitment);
    assert!(!bob_out[0].is_coinbase);

    // ── 9. Sender change is correct. ────────────────────────────────────────
    let alice_tip = wallet_rescan(&mut alice, &shim_a, now).await;
    assert_eq!(alice_tip, conf_tip);
    assert_eq!(
        confirmed_total(&alice, alice_tip),
        alice_funded + INITIAL_BLOCK_REWARD - G0_AMOUNT - G0_FEE,
        "sender_change_is_correct: the newly matured coinbase joins, and exactly \
         amount+fee leaves"
    );
    let change_out = alice
        .outputs
        .get(&change_commitment)
        .expect("alice must still own her change output");
    assert_eq!(
        change_out.value, expected_change,
        "the change value must be inputs - amount - fee"
    );
    assert_eq!(change_out.status, OutputStatus::Confirmed);
    for c in &sent.slate.sender_inputs {
        let spent = alice
            .outputs
            .get(c.as_bytes())
            .expect("the spent input is retained (INV-RET)");
        assert_eq!(
            spent.status,
            OutputStatus::Spent,
            "every selected input must be marked Spent"
        );
    }
    eprintln!(
        "[G0] balances after confirm: alice={} bob={}",
        confirmed_total(&alice, alice_tip),
        confirmed_total(&bob, bob_tip)
    );

    // ── 10. Restart both nodes and both wallets; rescan must reproduce state.
    save_wallet_state(&alice, &alice_v2_path, "pw-a-v2").expect("persist alice");
    save_wallet_state(&bob, &bob_v2_path, "pw-b-v2").expect("persist bob");
    let alice_before: Vec<_> = {
        let mut v: Vec<_> = alice
            .outputs
            .iter()
            .map(|o| (o.commitment, o.value, o.status, o.is_coinbase))
            .collect();
        v.sort_by_key(|e| e.0);
        v
    };
    let bob_before: Vec<_> = {
        let mut v: Vec<_> = bob
            .outputs
            .iter()
            .map(|o| (o.commitment, o.value, o.status, o.is_coinbase))
            .collect();
        v.sort_by_key(|e| e.0);
        v
    };

    node_a.request_shutdown().await;
    node_b.request_shutdown().await;
    drop(node_a);
    drop(node_b);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut cfg_a2 = test_config("g0-alice-restart", p2p_a, false);
    cfg_a2.data_dir = data_dir_a.to_string_lossy().into_owned();
    cfg_a2.wallet_path = Some(alice_nodewallet.to_string_lossy().into_owned());
    cfg_a2.wallet_password = Some("pw-alice".into());
    cfg_a2.rpc_listen_addr = Some(rpc_a.clone());
    cfg_a2.rpc_bearer_token = Some("g0-token-a".into());
    let mut cfg_b2 = test_config("g0-bob-restart", p2p_b, false);
    cfg_b2.data_dir = data_dir_b.to_string_lossy().into_owned();
    cfg_b2.seed_peers = vec![p2p_a_addr.clone()];
    cfg_b2.rpc_listen_addr = Some(rpc_b.clone());
    cfg_b2.rpc_bearer_token = Some("g0-token-b".into());

    let node_a = spawn_node(cfg_a2).await;
    let node_b = spawn_node(cfg_b2).await;
    tokio::spawn(node_a.clone().run());
    wait_for_listener_ready(&rpc_a, 20).await.expect("A rpc restart");
    tokio::spawn(node_b.clone().run());
    wait_for_listener_ready(&rpc_b, 20).await.expect("B rpc restart");
    wait_for_peer_count(&node_b, 1, Duration::from_secs(60))
        .await
        .expect("B must re-peer with A after restart");
    assert_eq!(
        node_a.chain.lock().await.tip_height.0,
        conf_tip,
        "node A must reload the canonical tip from disk"
    );
    assert_eq!(
        node_b.chain.lock().await.tip_height.0,
        conf_tip,
        "node B must reload the canonical tip from disk"
    );

    // Reload BOTH wallets from disk — no manual state insertion anywhere.
    let mut alice = load_wallet_state(&alice_v2_path, "pw-a-v2").expect("reload alice");
    let mut bob = load_wallet_state(&bob_v2_path, "pw-b-v2").expect("reload bob");
    let now = now_secs();
    let a_tip = wallet_rescan(&mut alice, &shim_a, now).await;
    let b_tip = wallet_rescan(&mut bob, &shim_b, now).await;
    assert_eq!((a_tip, b_tip), (conf_tip, conf_tip));

    let alice_after: Vec<_> = {
        let mut v: Vec<_> = alice
            .outputs
            .iter()
            .map(|o| (o.commitment, o.value, o.status, o.is_coinbase))
            .collect();
        v.sort_by_key(|e| e.0);
        v
    };
    let bob_after: Vec<_> = {
        let mut v: Vec<_> = bob
            .outputs
            .iter()
            .map(|o| (o.commitment, o.value, o.status, o.is_coinbase))
            .collect();
        v.sort_by_key(|e| e.0);
        v
    };
    assert_eq!(
        alice_before, alice_after,
        "restart_and_rescan_match: Alice's ownership and state must be reproduced exactly"
    );
    assert_eq!(
        bob_before, bob_after,
        "restart_and_rescan_match: Bob's ownership and state must be reproduced exactly"
    );
    assert_eq!(confirmed_total(&bob, b_tip), G0_AMOUNT);
    eprintln!("[G0] restart_and_rescan_match: OK");

    // ── 11. Bob spends what he received (spendable, not merely detectable). ──
    let bob_send: u64 = 400_000_000;
    let bob_fee: u64 = 987_654;
    assert!(bob_send + bob_fee < G0_AMOUNT, "second transfer must fit");
    let alice_req = alice
        .keychain
        .create_receive_request(bob_send)
        .expect("alice receive request");

    let now = now_secs();
    let sent2 = create_send(&mut bob, alice_req.amount, bob_fee, now)
        .expect("receiver_can_spend: Bob must be able to build a send from the received output");
    assert_eq!(
        sent2.slate.sender_inputs.len(),
        1,
        "Bob spends exactly the output Alice paid him"
    );
    assert_eq!(
        *sent2.slate.sender_inputs[0].as_bytes(),
        recipient_commitment,
        "the input must be the very output received in step 8"
    );
    let to_alice = over_the_wire(&sent2.slate);
    let answered2 = receive(&mut alice, to_alice, now).expect("alice receive");
    let back_to_bob = over_the_wire(&answered2);
    let (tx2, slate_hash2) = finalize_tracked(&mut bob, back_to_bob, now).expect("bob finalize");
    let tx2_bytes = verify_final_tx(&tx2, conf_tip, "bob-spend");
    let tx2_hash = *dom_crypto::blake2b_256(&tx2_bytes).as_bytes();

    let direct_b = format!("http://{rpc_b}");
    let (bob_after_submit, outcome2) = {
        let mut state = bob;
        let url = direct_b.clone();
        tokio::task::spawn_blocking(move || {
            let sink = RpcChainSource::new(url, RPC_TIMEOUT).expect("rpc sink");
            let out = submit_finalized(&mut state, &sink, slate_hash2, now);
            (state, out)
        })
        .await
        .expect("blocking submit 2")
    };
    bob = bob_after_submit;
    outcome2.expect("node B must accept Bob's spend of the received output");

    mine_blocks(&node_b, 1).await.expect("mine bob's spend");
    let tip2 = conf_tip + 1;
    wait_for_height(&node_a, tip2, Duration::from_secs(60))
        .await
        .expect("second block must propagate");
    {
        let mp = node_b.mempool.lock().await;
        assert!(
            mp.get_tx(&tx2_hash).is_none(),
            "Bob's spend must be mined out of the mempool"
        );
    }

    let now = now_secs();
    let b_tip = wallet_rescan(&mut bob, &shim_b, now).await;
    let a_tip = wallet_rescan(&mut alice, &shim_a, now).await;
    assert_eq!((a_tip, b_tip), (tip2, tip2));
    assert_eq!(
        confirmed_total(&bob, b_tip),
        G0_AMOUNT - bob_send - bob_fee,
        "receiver_can_spend: Bob's balance must drop by exactly amount+fee"
    );
    assert_eq!(
        bob.outputs
            .get(&recipient_commitment)
            .expect("Bob retains the spent output (INV-RET)")
            .status,
        OutputStatus::Spent,
        "the output Bob received in step 8 is now canonically spent"
    );
    assert!(
        confirmed_total(&alice, a_tip) > 0,
        "Alice remains solvent after being paid back"
    );
    eprintln!(
        "[G0] receiver_can_spend: OK — bob={} after spending {}",
        confirmed_total(&bob, b_tip),
        bob_send + bob_fee
    );

    // ── 12. Nothing Scriptless / DL2P touched this path. ────────────────────
    assert!(
        sent.slate.sender_change_recovery_capsule.is_empty()
            && sent.slate.recipient_recovery_capsule.is_empty()
            && sent2.slate.sender_change_recovery_capsule.is_empty()
            && sent2.slate.recipient_recovery_capsule.is_empty(),
        "scriptless_or_dl2p_fields must be 0"
    );

    eprintln!("[G0 PASS] §15.7 canonical scenario completed in {:?}", started.elapsed());
    node_a.request_shutdown().await;
    node_b.request_shutdown().await;
}

// ---------------------------------------------------------------------------
// §15.7 coverage variant — already-satisfied HEIGHT_LOCKED kernel.
// ---------------------------------------------------------------------------

/// Coverage variant: an already-satisfied `HEIGHT_LOCKED` kernel must confirm
/// without delaying funds.
///
/// **Wallet-surface finding.** `dom_wallet2::create_send`
/// (`crates/dom-wallet2/src/payment.rs:137-142`) takes no `lock_height` and calls
/// the zero-lock wrapper `dom_slate::build_send`
/// (`crates/dom-wallet2/src/payment.rs:162`); `grep lock_height` over
/// `crates/dom-wallet2/` returns nothing. v1 only ever echoes `slate.lock_height`
/// (`crates/dom-wallet/src/wallet.rs:2522`, `:2621`). The lock-height-capable
/// entry point `dom_slate::build_send_with_lock_height`
/// (`crates/dom-slate/src/lib.rs:266`) has NO caller in the repository outside
/// `build_send` itself. So this variant cannot be driven through the wallet's
/// public send API; it is driven through the production slate crate directly,
/// which is the deepest layer that can still express it. Everything downstream —
/// receiver response, finalize, mempool, consensus, block — is the unmodified
/// production path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g0_height_locked_cover_confirms_without_delay() {
    init_tracing();

    let seed = Bip39Seed::generate_new().expect("seed");
    let tmp = tempfile::tempdir().expect("tmp");
    let nodewallet = tmp.path().join("hl-node-wallet.dom");
    node_wallet_dir_from_seed(&nodewallet, "pw-hl", &seed);

    let rpc = format!("127.0.0.1:{}", free_local_port());
    let mut cfg = test_config("g0-heightlock", free_local_port(), false);
    cfg.data_dir = tmp.path().join("node-hl").to_string_lossy().into_owned();
    cfg.wallet_path = Some(nodewallet.to_string_lossy().into_owned());
    cfg.wallet_password = Some("pw-hl".into());
    cfg.rpc_listen_addr = Some(rpc.clone());
    cfg.rpc_bearer_token = Some("g0-token-hl".into());

    let node = spawn_node(cfg).await;
    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&rpc, 15).await.expect("rpc");
    let shim = spawn_bearer_shim(rpc.clone(), "g0-token-hl".into()).await;

    let mut sender = v2_wallet_from_seed(&seed);
    let mut recipient = v2_wallet_from_seed(&Bip39Seed::generate_new().expect("seed2"));

    mine_blocks(&node, K_FUNDING).await.expect("fund");
    let now = now_secs();
    let tip = wallet_rescan(&mut sender, &shim, now).await;
    assert_eq!(tip, K_FUNDING);
    let funded = confirmed_total(&sender, tip);
    assert!(funded > 0, "sender must be funded");

    // An ALREADY-SATISFIED lock: lock_height == the current tip, so
    // `validate_lock_heights` (`crates/dom-consensus/src/transaction.rs:566-576`,
    // reject iff `lock_height > current`) passes immediately. No funds are
    // delayed.
    let lock_height = tip;

    // Assemble the slate inputs from the wallet's OWN confirmed, mature outputs
    // (read-only; nothing is fabricated).
    let maturity = sender.network.coinbase_maturity();
    let mut chosen: Vec<dom_slate::SlateInput> = Vec::new();
    let mut sum = 0u64;
    let need = G0_AMOUNT + G0_FEE;
    for o in sender.outputs.iter() {
        if o.status != OutputStatus::Confirmed {
            continue;
        }
        if o.is_coinbase
            && !o
                .origin_block
                .map(|b| tip.saturating_sub(b.height) >= maturity)
                .unwrap_or(false)
        {
            continue;
        }
        chosen.push(dom_slate::SlateInput {
            commitment: o.commitment,
            blinding: *o.blinding,
        });
        sum += o.value;
        if sum >= need {
            break;
        }
    }
    assert!(sum >= need, "must be able to cover the height-locked send");

    let sender_slate = dom_slate::build_send_with_lock_height(
        &chosen,
        sum - need,
        G0_AMOUNT,
        G0_FEE,
        sender.chain_id,
        lock_height,
    )
    .expect("build_send_with_lock_height");
    assert_eq!(sender_slate.slate.version, CURRENT_SLATE_VERSION);
    assert_eq!(sender_slate.slate.lock_height, lock_height);

    // Receiver + finalize are the production slate steps, over the real wire.
    let on_wire = over_the_wire(&sender_slate.slate);
    let answered = receive(&mut recipient, on_wire, now).expect("recipient receive");
    assert_eq!(answered.lock_height, lock_height, "the lock must survive the round trip");
    let back = over_the_wire(&answered);
    let tx = dom_slate::finalize(
        &back,
        &sender_slate.excess_blinding,
        &sender_slate.nonce,
        &sender.chain_id,
    )
    .expect("finalize height-locked slate");

    assert_eq!(tx.kernels.len(), 1);
    assert_eq!(
        tx.kernels[0].features,
        dom_core::KERNEL_FEAT_HEIGHT_LOCKED,
        "an already-satisfied lock must still stamp HEIGHT_LOCKED"
    );
    assert_eq!(tx.kernels[0].lock_height, lock_height);
    let tx_bytes = verify_final_tx(&tx, tip, "height-locked");
    let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();

    // Broadcast through the node's public submit route and confirm in the very
    // next block — no waiting, no delay.
    let base = format!("http://{rpc}");
    let submitted = tokio::task::spawn_blocking(move || {
        let sink = RpcChainSource::new(base, RPC_TIMEOUT).expect("sink");
        <RpcChainSource as dom_wallet2::TxSink>::submit_tx(&sink, &tx)
    })
    .await
    .expect("blocking submit")
    .expect("mempool must accept an already-satisfied HEIGHT_LOCKED kernel");
    assert_eq!(submitted.tx_hash, tx_hash);

    {
        let mp = node.mempool.lock().await;
        assert!(mp.get_tx(&tx_hash).is_some(), "must be in the mempool");
    }
    mine_blocks(&node, 1).await.expect("inclusion mine");
    {
        let mp = node.mempool.lock().await;
        assert!(
            mp.get_tx(&tx_hash).is_none(),
            "height_locked_cover_confirms_without_delay: it must confirm in the \
             very next block"
        );
    }

    let now = now_secs();
    let new_tip = wallet_rescan(&mut recipient, &shim, now).await;
    assert_eq!(new_tip, tip + 1, "confirmed one block later — no delay");
    assert_eq!(
        confirmed_total(&recipient, new_tip),
        G0_AMOUNT,
        "the height-locked payment credits the recipient immediately"
    );

    eprintln!("[G0] height_locked_cover: confirmed at tip {new_tip} with lock_height {lock_height}");
    node.request_shutdown().await;
}

// ---------------------------------------------------------------------------
// G0-BLOCKER-002 — measured in isolation.
// ---------------------------------------------------------------------------

/// The CURRENT wallet, configured exactly as the shipping desktop wallet
/// configures it, builds a plain send that **every node rejects**.
///
/// Reproduces `wallet-desktop/src-tauri/src/wallet_manager.rs:1206-1210`:
/// ```ignore
/// fn genesis_chain_id(network: V1Network) -> Result<[u8; 32]> {
///     let genesis = dom_core::startup_genesis_hash_for_network_magic(network.magic())?;
///     Ok(*genesis.as_bytes())          // <-- raw genesis hash, NOT derive_chain_id
/// }
/// ```
/// fed to `WalletV2State::new(network, chain_id)`.
///
/// The node validates the aggregate kernel Schnorr signature against
/// `derive_chain_id(network_magic, genesis_hash)`
/// (`crates/dom-node/src/node.rs:369`), so the signature never verifies.
/// Wallet v1 does the derivation internally
/// (`crates/dom-wallet/src/wallet.rs:272`) and is therefore unaffected — which is
/// why the v1 end-to-end test `transfer_slate_e2e.rs` passes while the current
/// engine cannot spend at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g0_current_wallet_chain_id_is_rejected_by_consensus() {
    init_tracing();

    // The two chain ids are genuinely different values.
    assert_ne!(
        DESKTOP_CHAIN_ID,
        node_chain_id(),
        "precondition: the desktop's chain id must differ from the node's derived one"
    );

    let seed = Bip39Seed::generate_new().expect("seed");
    let tmp = tempfile::tempdir().expect("tmp");
    let nodewallet = tmp.path().join("blocker2-node-wallet.dom");
    node_wallet_dir_from_seed(&nodewallet, "pw-b2", &seed);

    let rpc = format!("127.0.0.1:{}", free_local_port());
    let mut cfg = test_config("g0-blocker2", free_local_port(), false);
    cfg.data_dir = tmp.path().join("node-b2").to_string_lossy().into_owned();
    cfg.wallet_path = Some(nodewallet.to_string_lossy().into_owned());
    cfg.wallet_password = Some("pw-b2".into());
    cfg.rpc_listen_addr = Some(rpc.clone());
    cfg.rpc_bearer_token = Some("g0-token-b2".into());

    let node = spawn_node(cfg).await;
    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&rpc, 15).await.expect("rpc");
    let shim = spawn_bearer_shim(rpc.clone(), "g0-token-b2".into()).await;

    // Both wallets configured the way the desktop configures them.
    let mut sender = v2_wallet_from_seed_with_chain_id(&seed, DESKTOP_CHAIN_ID);
    let mut recipient = v2_wallet_from_seed_with_chain_id(
        &Bip39Seed::generate_new().expect("seed2"),
        DESKTOP_CHAIN_ID,
    );

    mine_blocks(&node, K_FUNDING).await.expect("fund");
    let now = now_secs();
    let tip = wallet_rescan(&mut sender, &shim, now).await;
    assert!(
        confirmed_total(&sender, tip) >= G0_AMOUNT + G0_FEE,
        "sender must be funded before the send"
    );

    // The whole wallet-side flow SUCCEEDS — both wallets agree with each other.
    let sent = create_send(&mut sender, G0_AMOUNT, G0_FEE, now).expect("create_send");
    assert_eq!(sent.slate.chain_id, DESKTOP_CHAIN_ID);
    let answered = receive(&mut recipient, over_the_wire(&sent.slate), now).expect("receive");
    let (tx, slate_hash) = finalize_tracked(&mut sender, answered, now).expect("finalize");

    // It even passes the wallet's own self-consistent local validation.
    let _ = verify_final_tx_with_chain_id(&tx, tip, "desktop-config", DESKTOP_CHAIN_ID);

    // But the node rejects it.
    let base = format!("http://{rpc}");
    let (_state, outcome) = tokio::task::spawn_blocking(move || {
        let mut s = sender;
        let sink = RpcChainSource::new(base, RPC_TIMEOUT).expect("sink");
        let out = submit_finalized(&mut s, &sink, slate_hash, now);
        (s, out)
    })
    .await
    .expect("blocking submit");

    match outcome {
        Ok(o) => panic!(
            "G0-BLOCKER-002 appears fixed: the node accepted a v2 tx built with the \
             desktop's chain id ({o:?}). Re-adjudicate Gate G0."
        ),
        Err(e) => {
            let msg = format!("{e:?}");
            assert!(
                msg.contains("Schnorr signature invalid") || msg.contains("InvalidSignature"),
                "expected a kernel signature rejection, got: {msg}"
            );
            eprintln!(
                "[G0-BLOCKER-002 CONFIRMED] the node rejected a plain send built by the \
                 CURRENT wallet as configured in production: {msg}\n\
                 wallet chain_id  = {} (raw genesis hash; wallet-desktop/src-tauri/src/wallet_manager.rs:1206-1210)\n\
                 node   chain_id  = {} (derive_chain_id; crates/dom-node/src/node.rs:369)\n\
                 v1 derives it internally at crates/dom-wallet/src/wallet.rs:272, which is why \
                 the v1 test transfer_slate_e2e.rs passes and the current engine does not.",
                hex::encode(DESKTOP_CHAIN_ID),
                hex::encode(node_chain_id()),
            );
        }
    }

    node.request_shutdown().await;
}
