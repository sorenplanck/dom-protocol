//! FABLE5-001 — STEP 1: proves or refutes whether a transaction replay reaches
//! cryptographic validation (`validate_transaction` → Bulletproof + Schnorr) on
//! the real P2P path, or is cut off earlier by an inventory, gossip, or dedup
//! layer.
//!
//! ## Question
//! A peer sends the SAME transaction bytes again. Does every replay invoke the
//! expensive `validate_transaction`, or is it discarded first?
//!
//! ## Deterministic observation, not timing
//! The P2P transaction path (`Command::Tx`, `dom-node/src/node.rs:3865`) has no
//! `Command::Inv` handler and does not consult a cache before
//! `accept_tx_with_chain_view`. A transaction with a valid range proof but an
//! invalid Schnorr signature is rejected by `validate_transaction` with
//! `DomError::Invalid`, which `peer_violation_score` scores as
//! `INVALID_SIGNATURE (25)`. The peer score is available through
//! `PeerManager::ban_score(addr)`.
//!
//! Therefore, if EACH replay reaches cryptography, the score rises by 25 per
//! send. If a dedup layer ran BEFORE validation, keyed by the byte hash,
//! identical replays would be discarded and the score would plateau at 25. The
//! proof is the score progression (25, 50, 75, ...), not elapsed time.
//!
//! The proof uses a valid range proof and a deliberately corrupted signature to
//! guarantee that the expensive `bp_verify` step runs before signature
//! rejection. Every replay therefore pays for a real Bulletproof verification.

use dom_config::Network;
use dom_consensus::derive_chain_id;
use dom_consensus::transaction::{
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, Hash256, KERNEL_FEAT_PLAIN, MIN_RELAY_FEE_RATE, PROTOCOL_VERSION, TAG_KERNEL_MSG,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::{bp2_prove, schnorr_sign, SecretKey};
use dom_integration_tests::helpers::*;
use dom_node::node::DomNode;
use dom_serialization::DomSerialize;
use dom_wire::codec::NoiseCodec;
use dom_wire::handshake::{generate_static_keypair, perform_handshake_initiator};
use dom_wire::message::{Command, HelloPayload, WireMessage};
use dom_wire::peer::ban_scores;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn chain_id_for(network: Network) -> [u8; 32] {
    let genesis_hash = match network {
        Network::Mainnet => dom_core::GENESIS_HASH_MAINNET,
        Network::Testnet => dom_core::GENESIS_HASH_TESTNET,
        Network::Regtest => dom_core::GENESIS_HASH_REGTEST,
    };
    *derive_chain_id(network.magic(), &Hash256::from_bytes(genesis_hash)).as_bytes()
}

async fn connect_adversarial_peer(node: &Arc<DomNode>) -> (tokio::net::TcpStream, NoiseCodec) {
    let config = node.config.clone();
    let mut stream = tokio::net::TcpStream::connect(&config.p2p_listen_addr)
        .await
        .expect("connect adversarial peer");
    let (privkey, _) = generate_static_keypair();
    let chain_id = chain_id_for(config.network);
    let transport =
        perform_handshake_initiator(&mut stream, &privkey, config.network.magic(), &chain_id)
            .await
            .expect("perform Noise handshake");
    let mut codec = NoiseCodec::new(transport, config.network.magic());

    let hello = HelloPayload {
        version: PROTOCOL_VERSION,
        network_magic: config.network.magic(),
        chain_id,
        best_height: 0,
        best_hash: [0u8; 32],
        user_agent: "dom-fable5-replay-test".into(),
        local_timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let wire = WireMessage {
        magic: config.network.magic(),
        command: Command::Hello,
        payload: hello.to_bytes().expect("serialize hello"),
    };
    codec.send(&mut stream, &wire).await.expect("send hello");
    let response = codec.recv(&mut stream).await.expect("receive hello");
    assert_eq!(response.command, Command::Hello);

    (stream, codec)
}

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

/// A tx with VALID Pedersen commitments and a VALID Bulletproof range proof, but
/// a DELIBERATELY corrupted Schnorr signature. `validate_transaction` runs the
/// range proof (expensive, passes) before the kernel signature (fails) — so each
/// time this tx is validated, a real Bulletproof verification executes and then
/// the signature check rejects it with `DomError::Invalid`.
fn tx_valid_proof_bad_signature(chain_id: &[u8; 32], fee: u64, seed: u8) -> Vec<u8> {
    let input_value = 10_000 + fee;
    let input_blinding = scalar(seed);
    let output_value = input_value - fee;
    let kernel_blinding = scalar(seed.wrapping_add(80));
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding");
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = bp2_prove(output_value, &output_blinding).expect("range proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), chain_id).expect("kernel signature");

    // Corrupt the signature's scalar `s` so from_bytes still parses (R on-curve,
    // s in range) but schnorr_verify fails. Flipping a low bit keeps s in (0, n).
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[64] ^= 0x01;

    let tx = Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess,
            excess_signature: sig_bytes,
        }],
        offset: [0u8; 32],
    };
    tx.to_bytes().expect("serialize tx")
}

async fn ban_score_of(node: &Arc<DomNode>, peer_key: &str) -> Option<u32> {
    node.peers.lock().await.ban_score(peer_key)
}

/// Poll the peer's ban score until it reaches `target` (or time out). Waiting on
/// an async-processed result via polling is NOT a timing assertion: the outcome
/// (reaches `target` vs. plateaus) is what discriminates "crypto ran on each
/// replay" from "replay cut before crypto".
async fn wait_for_ban_score(
    node: &Arc<DomNode>,
    peer_key: &str,
    target: u32,
    timeout: Duration,
) -> Result<u32, u32> {
    let start = std::time::Instant::now();
    loop {
        let score = ban_score_of(node, peer_key).await.unwrap_or(0);
        if score >= target {
            return Ok(score);
        }
        if start.elapsed() >= timeout {
            return Err(score);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// STEP 1: prove that every transaction replay reaches `validate_transaction`
/// on the real P2P path. Send the SAME invalid-signature transaction N times
/// and observe the peer score rise by `INVALID_SIGNATURE` for each send.
#[tokio::test]
async fn robustness_p2p_tx_replay_reaches_crypto_each_time() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("fable5-replay-reaches-crypto", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    let (mut stream, mut codec) = connect_adversarial_peer(&node).await;
    // The node keys the peer's ban score by the inbound connection's remote addr,
    // which is THIS stream's local addr.
    let peer_key = stream.local_addr().expect("local addr").to_string();

    let chain_id = chain_id_for(node.config.network);
    // A single fixed tx (same bytes every send → genuine replay).
    let tx_bytes = tx_valid_proof_bad_signature(&chain_id, MIN_RELAY_FEE_RATE * 30, 0x51);
    let msg = WireMessage {
        magic: node.config.network.magic(),
        command: Command::Tx,
        payload: tx_bytes,
    };

    // Send the SAME invalid tx 3 times. A bad-signature tx scores
    // INVALID_SIGNATURE = 25, BAN_THRESHOLD = 100, so 3 sends (score 75) stays
    // below a ban — the connection stays open and every send is processed.
    let sends = 3u32;
    for i in 0..sends {
        codec
            .send(&mut stream, &msg)
            .await
            .unwrap_or_else(|e| panic!("send replay #{i} failed: {e:?}"));
    }

    let expected = ban_scores::INVALID_SIGNATURE * sends; // 75
    let score = wait_for_ban_score(&node, &peer_key, expected, Duration::from_secs(10))
        .await
        .unwrap_or_else(|got| {
            panic!(
                "ban score plateaued at {got} (expected {expected}). A score below \
                 {expected} would mean replays were cut BEFORE validate_transaction \
                 — i.e. an inventory/dedup layer exists. It does not."
            )
        });

    assert!(
        score >= expected,
        "each of {sends} identical replays must add INVALID_SIGNATURE ({}) — \
         score {score} proves every replay reached validate_transaction (crypto)",
        ban_scores::INVALID_SIGNATURE
    );

    // STEP 1 CONCLUSION: the replay reaches cryptography on the real P2P path.
    // No inventory or dedup layer runs before validate_transaction.
    eprintln!(
        "STEP 1 RESULT: replay reaches cryptography on the real P2P path. \
         ban score after {sends} identical replays = {score} (= {sends} × {}). \
         No pre-validation inventory/dedup exists.",
        ban_scores::INVALID_SIGNATURE
    );
}

/// A structurally valid transaction (valid SEC1 commitments, dummy proof/sig).
/// It passes `validate_transaction_structure` — enough to be seeded into the
/// mempool via the legacy `accept_tx` path — but is NOT cryptographically valid.
/// Used only to populate the node's mempool so we can replay it over the wire.
fn structurally_valid_tx(fee: u64, seed: u8) -> (Transaction, Vec<u8>, [u8; 32]) {
    // secp256k1 generator G — a valid compressed point, reused for both the
    // output and the kernel excess (structure validation only parses the point).
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    let commit = Commitment::from_compressed_bytes(&g).unwrap();
    let tx = Transaction {
        inputs: vec![],
        outputs: vec![TransactionOutput {
            commitment: commit.clone(),
            proof: vec![seed; 100],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).unwrap(),
            lock_height: 0,
            excess: commit,
            excess_signature: [0u8; 65],
        }],
        offset: [0u8; 32],
    };
    let tx_bytes = tx.to_bytes().expect("serialize tx");
    let tx_hash = *dom_crypto::blake2b_256(&tx_bytes).as_bytes();
    (tx, tx_bytes, tx_hash)
}

/// STEP 3: a transaction already present in the node's mempool, when replayed
/// over the real P2P path, is short-circuited BEFORE deserialization / chain
/// lock / validation. We observe the dedicated `suppressed_duplicate_tx_relays`
/// counter increment — a deterministic signal (not timing). Without the
/// short-circuit the replay would instead reach `accept_tx_with_chain_view` and
/// be rejected as a duplicate there, leaving the counter at zero.
#[tokio::test]
async fn robustness_p2p_known_tx_replay_is_short_circuited_before_validation() {
    init_tracing();
    let port = free_local_port();
    let config = test_config("fable5-known-tx-skip", port, false);
    let node = spawn_node(config).await;

    tokio::spawn(node.clone().run());
    wait_for_listener_ready(&format!("127.0.0.1:{port}"), 10)
        .await
        .expect("listener ready");

    // Seed the mempool with a structurally valid tx under the canonical hash the
    // P2P handler will compute (blake2b of the serialized bytes).
    let (tx, tx_bytes, tx_hash) = structurally_valid_tx(MIN_RELAY_FEE_RATE * 50, 0x77);
    {
        let mut m = node.mempool.lock().await;
        m.accept_tx(tx, tx_hash, 0)
            .expect("seed mempool with known tx");
        assert!(m.contains(&tx_hash), "tx must be pooled before replay");
    }

    let before = node
        .metrics
        .suppressed_duplicate_tx_relays
        .load(Ordering::Relaxed);

    let (mut stream, mut codec) = connect_adversarial_peer(&node).await;
    let msg = WireMessage {
        magic: node.config.network.magic(),
        command: Command::Tx,
        payload: tx_bytes,
    };
    // Replay the already-pooled tx several times over the wire.
    for _ in 0..3 {
        codec
            .send(&mut stream, &msg)
            .await
            .expect("send known tx replay");
    }

    // The suppression counter must rise — proving each replay was cut before
    // validation rather than re-validated as a duplicate.
    let ok = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let now = node
                .metrics
                .suppressed_duplicate_tx_relays
                .load(Ordering::Relaxed);
            if now > before {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("known-tx replay must increment suppressed_duplicate_tx_relays");

    assert!(
        ok > before,
        "replays of a pooled tx must be suppressed before validation (counter {before} → {ok})"
    );

    // The known tx must NOT have peer-scored the sender: a duplicate is not a
    // protocol violation. (Confirms the short-circuit path is unscored.)
    let peer_key = stream.local_addr().expect("local addr").to_string();
    let score = ban_score_of(&node, &peer_key).await.unwrap_or(0);
    assert_eq!(
        score, 0,
        "duplicate replay must not score the peer, got {score}"
    );
}
