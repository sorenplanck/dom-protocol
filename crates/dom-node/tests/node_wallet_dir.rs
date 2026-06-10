//! Regressão do bug de integração nó ↔ WalletDir (fix/node-wallet-dir-integration).
//!
//! O CLI (`dom-wallet init`) e a wallet-desktop criam a wallet como DIRETÓRIO
//! WalletDir (wallet.dat + config.json + wallet.lock + journal). O nó abria com
//! `Wallet::open` (formato de ARQUIVO) e, ao receber o diretório, falhava
//! ("Is a directory") e caía no fail-closed — todo usuário que criava a wallet
//! pela interface ficava sem minerar. Estes testes provam:
//!
//! 1. o nó abre uma WalletDir criada por `create_from_seed` (mesmo formato do
//!    CLI/desktop) e o Wallet fica disponível para o miner;
//! 2. apontar para um diretório WalletDir válido NÃO falha mais (regressão);
//! 3. sem wallet (ou senha errada), o fail-closed DOM-SEC-004 é preservado:
//!    `node.wallet == None` — e o miner já recusa minerar em rede pública sem
//!    wallet (coberto por no_wallet_mining_testnet_fail_closed.rs);
//! 4. a wallet aberta pelo nó é DETERMINÍSTICA (keychain com seed), não legacy.

use dom_config::NodeConfig;
use dom_core::{BlockHeight, Hash256};
use dom_node::node::DomNode;
use dom_wallet::{Bip39Seed, Network, WalletDir};
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

fn regtest_genesis() -> Hash256 {
    Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST)
}

fn node_config(data_dir: &TempDir, wallet_path: &std::path::Path, password: &str) -> NodeConfig {
    let mut config = NodeConfig::regtest();
    config.data_dir = data_dir.path().to_string_lossy().into_owned();
    config.wallet_path = Some(wallet_path.to_string_lossy().into_owned());
    config.wallet_password = Some(password.into());
    config.mine = false;
    config
}

/// Provas 1 e 4: o nó abre a WalletDir determinística criada por seed (o que o
/// CLI/desktop produzem) e o Wallet exposto ao miner é utilizável e tem
/// keychain determinística — nunca a legacy sem seed recuperável.
#[test]
fn node_opens_deterministic_wallet_dir_created_from_seed() {
    let data_dir = TempDir::new().expect("data dir");
    let wallet_root = TempDir::new().expect("wallet root");
    let wallet_path = wallet_root.path().join("minha-wallet");

    let seed = Bip39Seed::generate_new().expect("seed");
    let dir = WalletDir::create_from_seed(
        &wallet_path,
        "password123",
        Network::Regtest,
        &regtest_genesis(),
        &seed,
    )
    .expect("create deterministic wallet dir");
    drop(dir); // solta o lock exclusivo para o nó assumir

    let node = DomNode::init_with_map_size(
        node_config(&data_dir, &wallet_path, "password123"),
        TEST_LMDB_MAP_SIZE,
    )
    .expect("node init");

    let wallet_arc = node
        .wallet
        .as_ref()
        .expect("node must open the WalletDir the CLI/desktop creates");
    let mut wallet_dir = wallet_arc.try_lock().expect("wallet lock");

    assert!(
        wallet_dir.wallet().has_deterministic_seed(),
        "node-opened wallet must be deterministic (seed-backed), not legacy"
    );

    // O que o miner faz: coinbase com blinding determinístico.
    wallet_dir
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("miner-style build_coinbase through the node-held WalletDir");
}

/// Prova 2 (regressão direta do bug): apontar wallet_path para um DIRETÓRIO
/// WalletDir válido não pode mais falhar. Antes: "failed to rename wallet file
/// atomically: Is a directory" → wallet None. Usa o formato V1 (legacy) para
/// provar que QUALQUER WalletDir válida abre — o nó só recusa CRIAR.
#[test]
fn node_opens_existing_wallet_dir_regression() {
    let data_dir = TempDir::new().expect("data dir");
    let wallet_root = TempDir::new().expect("wallet root");
    let wallet_path = wallet_root.path().join("wallet-do-cli");

    let dir = WalletDir::create(
        &wallet_path,
        "password123",
        Network::Regtest,
        &regtest_genesis(),
    )
    .expect("create wallet dir");
    drop(dir);

    let node = DomNode::init_with_map_size(
        node_config(&data_dir, &wallet_path, "password123"),
        TEST_LMDB_MAP_SIZE,
    )
    .expect("node init");

    assert!(
        node.wallet.is_some(),
        "pointing the node at a valid WalletDir directory must not fail"
    );
}

/// Prova 3a: sem wallet no caminho configurado → fail-closed preservado
/// (node.wallet None; nenhuma wallet criada silenciosamente no lugar).
#[test]
fn missing_wallet_dir_keeps_fail_closed_and_creates_nothing() {
    let data_dir = TempDir::new().expect("data dir");
    let wallet_root = TempDir::new().expect("wallet root");
    let wallet_path = wallet_root.path().join("nao-existe");

    let node = DomNode::init_with_map_size(
        node_config(&data_dir, &wallet_path, "password123"),
        TEST_LMDB_MAP_SIZE,
    )
    .expect("node init must survive a missing wallet (fail-closed, not crash)");

    assert!(
        node.wallet.is_none(),
        "missing wallet must leave mining disabled (DOM-SEC-004)"
    );
    assert!(
        !wallet_path.exists(),
        "the node must NEVER silently create a wallet (legacy keychain has no \
         recoverable seed)"
    );
}

/// Prova 3b: wallet existe mas a senha está errada → fail-closed, sem
/// sobrescrever nem criar nada por cima.
#[test]
fn wrong_password_keeps_fail_closed_without_touching_wallet() {
    let data_dir = TempDir::new().expect("data dir");
    let wallet_root = TempDir::new().expect("wallet root");
    let wallet_path = wallet_root.path().join("wallet-protegida");

    let seed = Bip39Seed::generate_new().expect("seed");
    let dir = WalletDir::create_from_seed(
        &wallet_path,
        "senha-correta",
        Network::Regtest,
        &regtest_genesis(),
        &seed,
    )
    .expect("create wallet dir");
    drop(dir);

    let node = DomNode::init_with_map_size(
        node_config(&data_dir, &wallet_path, "senha-errada"),
        TEST_LMDB_MAP_SIZE,
    )
    .expect("node init must survive an unopenable wallet");

    assert!(
        node.wallet.is_none(),
        "wrong password must leave mining disabled (DOM-SEC-004)"
    );

    // A wallet original continua abrível com a senha certa — nada foi tocado.
    WalletDir::open(&wallet_path, "senha-correta")
        .expect("original wallet must remain intact and openable");
}
