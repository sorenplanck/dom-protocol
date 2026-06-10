//! Regressão: restore por seed deve recuperar coinbases pré-existentes.
//!
//! Cenário do bug (VPS minera coinbases para a seed S; depois restauro S em
//! outra máquina e o saldo fica zero): `restore_from_phrase` persiste a seed mas
//! NÃO escaneia a cadeia, então o índice de outputs fica vazio. O fix expõe
//! `DomNode::rescan_wallet_dir`, que varre a cadeia que o nó embutido já tem em
//! disco e reconstrói o índice da wallet restaurada.
//!
//! Este teste prova, ponta a ponta:
//!   1. um nó minera K coinbases para a wallet S (a wallet do minerador);
//!   2. uma OUTRA wallet, restaurada da MESMA seed num diretório separado, nasce
//!      com saldo zero (create_from_seed não escaneia — esse é o bug);
//!   3. após `node.rescan_wallet_dir(&mut restaurada)`, ela recupera exatamente
//!      os K coinbases (soma das recompensas de altura 1..=K), provando que uma
//!      wallet recém-restaurada passa a ver os coinbases pré-existentes.

use dom_config::NodeConfig;
use dom_core::{block_reward, BlockHeight, Hash256};
use dom_node::node::DomNode;
use dom_wallet::{Bip39Seed, Network, SeedAcceptance, WalletDir};
use std::sync::Arc;
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB
/// Coinbases minerados para a seed. REGTEST_COINBASE_MATURITY == 1, então no tip
/// = K só o último coinbase fica imaturo; os anteriores maturam. Por isso a prova
/// forte é sobre o TOTAL recuperado (= soma das recompensas) e a CONTAGEM (= K),
/// não sobre o split immature/confirmed.
const K: u64 = 5;

fn regtest_genesis() -> Hash256 {
    Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST)
}

fn sum_rewards(heights: std::ops::RangeInclusive<u64>) -> u64 {
    heights.map(|h| block_reward(BlockHeight(h)).noms()).sum()
}

#[tokio::test]
async fn restored_wallet_recovers_preexisting_coinbases_via_node_rescan() {
    // PoW trivial só de regtest, para minerar em milissegundos.
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");

    let genesis = regtest_genesis();

    // ── Wallet S: a wallet determinística que o nó usa para minerar. ──────────
    let data_dir = TempDir::new().expect("data dir");
    let miner_root = TempDir::new().expect("miner wallet root");
    let miner_path = miner_root.path().join("wallet-S");
    let seed = Bip39Seed::generate_new().expect("seed");
    let phrase = seed.phrase().to_string();
    let miner_dir =
        WalletDir::create_from_seed(&miner_path, "pw-miner", Network::Regtest, &genesis, &seed)
            .expect("create miner wallet S");
    drop(miner_dir); // solta o lock exclusivo para o nó assumir a wallet S

    let mut config = NodeConfig::regtest();
    config.data_dir = data_dir.path().to_string_lossy().into_owned();
    config.wallet_path = Some(miner_path.to_string_lossy().into_owned());
    config.wallet_password = Some("pw-miner".into());
    config.mine = false;
    let node = Arc::new(
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("node init with wallet S"),
    );

    // ── Minera K coinbases endereçados à seed S. ──────────────────────────────
    dom_node::miner::create_genesis_block(node.clone())
        .await
        .expect("regtest genesis");
    for _ in 0..K {
        dom_node::miner::mine_one_block(node.clone())
            .await
            .expect("mine block to wallet S");
    }
    let tip = K;
    let expected_total = sum_rewards(1..=K);

    // Sanidade: a própria wallet do minerador (que recebeu os outputs via
    // build_coinbase no momento da mineração) enxerga os K coinbases.
    {
        let wallet_arc = node.wallet.as_ref().expect("node holds wallet S");
        let miner_wallet = wallet_arc.lock().await;
        assert_eq!(
            miner_wallet.wallet().balance(tip).total(),
            expected_total,
            "precondição: a wallet do minerador já contém os K coinbases"
        );
    }

    // ── Wallet restaurada: MESMA seed, diretório separado. ────────────────────
    let restore_root = TempDir::new().expect("restore wallet root");
    let restore_path = restore_root.path().join("wallet-S-restaurada");
    let restored_seed =
        Bip39Seed::from_phrase(&phrase, SeedAcceptance::LegacyRestore).expect("seed from phrase");
    let mut restored = WalletDir::create_from_seed(
        &restore_path,
        "pw-restore",
        Network::Regtest,
        &genesis,
        &restored_seed,
    )
    .expect("restore wallet from seed S");

    // BUG REPRODUZIDO: só restaurar (create_from_seed) NÃO escaneia a cadeia.
    assert_eq!(
        restored.wallet().balance(tip).total(),
        0,
        "create_from_seed sozinho não escaneia a cadeia — saldo deve nascer zero"
    );

    // ── O FIX: escaneia a cadeia do nó embutido e reconstrói o índice. ────────
    let summary = node
        .rescan_wallet_dir(&mut restored)
        .await
        .expect("rescan da wallet restaurada contra a cadeia do nó");

    assert_eq!(
        summary.rebuilt_outputs as u64, K,
        "o rescan deve recuperar exatamente os K coinbases pré-existentes"
    );
    assert_eq!(summary.scanned_tip, tip);
    assert!(summary.repaired, "Repair deve gravar o índice reconstruído");

    let balance = restored.wallet().balance(tip);
    assert_eq!(
        balance.total(),
        expected_total,
        "a wallet restaurada deve ver o valor total dos K coinbases"
    );

    // Split exato sob REGTEST_COINBASE_MATURITY == 1: o coinbase da altura K
    // ainda está imaturo (tip - K == 0 < 1); os de 1..=K-1 já maturaram.
    assert_eq!(
        balance.immature,
        block_reward(BlockHeight(K)).noms(),
        "apenas o coinbase do topo (altura K) está imaturo no tip=K"
    );
    assert_eq!(
        balance.confirmed,
        sum_rewards(1..=K - 1),
        "os coinbases de altura 1..=K-1 já estão maduros (confirmados)"
    );

    // Idempotência: reabrir e rescanear de novo bate o mesmo dígito canônico.
    let digest_after = restored.wallet().canonical_digest();
    drop(restored);
    let mut reopened = WalletDir::open(&restore_path, "pw-restore").expect("reopen restored");
    let again = node
        .rescan_wallet_dir(&mut reopened)
        .await
        .expect("segundo rescan");
    assert_eq!(
        reopened.wallet().canonical_digest(),
        digest_after,
        "rescan é idempotente: estado reconstruído estável entre execuções"
    );
    assert!(again.matched_persisted, "segundo rescan já bate o persistido");
}
