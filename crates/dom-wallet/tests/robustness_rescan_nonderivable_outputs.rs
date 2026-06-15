//! Robustez do rescan canônico (modo Repair) para outputs cujo blinding NÃO é
//! re-derivável a partir da seed: receive-slates confirmados e change de spend.
//!
//! Contexto (auditoria FABLE5 2026-06-12): o loop de background do
//! wallet-desktop roda `rescan_canonical_chain(Repair)` a cada avanço de tip
//! (`wallet-desktop/src-tauri/src/lib.rs`). O Repair substitui `self.outputs`
//! pelo conjunto reconstruído (`wallet.rs`), que só contém o que é
//! re-derivável (coinbase por altura, receive-requests por índice) ou o que
//! ainda está pendente (receive-slates com secrets no pending). Um output de
//! slate JÁ CONFIRMADO — ou um change confirmado — tem blinding aleatório que
//! só existe no output index, e portanto NÃO deve ser descartado por um
//! rescan subsequente.
//!
//! Estes testes asseram o comportamento CORRETO (output sobrevive ao rescan
//! seguinte). Se falharem, o defeito é o achado — não afrouxar.
//!
//! SUÍTE DE ACEITAÇÃO DA WALLET v2 (dom-wallet2, Fase 2). VERMELHOS contra o
//! v1 por design: documentam o defeito WDSF-002 (rescan Repair destrói
//! blinding aleatório não re-derivável). Devem ficar VERDES quando portados ao
//! dom-wallet2 com `StoredOutput` + reconciliador status-only (rescan =
//! reconciliação, não reconstrução). Não usar `#[ignore]` — a falha é o achado.

use dom_core::BlockHeight;
use dom_crypto::Hash256;
use dom_wallet::{InMemoryChainScan, Network, ScanBlock, WalletDir, WalletRescanMode};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

fn block_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn scan_with_blocks(blocks: Vec<ScanBlock>) -> InMemoryChainScan {
    let mut scan = InMemoryChainScan::new();
    for block in blocks {
        scan.insert(block);
    }
    scan
}

fn empty_scan_block(height: u64) -> ScanBlock {
    ScanBlock {
        height,
        block_hash: Some(block_hash(height as u8)),
        output_commitments: vec![],
        input_commitments: vec![],
        total_fees_noms: 0,
    }
}

/// Um receive-slate confirmado pelo 1º rescan Repair deve SOBREVIVER ao 2º
/// rescan Repair (o gatilho real é o loop de rescan do desktop a cada bloco).
#[test]
fn robustness_confirmed_slate_receive_survives_subsequent_repair_rescan() {
    // --- Remetente A: coinbase espendível para originar o slate. ---
    let temp_a = TempDir::new().unwrap();
    let mut sender =
        WalletDir::create(&temp_a.path().join("a"), "pw", Network::Regtest, &test_genesis())
            .unwrap();
    let coinbase = sender
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let coinbase_commitment = *coinbase.output.commitment.as_bytes();
    let scan_a = scan_with_blocks(vec![ScanBlock {
        height: 1,
        block_hash: Some(block_hash(1)),
        output_commitments: vec![coinbase_commitment],
        input_commitments: vec![],
        total_fees_noms: 0,
    }]);
    sender
        .wallet_mut()
        .rescan_canonical_chain(&scan_a, WalletRescanMode::Repair)
        .expect("sender rescan");

    let reward = dom_core::block_reward(BlockHeight(1)).noms();
    let amount = reward - 100;
    let slate = sender
        .wallet_mut()
        .create_send_slate(amount, 100, 3)
        .expect("send slate");

    // --- Destinatário B: responde o slate (blinding aleatório no pending). ---
    let temp_b = TempDir::new().unwrap();
    let mut recipient =
        WalletDir::create(&temp_b.path().join("b"), "pw", Network::Regtest, &test_genesis())
            .unwrap();
    let response = recipient
        .wallet_mut()
        .receive_slate(slate, 3)
        .expect("receive slate");
    let recipient_commitment = *response
        .recipient_output
        .as_ref()
        .expect("recipient output")
        .commitment
        .as_bytes();

    // --- Bloco 2 canônico inclui o output do destinatário. ---
    let block2 = ScanBlock {
        height: 2,
        block_hash: Some(block_hash(2)),
        output_commitments: vec![recipient_commitment],
        input_commitments: vec![coinbase_commitment],
        total_fees_noms: 100,
    };

    // 1º rescan Repair: confirma o receive (pending -> output index).
    let scan_tip2 = scan_with_blocks(vec![block2.clone()]);
    recipient
        .wallet_mut()
        .rescan_canonical_chain(&scan_tip2, WalletRescanMode::Repair)
        .expect("first repair rescan");
    let confirmed = recipient
        .wallet()
        .outputs()
        .find(|o| o.commitment == recipient_commitment)
        .expect("first rescan must confirm the slate-received output");
    assert_eq!(confirmed.value, amount);
    assert!(
        !recipient
            .wallet()
            .outputs()
            .find(|o| o.commitment == recipient_commitment)
            .unwrap()
            .spent
    );

    // 2º rescan Repair com o tip avançado (bloco 3 vazio) — exatamente o que o
    // loop de background do desktop dispara no próximo bloco.
    let scan_tip3 = scan_with_blocks(vec![block2, empty_scan_block(3)]);
    recipient
        .wallet_mut()
        .rescan_canonical_chain(&scan_tip3, WalletRescanMode::Repair)
        .expect("second repair rescan");

    let survivor = recipient
        .wallet()
        .outputs()
        .find(|o| o.commitment == recipient_commitment);
    assert!(
        survivor.is_some(),
        "DEFEITO: o output de receive-slate confirmado foi destruído pelo rescan \
         Repair seguinte (blinding aleatório não re-derivável — perda permanente \
         de fundos disparada automaticamente pelo loop de rescan do desktop)"
    );
    assert_eq!(survivor.unwrap().value, amount);
}

/// O change de um spend confirmado deve sobreviver a um rescan Repair: o
/// blinding do change é aleatório e o registro só existe no output index (e no
/// evento `Built` do journal, que o rescan não consulta).
#[test]
fn robustness_confirmed_change_survives_repair_rescan() {
    let temp = TempDir::new().unwrap();
    let mut wd =
        WalletDir::create(&temp.path().join("w"), "pw", Network::Regtest, &test_genesis())
            .unwrap();

    let coinbase = wd
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let coinbase_commitment = *coinbase.output.commitment.as_bytes();
    let scan1 = scan_with_blocks(vec![ScanBlock {
        height: 1,
        block_hash: Some(block_hash(1)),
        output_commitments: vec![coinbase_commitment],
        input_commitments: vec![],
        total_fees_noms: 0,
    }]);
    wd.wallet_mut()
        .rescan_canonical_chain(&scan1, WalletRescanMode::Repair)
        .expect("seed rescan");

    // Spend com change: amount + fee < reward.
    let reward = dom_core::block_reward(BlockHeight(1)).noms();
    let spend_amount = reward / 2;
    let recipient_blinding = dom_crypto::BlindingFactor::random();
    let recipient =
        dom_crypto::pedersen::Commitment::commit(spend_amount, &recipient_blinding);
    let recipient_commitment = *recipient.as_bytes();
    let tx = wd
        .wallet_mut()
        .build_spend(recipient, recipient_blinding, spend_amount, 100, 3)
        .expect("build spend");
    let change_commitment = tx
        .outputs
        .iter()
        .map(|o| *o.commitment.as_bytes())
        .find(|c| *c != recipient_commitment)
        .expect("spend must produce a change output");

    // Bloco 2 minera a tx (inputs gastos, outputs criados).
    let block2 = ScanBlock {
        height: 2,
        block_hash: Some(block_hash(2)),
        output_commitments: tx
            .outputs
            .iter()
            .map(|o| *o.commitment.as_bytes())
            .collect(),
        input_commitments: tx
            .inputs
            .iter()
            .map(|i| *i.commitment.as_bytes())
            .collect(),
        total_fees_noms: 100,
    };
    let scan2 = scan_with_blocks(vec![
        ScanBlock {
            height: 1,
            block_hash: Some(block_hash(1)),
            output_commitments: vec![coinbase_commitment],
            input_commitments: vec![],
            total_fees_noms: 0,
        },
        block2,
    ]);
    wd.wallet_mut()
        .rescan_canonical_chain(&scan2, WalletRescanMode::Repair)
        .expect("post-mine rescan");

    let change = wd
        .wallet()
        .outputs()
        .find(|o| o.commitment == change_commitment);
    assert!(
        change.is_some(),
        "DEFEITO: o change confirmado on-chain não é reconstruído pelo rescan \
         Repair (blinding aleatório vive só no output index / journal `Built`, \
         que o rescan não consulta) — o saldo do change desaparece"
    );
    let change = change.unwrap();
    assert_eq!(change.value, reward - spend_amount - 100);
    assert!(!change.spent, "change não foi gasto");
}
