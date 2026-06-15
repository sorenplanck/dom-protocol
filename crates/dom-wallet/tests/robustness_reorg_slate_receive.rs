//! Robustez do ciclo de vida de um receive-slate sob reorg.
//!
//! Cenário real (nó embutido): a wallet do destinatário confirma o receive via
//! `apply_canonical_block` quando o bloco entra na chain. Se um reorg remove
//! esse bloco e a MESMA transação é re-minerada na branch vencedora (o caso
//! comum — txs sobrevivem a reorgs via mempool), a wallet deve voltar a
//! reconhecer o output recebido. Para o remetente esse roundtrip funciona
//! (`Reorged` → pending reinstalado → re-`Confirmed`); este teste verifica a
//! simetria para o destinatário.
//!
//! O teste asserta o comportamento CORRETO (fundos recebidos sobrevivem a
//! reorg + re-mineração). Se falhar, o defeito é o achado — não afrouxar.
//!
//! SUÍTE DE ACEITAÇÃO DA WALLET v2 (dom-wallet2, Fase 2). Este teste é
//! VERMELHO contra o v1 por design: documenta o defeito WDSF-001 (perda de
//! receive não-derivável sob reorg). Deve ficar VERDE quando portado ao
//! dom-wallet2 com `StoredOutput` (blinding sempre persistido) + reconciliador
//! status-only. Não usar `#[ignore]` — a falha é o achado rastreado.

use dom_core::BlockHeight;
use dom_crypto::Hash256;
use dom_wallet::{InMemoryChainScan, Network, ScanBlock, WalletDir, WalletRescanMode};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
}

#[test]
fn robustness_slate_receive_survives_reorg_when_tx_is_remined() {
    // --- Remetente A com coinbase espendível. ---
    let temp_a = TempDir::new().unwrap();
    let mut sender =
        WalletDir::create(&temp_a.path().join("a"), "pw", Network::Regtest, &test_genesis())
            .unwrap();
    let coinbase = sender
        .wallet_mut()
        .build_coinbase(BlockHeight(1), 0)
        .expect("coinbase");
    let coinbase_commitment = *coinbase.output.commitment.as_bytes();
    let mut scan = InMemoryChainScan::new();
    scan.insert(ScanBlock {
        height: 1,
        block_hash: Some([1u8; 32]),
        output_commitments: vec![coinbase_commitment],
        input_commitments: vec![],
        total_fees_noms: 0,
    });
    sender
        .wallet_mut()
        .rescan_canonical_chain(&scan, WalletRescanMode::Repair)
        .expect("sender rescan");

    let reward = dom_core::block_reward(BlockHeight(1)).noms();
    let amount = reward - 100;
    let slate = sender
        .wallet_mut()
        .create_send_slate(amount, 100, 3)
        .expect("send slate");

    // --- Destinatário B responde; A finaliza a transação agregada. ---
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
    let finalized = sender
        .wallet_mut()
        .finalize_slate(response, 3)
        .expect("finalize slate");

    // --- Bloco 2 canônico entrega a tx: B confirma o receive. ---
    recipient
        .wallet_mut()
        .apply_canonical_block_with_hash(
            std::slice::from_ref(&finalized.tx),
            2,
            Some([2u8; 32]),
        )
        .expect("apply block 2");
    assert!(
        recipient
            .wallet()
            .outputs()
            .any(|o| o.commitment == recipient_commitment),
        "receive deve estar confirmado após o bloco 2"
    );

    // --- Reorg: bloco 2 sai da chain (rollback ao ancestral comum, altura 1).
    recipient
        .wallet_mut()
        .rollback_to(1)
        .expect("rollback to height 1");

    // --- A MESMA tx é re-minerada no bloco 2' da branch vencedora. ---
    recipient
        .wallet_mut()
        .apply_canonical_block_with_hash(
            std::slice::from_ref(&finalized.tx),
            2,
            Some([0xB2u8; 32]),
        )
        .expect("apply block 2'");

    let survivor = recipient
        .wallet()
        .outputs()
        .find(|o| o.commitment == recipient_commitment);
    assert!(
        survivor.is_some(),
        "DEFEITO: após reorg + re-mineração da MESMA tx, a wallet do destinatário \
         não re-reconhece o output recebido — `rollback_to` removeu o output e o \
         blinding (aleatório) não existe em lugar nenhum: nem o pending (status \
         `Received` é terminal, não rebobina) nem o journal `ReceiveConfirmed` \
         (não guarda blinding). Fundos recebidos perdidos permanentemente."
    );
    assert_eq!(survivor.unwrap().value, amount);
}
