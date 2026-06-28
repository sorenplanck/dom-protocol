use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_wallet2::{
    create_send, finalize_tracked, receive, submit_finalized, BlockRef, InMemoryTxSink, Network,
    OutputOrigin, StoredOutput, WalletV2State,
};

const CHAIN_ID: [u8; 32] = [0x72; 32];

fn spendable_output(value: u64, height: u64) -> StoredOutput {
    let blinding = BlindingFactor::random();
    let commitment = *Commitment::commit(value, &blinding).as_bytes();
    let mut output = StoredOutput::new_unconfirmed(
        commitment,
        value,
        *blinding.as_bytes(),
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1000,
    );
    output
        .confirm(
            BlockRef {
                height,
                hash: [height as u8; 32],
            },
            1000,
        )
        .unwrap();
    output
}

#[test]
fn finalized_payment_can_submit_after_state_round_trip() {
    let mut sender = WalletV2State::new(Network::Regtest, CHAIN_ID);
    sender.meta.last_reconciled_tip = 100;
    sender.outputs.insert(spendable_output(1200, 10)).unwrap();

    let sent = create_send(&mut sender, 1000, 10, 2000).unwrap();
    let mut receiver = WalletV2State::new(Network::Regtest, CHAIN_ID);
    let answered = receive(&mut receiver, sent.slate, 3000).unwrap();
    let (_tx, slate_hash) = finalize_tracked(&mut sender, answered, 4000).unwrap();

    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("wallet.dombak");
    dom_wallet2::export_full_backup(&sender, &path, "pw", 5000).unwrap();
    let mut restored = dom_wallet2::import_full_backup(&path, "pw", CHAIN_ID).unwrap();

    let sink = InMemoryTxSink::accepting([0x44; 32]);
    submit_finalized(&mut restored, &sink, slate_hash, 6000).unwrap();
    assert_eq!(sink.calls(), 1);
}
