mod common;

use dom_slate::{finalize, respond_receive, SlateError};
use dom_tx::slate::RECOVERY_SLATE_VERSION;

#[test]
fn respond_receive_rejects_unsupported_slate_version() {
    let sender = common::build_balanced_send(1_000, 10, 500);
    let mut slate = sender.slate;
    slate.version = RECOVERY_SLATE_VERSION + 1;

    let err = match respond_receive(slate, &common::TEST_CHAIN_ID) {
        Ok(_) => panic!("expected unsupported version rejection"),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            SlateError::UnsupportedVersion(version, expected)
                if version == RECOVERY_SLATE_VERSION + 1 && expected == RECOVERY_SLATE_VERSION
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn finalize_rejects_unsupported_slate_version() {
    let sender = common::build_balanced_send(1_000, 10, 500);
    let response = respond_receive(sender.slate.clone(), &common::TEST_CHAIN_ID)
        .expect("honest recipient response");
    let mut slate = response.slate;
    slate.version = RECOVERY_SLATE_VERSION + 1;

    let err = finalize(
        &slate,
        &sender.excess_blinding,
        &sender.nonce,
        &common::TEST_CHAIN_ID,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            SlateError::UnsupportedVersion(version, expected)
                if version == RECOVERY_SLATE_VERSION + 1 && expected == RECOVERY_SLATE_VERSION
        ),
        "unexpected error: {err:?}"
    );
}
