#![no_main]

use std::sync::OnceLock;

use btc_evidence::{
    BitcoinEvidenceNetworkV2, BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2,
    BitcoinOutPointV2, BitcoinOutcomeV2, BitcoinTransactionClaimV2, KeystoneBitcoinEvidenceV2,
};
use libfuzzer_sys::fuzz_target;

fn canonical_v2_seed() -> &'static [u8] {
    static SEED: OnceLock<Vec<u8>> = OnceLock::new();

    SEED.get_or_init(|| {
        KeystoneBitcoinEvidenceV2::new(
            BitcoinEvidenceRouteBindingV2::new([2; 32], [3; 32])
                .expect("fixed V2 route binding is valid"),
            BitcoinHeaderPolicyBindingV2::new(
                BitcoinEvidenceNetworkV2::Regtest,
                [1; 32],
                8,
                [10; 32],
                [11; 32],
                2,
            )
            .expect("fixed V2 policy binding is valid"),
            BitcoinTransactionClaimV2::new(
                [6; 32],
                [7; 32],
                BitcoinOutPointV2::new([4; 32], 5).expect("fixed V2 outpoint is valid"),
                10,
                9,
                BitcoinOutcomeV2::KeyPathClaim,
            )
            .expect("fixed V2 transaction claim is valid"),
            vec![1, 2, 3],
            vec![[12; 80]],
        )
        .expect("fixed V2 evidence is bounded")
        .encode()
        .expect("fixed V2 evidence encodes")
    })
}

fn exercise_exact_decoder(bytes: &[u8]) {
    let Ok(decoded) = KeystoneBitcoinEvidenceV2::decode(bytes) else {
        return;
    };
    let encoded = decoded
        .encode()
        .expect("every decoded V2 value must re-encode canonically");
    let round_trip = KeystoneBitcoinEvidenceV2::decode(&encoded)
        .expect("canonical V2 output must decode exactly");
    assert!(
        round_trip == decoded,
        "canonical V2 decode/encode/decode must preserve the value"
    );
}

fuzz_target!(|data: &[u8]| {
    // Raw input reaches magic/version/truncation/trailing and all pre-allocation
    // bounds directly. There is intentionally no attempt to decode V1.
    exercise_exact_decoder(data);

    // A valid constructor-produced seed lets byte-level mutations reach deep V2
    // fields without checking in a lockstep binary corpus. Raw input above still
    // covers insertion, deletion and arbitrary-length cases.
    let mut structured = canonical_v2_seed().to_vec();
    let (mutations, _) = data.as_chunks::<3>();
    for mutation in mutations.iter().take(1_024) {
        let index = usize::from(u16::from_be_bytes([mutation[0], mutation[1]])) % structured.len();
        structured[index] ^= mutation[2];
    }
    exercise_exact_decoder(&structured);
});
