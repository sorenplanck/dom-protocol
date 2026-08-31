use btc_crypto::SecpContext;

const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

#[test]
fn canonical_scalar_derives_the_known_generator_x_coordinate() {
    let context = SecpContext::new(&[0x51; 32]);
    let mut scalar_one = [0_u8; 32];
    scalar_one[31] = 1;
    let derived = context
        .xonly_public_key(&scalar_one)
        .expect("canonical scalar");
    assert_eq!(derived, GENERATOR_X);
    assert!(context.validate_xonly_key(&derived).is_ok());
}

#[test]
fn zero_and_out_of_range_scalars_are_refused_without_signing() {
    let context = SecpContext::new(&[0x52; 32]);
    assert!(context.xonly_public_key(&[0; 32]).is_err());
    assert!(context.xonly_public_key(&[0xff; 32]).is_err());
}
