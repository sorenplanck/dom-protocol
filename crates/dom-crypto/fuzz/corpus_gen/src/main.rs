use std::fs;
use std::path::Path;
use dom_crypto::{bp2_prove};
use dom_crypto::BlindingFactor;

fn write_seed(dir: &Path, name: &str, commitment: &[u8; 33], proof: &[u8]) {
    let mut buf = Vec::with_capacity(33 + proof.len());
    buf.extend_from_slice(commitment);
    buf.extend_from_slice(proof);
    fs::write(dir.join(name), &buf).expect("write seed");
    println!("seed {} -> {} bytes", name, buf.len());
}

fn main() {
    let dir = Path::new("corpus/fuzz_bp2_verify");
    fs::create_dir_all(dir).expect("mkdir corpus");

    for (i, v) in [0u64, 1, 42, 1_000_000, u64::MAX].iter().enumerate() {
        let blinding = BlindingFactor::from_bytes([ (i as u8) + 1; 32 ])
            .expect("blinding");
        match bp2_prove(*v, &blinding) {
            Ok((proof, commitment)) => {
                write_seed(dir, &format!("valid_{}.bin", i), &commitment, &proof);
            }
            Err(e) => eprintln!("bp2_prove({}) failed: {:?}", v, e),
        }
    }

    let zero_commit = [2u8; 33];
    write_seed(dir, "edge_empty.bin", &zero_commit, &[]);
    write_seed(dir, "edge_1.bin", &zero_commit, &[0u8]);
    write_seed(dir, "edge_max768.bin", &zero_commit, &vec![0u8; 768]);
    write_seed(dir, "edge_769.bin", &zero_commit, &vec![0u8; 769]);
}
