use dom_bp_migration_lab::{CurrentOracle, OracleCase, OracleResponse};
use std::io::{self, BufRead, Write};

fn main() {
    let oracle = CurrentOracle;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    for line in io::stdin().lock().lines() {
        let response = match line {
            Ok(line) => match serde_json::from_str::<OracleCase>(&line) {
                Ok(case) => oracle.prove_verify(&case),
                Err(_) => OracleResponse::malformed_input(),
            },
            Err(_) => OracleResponse::malformed_input(),
        };
        let encoded =
            serde_json::to_string(&response).expect("response serialization is infallible");
        writeln!(output, "{encoded}").expect("stdout write failed");
    }
}
