//! dom-test-runner
//!
//! Portable Windows-first validation tool for the DOM Protocol workspace.
//!
//! This binary is intentionally dependency-free (std only) so the compiled
//! `dom-test-runner.exe` is small, fast to build on CI, and easy to audit.
//!
//! See `docs/testing/WINDOWS_TEST_RUNNER.md` for user documentation.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::process::ExitCode;

mod affected;
mod env;
mod profiles;
mod report;
mod repo;
mod runner;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");

    let result = match cmd {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "doctor" => runner::cmd_doctor(),
        "fast-check" => runner::run_profile("fast-check"),
        "affected" => runner::cmd_affected(false),
        "explain" => {
            // `explain affected` is the only documented subcommand.
            let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if sub == "affected" {
                runner::cmd_affected(true)
            } else {
                eprintln!("[dom-test-runner] error: unknown 'explain' subcommand: {sub:?}");
                eprintln!("                 hint: try `dom-test-runner explain affected`");
                return ExitCode::from(2);
            }
        }
        "pre-push" => runner::cmd_pre_push(),
        "unit" => runner::run_profile("unit"),
        "mempool" => runner::run_profile("mempool"),
        "node" => runner::run_profile("node"),
        "wire" => runner::run_profile("wire"),
        "pow" => runner::run_profile("pow"),
        "chain" => runner::run_profile("chain"),
        "store" => runner::run_profile("store"),
        "wallet" => runner::run_profile("wallet"),
        "wallet-app" => runner::run_profile("wallet-app"),
        "integration" => runner::run_profile("integration"),
        "integration-mempool" => runner::run_profile("integration-mempool"),
        "integration-network" => runner::run_profile("integration-network"),
        "two-node" => runner::run_profile("two-node"),
        "reorg" => runner::run_profile("reorg"),
        "ibd" => runner::run_profile("ibd"),
        "full" => runner::run_profile("full"),
        "all" => runner::run_profile("all"),
        "clean" => runner::cmd_clean(),
        "report" => runner::cmd_report(),
        other => {
            eprintln!("[dom-test-runner] error: unknown command: {other:?}");
            eprintln!("                 hint: run `dom-test-runner help`");
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[dom-test-runner] FAIL: {e}");
            ExitCode::from(1)
        }
    }
}

fn print_help() {
    // Plain ASCII output. No ANSI escapes. Works in default Windows terminal,
    // PowerShell without execution-policy changes, and cmd.exe.
    println!(
        "dom-test-runner — portable DOM Protocol validation tool\n\
\n\
USAGE:\n  \
dom-test-runner <COMMAND>\n\
\n\
COMMANDS:\n  \
doctor                Check environment (repo, cargo, rustc, git).\n  \
fast-check            Fastest sanity check (cargo check on hot crates).\n  \
affected              Run tests selected automatically from changed files.\n  \
explain affected      Print which profiles `affected` would select and why.\n  \
pre-push              Minimum safe validation before commit/push.\n  \
unit                  Workspace lib-only unit tests.\n  \
mempool               Mempool + node mempool tests (single-threaded).\n  \
node                  dom-node tests (single-threaded).\n  \
wire                  dom-wire tests (single-threaded).\n  \
pow                   dom-pow tests + node miner tests.\n  \
chain                 dom-chain tests (single-threaded).\n  \
store                 dom-store tests (single-threaded).\n  \
wallet                dom-wallet tests (single-threaded).\n  \
wallet-app            dom-wallet-app check + tests (if any).\n  \
integration           Full dom-integration-tests suite.\n  \
integration-mempool   mempool_relay integration test only.\n  \
integration-network   two_node + three_node integration tests.\n  \
two-node              two_node integration test only.\n  \
reorg                 reorg integration test only.\n  \
ibd                   ibd integration test only.\n  \
full                  check + test workspace + clippy -D warnings.\n  \
all                   Attempt complete workspace validation (incl. ignored).\n  \
clean                 Remove target/dom-test-runner/* only.\n  \
report                Print latest run report path.\n  \
help                  This message.\n\
\n\
ENVIRONMENT (set automatically for test profiles):\n  \
DOM_NETWORK=regtest        — selects regtest network for tests\n  \
DOM_REGTEST_FAST_MINING=1  — opt-in flag honored ONLY in regtest/devtest/test\n  \
RUST_BACKTRACE=1           — for better failure diagnostics\n\
\n\
Logs:    target/dom-test-runner/logs/\n\
Reports: target/dom-test-runner/reports/\n\
Latest:  target/dom-test-runner/reports/latest-report.txt\n"
    );
}
