//! dom-agent-runner
//!
//! Portable Windows-first orchestrator. Calls the installed Codex CLI as an
//! external process, then drives `dom-test-runner.exe` for validation, then
//! commits / pushes only if everything is green, and writes a full audit
//! report under `target/dom-agent-runner/runs/<timestamp>/`.
//!
//! No secrets are stored. Codex auth, GitHub auth, and Git config come from
//! the user's existing local environment.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::process::ExitCode;

mod cli;
mod doctor;
mod git;
mod prompt;
mod report;
mod repo;
mod run;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match cli::parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[dom-agent-runner] error: {e}");
            cli::print_help();
            return ExitCode::from(2);
        }
    };

    let result = match parsed {
        cli::Cmd::Help => {
            cli::print_help();
            Ok(())
        }
        cli::Cmd::Doctor => doctor::cmd_doctor(),
        cli::Cmd::Run(opts) => run::cmd_run(opts),
        cli::Cmd::ListPrompts => prompt::cmd_list(),
        cli::Cmd::ShowPrompt(path) => prompt::cmd_show(&path),
        cli::Cmd::Report => run::cmd_report(),
        cli::Cmd::Clean => run::cmd_clean(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[dom-agent-runner] FAIL: {e}");
            ExitCode::from(1)
        }
    }
}
