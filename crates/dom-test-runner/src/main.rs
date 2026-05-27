use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use dom_test_runner::{
    build_report_only, changed_files, clean_runner_data, command_plan_for_pre_push,
    detect_repo_root, explain_selection, profile_commands, run_steps, select_profiles, Profile,
};
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "dom-test-runner")]
#[command(about = "Portable DOM Protocol validation runner", long_about = None, disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Doctor,
    FastCheck,
    Affected,
    Explain {
        #[command(subcommand)]
        command: ExplainCommands,
    },
    PrePush,
    Unit,
    Mempool,
    Node,
    Wire,
    Pow,
    Chain,
    Store,
    Wallet,
    WalletApp,
    Integration,
    IntegrationMempool,
    IntegrationNetwork,
    TwoNode,
    Reorg,
    Ibd,
    Full,
    All,
    Clean,
    Report,
    Help,
}

#[derive(Subcommand)]
enum ExplainCommands {
    Affected,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor(),
        Commands::FastCheck => run_profile(Profile::FastCheck, "fast-check"),
        Commands::Unit => run_profile(Profile::Unit, "unit"),
        Commands::Mempool => run_profile(Profile::Mempool, "mempool"),
        Commands::Node => run_profile(Profile::Node, "node"),
        Commands::Wire => run_profile(Profile::Wire, "wire"),
        Commands::Pow => run_profile(Profile::Pow, "pow"),
        Commands::Chain => run_profile(Profile::Chain, "chain"),
        Commands::Store => run_profile(Profile::Store, "store"),
        Commands::Wallet => run_profile(Profile::Wallet, "wallet"),
        Commands::WalletApp => run_profile(Profile::WalletApp, "wallet-app"),
        Commands::Integration => run_profile(Profile::Integration, "integration"),
        Commands::IntegrationMempool => {
            run_profile(Profile::IntegrationMempool, "integration-mempool")
        }
        Commands::IntegrationNetwork => {
            run_profile(Profile::IntegrationNetwork, "integration-network")
        }
        Commands::TwoNode => run_profile(Profile::TwoNode, "two-node"),
        Commands::Reorg => run_profile(Profile::Reorg, "reorg"),
        Commands::Ibd => run_profile(Profile::Ibd, "ibd"),
        Commands::Full => run_profile(Profile::Full, "full"),
        Commands::All => run_profile(Profile::All, "all"),
        Commands::Affected => affected(),
        Commands::Explain { command } => match command {
            ExplainCommands::Affected => explain_affected(),
        },
        Commands::PrePush => pre_push(),
        Commands::Clean => clean(),
        Commands::Report => report(),
        Commands::Help => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn repo_root() -> Result<PathBuf> {
    detect_repo_root(&std::env::current_dir()?)
}

fn doctor() -> Result<()> {
    let root = repo_root()?;
    println!("Repository root: {}", root.display());
    let tools = ["git", "cargo", "rustc", "codex"];
    for tool in tools {
        let output = Command::new(tool).arg("--version").output();
        match output {
            Ok(out) if out.status.success() => {
                println!("PASS: {tool} available");
            }
            Ok(out) => {
                println!("FAIL: {tool} --version returned {}", out.status);
                if tool == "codex" {
                    println!("Install Codex CLI and ensure it is on PATH.");
                }
            }
            Err(err) => {
                println!("FAIL: {tool} unavailable: {err}");
                if tool == "codex" {
                    println!("Install Codex CLI and ensure it is on PATH.");
                }
            }
        }
    }
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(&root)
        .output()?;
    if output.status.success() {
        println!("PASS: git remote origin exists");
    } else {
        println!("FAIL: git remote origin not configured");
    }
    Ok(())
}

fn run_profile(profile: Profile, run_name: &str) -> Result<()> {
    let root = repo_root()?;
    let steps = profile_commands(profile, &root)?;
    let summary = run_steps(&root, run_name, profile.name(), steps)?;
    println!("Final status: {}", summary.final_status.as_str());
    Ok(())
}

fn affected() -> Result<()> {
    let root = repo_root()?;
    let files = changed_files(&root)?;
    if files.is_empty() {
        println!("No local changes detected; running fast-check only.");
        let summary = run_steps(
            &root,
            "affected",
            "fast-check",
            profile_commands(Profile::FastCheck, &root)?,
        )?;
        println!("Final status: {}", summary.final_status.as_str());
        return Ok(());
    }
    let selection = select_profiles(&files);
    println!("{}", explain_selection(&selection));
    let mut steps = Vec::new();
    for selected in &selection.profiles {
        steps.extend(profile_commands(selected.profile, &root)?);
    }
    if steps.is_empty() {
        steps = profile_commands(Profile::FastCheck, &root)?;
    }
    let summary = run_steps(&root, "affected", "affected", steps)?;
    println!("Final status: {}", summary.final_status.as_str());
    Ok(())
}

fn explain_affected() -> Result<()> {
    let root = repo_root()?;
    let files = changed_files(&root)?;
    let selection = select_profiles(&files);
    println!("{}", explain_selection(&selection));
    Ok(())
}

fn pre_push() -> Result<()> {
    let root = repo_root()?;
    let files = changed_files(&root)?;
    let selection = select_profiles(&files);
    let steps = command_plan_for_pre_push(&root, &selection)?;
    let summary = run_steps(&root, "pre-push", "pre-push", steps)?;
    println!("Final status: {}", summary.final_status.as_str());
    Ok(())
}

fn clean() -> Result<()> {
    let root = repo_root()?;
    clean_runner_data(&root)?;
    println!("Cleaned {}", root.join("target/dom-test-runner").display());
    Ok(())
}

fn report() -> Result<()> {
    let root = repo_root()?;
    build_report_only(&root)
}
