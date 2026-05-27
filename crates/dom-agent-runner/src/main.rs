use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser, Subcommand};
use dom_agent_runner::{
    agent_latest_run, build_or_verify_test_runner, changed_files, clean_agent_data,
    create_isolated_worktree, create_run_paths, git_changed_files, git_head,
    git_remote_origin_exists, git_staged_files, git_status_short, list_prompts,
    perform_pre_push_steps, prompt_from_text, read_prompt_file, repo_root, run_codex,
    selected_profiles_for_changed_files, stage_files, timestamp_label, write_final_report,
    write_text, PromptInput,
};
use dom_test_runner::{profile_commands, run_steps, Profile, StepStatus};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "dom-agent-runner")]
#[command(about = "Portable DOM Protocol Codex automation runner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Doctor,
    Run {
        #[arg(long)]
        prompt_file: Option<PathBuf>,
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long)]
        push: bool,
        #[arg(long, default_value = "affected")]
        profile: String,
    },
    ListPrompts,
    ShowPrompt {
        file: PathBuf,
    },
    Report,
    Clean,
    Help,
}

#[derive(Debug, Clone, Default)]
struct RunOutcome {
    final_status: &'static str,
    commit_hash: Option<String>,
    push_status: Option<String>,
    remote_head: Option<String>,
    staged: Vec<String>,
    error: Option<String>,
    codex_command: Option<String>,
    codex_exit_code: Option<i32>,
    dom_test_runner_executed: bool,
    commit_created: bool,
    push_attempted: bool,
    worktree_created: bool,
}

impl RunOutcome {
    fn fail() -> Self {
        Self {
            final_status: "FAIL",
            ..Self::default()
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Run {
            prompt_file,
            prompt,
            push,
            profile,
        } => run(prompt_file, prompt, push, profile),
        Commands::ListPrompts => list_prompt_files(),
        Commands::ShowPrompt { file } => show_prompt_file(file),
        Commands::Report => report(),
        Commands::Clean => clean(),
        Commands::Help => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

fn current_repo_root() -> Result<PathBuf> {
    repo_root(&std::env::current_dir()?)
}

fn doctor() -> Result<()> {
    let root = current_repo_root()?;
    println!("Repository root: {}", root.display());

    for tool in ["git", "cargo", "rustc", "codex"] {
        let output = Command::new(tool).arg("--version").output();
        match output {
            Ok(out) if out.status.success() => println!("PASS: {tool} available"),
            Ok(out) => println!("FAIL: {tool} --version returned {}", out.status),
            Err(err) => {
                println!("FAIL: {tool} unavailable: {err}");
                if tool == "codex" {
                    println!("Install the Codex CLI and ensure `codex` is on PATH.");
                }
            }
        }
    }

    match git_remote_origin_exists(&root)? {
        true => println!("PASS: git remote origin exists"),
        false => println!("FAIL: git remote origin is missing"),
    }

    match build_or_verify_test_runner(&root) {
        Ok(path) => println!("PASS: dom-test-runner available at {}", path.display()),
        Err(err) => println!("FAIL: dom-test-runner unavailable: {err}"),
    }

    Ok(())
}

fn list_prompt_files() -> Result<()> {
    let root = current_repo_root()?;
    for file in list_prompts(&root)? {
        println!("{}", file.display());
    }
    Ok(())
}

fn show_prompt_file(file: PathBuf) -> Result<()> {
    let prompt = read_prompt_file(&file)?;
    println!("{}", prompt.content);
    Ok(())
}

fn report() -> Result<()> {
    let root = current_repo_root()?;
    let latest = agent_latest_run(&root)?;
    let run_dir = PathBuf::from(latest.trim());
    let report = fs::read_to_string(run_dir.join("final-report.txt"))?;
    println!("{report}");
    Ok(())
}

fn clean() -> Result<()> {
    let root = current_repo_root()?;
    clean_agent_data(&root)?;
    println!("Cleaned {}", root.join("target/dom-agent-runner").display());
    Ok(())
}

fn resolve_prompt(prompt_file: Option<PathBuf>, prompt: Option<String>) -> Result<PromptInput> {
    match (prompt_file, prompt) {
        (Some(file), None) => read_prompt_file(&file),
        (None, Some(text)) => prompt_from_text(text),
        (Some(_), Some(_)) => Err(anyhow!("use either --prompt-file or --prompt, not both")),
        (None, None) => Err(anyhow!("a prompt is required")),
    }
}

fn run(
    prompt_file: Option<PathBuf>,
    prompt: Option<String>,
    push: bool,
    profile: String,
) -> Result<()> {
    let root = current_repo_root()?;
    let prompt = resolve_prompt(prompt_file, prompt)?;

    let timestamp = timestamp_label();
    let paths = create_run_paths(&root, &timestamp)?;
    write_text(&paths.prompt_file, &prompt.content)?;
    write_text(&paths.git_status_before, git_status_short(&root)?)?;
    write_text(&paths.changed_files, git_changed_files(&root)?)?;
    write_text(&paths.staged_files, git_staged_files(&root)?)?;
    let initial_head = git_head(&root)?;

    let mut outcome = RunOutcome::fail();
    write_run_report(
        &paths,
        &prompt,
        &root,
        &initial_head,
        &outcome,
        &[],
        "STARTED",
    )?;
    let run_result: Result<(RunOutcome, Vec<String>)> = (|| {
        let worktree = create_isolated_worktree(&root, &paths)?;
        outcome.worktree_created = true;
        outcome.codex_command = Some(dom_agent_runner::codex_command(&worktree)?.display());
        write_run_report(
            &paths,
            &prompt,
            &root,
            &initial_head,
            &outcome,
            &[],
            "RUNNING",
        )?;
        let codex_output = run_codex(&worktree, &prompt, &paths.codex_log)?;
        outcome.codex_exit_code = codex_output.status.code();
        let codex_ok = codex_output.status.success();
        if !codex_ok {
            return Ok((
                RunOutcome {
                    error: Some(format!(
                        "codex failed with exit code {}; see {}",
                        codex_output
                            .status
                            .code()
                            .map(|code| code.to_string())
                            .unwrap_or_else(|| "unknown".into()),
                        paths.codex_log.display()
                    )),
                    ..outcome.clone()
                },
                Vec::new(),
            ));
        }

        let test_runner = build_or_verify_test_runner(&worktree)?;
        outcome.dom_test_runner_executed = true;
        write_text(
            &paths.test_log,
            format!(
                "dom-test-runner: {}\nstatus: started\n",
                test_runner.display()
            ),
        )?;
        write_run_report(
            &paths,
            &prompt,
            &root,
            &initial_head,
            &outcome,
            &[],
            "RUNNING_TESTS",
        )?;
        let test_output = if profile == "pre-push" {
            let selection = selected_profiles_for_changed_files(&changed_files(&worktree)?);
            let steps = perform_pre_push_steps(&worktree, &selection)?;
            run_steps(&worktree, "pre-push", "pre-push", steps)?
        } else if profile == "affected" {
            let selection = selected_profiles_for_changed_files(&changed_files(&worktree)?);
            let mut steps = Vec::new();
            for selected in &selection.profiles {
                steps.extend(profile_commands(selected.profile, &worktree)?);
            }
            run_steps(&worktree, "affected", "affected", steps)?
        } else {
            let profile_enum = match profile.as_str() {
                "full" => Profile::Full,
                "all" => Profile::All,
                other => {
                    return Err(anyhow!(
                        "unsupported profile {other}; use affected, full, all, or pre-push"
                    ))
                }
            };
            let steps = profile_commands(profile_enum, &worktree)?;
            run_steps(&worktree, &profile, &profile, steps)?
        };

        write_text(
            &paths.test_log,
            format!(
                "dom-test-runner: {}\nfinal status: {}\n",
                test_runner.display(),
                test_output.final_status.as_str()
            ),
        )?;

        let changed = git_changed_files(&worktree)?;
        write_text(&paths.changed_files, &changed)?;
        let changed_list: Vec<String> = changed
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        let mut local_outcome = outcome.clone();
        if test_output.final_status == StepStatus::Pass {
            local_outcome.staged = stage_files(&worktree, &changed_list)?;
            write_text(&paths.staged_files, local_outcome.staged.join("\n"))?;
            if local_outcome.staged.is_empty() {
                local_outcome.error = Some("no files were staged".into());
            } else {
                let commit_msg = format!("feat: codex automation run {timestamp}");
                let commit_output = Command::new("git")
                    .args(["commit", "-m", &commit_msg])
                    .current_dir(&worktree)
                    .output()?;
                write_text(
                    &paths.commit_file,
                    dom_agent_runner::command_output_text(&commit_output),
                )?;
                if commit_output.status.success() {
                    local_outcome.commit_hash = Some(git_head(&worktree)?);
                    local_outcome.commit_created = true;
                    if push {
                        local_outcome.push_attempted = true;
                        let push_output = Command::new("git")
                            .args(["push", "origin", "main"])
                            .current_dir(&worktree)
                            .output()?;
                        local_outcome.push_status =
                            Some(dom_agent_runner::command_output_text(&push_output));
                        if push_output.status.success() {
                            let remote_output = Command::new("git")
                                .args(["ls-remote", "origin", "refs/heads/main"])
                                .current_dir(&worktree)
                                .output()?;
                            local_outcome.remote_head =
                                Some(dom_agent_runner::command_output_text(&remote_output));
                            write_text(
                                &paths.remote_head,
                                local_outcome.remote_head.as_ref().unwrap(),
                            )?;
                            local_outcome.final_status = "PASS";
                        } else {
                            local_outcome.error = Some("push failed".into());
                        }
                    } else {
                        local_outcome.final_status = "PASS";
                    }
                } else {
                    local_outcome.error =
                        Some(dom_agent_runner::command_output_text(&commit_output));
                }
            }
        } else {
            local_outcome.error = Some("tests failed".into());
        }

        write_text(&paths.git_status_after, git_status_short(&worktree)?)?;
        let tests_run: Vec<String> = test_output
            .steps
            .iter()
            .map(|step| step.command.clone())
            .collect();
        Ok((local_outcome, tests_run))
    })();

    let tests_run = match run_result {
        Ok((outcome_result, tests)) => {
            outcome = outcome_result;
            tests
        }
        Err(err) => {
            outcome.error = Some(err.to_string());
            if paths.worktree_dir.exists() {
                outcome.worktree_created = true;
                if outcome.codex_command.is_none() {
                    if let Ok(command) = dom_agent_runner::codex_command(&paths.worktree_dir) {
                        outcome.codex_command = Some(command.display());
                    }
                }
            }
            Vec::new()
        }
    };

    write_run_report(
        &paths,
        &prompt,
        &root,
        &initial_head,
        &outcome,
        &tests_run,
        outcome.final_status,
    )?;

    if outcome.final_status == "PASS" {
        println!("Run complete: {}", paths.final_report.display());
    } else {
        println!("Run failed: {}", paths.final_report.display());
        if let Some(error) = &outcome.error {
            println!("Error: {error}");
        }
        if outcome.codex_exit_code.is_some() || paths.codex_log.exists() {
            println!("Codex output: {}", paths.codex_log.display());
        }
        if outcome.worktree_created && !outcome.commit_created {
            println!(
                "Run failed before commit. Worktree preserved for inspection at: {}",
                paths.worktree_dir.display()
            );
        }
    }
    Ok(())
}

fn changed_list_or_empty(path: &PathBuf) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect())
}

fn write_run_report(
    paths: &dom_agent_runner::RunPaths,
    prompt: &PromptInput,
    root: &std::path::Path,
    initial_head: &str,
    outcome: &RunOutcome,
    tests_run: &[String],
    status: &str,
) -> Result<()> {
    let changed_list = changed_list_or_empty(&paths.changed_files)?;
    write_final_report(
        paths,
        prompt,
        root,
        initial_head,
        outcome.commit_hash.as_deref(),
        outcome.remote_head.as_deref(),
        &changed_list,
        &outcome.staged,
        tests_run,
        outcome.codex_command.as_deref(),
        outcome.codex_exit_code,
        outcome.dom_test_runner_executed,
        status,
        outcome.commit_hash.as_deref(),
        outcome.commit_created,
        outcome.push_attempted,
        outcome.push_status.as_deref(),
        outcome.error.as_deref(),
    )
}
