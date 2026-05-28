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

const IN_PLACE_DIRTY_ERROR: &str = "Refusing --in-place run because the worktree is not clean. Commit, stash, or use isolated mode.";

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
        #[arg(long)]
        in_place: bool,
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
    execution_mode: ExecutionMode,
}

impl RunOutcome {
    fn fail() -> Self {
        Self {
            final_status: "FAIL",
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ExecutionMode {
    #[default]
    IsolatedWorktree,
    InPlace,
}

impl ExecutionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::IsolatedWorktree => "isolated-worktree",
            Self::InPlace => "in-place",
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
            in_place,
        } => run(prompt_file, prompt, push, profile, in_place),
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
    in_place: bool,
) -> Result<()> {
    let root = current_repo_root()?;
    let prompt = resolve_prompt(prompt_file, prompt)?;
    let execution_mode = if in_place {
        ExecutionMode::InPlace
    } else {
        ExecutionMode::IsolatedWorktree
    };

    let initial_git_status = git_status_short(&root)?;
    let timestamp = timestamp_label();
    let paths = create_run_paths(&root, &timestamp)?;
    write_text(&paths.prompt_file, &prompt.content)?;
    write_text(&paths.git_status_before, &initial_git_status)?;
    write_text(&paths.changed_files, git_changed_files(&root)?)?;
    write_text(&paths.staged_files, git_staged_files(&root)?)?;
    let initial_head = git_head(&root)?;

    let mut outcome = RunOutcome {
        execution_mode,
        ..RunOutcome::fail()
    };
    write_run_report(
        &paths,
        &prompt,
        &root,
        &initial_head,
        &outcome,
        &[],
        "STARTED",
    )?;
    if execution_mode == ExecutionMode::InPlace && !initial_git_status.trim().is_empty() {
        outcome.error = Some(IN_PLACE_DIRTY_ERROR.into());
        write_text(&paths.git_status_after, &initial_git_status)?;
        write_run_report(
            &paths,
            &prompt,
            &root,
            &initial_head,
            &outcome,
            &[],
            outcome.final_status,
        )?;
        println!("{IN_PLACE_DIRTY_ERROR}");
        println!("Run failed: {}", paths.final_report.display());
        return Ok(());
    }

    let run_result: Result<(RunOutcome, Vec<String>)> = (|| {
        let execution_root = match execution_mode {
            ExecutionMode::InPlace => root.clone(),
            ExecutionMode::IsolatedWorktree => {
                let worktree = create_isolated_worktree(&root, &paths)?;
                outcome.worktree_created = true;
                worktree
            }
        };
        outcome.codex_command = Some(dom_agent_runner::codex_command(&execution_root)?.display());
        write_run_report(
            &paths,
            &prompt,
            &root,
            &initial_head,
            &outcome,
            &[],
            "RUNNING",
        )?;
        let codex_output = run_codex(&execution_root, &prompt, &paths.codex_log)?;
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

        let test_runner = build_or_verify_test_runner(&execution_root)?;
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
        let test_output = run_validation_profile(
            &execution_root,
            &profile,
            execution_mode == ExecutionMode::InPlace,
        )?;

        write_text(
            &paths.test_log,
            format!(
                "dom-test-runner: {}\nfinal status: {}\n",
                test_runner.display(),
                test_output.final_status.as_str()
            ),
        )?;

        let changed = git_changed_files(&execution_root)?;
        write_text(&paths.changed_files, &changed)?;
        let changed_list: Vec<String> = changed
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        let mut local_outcome = outcome.clone();
        if test_output.final_status == StepStatus::Pass {
            local_outcome.staged = stage_files(&execution_root, &changed_list)?;
            write_text(&paths.staged_files, local_outcome.staged.join("\n"))?;
            if local_outcome.staged.is_empty() {
                local_outcome.error = Some("no files were staged".into());
            } else {
                let commit_msg = format!("feat: codex automation run {timestamp}");
                let commit_output = Command::new("git")
                    .args(["commit", "-m", &commit_msg])
                    .current_dir(&execution_root)
                    .output()?;
                write_text(
                    &paths.commit_file,
                    dom_agent_runner::command_output_text(&commit_output),
                )?;
                if commit_output.status.success() {
                    local_outcome.commit_hash = Some(git_head(&execution_root)?);
                    local_outcome.commit_created = true;
                    if push {
                        local_outcome.push_attempted = true;
                        let push_output = Command::new("git")
                            .args(["push", "origin", "main"])
                            .current_dir(&execution_root)
                            .output()?;
                        local_outcome.push_status =
                            Some(dom_agent_runner::command_output_text(&push_output));
                        if push_output.status.success() {
                            let remote_output = Command::new("git")
                                .args(["ls-remote", "origin", "refs/heads/main"])
                                .current_dir(&execution_root)
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

        write_text(&paths.git_status_after, git_status_short(&execution_root)?)?;
        Ok((local_outcome, test_output.steps))
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

struct ValidationOutput {
    final_status: StepStatus,
    steps: Vec<String>,
}

fn run_validation_profile(
    repo_root: &std::path::Path,
    profile: &str,
    run_pre_push_after_affected: bool,
) -> Result<ValidationOutput> {
    if profile == "pre-push" {
        let selection = selected_profiles_for_changed_files(&changed_files(repo_root)?);
        let steps = perform_pre_push_steps(repo_root, &selection)?;
        let output = run_steps(repo_root, "pre-push", "pre-push", steps)?;
        return Ok(ValidationOutput {
            final_status: output.final_status,
            steps: output
                .steps
                .iter()
                .map(|step| step.command.clone())
                .collect(),
        });
    }

    if profile == "affected" {
        let selection = selected_profiles_for_changed_files(&changed_files(repo_root)?);
        let mut steps = Vec::new();
        for selected in &selection.profiles {
            steps.extend(profile_commands(selected.profile, repo_root)?);
        }
        let affected = run_steps(repo_root, "affected", "affected", steps)?;
        let mut commands: Vec<String> = affected
            .steps
            .iter()
            .map(|step| step.command.clone())
            .collect();
        if affected.final_status != StepStatus::Pass || !run_pre_push_after_affected {
            return Ok(ValidationOutput {
                final_status: affected.final_status,
                steps: commands,
            });
        }

        let steps = perform_pre_push_steps(repo_root, &selection)?;
        let pre_push = run_steps(repo_root, "pre-push", "pre-push", steps)?;
        commands.extend(pre_push.steps.iter().map(|step| step.command.clone()));
        return Ok(ValidationOutput {
            final_status: pre_push.final_status,
            steps: commands,
        });
    }

    let profile_enum = match profile {
        "full" => Profile::Full,
        "all" => Profile::All,
        other => {
            return Err(anyhow!(
                "unsupported profile {other}; use affected, full, all, or pre-push"
            ))
        }
    };
    let steps = profile_commands(profile_enum, repo_root)?;
    let output = run_steps(repo_root, profile, profile, steps)?;
    Ok(ValidationOutput {
        final_status: output.final_status,
        steps: output
            .steps
            .iter()
            .map(|step| step.command.clone())
            .collect(),
    })
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
        outcome.execution_mode.as_str(),
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
