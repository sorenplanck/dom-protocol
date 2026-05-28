//! Tiny argument parser. We avoid pulling clap so the .exe stays small.

use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Help,
    Doctor,
    Run(RunOptions),
    ListPrompts,
    ShowPrompt(PathBuf),
    Report,
    Clean,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RunOptions {
    /// Inline prompt text (mutually exclusive with `prompt_file`).
    pub prompt: Option<String>,
    /// Path to a prompt file (mutually exclusive with `prompt`).
    pub prompt_file: Option<PathBuf>,
    /// Whether to push to origin after a successful commit.
    pub push: bool,
    /// Which dom-test-runner profile to use. Defaults to "affected".
    pub profile: String,
}

pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let head = args.first().map(|s| s.as_str()).unwrap_or("help");
    match head {
        "help" | "--help" | "-h" => Ok(Cmd::Help),
        "doctor" => Ok(Cmd::Doctor),
        "list-prompts" => Ok(Cmd::ListPrompts),
        "show-prompt" => {
            let p = args
                .get(1)
                .ok_or("show-prompt requires a path argument")?;
            Ok(Cmd::ShowPrompt(PathBuf::from(p)))
        }
        "report" => Ok(Cmd::Report),
        "clean" => Ok(Cmd::Clean),
        "run" => {
            let opts = parse_run(&args[1..])?;
            Ok(Cmd::Run(opts))
        }
        other => Err(format!("unknown command: {other:?}")),
    }
}

fn parse_run(args: &[String]) -> Result<RunOptions, String> {
    let mut opts = RunOptions {
        prompt: None,
        prompt_file: None,
        push: false,
        profile: "affected".to_string(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--prompt" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--prompt requires a value")?
                    .to_string();
                opts.prompt = Some(v);
                i += 2;
            }
            "--prompt-file" => {
                let v = args.get(i + 1).ok_or("--prompt-file requires a value")?;
                opts.prompt_file = Some(PathBuf::from(v));
                i += 2;
            }
            "--push" => {
                opts.push = true;
                i += 1;
            }
            "--profile" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--profile requires a value")?
                    .to_string();
                match v.as_str() {
                    "affected" | "full" | "all" | "pre-push" => {
                        opts.profile = v;
                    }
                    other => return Err(format!("invalid profile: {other:?}")),
                }
                i += 2;
            }
            other => return Err(format!("unknown run flag: {other:?}")),
        }
    }
    match (&opts.prompt, &opts.prompt_file) {
        (None, None) => Err("run requires --prompt or --prompt-file".to_string()),
        (Some(_), Some(_)) => {
            Err("--prompt and --prompt-file are mutually exclusive".to_string())
        }
        _ => Ok(opts),
    }
}

pub fn print_help() {
    println!(
        "dom-agent-runner — Codex orchestrator for DOM Protocol\n\
\n\
USAGE:\n  \
dom-agent-runner <COMMAND>\n\
\n\
COMMANDS:\n  \
doctor                                       Check repo, codex, git, cargo.\n  \
run --prompt-file <file> [--push] [--profile P]\n  \
run --prompt \"<text>\" [--push] [--profile P]\n  \
list-prompts                                 List prompts/*.txt.\n  \
show-prompt <file>                           Print a prompt before running.\n  \
report                                       Print latest run report path.\n  \
clean                                        Remove target/dom-agent-runner/* only.\n  \
help                                         This message.\n\
\n\
RUN OPTIONS:\n  \
--prompt-file <FILE>   UTF-8 prompt file (preserved as-is).\n  \
--prompt \"<TEXT>\"      Inline prompt.\n  \
--push                 After a successful commit, push to origin.\n  \
--profile <P>          One of: affected (default), full, all, pre-push.\n\
\n\
SAFETY:\n  \
- No commit unless tests pass.\n  \
- No push unless commit succeeds and remote HEAD verifies.\n  \
- No secrets stored. Uses local Codex/Git auth.\n"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_doctor() {
        assert_eq!(parse(&s(&["doctor"])).unwrap(), Cmd::Doctor);
    }

    #[test]
    fn parses_help() {
        assert_eq!(parse(&s(&["help"])).unwrap(), Cmd::Help);
        assert_eq!(parse(&s(&["--help"])).unwrap(), Cmd::Help);
        assert_eq!(parse(&[]).unwrap(), Cmd::Help);
    }

    #[test]
    fn parses_run_with_inline_prompt() {
        let cmd = parse(&s(&["run", "--prompt", "hello world"])).unwrap();
        match cmd {
            Cmd::Run(o) => {
                assert_eq!(o.prompt.as_deref(), Some("hello world"));
                assert!(o.prompt_file.is_none());
                assert!(!o.push);
                assert_eq!(o.profile, "affected");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parses_run_with_file_and_push() {
        let cmd =
            parse(&s(&["run", "--prompt-file", "prompts/x.txt", "--push"])).unwrap();
        match cmd {
            Cmd::Run(o) => {
                assert!(o.push);
                assert_eq!(o.prompt_file.as_ref().unwrap().to_string_lossy(), "prompts/x.txt");
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn rejects_run_without_any_prompt() {
        let err = parse(&s(&["run", "--push"])).unwrap_err();
        assert!(err.contains("requires"));
    }

    #[test]
    fn rejects_run_with_both_prompts() {
        let err =
            parse(&s(&["run", "--prompt", "a", "--prompt-file", "b.txt"])).unwrap_err();
        assert!(err.contains("mutually exclusive"));
    }

    #[test]
    fn rejects_invalid_profile() {
        let err = parse(&s(&["run", "--prompt", "x", "--profile", "wat"])).unwrap_err();
        assert!(err.contains("invalid profile"));
    }

    #[test]
    fn show_prompt_requires_path() {
        let err = parse(&s(&["show-prompt"])).unwrap_err();
        assert!(err.contains("requires"));
    }
}
