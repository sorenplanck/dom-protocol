# Windows Agent Runner

`dom-agent-runner.exe` orchestrates development work by calling the installed Codex CLI, running DOM validation, and then committing and pushing if validation passes.

## Requirements

- Codex CLI installed locally and available as `codex`
- Git installed and authenticated
- Cargo and rustc installed

The runner uses local Codex and Git authentication. It does not store OpenAI keys or GitHub tokens.
Codex is invoked in non-interactive mode as:

```bash
codex exec -C <isolated-worktree> --dangerously-bypass-approvals-and-sandbox --color never -
```

## Build

```bash
cargo build -p dom-agent-runner --release
```

## Run

```bash
target/release/dom-agent-runner.exe doctor
target/release/dom-agent-runner.exe list-prompts
target/release/dom-agent-runner.exe run --prompt-file prompts/example-mempool-package-policy.txt --push
```

You can also pass an inline prompt:

```bash
target/release/dom-agent-runner.exe run --prompt "Update the mempool policy tests."
```

## Prompt Files

Prompts live under `prompts/*.txt`. The runner copies the prompt into each run report directory for auditability.

## Test Selection

After Codex edits the repository, the runner selects tests automatically using the affected-file mapping and then runs `dom-test-runner.exe` with the appropriate profile.

## Commit and Push Safety

- If tests fail, the runner does not commit or push.
- If commit fails, the runner does not push.
- If `--push` is not provided, the runner does not push.
- Unrelated files are not staged.
- If Codex fails before a commit is created, the isolated worktree is preserved and the terminal prints its path.

## Reports

Every run writes:

- `target/dom-agent-runner/runs/<timestamp>/prompt.txt`
- `target/dom-agent-runner/runs/<timestamp>/codex-output.log`
- `target/dom-agent-runner/runs/<timestamp>/test-output.log`
- `target/dom-agent-runner/runs/<timestamp>/final-report.txt`

## Troubleshooting

If Codex, Git, or Cargo are missing, run `doctor` first and verify that the commands are on `PATH`.
If Codex cannot be launched or returns a non-zero exit code, inspect `target/dom-agent-runner/runs/<timestamp>/codex-output.log`.
Every run writes `final-report.txt`, including early failures.

To remove stale agent worktrees and reports:

```bash
target/release/dom-agent-runner.exe clean
```
