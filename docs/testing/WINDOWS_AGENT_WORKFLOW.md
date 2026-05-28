# DOM Agent Runner — Windows portable .exe

`dom-agent-runner.exe` is a portable Rust binary that orchestrates a single
development task end-to-end:

1. **Codex** edits the DOM repository (via the locally installed Codex CLI).
2. **dom-test-runner** validates the change (`affected` profile by default,
   then `pre-push`).
3. **git** stages only the files changed by this task, commits, and (with
   `--push`) pushes to `origin`.
4. The agent verifies remote `HEAD` (`git ls-remote origin refs/heads/<branch>`).
5. A full audit report lands under `target/dom-agent-runner/runs/<timestamp>/`.

## Important properties

- **No secrets stored.** It uses your local Codex auth and your local Git
  credentials (helper, ssh-agent, `gh`). It never reads `OPENAI_API_KEY` or
  similar from a config file it owns.
- **Codex is an external process**, called via `codex --version` /
  `codex` (stdin). The agent does not embed Codex as a library.
- **Commit/push safety:** no commit if tests fail; no push if commit fails;
  no push if remote HEAD is not retrievable afterward; `Cargo.lock` is
  never staged unless you stage it manually first.
- **`clean` is scoped** — it can only delete `target/dom-agent-runner/`.

## Build locally

```
cargo build -p dom-agent-runner --release
```

Binary: `target/release/dom-agent-runner.exe` (or `dom-agent-runner` on
Linux/macOS).

You will also want `dom-test-runner.exe` built — the agent shells out to it:

```
cargo build -p dom-test-runner --release
```

## Use

```
target\release\dom-agent-runner.exe doctor

target\release\dom-agent-runner.exe list-prompts
target\release\dom-agent-runner.exe show-prompt prompts/example-mempool-package-policy.txt

target\release\dom-agent-runner.exe run --prompt-file prompts/example-mempool-package-policy.txt
target\release\dom-agent-runner.exe run --prompt-file prompts/example-mempool-package-policy.txt --push
target\release\dom-agent-runner.exe run --prompt "small inline task"
target\release\dom-agent-runner.exe run --prompt-file prompts/x.txt --profile pre-push --push

target\release\dom-agent-runner.exe report
target\release\dom-agent-runner.exe clean
```

`--profile` accepts: `affected` (default), `full`, `all`, `pre-push`.

## How tests are selected automatically

The agent calls `dom-test-runner.exe <profile>`. With the default
`affected`, the runner inspects `git diff` after Codex finishes and picks
profiles by changed paths (see `WINDOWS_TEST_RUNNER.md`). Then it runs
`pre-push` as a final guard.

If anything fails, the agent stops before any commit or push.

## How GitHub authentication works

The agent never asks for a token. `git push` uses whatever credentials you
already have configured on the machine:

- HTTPS with a credential helper (recommended on Windows)
- SSH key in your ssh-agent
- `gh auth login` (works because `gh` registers a credential helper)

If `git ls-remote origin` fails during `doctor`, fix your local Git/GitHub
auth before running with `--push`.

## Report layout

```
target/dom-agent-runner/runs/<timestamp>/
  prompt.txt              — the exact prompt sent to Codex
  prompt-source.txt       — path of the prompt file (if any)
  codex-output.log        — stdout/stderr from the Codex run
  test-output.log         — stdout/stderr from dom-test-runner
  git-status-before.txt   — git status --short before Codex
  git-status-after.txt    — git status --short after commit
  changed-files.txt       — files Codex modified
  staged-files.txt        — files actually staged (Cargo.lock filtered)
  commit.txt              — commit hash, if any
  remote-head.txt         — remote HEAD after push, if pushed
  final-report.txt        — human summary
```

## Troubleshooting

- **`codex` not found.** Install Codex CLI and reopen your terminal so PATH
  picks it up. `codex --version` must work.
- **`git push` fails with auth error.** Fix your credential helper or
  ssh-agent. The agent does not handle credentials itself.
- **Tests fail in `pre-push`.** Read `test-output.log`. The corresponding
  per-step log is under `target/dom-test-runner/logs/`.
- **Worktree was dirty before the run.** The agent warns but proceeds; for
  a strictly clean run, commit/stash your local changes first, or run from
  a fresh worktree of `origin/main`.

## CI

`.github/workflows/windows-agent-runner.yml` builds and tests the binary on
`windows-latest` and uploads `DOM-Agent-Runner-Windows-Portable`.
**Real Codex never runs in CI** — only the build and a safe `doctor` call.
