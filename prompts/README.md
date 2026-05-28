# prompts/

UTF-8 text files in this directory are development prompts that
`dom-agent-runner.exe` can read and feed to the Codex CLI.

## Conventions

- One prompt per file, suffix `.txt`.
- Use a descriptive name, e.g. `mempool-package-policy.txt`,
  `wallet-recovery-reorg.txt`, `pow-cfg-test-fast-miner.txt`.
- Multiline is fine; the agent preserves the file verbatim.

## Use

```
dom-agent-runner.exe list-prompts
dom-agent-runner.exe show-prompt prompts/example-mempool-package-policy.txt
dom-agent-runner.exe run --prompt-file prompts/example-mempool-package-policy.txt --push
```

Every run copies the exact prompt into the run's audit directory:

```
target/dom-agent-runner/runs/<timestamp>/prompt.txt
```

so the prompt that produced any given commit is recoverable later.

## Safety

The agent does NOT modify files in `prompts/`. They are read-only inputs
from its perspective.
