# DOM Protocol — Princípios de Trabalho

Este arquivo define como qualquer agente deve trabalhar neste repositório.
Vale para TODA sessão, não só auditorias.

## Autoria
- AUTOR ÚNICO, SEMPRE: Soren Planck <sorenplanck@tutamail.com>.
- NUNCA adicionar co-autor a nenhum commit. Sem linhas "Co-authored-by:",
  sem "Co-authored-by: Claude", sem créditos de IA, sem "Generated with",
  sem qualquer Trailer de co-autoria no corpo da mensagem de commit.
- Todo commit tem exatamente um autor: Soren Planck. Nada de autor secundário.
- Manter o nome de autor uniforme (sem variações de grafia nem e-mails pessoais).


## Integridade — nunca mascarar falha
- NUNCA afrouxar uma asserção, marcar #[ignore], inserir sleep, ou ajustar um
  teste só para ele "passar". Se um teste falha, ou o teste está errado (corrija
  o teste pelo motivo certo) ou o código está errado (o bug é o achado).
- Distinguir bug real de teste flaky SEMPRE com evidência, nunca por suposição.
- Trabalhar contra o CÓDIGO REAL, nunca contra relatórios, docstrings ou
  comentários. Comentário não é prova; confirme na fonte e, quando der, com teste
  que executa.
- Não reportar "concluído" sem que cargo build e cargo test estejam verdes (ou
  sem explicar exatamente o que ficou vermelho e por quê).

## Decisões de mérito ficam com o humano
- Mudanças de consenso, design, economia (supply, reward, fees) ou qualquer coisa
  que altere o comportamento do protocolo NÃO são decisão do agente.
- Diante de uma decisão de mérito: documente as opções com trade-offs, marque
  "PRECISA DECISÃO HUMANA" e pare. Não escolha sozinho.

## Git e merges
- Merge para a branch principal pode ser feito por push direto APÓS revisão
  local do diff. PR continua sendo opção válida para mudanças grandes ou quando
  se quer rastro de revisão.
- Não rodar git push, git rebase, force-push, alterar branch ou reescrever
  histórico sem autorização explícita na tarefa.
- Não commitar binários (.exe, artefatos de build) nem segredos no repositório.

## Segurança e escopo
- Todo trabalho de segurança é DEFENSIVO: hardening deste repositório.
- Tudo permanece local. Sem exfiltração de código ou dados.

## Estilo de trabalho
- Medir números reais (tamanhos, limites, thresholds), não estimar.
- Ser explícito sobre o que NÃO foi testado e por quê (limitações de método).
- Preferir provar afirmações com um teste que roda a afirmar por leitura.

## Operational Authorization Policy

Claude Code may be launched with elevated or bypass permissions for workflow efficiency. This does not grant open-ended authorization.

Claude is authorized to perform only the explicit task described in the current user prompt.

Claude must not infer additional work, expand the task, open new audit fronts, refactor unrelated code, clean unrelated files, modify unrelated state, or make opportunistic improvements unless the current prompt explicitly asks for them.

Claude may operate only inside the current repository unless the user explicitly authorizes another path.

Claude must not read, edit, move, delete, or inspect secrets, .env files, SSH keys, API keys, credentials, wallet keys, private keys, files outside the repository, or unrelated system files.

Claude must always run git status before modifying files.

Claude must preserve unrelated changes.

Claude must not modify, stage, commit, reset, delete, or clean unrelated files unless the current user prompt explicitly authorizes it.

Claude must not run git reset --hard, git clean -fd, git push --force, history rewrites, rm -rf, mass deletion, chmod/chown over broad paths, database deletion, firewall changes, SSH changes, systemd changes, Docker changes, or server configuration changes unless the current user prompt explicitly requests that exact action.

Claude may run tests, builds, formatters, linters, and targeted verification commands only when relevant to the current task.

Claude must avoid long-running campaigns unless explicitly requested.

For fuzzing, Claude may build fuzz targets when requested, but must not run long fuzz campaigns unless the prompt explicitly asks for fuzz execution and gives duration/scope.

After each successful commit, Claude may push to GitHub unless the current user prompt explicitly says not to push.

At the end of each task, Claude must report:
1. what was changed;
2. what commands were run;
3. what tests/checks passed or failed;
4. what files were modified;
5. whether unrelated files were preserved;
6. whether commit/push occurred.

## dom-shield: test-construction method (locked 2026-06-22)

The goal of dom-shield is to BUILD THE TESTS that discover bugs by running — not
to audit-and-fix by hand. The shield is the auditor; we build the auditor.

For EACH part of the code (attackable crate/module/function), the flow is:

1. **EXHAUSTIVELY ENUMERATE the attack vectors** — NOT "find the bug". List EVERY
   way to break/attack the part, through two lenses:
   - Lens A (bug-per-function): panic/crash, incorrect result / non-conformance
     with spec, non-determinism, malleability, DoS/amplification, overflow.
   - Lens B (Lazarus Group / crypto APT): key extraction (zeroization of ALL
     intermediates, not just fields), prediction (entropy/CSPRNG), side-channel
     (every op over secret bytes non constant-time), supply-chain (provenance of
     each dep), cross-impl differential (do versions derive identically?).

2. **ONE TEST PER VECTOR.** If the part has N distinct vectors, it has N tests.
   No fewer (no uncovered door), no more (no theater). The number of tests =
   the number of attack vectors.

3. **RIGHT TECHNIQUE PER VECTOR** — choose the one fit for that door, not a default:
   - correctness/conformance → known-answer vectors (KAV) against spec/external reference
   - panic/crash/OOB → fuzz (cargo-fuzz)
   - invariant/property → proptest
   - corrupted persisted state → directed-corruption test
   - side-channel → timing test (dudect) / static review
   - divergence between implementations → differential harness (XDIFF)
   - supply-chain → cargo-deny/cargo-audit
   - DoS-amplification → fuzz + resource-limit assert, or analysis if there is no multiplier

4. **ANTI-THEATER:** a test is justified only if the vector is genuinely
   attackable. Proving by analysis that a vector is NOT exploitable (bounded by
   construction, source outside the threat model) is worth as much as writing the
   test — record it with justification, no theater test.

5. **SCOPE:** every attackable surface is in (incl. funds-safety/crypto labeled
   as wallet). Only genuinely non-attackable tooling (cli, test-runners) stays out.
   Privacy/de-anon (I4) is deprioritized for being outside the critical threat
   model, not for being non-attackable.

6. **PER-TEST RITUAL:** create in dom-protocol (Part A) → register in dom-shield
   COVERAGE.md + run-audit.sh if fuzz (Part B) → atomic commit (Soren Planck, no
   trailers). Push is a human decision after OPSEC verification.

7. **BUILDING A TEST ≠ FIXING A BUG.** Building the test is safe (read-only over
   behavior). Fixing what the test exposes is a separate task and REQUIRES HUMAN
   DECISION when it touches consensus/key-derivation/format. The shield discovers;
   the fix is a separate queue.

**Reference example — dom-wallet-keys:** 41 distinct attack vectors enumerated
(Lens A: BIP-32 conformance, modular reduction, panic on seed/path,
blinding/masks; Lens B: zeroization, entropy, side-channel, supply-chain,
cross-impl v1↔v2). 41 vectors = ~41 tests. That is the real scale of covering a
part properly.
