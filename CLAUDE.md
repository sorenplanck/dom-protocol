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
