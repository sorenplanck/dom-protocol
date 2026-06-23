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

## dom-shield: método de construção de testes (locked 2026-06-22)

O objetivo do dom-shield é CONSTRUIR OS TESTES que descobrem bugs ao rodar — não
auditar-e-corrigir à mão. O escudo é o auditor; nós construímos o auditor.

Para CADA parte do código (crate/módulo/função atacável), o fluxo é:

1. **ENUMERAR EXAUSTIVAMENTE os vetores de ataque** — NÃO "achar o bug". Listar
   TODA forma de quebrar/atacar a parte, com duas lentes:
   - Lente A (bug-por-função): panic/crash, resultado incorreto/não-conformidade
     com spec, não-determinismo, maleabilidade, DoS/amplificação, overflow.
   - Lente B (Lazarus Group / APT de cripto): extração de chave (zeroização de
     TODOS os intermediários, não só campos), previsão (entropia/CSPRNG),
     side-channel (toda op sobre bytes secretos não constant-time), supply-chain
     (procedência de cada dep), cross-impl diferencial (versões derivam idêntico?).

2. **UM TESTE POR VETOR.** Se a parte tem N vetores distintos, ela tem N testes.
   Não menos (sem porta descoberta), não mais (sem teatro). O número de testes =
   número de vetores de ataque.

3. **TÉCNICA CERTA POR VETOR** — escolher a adequada àquela porta, não uma default:
   - corretude/conformância → known-answer vectors (KAV) contra spec/referência externa
   - panic/crash/OOB → fuzz (cargo-fuzz)
   - invariante/propriedade → proptest
   - estado persistido corrompido → teste de corrupção dirigida
   - side-channel → teste de timing (dudect) / review estático
   - divergência entre implementações → harness diferencial (XDIFF)
   - supply-chain → cargo-deny/cargo-audit
   - DoS-amplificação → fuzz + assert de limite, ou análise se não há multiplicador

4. **ANTI-TEATRO:** um teste só se justifica se o vetor é genuinamente atacável.
   Provar por análise que um vetor NÃO é explorável (bounded por construção, fonte
   fora do threat model) vale tanto quanto escrever o teste — registrar com
   justificativa, sem teste de teatro.

5. **ESCOPO:** toda superfície atacável entra (incl. funds-safety/cripto rotulada
   como wallet). Só tooling genuinamente não-atacável (cli, test-runners) fica fora.
   Privacy/de-anon (I4) deprioritizado por estar fora do threat model crítico, não
   por ser não-atacável.

6. **RITUAL POR TESTE:** criar no dom-protocol (Parte A) → registrar no dom-shield
   COVERAGE.md + run-audit.sh se fuzz (Parte B) → commit atômico (Soren Planck, sem
   trailers). Push é decisão humana após verificação OPSEC.

7. **CONSTRUIR TESTE ≠ CORRIGIR BUG.** Construir o teste é seguro (read-only sobre
   comportamento). Corrigir o que o teste expõe é tarefa separada e PRECISA DECISÃO
   HUMANA quando toca consenso/derivação de chave/formato. O escudo descobre; a
   correção é fila à parte.

**Exemplo de referência — dom-wallet-keys:** 41 vetores de ataque distintos
enumerados (Lente A: conformância BIP-32, redução modular, panic em seed/path,
blinding/máscaras; Lente B: zeroização, entropia, side-channel, supply-chain,
cross-impl v1↔v2). 41 vetores = ~41 testes. É a escala real de cobrir uma parte
direito.
