# DOM Protocol — Codex Operational Instructions

## Mission

You are operating inside the real DOM Protocol repository. Treat this repository as a pre-mainnet blockchain protocol codebase. Your role is to assist with security review, protocol hardening, validation, test creation, and controlled remediation.

## Mandatory Reading Before Any Audit or Patch

Before auditing, modifying, refactoring, deleting, renaming, or generating files, read these documents:

1. `audit/00_MASTER_INDEX.md`
2. `audit/01_PROTOCOL_OVERVIEW.md`
3. `audit/02_CONSENSUS_INVARIANTS.md`
4. `audit/03_CRYPTOGRAPHIC_ASSUMPTIONS.md`
5. `audit/04_THREAT_MODEL.md`
6. `audit/05_ATTACK_SURFACES.md`
7. `audit/06_AUDIT_CHECKLIST.md`
8. `audit/07_FORBIDDEN_FILES.md`
9. `audit/08_VALIDATION_COMMANDS.md`
10. `audit/09_KNOWN_RISKS.md`
11. `audit/10_REPORT_TEMPLATE.md`

## Operating Rules

- Do not treat these files as documentation to summarize only. Use them as mandatory operational constraints.
- Do not modify forbidden files unless the user explicitly authorizes the exact file and exact purpose.
- Never weaken consensus, cryptographic, validation, difficulty, wallet, mempool, chain, or P2P invariants to make tests pass.
- Never replace real validation with stubs, mocks, fake values, placeholder checks, or permissive bypasses.
- Prefer adding tests before changing protocol logic.
- Preserve backward-compatible behavior unless the task explicitly requires a breaking protocol change.
- Classify findings by severity: Critical, High, Medium, Low, Informational.
- Every security finding must include: impact, exploitability, affected files, proof or reasoning, recommended fix, and validation commands.
- Every patch must include validation evidence.
- After every successful commit, push commits to GitHub unless explicitly told not to.

## Required Workflow

1. Recon: map affected crates, modules, invariants, and tests.
2. Risk analysis: identify protocol-critical paths and possible exploit classes.
3. Plan: produce a concise implementation/audit plan before edits.
4. Test-first when feasible: add regression or negative tests before patching.
5. Patch: minimal, scoped, auditable changes.
6. Validate: run the commands defined in `audit/08_VALIDATION_COMMANDS.md`.
7. Report: produce final audit or patch report using `audit/10_REPORT_TEMPLATE.md`.

## Hard Stop Conditions

Stop and report instead of patching if:

- A change would alter consensus rules without explicit authorization.
- A change would modify genesis, emission, difficulty, cryptographic verification, kernel validation, or block acceptance rules.
- A validation failure appears unrelated to the requested scope and could indicate baseline corruption.
- You cannot distinguish between expected protocol behavior and a security flaw.

## dom-shield: método de construção de testes (locked 2026-06-22)

O objetivo do dom-shield é CONSTRUIR OS TESTES que descobrem bugs ao rodar — não auditar-e-corrigir à mão. O escudo é o auditor; nós construímos o auditor.

Para CADA parte do código (crate/módulo/função atacável), o fluxo é:

1. **ENUMERAR EXAUSTIVAMENTE os vetores de ataque** — NÃO "achar o bug". Listar TODA forma de quebrar/atacar a parte, com duas lentes:
   - Lente A (bug-por-função): panic/crash, resultado incorreto/não-conformidade com spec, não-determinismo, maleabilidade, DoS/amplificação, overflow.
   - Lente B (Lazarus Group / APT de cripto): extração de chave (zeroização de TODOS os intermediários, não só campos), previsão (entropia/CSPRNG), side-channel (toda op sobre bytes secretos não constant-time), supply-chain (procedência de cada dep), cross-impl diferencial (versões derivam idêntico?).

2. **UM TESTE POR VETOR.** Se a parte tem N vetores distintos, ela tem N testes. Não menos (sem porta descoberta), não mais (sem teatro). O número de testes = número de vetores de ataque.

3. **TÉCNICA CERTA POR VETOR** — escolher a adequada àquela porta, não uma default:
   - corretude/conformância → known-answer vectors (KAV) contra spec/referência externa
   - panic/crash/OOB → fuzz (cargo-fuzz)
   - invariante/propriedade → proptest
   - estado persistido corrompido → teste de corrupção dirigida
   - side-channel → teste de timing (dudect) / review estático
   - divergência entre implementações → harness diferencial (XDIFF)
   - supply-chain → cargo-deny/cargo-audit
   - DoS-amplificação → fuzz + assert de limite, ou análise se não há multiplicador

4. **ANTI-TEATRO:** um teste só se justifica se o vetor é genuinamente atacável. Provar por análise que um vetor NÃO é explorável (bounded por construção, fonte fora do threat model) vale tanto quanto escrever o teste — registrar com justificativa, sem teste de teatro.

5. **ESCOPO:** toda superfície atacável entra (incl. funds-safety/cripto rotulada como wallet). Só tooling genuinamente não-atacável (cli, test-runners) fica fora. Privacy/de-anon (I4) deprioritizado por estar fora do threat model crítico, não por ser não-atacável.

6. **RITUAL POR TESTE:** criar no dom-protocol (Parte A) → registrar no dom-shield COVERAGE.md + run-audit.sh se fuzz (Parte B) → commit atômico (Soren Planck, sem trailers). Push é decisão humana após verificação OPSEC.

7. **CONSTRUIR TESTE ≠ CORRIGIR BUG.** Construir o teste é seguro (read-only sobre comportamento). Corrigir o que o teste expõe é tarefa separada e PRECISA DECISÃO HUMANA quando toca consenso/derivação de chave/formato. O escudo descobre; a correção é fila à parte.

**Exemplo de referência — dom-wallet-keys:** 41 vetores de ataque distintos enumerados (Lente A: conformância BIP-32, redução modular, panic em seed/path, blinding/máscaras; Lente B: zeroização, entropia, side-channel, supply-chain, cross-impl v1↔v2). 41 vetores = ~41 testes. É a escala real de cobrir uma parte direito.

