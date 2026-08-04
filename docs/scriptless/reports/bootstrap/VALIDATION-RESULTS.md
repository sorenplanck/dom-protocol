# Resultados de validação do bootstrap

Data: 2026-08-04. Compilações limitadas a quatro jobs.

## Aprovados

| Comando | Resultado objetivo |
|---|---|
| `cargo metadata --no-deps --format-version 1` | exit 0; `dom-adaptor` consta como membro do workspace |
| `cargo fmt --all --check` | exit 0 |
| `cargo check --workspace --jobs 4` | exit 0; 30 crates do workspace, incluindo `dom-adaptor`; primeira execução 3m09s |
| `cargo test -p dom-adaptor --jobs 4` | exit 0; 0 testes unitários e 0 doctests, esperado para esqueleto sem API |
| `cargo clippy -p dom-adaptor --all-targets -- -D warnings` | exit 0 |
| `scripts/scriptless/baseline-tests.sh` | exit 0; metadata, fmt, workspace check e teste do crate |
| `scripts/scriptless/preflight.sh` | exit 0, `PREFLIGHT OK` |
| `scripts/scriptless/verify-isolation.sh` | exit 0, `ISOLATION OK` |
| `.githooks/pre-push local no_push://local-test` | exit 1 esperado; push bloqueado antes de rede |
| `sha256sum --check test-vectors/scriptless/MANIFEST.sha256` | exit 0 |
| Wallet: `cargo metadata --no-deps --locked --format-version 1` | exit 0 |
| Wallet: `cargo fmt --all --check` | exit 0 |
| Wallet: `cargo check --locked -p dom-wallet-domain -p dom-wallet-core -p dom-wallet-production-backend --jobs 4` | exit 0 em 2m03s |
| Wallet: `npm ci --prefix frontend` | exit 0; 36 pacotes; auditoria local reportou 0 vulnerabilidades |
| Wallet: `npm test --prefix frontend` | exit 0; 46/46 testes aprovados |
| Wallet: `npm run typecheck --prefix frontend` | exit 0 |
| Wallet: `npm run build --prefix frontend` | exit 0 |
| `bash -n scripts/scriptless/*.sh .githooks/pre-push` | exit 0 |
| `git diff --check` | exit 0 |

## Gate esperado como reprovado

`scripts/scriptless/phase1-gate.sh` validou o manifesto/fixture, encontrou 38 itens pendentes e saiu com código 1. Esse resultado é correto: G1a e G1b não estão aprovados e nenhuma implementação criptográfica foi iniciada.

## Bateria pesada não repetida integralmente

O comando `cargo test -p dom-core -p dom-crypto -p dom-consensus -p dom-serialization --jobs 4` foi iniciado. Todos os testes concluídos antes da interrupção passaram, incluindo o diferencial Bulletproof de 1.000 casos. Durante `range_proof_final_vectors`, o operador autorizou explicitamente pular testes longos já executados no desenvolvimento da DOM; o processo foi interrompido com exit 130. Não houve falha de teste observada, mas o comando completo não é declarado aprovado.

Também não foram repetidos os testes completos do workspace, integração multi-node, testes ignorados, fuzz, Kani e toda a matriz Wallet. Comandos canônicos para uma campanha futura:

```text
cargo test --workspace --exclude dom-integration-tests --exclude dom-node --all-targets --jobs 4
cargo test -p dom-node --all-targets --jobs 4 -- --test-threads=1
cargo test -p dom-integration-tests --jobs 4 -- --test-threads=1
cargo test --locked --workspace --all-targets --jobs 4
```

Consequência: a baseline mínima do bootstrap está verde, mas não se declara a baseline integralmente verde nem G1 aprovado.

## Divergência de ambiente

Os checks frontend passaram com Node 24.16.0; a CI da Wallet fixa Node 22. O resultado local é válido como check básico, não como equivalência binária da CI.
