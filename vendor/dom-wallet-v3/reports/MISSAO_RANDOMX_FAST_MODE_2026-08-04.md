# Relatório final — RandomX fast mode no minerador do app

Data: 2026-08-04

Branch: `redesign/restore-remote-scan`

Commit desta missão: `fix(miner): use persistent RandomX fast-mode VMs` (o commit que contém este próprio relatório; o hash efetivo é informado pelo Git após sua criação).

## Resultado

O minerador embutido da Wallet deixou de chamar o caminho de validação `randomx_pool::randomx_hash` a cada nonce. A sessão do app agora mantém workers de longa duração; cada worker cria uma única `MinerVm` fora do laço de nonces, reutiliza essa VM entre renovações de template e a substitui somente quando a seed da época RandomX muda.

O `MinerVm::new` da revisão de protocolo já fixada continua sendo a autoridade para a implementação: ele usa `FLAG_FULL_MEM` e o `MinerPool` interno mantém um único dataset completo, compartilhado entre as VMs dos workers e rotacionado por seed.

Também foram implementados:

- log `INFO` na inicialização/rotação da VM com modo efetivo, flags recomendadas obtidas em runtime, flags efetivas da VM (incluindo `FULL_MEM`), estado de large pages e quantidade de workers;
- detecção de large pages no Linux por `HugetlbPages` do próprio processo, depois da criação do dataset;
- hashrate exibido calculado numa janela móvel de 30 segundos, alimentada por um sampler de 1 segundo, em vez da média desde o início da sessão;
- probe release reproduzível em `crates/dom-wallet-embedded-core/examples/randomx_hashrate.rs`.

## Medição de aceite na mesma máquina

Máquina: Intel Core i5-8250U, 4C/8T. Cada fase mediu uma única thread durante 15 segundos. A inicialização única do dataset foi excluída da janela fast, como deve ser num teste de throughput estacionário.

Comando principal:

```text
cargo run --release -p dom-wallet-embedded-core --example randomx_hashrate -- 15
```

| Caminho | Hashrate por thread |
|---|---:|
| Antes: VM light descartável por hash | 21,02 H/s |
| Depois: `MinerVm` fast persistente | 139,93 H/s |
| Ganho | 6,66× |

Repetição com o probe e o worker concorrente presos ao mesmo CPU lógico:

| Caminho | Hashrate por thread |
|---|---:|
| Antes | 21,58 H/s |
| Depois | 120,64 H/s |
| Ganho | 5,59× |

A máquina já executava um `dom-node` com quatro workers (~395% de CPU) durante as duas medições e ele não foi pausado nem alterado. Esse processo também já possuía 2.129.920 kB de Hugetlb; restavam apenas 240 huge pages de 2 MB, insuficientes para outro dataset completo. Portanto, o probe da Wallet caiu corretamente para páginas normais e os números são conservadores. Mesmo sob essa carga idêntica antes/depois, o ganho foi multiplicativo e da mesma ordem do comparativo de campo fornecido (42 H/s contra ~255 H/s, 6,07×), não um ganho percentual marginal.

## Verificações executadas

```text
cargo check -p dom-wallet-embedded-core -p dom-wallet-tauri-shell
cargo clippy -p dom-wallet-embedded-core -p dom-wallet-tauri-shell --all-targets -- -D warnings
cargo test -p dom-wallet-core-recovery wallet_owned_miner --test recovery
cargo test -p dom-wallet-embedded-core --lib
cargo test -p dom-wallet-tauri-shell mining_hashrate_uses_only_the_recent_window --lib
```

Resultados:

- check: aprovado;
- clippy com warnings tratados como erro: aprovado;
- mineração/regtest: 2 aprovados;
- `dom-wallet-embedded-core`: 20 aprovados, 1 teste live ignorado por definição;
- janela móvel: 1 aprovado.

## Escopo e arquivos

Arquivos alterados nesta missão:

- `Cargo.toml`
- `Cargo.lock`
- `crates/dom-wallet-embedded-core/Cargo.toml`
- `crates/dom-wallet-embedded-core/src/lib.rs`
- `crates/dom-wallet-embedded-core/src/miner.rs`
- `crates/dom-wallet-embedded-core/examples/randomx_hashrate.rs`
- `src-tauri/src/lib.rs`
- este relatório

Não houve alteração em `dom-pow`, no minerador do `dom-node` ou na revisão fixada do protocolo. Os três relatórios não rastreados que já estavam no worktree antes da missão foram preservados e não fazem parte do commit.

## Commits locais ainda não enviados ao upstream

Upstream: `origin/redesign/restore-remote-scan`.

Em ordem cronológica:

1. `fa2f3e7` — `fix(wallet): let users cancel abandoned slates`
2. `767788b` — `fix(wallet): expire safe abandoned reservations`
3. `b4847f2` — `feat(wallet): plumb height-locked sender kernels`
4. `abb5731` — `fix(wallet): decouple finalized tx from slate expiry`
5. Commit que contém este relatório — `fix(miner): use persistent RandomX fast-mode VMs`

Nenhum push foi executado.
