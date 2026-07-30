# Relatório completo de implementação — Hard fork v3

## 1. Identificação

| Campo | Valor |
|---|---|
| Repositório | `/home/leonardov/dom-release` |
| Branch | `release/mainnet` |
| Data da implementação e verificação | 2026-07-30 |
| Commit de separação wire/bloco | `d9c927e refactor(protocol): separate wire and block versions` |
| Commit principal | `2ec7735 feat(consensus): activate block v3 with rolling finality` |
| Ativação Mainnet | altura `12_500` |
| Versão de bloco anterior | `2` |
| Versão de bloco após ativação | `3` |
| Versão wire/P2P | `2`, sem alteração |
| Finalidade rolante | reorgs de profundidade `360` ou maior são recusados |
| Genesis | não alterado |

## 2. Resumo executivo

Foi implementado o hard fork v3 com ativação determinística por altura e
finalidade rolante. Na Mainnet, blocos de versão 2 permanecem válidos até a
altura 12.499. A partir da altura 12.500, somente blocos de versão 3 são
válidos. A regra é bidirecional: um bloco v3 antes da ativação também é
inválido.

A validação da versão ocorre antes da comparação de trabalho acumulado. Dessa
forma, uma chain v2 pós-ativação é `Invalid` e não pode vencer o fork-choice,
mesmo que declare ou acumule mais trabalho do que a chain local. Essa
precedência também é aplicada a side chains previamente persistidas.

A finalidade rolante recusa reorganizações que desconectariam 360 blocos ou
mais de uma chain local estabelecida. Reorgs de profundidade 359 continuam
elegíveis. O corte é ativo desde o início do processo, sem depender da altura
12.500. Sincronização inicial e extensões normais não são bloqueadas.

O protocolo P2P permanece em versão 2. Nós antigos e atualizados continuam
capazes de realizar o handshake, mas nós sem as regras v3 não acompanharão a
chain válida depois da altura de ativação.

Nenhuma regra de emissão, dificuldade, pesos, recompensa, identidade de rede ou
genesis foi alterada.

## 3. Parâmetros implementados

Os parâmetros estão em `crates/dom-core/src/constants.rs`:

```rust
pub const WIRE_PROTOCOL_VERSION: u32 = 2;
pub const BLOCK_VERSION_LEGACY: u32 = 2;
pub const BLOCK_VERSION_V3: u32 = 3;
pub const MAINNET_V3_ACTIVATION_HEIGHT: u64 = 12_500;
pub const TESTNET_V3_ACTIVATION_HEIGHT: u64 = 1;
pub const REGTEST_V3_ACTIVATION_HEIGHT: u64 = 1;
```

A agenda Mainnet é calculada por:

```rust
pub const fn required_block_version(height: u64) -> u32 {
    if height >= MAINNET_V3_ACTIVATION_HEIGHT {
        BLOCK_VERSION_V3
    } else {
        BLOCK_VERSION_LEGACY
    }
}
```

Testnet e Regtest preservam seus genesis congelados em versão 2 e exigem versão
3 a partir do primeiro bloco pós-genesis. Isso permite que testes exercitem a
regra v3 sem construir 12.500 blocos e, ao mesmo tempo, evita qualquer mudança
de identidade do genesis.

## 4. Investigação prévia confirmada

### 4.1 Versão e serialização do `BlockHeader`

O `BlockHeader` já possuía o campo:

```rust
pub version: u32
```

Referências:

- estrutura e tipo: `crates/dom-consensus/src/block.rs:96-105`;
- serialização: `crates/dom-consensus/src/block.rs:181-196`;
- desserialização: `crates/dom-consensus/src/block.rs:201-220`;
- preimage de PoW: `crates/dom-consensus/src/block.rs:127-149`.

O campo é o primeiro item serializado, como `u32` little-endian, ocupando os
bytes de offset `0..4`. O header continua com tamanho mínimo serializado de 256
bytes. Alterar o valor de 2 para 3 muda o hash e o preimage de PoW do bloco,
como esperado, mas não altera o formato, tamanho, ordem dos campos nem regras
de parsing.

Por o campo já existir no formato histórico, não foi necessária serialização
condicionada à altura e não foi criado um segundo formato de header.

Foi adicionado um teste de vetor estrutural que serializa headers v2 e v3,
confirma o mesmo tamanho, confirma os quatro primeiros bytes e verifica que
todos os bytes posteriores são idênticos.

### 4.2 Ordem de validação e fork-choice

O caminho de conexão de bloco está em
`crates/dom-chain/src/chain_state.rs:296-379`.

A ordem relevante é:

1. validação sintática do header, incluindo versão por altura;
2. identidade do genesis;
3. vínculo e altura do parent;
4. timestamps;
5. PoW;
6. target e trabalho acumulado declarado;
7. validação integral do bloco;
8. somente então comparação de fork-choice.

A promoção de uma side chain persistida está em
`crates/dom-chain/src/chain_state.rs:1312-1399`. A branch candidata inteira,
desde o tip até o ancestral comum, é revalidada quanto à sintaxe e versão em
`crates/dom-chain/src/chain_state.rs:1347`, antes da comparação de trabalho em
`crates/dom-chain/src/chain_state.rs:1349-1359`.

O helper de revalidação da branch está em
`crates/dom-chain/src/chain_state.rs:1798-1819`.

Essa ordem materializa a regra de segurança: uma chain v2 pós-ativação nunca é
uma candidata válida ao fork-choice, independentemente do trabalho acumulado.

### 4.3 Ponto de reorg e profundidade

O ancestral comum é encontrado em
`crates/dom-chain/src/chain_state.rs:1328-1345`.

A profundidade é calculada como:

```text
tip_height_local - ancestor_height
```

O cálculo e o corte de finalidade estão em
`crates/dom-chain/src/chain_state.rs:1361-1375`.

O código ainda confere que a profundidade calculada por altura coincide com a
quantidade efetiva de blocos coletados para desconexão, evitando divergência
entre metadados e a branch materializada.

### 4.4 Escolha da versão pelo miner

O miner calcula a próxima altura em
`crates/dom-node/src/miner.rs:918`.

A versão do template é derivada da rede e da próxima altura em
`crates/dom-node/src/miner.rs:1048`, por meio de
`required_block_version_for_network`. O valor é colocado no header em
`crates/dom-node/src/miner.rs:1392-1395`.

Não existe flag manual de ativação. O último template v2 da Mainnet é criado na
altura 12.499 e o primeiro template v3 na altura 12.500.

### 4.5 Separação wire e consenso

O commit isolado `d9c927e` separou:

- `WIRE_PROTOCOL_VERSION`, usado pela camada P2P;
- `BLOCK_VERSION_LEGACY` e `BLOCK_VERSION_V3`, usados pelo consenso;
- as funções de versão requerida por altura.

O `Hello` envia e valida `WIRE_PROTOCOL_VERSION` em
`crates/dom-node/src/node.rs:1932-1966`.

O prologue Noise usa `WIRE_PROTOCOL_VERSION` em
`crates/dom-wire/src/handshake.rs:71-75`.

O valor wire permanece exatamente 2.

## 5. Implementação do versionamento por altura

### 5.1 Validação de header

`validate_header_syntax` passou a receber o `network_magic` e obtém a versão
exata exigida para a altura do próprio header:

```rust
let required_version =
    required_block_version_for_network(network_magic, header.height.0);
if header.version != required_version {
    return Err(DomError::Invalid(...));
}
```

Referência: `crates/dom-consensus/src/block.rs:224-233`.

A comparação por desigualdade implementa as duas direções:

- v2 em 12.500 ou acima: inválido;
- v3 abaixo de 12.500: inválido.

### 5.2 Validação integral por rede

Foi criada `validate_block_for_network` em
`crates/dom-consensus/src/block_full.rs`. O `ChainState` usa essa função em
conexão normal e na promoção de reorg, garantindo que a agenda apropriada da
rede seja aplicada em todos os caminhos de bloco completo.

O wrapper histórico `validate_block` foi preservado com semântica Mainnet para
compatibilidade da API interna existente.

### 5.3 Ingressos cobertos

A regra é aplicada nos seguintes caminhos:

- conexão normal de bloco;
- validação de bloco completo;
- validação de header individual;
- batch de headers durante IBD;
- IBD retomável/por etapas;
- promoção de side chain persistida;
- revalidação de todos os headers da branch candidata antes do fork-choice.

Isso impede que uma branch inválida entre na comparação por uma rota
alternativa ou por estado previamente armazenado.

## 6. Implementação da finalidade rolante

O parâmetro foi definido em `crates/dom-chain/src/reorg.rs:13-18`:

```rust
pub const MAX_REORG_DEPTH: u64 = 360;
```

O critério objetivo de chain estabelecida é:

```text
local_tip_height >= MAX_REORG_DEPTH
```

Para uma chain estabelecida:

```text
disconnect_count >= MAX_REORG_DEPTH
```

é recusado com `DomError::PolicyRejected`.

Portanto:

| Profundidade | Resultado |
|---:|---|
| 0 | extensão normal, não bloqueada |
| 1 | reorg curto, não bloqueado |
| 359 | elegível |
| 360 | recusado |
| 361 | recusado |
| 400 | recusado |

O corte é executado somente depois de a branch candidata ter sido validada
quanto à versão e antes de coletar/aplicar corpos para a reorganização.

Uma chain local com tip abaixo de 360 é classificada objetivamente como curta e
não sofre o corte. Além disso, IBD linear do genesis consiste em extensões
normais, e não em desconexão profunda da chain local.

### 6.1 Log operacional

Uma recusa por finalidade emite `WARN` com:

- `depth`;
- `local_tip`;
- `rejected_tip`;
- mensagem `rolling finality rejected deep reorg`.

Referência: `crates/dom-chain/src/chain_state.rs:1366-1373`.

## 7. Preservação do genesis

Nenhum arquivo de genesis entrou no diff. Em particular:

- `crates/dom-chain/src/genesis.rs` não foi alterado;
- versões congeladas de genesis não foram alteradas;
- hashes não foram alterados;
- nonces não foram alterados;
- mensagens não foram alteradas;
- PMMR roots não foram alteradas;
- vetores congelados não foram alterados;
- identidade e chain ID não foram alterados.

Testnet e Regtest continuam com genesis v2. A ativação v3 nesses ambientes
ocorre na altura 1.

As verificações finais específicas incluíram:

- `genesis_identity`: 6 testes aprovados;
- `genesis_determinism_tests`: 25 testes aprovados;
- vetores congelados de Testnet aprovados;
- persistência/reabertura de estado de genesis aprovada;
- determinismo de coinbase e PMMR roots aprovado.

## 8. Cobertura dos testes obrigatórios

### 8.1 Fronteira de ativação

| ID | Cenário | Cobertura |
|---|---|---|
| T1 | v2 em 12.499 aceito | `mainnet_v3_activation_boundary_is_bidirectional` |
| T2 | v3 em 12.500 aceito | `mainnet_v3_activation_boundary_is_bidirectional` |
| T3 | v2 em 12.500+ rejeitado | teste de fronteira e testes de ingress/reorg |
| T4 | v3 em 12.499- rejeitado | `mainnet_v3_activation_boundary_is_bidirectional` |
| T5 | miner troca automaticamente | `miner_switches_automatically_at_mainnet_v3_activation` |
| T6 | IBD atravessa fronteira | IBD real Regtest atravessa genesis v2 para blocos v3 |
| T7 | reorg atravessa fronteira | testes reais de reorg em Regtest e validação integral da branch |
| T8 | chain v2 com mais trabalho é inválida | `post_activation_v2_candidate_with_more_work_is_invalid_before_fork_choice` e `persisted_v2_side_tip_is_revalidated_before_fork_choice` |

O teste T8 verifica também que um bloco v2 inválido recebido normalmente não é
persistido no known-chain store. O segundo teste injeta deliberadamente uma
side chain v2 pós-ativação no store e comprova que ela é revalidada e rejeitada
antes da comparação de trabalho.

### 8.2 Finalidade

| ID | Cenário | Cobertura |
|---|---|---|
| T9 | profundidade 359 aceita | `rolling_finality_accepts_depth_359` |
| T10 | profundidade 360 recusada | `rolling_finality_rejects_depth_360` |
| T11 | profundidade 361 recusada | `rolling_finality_rejects_depth_361` |
| T12 | nó novo sincroniza do genesis | teste de bootstrap curto e suíte IBD real |
| T13 | WARN contém campos corretos | `rejected_deep_reorg_emits_warn_with_depth_and_both_tips` |
| T14 | branch v3 válida, mais pesada, depth 400 | `valid_heavier_v3_chain_at_depth_400_is_rejected_by_rolling_finality` |

O T14 constrói uma árvore de headers v3 sintaticamente válida, coloca a branch
concorrente com mais trabalho e confirma que a recusa ocorre especificamente
pela finalidade rolante.

## 9. Testes e verificações executados

### 9.1 Consenso

Executado:

```text
cargo test -p dom-consensus
```

Resultado: suíte completa verde, incluindo 62 testes unitários e os testes de
integração/propriedade do crate.

Repetição no commit final:

```text
cargo test -p dom-consensus mainnet_v3_activation_boundary_is_bidirectional
```

Resultado: 1 aprovado, 0 falhas.

### 9.2 Chain e reorg

Executados:

```text
cargo test -p dom-chain --lib
cargo test -p dom-chain --no-fail-fast
cargo test -p dom-chain --test reorg_equivalence
cargo test -p dom-chain --test ibd_batch_step_xdiff
```

Resultados relevantes:

- biblioteca: 56 aprovados;
- `reorg_equivalence` no commit final: 15 aprovados, 0 falhas;
- IBD batch/step: 6 aprovados;
- profundidades 359, 360, 361 e 400 cobertas;
- validação v2 inválida antes do fork-choice coberta;
- WARN operacional capturado e validado.

Também foram repetidas, depois do endurecimento da precedência, as suítes:

```text
block_validation_ingress_adversarial
coinbase_reorg_maturity
fix018_reorg_future_timestamp_probe
shield_i3_convergence
shield_reorg_cross_branch_directed
shield_reorg_cross_branch_proptest
shield_reorg_shared_tx_directed
```

Todas ficaram verdes.

### 9.3 Node e miner

Executados:

```text
cargo test -p dom-node --lib --no-fail-fast
cargo test -p dom-node --test multinode_reordered_delivery
cargo test -p dom-node --test shield_ban_port_rotation_kav
cargo test -p dom-node block_version_tests
cargo test -p dom-node genesis_determinism_tests
```

Resultados:

- biblioteca do node: 269 aprovados, 1 teste manual ignorado, 0 falhas;
- entrega multinode reordenada: 7 aprovados;
- `shield_ban_port_rotation_kav`: aprovado;
- troca automática do miner: 2 aprovados;
- determinismo/genesis no commit final: 25 aprovados.

### 9.4 IBD real de múltiplos nós

Executado:

```text
cargo test -p dom-integration-tests --test ibd_two_node -- --test-threads=1
```

Resultado:

- 7 testes aprovados;
- 0 falhas;
- duração total aproximada de 60,6 minutos;
- chain de 2.060 blocos utilizada no principal cenário;
- nós de origem, sincronização e novo participante convergiram;
- duração superior aos 20 minutos de teste real exigidos.

### 9.5 P2P e reputação

Executados:

```text
cargo test -p dom-wire manager::tests
cargo test -p dom-wire --test eclipse_resistance
cargo test -p dom-wire
```

Resultados:

- manager/reputação: 41 aprovados;
- resistência a eclipse: 13 aprovados;
- suíte completa do wire: 98 unitários, 13 de eclipse, 7 de roundtrip e 2 de timeout aprovados.

### 9.6 Compilação global

Executado:

```text
cargo test --workspace --all-targets --no-run
```

Resultado: todos os crates e todos os alvos de teste do workspace compilaram com
sucesso.

### 9.7 Clippy

O comando estrito inicialmente encontrou dois problemas preexistentes e fora
do escopo:

- `clippy::incompatible-msrv` em `dom-pow`, relacionado a `is_none_or`;
- `clippy::large-enum-variant` em código preexistente do miner.

Sem alterar esses pontos, foi executado:

```text
cargo clippy -p dom-core -p dom-consensus -p dom-chain -p dom-node \
  --all-targets -- \
  -A clippy::incompatible-msrv \
  -A clippy::large-enum-variant \
  -D warnings
```

Resultado: verde, sem warnings adicionais.

### 9.8 Formatação e integridade do diff

`git diff --check` ficou verde.

Todos os arquivos Rust modificados, exceto um arquivo que já possuía drift de
formatação anterior à missão, passaram por `rustfmt --check` direcionado.

O `cargo fmt --check` global continua apontando formatação preexistente em:

- `crates/dom-integration-tests/tests/ibd_two_node.rs`;
- `crates/dom-node/src/bin/dom-wallet-rescan.rs`;
- `crates/dom-pow/tests/miner_light_equivalence.rs`.

Esses trechos não foram reformados em massa para evitar alterações fora do
escopo.

## 10. Build release

Executado:

```text
cargo build --release -p dom-node
```

Resultado:

- build concluído com sucesso;
- binário: `/home/leonardov/dom-release/target/release/dom-node`;
- versão reportada: `dom-node 0.1.0`;
- formato: ELF 64-bit x86-64 PIE, dinamicamente ligado;
- SHA-256:

```text
1626ca440a8c6178ede355ef296db7a6e1cd542693bac52604a112a23109c2a0
```

## 11. Arquivos diretamente alterados

### 11.1 Produção

- `crates/dom-core/src/constants.rs`
- `crates/dom-consensus/src/block.rs`
- `crates/dom-consensus/src/block_full.rs`
- `crates/dom-consensus/src/lib.rs`
- `crates/dom-chain/src/chain_state.rs`
- `crates/dom-chain/src/reorg.rs`
- `crates/dom-node/src/miner.rs`

### 11.2 Testes e fixtures

Fixtures que criavam headers Regtest/Testnet com versão fixa 2 foram atualizadas
para usar a versão exigida pela rede e altura. Isso preserva a intenção
original de cada teste e impede que testes de outras regras falhem antes, por
uma versão de bloco inválida.

Arquivos de teste alterados:

- `crates/dom-chain/tests/block_validation_ingress_adversarial.rs`
- `crates/dom-chain/tests/coinbase_reorg_maturity.rs`
- `crates/dom-chain/tests/difficulty_adjustment.rs`
- `crates/dom-chain/tests/duplicate_kernel_excess_production_path.rs`
- `crates/dom-chain/tests/fix018_reorg_future_timestamp_probe.rs`
- `crates/dom-chain/tests/ibd_batch_step_xdiff.rs`
- `crates/dom-chain/tests/reorg_equivalence.rs`
- `crates/dom-chain/tests/same_block_spend_cutthrough.rs`
- `crates/dom-chain/tests/shield_i3_convergence.rs`
- `crates/dom-chain/tests/shield_reorg_cross_branch_directed.rs`
- `crates/dom-chain/tests/shield_reorg_cross_branch_proptest.rs`
- `crates/dom-chain/tests/shield_reorg_shared_tx_directed.rs`
- `crates/dom-integration-tests/tests/ibd_two_node.rs`
- `crates/dom-node/src/node.rs`, somente fixtures internas de teste;
- `crates/dom-node/tests/multinode_reordered_delivery.rs`

### 11.3 Suporte a teste e documentação

- `crates/dom-chain/Cargo.toml`, adicionando `tracing-subscriber` como dependência de desenvolvimento para captura do WARN;
- `Cargo.lock`, refletindo a dependência já existente no workspace;
- `docs/RELEASE_V3.md`, contendo aviso e ordem operacional de rollout.

## 12. Commits e disciplina de separação

Os commits locais relevantes, em ordem, são:

```text
d9c927e refactor(protocol): separate wire and block versions
2ec7735 feat(consensus): activate block v3 with rolling finality
```

A separação wire/bloco ficou isolada do commit principal de consenso e
finalidade. Os fixes de rede/reputação aprovados já estavam em commits
anteriores da linha de release e não foram misturados com novas regras de
consenso.

No encerramento da implementação, a branch estava dois commits à frente de
`origin/release/mainnet`, antes da criação deste relatório.

## 13. Checklist de rollout preparado

O documento `docs/RELEASE_V3.md` registra:

- hard fork na altura 12.500;
- nós v2 não seguirão a chain após essa altura;
- finalidade rolante de 360 blocos;
- wire protocol permanece 2;
- cálculo operacional de aproximadamente 53 horas a partir da altura 10.900;
- ordem de atualização de seed1, seed2, observador e minerador;
- bloqueio da wallet até resolução da paridade de restore;
- canais de anúncio;
- monitoramento na ativação.

## 14. Operações externas não executadas

As seguintes ações não foram executadas:

- assinatura minisign do artefato;
- criação de tag;
- push dos commits;
- publicação de release;
- atualização de seed1;
- atualização de seed2;
- atualização do observador;
- atualização do minerador externo;
- avanço do pin da wallet;
- publicação da wallet;
- anúncios em Discord, Telegram, Bitcointalk ou GitHub.

Motivos:

1. somente chaves públicas minisign foram localizadas; nenhuma chave secreta
   utilizável foi encontrada;
2. o nome/versão da tag de release não foi definido;
3. a publicação da wallet permanece explicitamente condicionada à resolução
   do blocker de paridade do restore;
4. não foram fornecidos destinos, credenciais ou comandos autorizados para os
   servidores e canais externos.

Nenhuma assinatura fictícia, tag inferida ou publicação parcial foi realizada.

## 15. Estado final e garantias

Ao final:

- a implementação exigida estava commitada;
- o worktree estava limpo antes da criação deste relatório;
- o build release estava disponível;
- as suítes obrigatórias estavam verdes;
- todos os alvos do workspace compilavam;
- blocos v2 pós-ativação eram inválidos mesmo com mais trabalho;
- blocos v3 prematuros eram inválidos;
- a finalidade recusava profundidade 360 ou maior;
- IBD de nó novo permanecia funcional;
- o wire protocol permanecia versão 2;
- o genesis permanecia byte-identicamente preservado no código e nos vetores;
- nenhuma outra regra de consenso foi alterada.
