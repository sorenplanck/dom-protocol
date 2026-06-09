# DOM Protocol - Full Protocol Audit Report

Data: 2026-05-31  
Modo: auditoria somente leitura, com escrita autorizada apenas para este relatorio.  
Escopo: consenso, validacao de blocos/transacoes, kernels Mimblewimble, commitments, cut-through, mempool, reorg, difficulty adjustment, coinbase maturity, wallet, P2P, storage, configuracao testnet/mainnet, inflacao, double spend, chain split e DoS.

## 1. Resumo executivo

O protocolo ja contem varias protecoes importantes: validacao orquestrada de transacoes e blocos em `dom-consensus`, equacao agregada de commitments no bloco, assinatura de kernels com `chain_id`, PMMR roots recalculadas, rejeicao de spends internos ao bloco, ASERT/RandomX com isolamento de regtest, reorg atomico via overlay e indices LMDB com `NO_OVERWRITE` para UTXO e kernels.

A auditoria encontrou, porem, riscos que ainda impedem uma classificacao de pronto para mainnet:

- 1 achado Critical: criacao do genesis persiste o bloco sem inserir a coinbase genesis no UTXO/kernel index, enquanto a reabertura reconstrui e passa a inserir essa UTXO. Isso cria estado dependente de restart e risco de chain split se a coinbase genesis for spendable.
- 2 achados High: mempool aceita transacoes sem validacao criptografica/economica completa; side-chain blocks PoW-validos podem ser persistidos antes da validacao contextual de inputs.
- 4 achados Medium: proof de coinbase nao e verificado como Bulletproof; falhas de WAL do wallet sao best-effort; wallet/miner tem lacunas em coinbase/reorg; parser P2P e permissivo em payloads truncados/trailing.
- 3 achados Low/Informational: truncamento de dificuldade para `u128`, hardening de storage para spent UTXO inexistente e inconsistencias operacionais na knowledge base/ferramentas.

Nenhum codigo-fonte foi alterado.

## 2. Arquitetura resumida

- `dom-core`: constantes de consenso, rede, monetary policy, genesis, supply, limites de bloco/tx, tags criptograficas.
- `dom-crypto`: Pedersen commitments, Bulletproofs, Schnorr, chaves e hashing domain-separated.
- `dom-consensus`: estrutura e validacao de transacoes, kernels, blocos, cut-through, PMMR roots, coinbase e equacao agregada.
- `dom-chain`: conexao de blocos, tip, UTXO set, kernel index, reorg, side-chain retention, reconstrucoes de storage.
- `dom-pow`: RandomX, ASERT, compact target, expected target, target bounds, difficulty.
- `dom-mempool`: admissao local, politicas de fee/weight, selecao para bloco, reinjecao apos reorg.
- `dom-wire` e `dom-node`: mensagens P2P, handshake Noise, relay, Dandelion, peer manager, IBD, RPC/node runtime, miner.
- `dom-store`: LMDB, headers/bodies, height index, UTXO set, kernel index, snapshots e reorg atomico.
- `dom-wallet`: seed/HD wallet, coinbase blinding, spend lifecycle, journal, rollback/rescan, wallet dir.
- `dom-config`: Network `Mainnet`, `Testnet`, `Regtest`, network magic, ports e coinbase maturity por rede.

## 3. Partes mais criticas do protocolo

1. `crates/dom-consensus/src/lib.rs` e `crates/dom-consensus/src/block_full.rs`: ponto central de validade de transacoes e blocos.
2. `crates/dom-chain/src/chain_state.rs`: aplicacao de blocos, UTXO set, reorg, side-chain e reconstrucoes de estado.
3. `crates/dom-store/src/db.rs`: atomicidade e indices persistidos para UTXO/kernel/header/body.
4. `crates/dom-crypto/src/*`: assumptions de Bulletproof, Pedersen, Schnorr e domain separation.
5. `crates/dom-pow/src/lib.rs`: RandomX, ASERT, target e difficulty acumulada.
6. `crates/dom-node/src/miner.rs`: genesis, miner, coinbase, montagem/finalizacao de blocos.
7. `crates/dom-mempool/src/lib.rs`: fronteira entre rede/RPC e candidatos a bloco.
8. `crates/dom-wire/src/*` e `crates/dom-node/src/node.rs`: P2P, IBD, relay e DoS surface.
9. `crates/dom-wallet/src/wallet.rs`: ownership de outputs, coinbase recovery, journal e reorg.
10. `crates/dom-core/src/constants.rs` e `crates/dom-config/src/lib.rs`: parametros hard-fork e isolamento de redes.

## 4. Invariantes de consenso principais

- Emissao: coinbase deve pagar exatamente `reward(height) + total_tx_fees`.
- Supply: nenhuma combinacao de commitments, fees, offsets e kernels pode criar valor liquido.
- Transacoes normais: sem kernels coinbase, sem features desconhecidas, sem inputs/outputs duplicados, fees sem overflow, lock_height respeitado, Bulletproofs validos, assinaturas de kernels validas e equacao de balance valida.
- Blocos: header canonico, PoW valido, target esperado, timestamp/MTP validos, PMMR roots recalculadas, peso/quantidade limitados, sem duplicate inputs/outputs, sem spend de output criado no mesmo bloco.
- Coinbase maturity: coinbase so pode ser gasto apos maturidade da rede (`1000` em mainnet/testnet, `1` em regtest).
- Reorg: somente cadeia com mais trabalho acumulado, dentro da profundidade permitida, aplicando disconnect/connect atomico e validando inputs/duplicates/kernel replay.
- P2P: peers de redes diferentes nao devem compartilhar frames validos por magic/chain_id/prologue.
- Storage: UTXO set e kernel index persistidos devem ser equivalentes a historia canonica reconstruida.

## 5. Mapa de riscos por superficie

- Inflacao: maior risco residual em coinbase proof nao verificado e em qualquer divergencia entre genesis persistido e genesis reconstruido.
- Double spend: protecoes fortes em UTXO lookup, duplicate input, kernel replay e reorg overlay; risco indireto se estado genesis divergir por restart.
- Chain split: risco critico no genesis state drift; risco operacional em parametros/mainnet genesis se gate for alterado sem ceremonia.
- DoS: mempool aceita transacoes criptograficamente invalidas; side-chain blocks invalidos contextualizados podem ocupar storage; P2P parsers permissivos aceitam payloads ambiguos.
- Wallet loss: journal best-effort e lacunas de apply/scan para coinbase/reorg.
- Privacy: Dandelion usa RNG thread-local e selecao aleatoria; nao foi encontrado seed fixo no `dom-wire`, mas privacidade ainda depende de peer diversity.

## 6. Achados

### DOM-AUDIT-001 - Genesis e persistido sem UTXO/kernel changeset, mas reopen reconstrui coinbase

- Severidade: Critical
- Arquivo afetado: `crates/dom-node/src/miner.rs`; relacionado a `crates/dom-chain/src/chain_state.rs` e `crates/dom-store/src/db.rs`
- Trecho ou funcao relevante: `create_genesis_block`; `ensure_canonical_utxo_set`; `reconstruct_canonical_utxo_set`; `build_utxo_changeset`; `commit_block`
- Impacto: estado canonico depende de restart. Um node que acabou de criar genesis persiste header/body sem UTXO coinbase genesis; um node reaberto reconstrui a historia canonica e passa a inserir a coinbase genesis. Se a coinbase genesis for spendable depois da maturity, isso pode causar aceitacao divergente de bloco/transacao e chain split.
- Cenario de exploracao: operador A cria genesis e permanece online; operador B cria/reabre ou repara storage. Depois da maturity, uma transacao gasta a commitment da coinbase genesis. B tem a UTXO reconstruida; A pode rejeitar por input ausente. A rede pode dividir em torno do primeiro bloco que gasta a genesis coinbase.
- Evidencia no codigo: `miner.rs:442-450` chama `chain.store.commit_block(..., &[], &[], &[])` para genesis. `chain_state.rs:1150-1158` reconstrui a coinbase do bloco canonico como UTXO. `chain_state.rs:1276-1280` mostra que o changeset normal incluiria a coinbase. `chain_state.rs:173` chama `ensure_canonical_utxo_set` no reopen.
- Correcao recomendada: criar genesis pelo mesmo caminho de changeset usado em blocos normais, ou introduzir um caminho especial de genesis que insira explicitamente a coinbase UTXO e kernel index de forma canonica. Se a coinbase genesis deve ser unspendable, documentar isso em consenso e garantir que reconstrucao tambem nao a insira.
- Testes necessarios: teste que compara UTXO/kernel index imediatamente apos `create_genesis_block` contra o estado apos reopen; teste de spend da genesis coinbase apos maturity com comportamento identico antes/depois de restart; teste de digest canonico da UTXO genesis.
- Prioridade de correcao: P0 antes de qualquer testnet/mainnet persistente.

### DOM-AUDIT-002 - Mempool nao executa validacao criptografica/economica completa

- Severidade: High
- Arquivo afetado: `crates/dom-mempool/src/lib.rs`; `crates/dom-node/src/node.rs`
- Trecho ou funcao relevante: `accept_tx`; `accept_tx_with_chain_view`; `validate_tx_against_chain_view`; handler `Command::Tx`
- Impacto: a mempool pode aceitar transacoes com inputs existentes e fee/estrutura aceitaveis, mas com Bulletproof, kernel signature ou balance equation invalidos. Consenso ainda rejeita blocos invalidos, mas a rede/miner pode ser usada para DoS e construcao repetida de blocos invalidos.
- Cenario de exploracao: atacante cria tx com input maduro real, fee alta, estrutura valida, mas assinatura de kernel invalida. O P2P/RPC chama `accept_tx_with_chain_view`; a tx entra na mempool e pode ser selecionada para mining. O bloco final e rejeitado em `connect_block`, desperdicando CPU e relay.
- Evidencia no codigo: `dom-mempool/src/lib.rs:44` importa apenas `validate_transaction_structure`; `:189` chama somente estrutura em `accept_tx`; `:212-214` faz estrutura + chain view e entao insere. `dom-node/src/node.rs:1066-1073` e `:3614-3622` usam esse caminho para RPC/P2P. A validacao completa existe em `dom-consensus/src/lib.rs:81-89` mas nao e chamada pela mempool.
- Correcao recomendada: adicionar validacao completa de transacao na admissao, com `ValidationContext` contendo `chain_id` e altura atual, alem da chain view. Se houver razao para politica diferente, documentar explicitamente cada diferenca e nunca permitir bypass de Bulletproof/signature/balance.
- Testes necessarios: mempool rejeita tx com Bulletproof invalido, kernel signature invalida, balance equation invalida, offset invalido e lock_height futuro; miner nao seleciona tx rejeitada; P2P aplica score a peers que enviam tx criptograficamente invalida.
- Prioridade de correcao: P0/P1.

### DOM-AUDIT-003 - Range proof da coinbase nao e verificada criptograficamente

- Severidade: Medium
- Arquivo afetado: `crates/dom-consensus/src/transaction.rs`; `crates/dom-consensus/src/lib.rs`
- Trecho ou funcao relevante: `CoinbaseTransaction::validate`; `validate_block_transactions`; `validate_range_proofs`
- Impacto: blocos podem aceitar uma coinbase cujo proof nao e vazio, mas nao e um Bulletproof valido. A equacao agregada limita inflacao direta quando commitment, excess e explicit value batem, mas o UTXO persistido carrega proof invalido, quebrando a invariante de que todo output confidencial tem range proof verificavel.
- Cenario de exploracao: miner monta coinbase com value correto e assinatura correta, mas proof bytes aleatorios nao vazios. `coinbase.validate` aceita o proof por nao estar vazio; `validate_range_proofs` so percorre `Transaction` normal. O bloco pode passar com coinbase UTXO criptograficamente malformado.
- Evidencia no codigo: `transaction.rs:380-387` verifica apenas `self.output.proof.is_empty()` antes de validar assinatura. `transaction.rs:556-564` verifica Bulletproofs somente para outputs de `Transaction`. `lib.rs:211` chama `coinbase.validate(...)`.
- Correcao recomendada: chamar `dom_crypto::bp_verify` tambem para `coinbase.output` dentro de `CoinbaseTransaction::validate`, mantendo limite de tamanho e erro deterministico.
- Testes necessarios: bloco com coinbase proof vazio rejeitado; bloco com coinbase proof aleatorio rejeitado; bloco com coinbase proof valido aceito; teste adversarial que proof invalido nao chega a `commit_block`.
- Prioridade de correcao: P1.

### DOM-AUDIT-004 - Side-chain block e armazenado antes da validacao contextual de inputs/maturity

- Severidade: High
- Arquivo afetado: `crates/dom-chain/src/chain_state.rs`; `crates/dom-store/src/db.rs`
- Trecho ou funcao relevante: `connect_block`; `validate_direct_extension_inputs`; `store_known_block`; `promote_heavier_known_tip`; `apply_connect`
- Impacto: um bloco side-chain que passa validacao estatica, PoW e PMMR pode ser gravado como known block antes de verificar se seus inputs existem na branch correta e se coinbase maturity e respeitada. A promocao revalida e deve rejeitar, entao o risco principal e DoS/storage pollution e delayed invalidity.
- Cenario de exploracao: atacante fornece uma side branch com PoW suficiente, headers validos e corpo internamente consistente, mas gastando UTXO inexistente para aquela branch. O node persiste header/body via `store_known_block`; so ao tentar promover a branch `apply_connect` detecta missing input.
- Evidencia no codigo: caminho direto chama `validate_direct_extension_inputs` antes de `commit_block` em `chain_state.rs:326-328`; caminho side-chain chama `store_known_block` em `:347-351` antes de `promote_heavier_known_tip` em `:353-355`. A validacao contextual aparece depois em `apply_connect`, `chain_state.rs:1390-1427`.
- Correcao recomendada: validar contextualidade da branch antes de persistir ou manter area de quarentena nao persistente para candidatos ainda nao contextualizados. Em qualquer caso, limitar custo por peer e registrar rejeicoes como score.
- Testes necessarios: side-chain com input inexistente nao deve permanecer em known block store; side-chain com coinbase imatura nao deve ser persistida; teste de peer scoring para storm de side-chain invalida.
- Prioridade de correcao: P1.

### DOM-AUDIT-005 - Wallet journal falha aberto quando append do WAL falha

- Severidade: Medium
- Arquivo afetado: `crates/dom-wallet/src/wallet.rs`
- Trecho ou funcao relevante: `record_journal`
- Impacto: eventos de lifecycle podem nao ser persistidos enquanto o estado em memoria continua. Em crash, disk full ou permissao negada, a recovery story do wallet fica inconsistente e pode perder informacao de pending/reservation/rollback.
- Cenario de exploracao: disco fica cheio ou journal fica bloqueado; `build_spend`/confirm/reorg continua alterando wallet em memoria e possivelmente salvando outros arquivos. Depois de crash, replay do journal nao contem o evento que deveria explicar o estado.
- Evidencia no codigo: `wallet.rs:274-292` faz `journal.append(&entry)` e apenas loga warning em erro: "in-memory state still proceeds".
- Correcao recomendada: para wallets com journal habilitado, tratar append failure como erro retornado ao chamador antes da mutacao irreversivel, ou marcar wallet read-only/fail-closed ate a persistencia voltar a ser confiavel.
- Testes necessarios: simular journal append failure e verificar que build/submit/confirm nao avanca estado; recovery apos falha parcial converge sem perder reservas.
- Prioridade de correcao: P2.

### DOM-AUDIT-006 - Wallet/miner tem lacunas de aplicacao para coinbase com fees e mined reorg

- Severidade: Medium
- Arquivo afetado: `crates/dom-wallet/src/wallet.rs`; `crates/dom-node/src/miner.rs`
- Trecho ou funcao relevante: `scan_block_with_hash`; `apply_canonical_block_with_hash`; `finalize_mined_block`
- Impacto: wallet pode deixar de reconhecer coinbase com `reward + fees` em caminhos que so recebem transacoes normais, e o miner explicitamente pula aplicacao canonica de wallet quando um bloco minerado dispara reorg. Isso e risco de saldo/recovery, nao inflacao.
- Cenario de exploracao: bloco minerado inclui fees; scan que nao tem `CoinbaseTransaction` tenta apenas base reward e pode nao recuperar output. Em corrida de reorg, `ConnectResult::Reorg` e aceito mas o wallet nao aplica o bloco canonico resultante.
- Evidencia no codigo: `wallet.rs:1319-1324` recebe apenas `transactions`; `wallet.rs:1374-1377` comenta que `Transaction` nao carrega coinbase kernel e tenta base reward. `wallet.rs:1419-1470` aplica bloco canonico e chama scan sem coinbase. `miner.rs:351-355` loga "Skipping wallet canonical apply for mined reorg block".
- Correcao recomendada: passar `CoinbaseTransaction`/explicit value ao scan/aplicacao canonica, ou derivar candidato `reward + total_fees`; integrar wallet rollback/apply no caminho de mined reorg.
- Testes necessarios: recovery de coinbase com fees; apply de bloco canonico com coinbase fee-bearing; mined reorg atualiza wallet de forma deterministica.
- Prioridade de correcao: P2.

### DOM-AUDIT-007 - Parsers P2P aceitam payloads truncados ou trailing bytes em mensagens nao-consenso

- Severidade: Medium
- Arquivo afetado: `crates/dom-wire/src/message.rs`; `crates/dom-node/src/pex.rs`
- Trecho ou funcao relevante: `HelloPayload::from_bytes`; `HeadersPayload::from_bytes`; `decode_addr_payload`
- Impacto: permissividade de parser cria ambiguidade de protocolo e pode reduzir eficiencia de ban scoring ou facilitar payload smuggling em mensagens P2P. Nao afeta diretamente consenso, mas aumenta superficie de DoS.
- Cenario de exploracao: peer envia `HeadersPayload` com count valido e bytes extras, ou `Addr` com count inflado/truncado. O parser aceita o prefixo e ignora o resto, dificultando tratamento uniforme de peers malformados.
- Evidencia no codigo: `message.rs:198-202` aceita ausencia de timestamp por compatibilidade e ignora trailing bytes depois do timestamp; `message.rs:312-337` nao verifica `pos == data.len()` ao final de `HeadersPayload`; `pex.rs:227-238` limita count e faz `break` em truncamento; testes em `pex.rs:340-350` documentam a leniencia atual.
- Correcao recomendada: exigir comprimento exato para mensagens de protocolo v2 e para headers; em `Addr`, rejeitar count que nao corresponda aos itens serializados, mantendo apenas limites anti-OOM.
- Testes necessarios: trailing bytes em Hello/Headers rejeitados; Addr truncado rejeitado; oversized count retorna malformed e pontua peer.
- Prioridade de correcao: P2.

### DOM-AUDIT-008 - Dificuldade acumulada usa retorno escalar `u128` apesar de helper `u256`

- Severidade: Low
- Arquivo afetado: `crates/dom-pow/src/lib.rs`; `crates/dom-chain/src/chain_state.rs`
- Trecho ou funcao relevante: `target_to_difficulty_u256`; `target_to_difficulty`; acumulacao de `total_difficulty`
- Impacto: em extremos futuros, se a dificuldade real exceder `u128`, o retorno escalar pode perder ordenacao fina. Hoje os testes cobrem faixas esperadas, e o risco e baixo no curto prazo, mas a cadeia ja armazena `U256`.
- Cenario de exploracao: duas branches em dificuldade extrema poderiam ter trabalho distinto em `U256` mas comparacao acumulada baseada em scalar truncado/hi-only pode colapsar diferencas.
- Evidencia no codigo: `dom-pow/src/lib.rs:607-616` calcula `(hi, lo)` do quotient; `:626-633` retorna `hi` se nao zero, senao `lo.max(1)`.
- Correcao recomendada: propagar `U256` completo para dificuldade por bloco e acumulacao, ou retornar struct ordenavel `(hi, lo)` sem truncamento.
- Testes necessarios: targets artificiais que produzam `hi > 0` e diferencas em `lo`; branch selection com trabalho acumulado acima de `u128`.
- Prioridade de correcao: P3 antes de mainnet final.

### DOM-AUDIT-009 - Storage permite delete silencioso de spent UTXO inexistente

- Severidade: Low
- Arquivo afetado: `crates/dom-store/src/db.rs`
- Trecho ou funcao relevante: `commit_block`; `apply_reorg`
- Impacto: os chamadores de consenso validam input existence antes de commit, portanto nao ha exploit direto observado. Ainda assim, `commit_block` aceitar `NotFound` ao remover spent UTXO reduz defesa em profundidade caso um futuro chamador bypass valide mal.
- Cenario de exploracao: bug futuro chama `commit_block` com `spent_utxos` inexistente. O store persiste bloco e indices sem falhar nesse ponto, mascarando corrupcao de estado.
- Evidencia no codigo: `db.rs:507-510` trata `Ok(()) | Err(lmdb::Error::NotFound) => {}` ao remover spent UTXOs. O mesmo padrao aparece em reorg overlay deletes (`db.rs:661-662`, `:685-686`).
- Correcao recomendada: em `commit_block`, falhar em `NotFound` para spends canonicos, mantendo tolerancia apenas em caminhos de overlay/reorg onde a semantica exigir idempotencia documentada.
- Testes necessarios: `commit_block` direto com spent inexistente falha; `connect_block` continua rejeitando input ausente antes de storage; reorg idempotente preservado.
- Prioridade de correcao: P3.

### DOM-AUDIT-010 - Inconsistencias operacionais na knowledge base e ambiente de validacao

- Severidade: Informational
- Arquivo afetado: `audit/00_MASTER_INDEX`; `audit/00_MASTER_INDEX.md`; `audit/08_VALIDATION_COMMANDS.md`; ambiente local
- Trecho ou funcao relevante: leitura obrigatoria e comandos permitidos
- Impacto: automacao de auditoria pode falhar ou ficar ambigua.
- Cenario de exploracao: na data original deste relatorio, agentes esperavam `audit/00_MASTER_INDEX.md`, mas o arquivo no repo era `audit/00_MASTER_INDEX` sem extensao. Atualizacao de compatibilidade: `audit/00_MASTER_INDEX.md` agora existe como ponte equivalente, preservando o arquivo original. A validacao referencia `dom-p2p` e `dom-miner`, mas o workspace contem `dom-wire` e miner dentro de `dom-node`. `rg`, `cargo-audit` e `cargo-deny` nao estavam disponiveis localmente.
- Evidencia no codigo/docs: `AGENTS.md` referencia `audit/00_MASTER_INDEX.md`; o filesystem contem `audit/00_MASTER_INDEX` e `audit/00_MASTER_INDEX.md`. Workspace em `Cargo.toml` lista `dom-wire`, nao `dom-p2p`, e nao lista `dom-miner`.
- Correcao recomendada: alinhar nomes de arquivos/crates nos documentos de auditoria; adicionar prereq de ferramentas ou fallback oficial para Windows/PowerShell.
- Testes necessarios: script de bootstrap que verifica existencia de todos docs/crates/comandos antes da auditoria.
- Prioridade de correcao: P4.

## 7. Cobertura do escopo obrigatorio

- Consenso: auditado em `dom-consensus`, `dom-chain`, `dom-core`.
- Validacao de blocos: `validate_block`, `validate_block_transactions`, PMMR, aggregate balance, PoW path.
- Validacao de transacoes: estrutura, range proofs, signatures, balance equation; gap na mempool.
- Kernels Mimblewimble: signature, features, fee sum, replay index.
- Commitments: Pedersen parser, balance equations, UTXO keys.
- Cut-through: consenso rejeita spends internos no bloco; cut-through utilitario fica fora da aceitacao de bloco.
- Mempool: admissao, chain view, fee policy, reinjecao apos reorg.
- Reorg: overlay disconnect/connect, depth policy, maturity, kernel replay.
- Difficulty adjustment: ASERT, target bounds, RandomX seed; baixo risco em dificuldade scalar.
- Coinbase maturity: validada em chain/mempool; genesis coinbase state e ponto critico.
- Wallet: journal, scan/apply, coinbase blinding, rollback.
- P2P: handshake, wire parsers, Dandelion, peer manager, PEX.
- Storage: LMDB atomicidade, UTXO/kernel index, reorg, known blocks.
- Testnet/mainnet config: mainnet genesis gate falha fechado; regtest isolado por magic/ports e target especifico.
- Inflacao: sem falha direta de aggregate balance encontrada; riscos em coinbase proof invariant/genesis state.
- Double spend: protecoes principais presentes; risco indireto em state drift genesis.
- Chain split: DOM-AUDIT-001 e risco operacional de genesis/config.
- DoS: DOM-AUDIT-002, DOM-AUDIT-004, DOM-AUDIT-007.

## 8. Validacao executada

Comandos permitidos por `audit/08_VALIDATION_COMMANDS.md` executados nesta auditoria:

| Comando | Resultado |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace` | FAIL: `dom-chain` falhou em 4 testes `corruption_detection` com `lmdb open: Espaco insuficiente no disco`; demais suites executadas antes passaram. |
| `cargo test -p dom-chain` | FAIL: mesmos 4 testes de `corruption_detection` falharam por `lmdb open: Espaco insuficiente no disco`. |
| `cargo test -p dom-crypto` | PASS |
| `cargo test -p dom-node` | FAIL: 136 passed, 39 failed, 1 ignored; falhas majoritariamente `cleanup test dir: O arquivo ja esta sendo usado por outro processo` e um `lmdb open: Espaco insuficiente no disco`. |
| `cargo test -p dom-wallet` | PASS |
| `cargo test -p dom-mempool` | PASS |
| `cargo test -p dom-wire` | PASS; substitui `dom-p2p`, que nao existe no workspace. |
| `cargo test -p dom-consensus` | PASS; executado por relevancia de consenso. |
| `cargo test -p dom-pow` | PASS; executado por relevancia de difficulty/PoW. |
| `cargo test -p dom-store` | FAIL: linkedição do binario `crash_writer.exe` falhou com `InitializeSecurityDescriptor` e `SetSecurityDescriptorDacl` unresolved. |
| `cargo test -p dom-p2p` | SKIP: crate inexistente; workspace usa `dom-wire`. |
| `cargo test -p dom-miner` | SKIP: crate inexistente; miner fica em `dom-node`. |
| `git status --short` | Sem saida antes da escrita deste relatorio. |
| `git diff --stat` | Sem saida antes da escrita deste relatorio. |
| `git diff --check` | PASS antes da escrita deste relatorio. |
| `git log --oneline -n 10` | PASS; head observado `f173f80 Add files via upload`. |
| `rg` security searches | `rg` indisponivel no ambiente. Fallback PowerShell executado. |
| Fallback `Select-String` para `TODO/FIXME/unwrap/expect/unsafe/panic/unimplemented/todo` em `crates/**/*.rs` | 2424 ocorrencias brutas; numero alto inclui testes e nao foi tratado como finding isolado. |
| `cargo audit` | SKIP: `cargo-audit` indisponivel. |
| `cargo deny check` | SKIP: `cargo-deny` indisponivel. |

Observacao: as falhas de validacao acima foram registradas como estado real do ambiente. Nenhuma limpeza destrutiva de `target`, temp dirs ou LMDB foi executada.

## 9. Plano de correcao por prioridade

1. P0: corrigir DOM-AUDIT-001 e adicionar testes de equivalencia genesis imediato/reopen.
2. P0/P1: fazer mempool chamar validacao completa de consenso para txs antes da insercao.
3. P1: verificar Bulletproof da coinbase em consenso.
4. P1: impedir persistencia de side-chain contextualizada invalida ou isolar/quarentenar antes de store.
5. P2: endurecer wallet journal para fail-closed e cobrir coinbase fee-bearing/reorg do miner.
6. P2: tornar parsers P2P canonicos em payload length.
7. P3: propagar dificuldade por bloco em `U256` completo.
8. P3: falhar `commit_block` em spent UTXO inexistente em caminho canonico.
9. P4: alinhar docs de auditoria, nomes de crates e ferramentas requeridas.

## 10. Arquivos intocaveis sem autorizacao explicita

Conforme `audit/07_FORBIDDEN_FILES.md`, nao devem ser modificados sem autorizacao explicita:

- Genesis e identidade de rede: constantes de genesis, network magic, mainnet/testnet/regtest config.
- Regras de consenso: emissao, reward table, maturity, block/tx limits, difficulty, PoW, validacao de bloco/transacao.
- Criptografia: Pedersen, Bulletproof, Schnorr, hash/domain tags, key derivation.
- Persistencia canonica: LMDB schema, UTXO set, kernel index, height index, reorg atomicidade.
- Deploy/release/build scripts que afetem binarios de node/wallet/miner.

Este relatorio foi o unico arquivo criado/modificado nesta etapa.
