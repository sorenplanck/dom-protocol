# DOM Protocol - Bootstrap Reading Report

Data: 2026-05-31
Branch: `audit/bootstrap-reading-report`
Base lida: `AGENTS.md` e knowledge base em `audit/`

## 1. Escopo Da Leitura

Arquivos lidos antes de qualquer auditoria, patch ou teste:

- `AGENTS.md`
- `audit/00_MASTER_INDEX`
- `audit/00_MASTER_INDEX.md` (compatibility path added later)
- `audit/01_PROTOCOL_OVERVIEW.md`
- `audit/02_CONSENSUS_INVARIANTS.md`
- `audit/03_CRYPTOGRAPHIC_ASSUMPTIONS.md`
- `audit/04_THREAT_MODEL.md`
- `audit/05_ATTACK_SURFACES.md`
- `audit/06_AUDIT_CHECKLIST.md`
- `audit/07_FORBIDDEN_FILES.md`
- `audit/08_VALIDATION_COMMANDS.md`
- `audit/09_KNOWN_RISKS.md`
- `audit/10_REPORT_TEMPLATE.md`

Observacao: na data original deste relatorio, a solicitacao mencionava `audit/00_MASTER_INDEX.md`, mas o repositorio continha apenas `audit/00_MASTER_INDEX` sem extensao `.md`. O conteudo desse arquivo foi lido e usado como indice operacional. Atualizacao de compatibilidade: `audit/00_MASTER_INDEX.md` agora existe como ponte equivalente, preservando o arquivo original.

## 2. Resumo Operacional Da Arquitetura

O DOM Protocol deve ser tratado como blockchain pre-mainnet, com revisao security-first. A arquitetura descrita pela base de auditoria se organiza nos seguintes subsistemas:

- Consenso e cadeia: validacao de blocos, headers, transicoes de estado, reorgs, dificuldade, coinbase, emissao e integridade do UTXO set.
- Criptografia Mimblewimble: Pedersen commitments, range proofs, kernel signatures, excess validation, cut-through, agregacao e equacao de balanceamento.
- Persistencia: armazenamento LMDB, atomicidade de commits, recuperacao de estado, equivalencia restart/replay e integridade de indices.
- PMMR: consistencia de roots, replay deterministico, divergencia entre estado persistido e estado reconstruido.
- Mempool: admissao de transacoes, conflitos, double-spend, orphans, reconciliacao apos reorg e resistencia a DoS.
- P2P: framing, parsing, limites de mensagem, propagacao, peer scoring, ban policy, diversidade de peers e resistencia a eclipse/DoS.
- RPC/API: autenticacao, validacao de entrada, endpoints administrativos, exposicao de debug e controle operacional.
- Wallet: seed/key management, construcao de transacoes, fee/change, WAL/journal, recuperacao, sync e reorg safety.
- Configuracao e deploy: network magic, chain id, seeds, parametros de mainnet/testnet/regtest, scripts de release e gates de validacao.

Principio central: nomes, comentarios e testes existentes nao provam corretude. Cada caminho critico precisa ser rastreado de entrada externa ate validacao, mutacao de estado e persistencia.

## 3. Partes Mais Criticas Do Protocolo

Prioridade maxima para auditoria:

1. Regras de consenso que podem aceitar blocos invalidos ou rejeitar blocos validos.
2. Validacao de transacoes, incluindo balance equation, duplicate inputs, duplicate outputs, range proofs, kernel signatures, lock heights e coinbase maturity.
3. Persistencia canonica da cadeia, UTXO set, indices, PMMR e equivalencia de replay/restart.
4. Reorg: desconectar/conectar blocos, restaurar/spender UTXOs, reconciliar mempool e manter chain selection deterministica.
5. Emissao monetaria: reward schedule, halvings, fees, coinbase, overflow/underflow e supply total.
6. Genesis e identidade de rede: genesis hash, network magic, chain id, protocol version, seeds e checkpoints.
7. Serializacao/hashing consensus-critical: canonical encoding, domain separation e independencia de ordem de mapas/plataforma.
8. P2P parsers e resource limits: rejeicao de payloads malformados, limites de tamanho, ban score e anti-amplificacao.
9. Wallet safety: seed handling, change output, journal/WAL, broadcast/retry, recovery e comportamento sob reorg.
10. RPC/admin surfaces: autenticacao, endpoints perigosos e configuracao de producao.

## 4. Mapa De Riscos

| Area | Risco principal | Severidade potencial | Evidencia da base |
|---|---|---:|---|
| Consenso | Inflacao, bloco invalido aceito, bloco valido rejeitado | Critical | `02_CONSENSUS_INVARIANTS.md`, `04_THREAT_MODEL.md` |
| UTXO | Missing spend, double-spend, insercao duplicada, remocao incorreta | Critical | `02_CONSENSUS_INVARIANTS.md` |
| Persistencia | Estado persistido diferente do replay, restart inconsistente | Critical | `02_CONSENSUS_INVARIANTS.md`, `05_ATTACK_SURFACES.md` |
| PMMR | Root divergente, replay nao equivalente, state commitment incorreto | Critical | Missao de auditoria fornecida pelo usuario |
| Criptografia | Range proof/signature/excess nao verificados ou mal vinculados | Critical | `03_CRYPTOGRAPHIC_ASSUMPTIONS.md` |
| Reorg | UTXO/mempool divergente, invalidacao incorreta, rollback incompleto | Critical/High | `02_CONSENSUS_INVARIANTS.md` |
| Mempool | Poisoning, conflito nao detectado, orphan bypass | High | `04_THREAT_MODEL.md`, `06_AUDIT_CHECKLIST.md` |
| P2P | DoS, malformed payloads, amplification, eclipse | High | `04_THREAT_MODEL.md`, `05_ATTACK_SURFACES.md` |
| Wallet | Perda de fundos, change irrecuperavel, WAL inconsistente | High | `04_THREAT_MODEL.md`, `09_KNOWN_RISKS.md` |
| Config/Deploy | Mainnet/testnet confusion, seeds inseguros, bypass debug | High/Medium | `05_ATTACK_SURFACES.md`, `07_FORBIDDEN_FILES.md` |

## 5. Invariantes De Consenso Principais

Invariantes que nao podem ser enfraquecidas:

- Nenhuma transacao pode criar valor fora das regras autorizadas de coinbase/emissao.
- A equacao de balanceamento entre inputs, outputs, fees e kernel excess deve validar deterministicamente.
- Coinbase deve obedecer regras de quantidade, maturidade, emissao e colocacao.
- Toda entrada deve referenciar output existente e nao gasto.
- Nenhum output pode ser gasto mais de uma vez.
- Duplicate inputs sao invalidos.
- Duplicate outputs/commitment collisions devem falhar ou ser tratados com seguranca, sem sobrescrita silenciosa.
- Todo spent output deve ser removido exatamente uma vez do UTXO set canonico.
- Todo novo output deve ser inserido exatamente uma vez.
- Range proofs e kernel signatures devem ser verificadas; falhas devem rejeitar tx/bloco.
- Headers, parent references, timestamps, dificuldade e limites de peso/tamanho devem ser validados de modo deterministico.
- Chain selection deve ser deterministica e nunca preferir cadeia invalida.
- Reorg deve produzir UTXO/PMMR/mempool equivalentes a replay canonico.
- Restart nao pode alterar estado de consenso.
- Genesis deve ser deterministico, imutavel e reproduzivel.
- Serializacao e hashing consensus-critical devem ser canonicos e independentes de plataforma, locale, ordem de `HashMap`, debug output ou wall-clock.

## 6. Threat Model Resumido

Assumir adversarios capazes de:

- Enviar transacoes arbitrarias.
- Conectar como peers e enviar mensagens P2P malformadas ou resource-heavy.
- Minerar ou simular blocos adversariais.
- Tentar reorgs, double-spends e conflitos de mempool.
- Reiniciar, dessincronizar ou exaurir recursos de nodes.
- Explorar bordas de serializacao, banco de dados, wallet, RPC e networking.
- Observar trafego publico.
- Rodar clientes modificados.

Classes criticas:

- Inflacao: explorar balance equation, range proof, kernel, coinbase, cut-through ou block connection.
- Double-spend: explorar UTXO spend marking, duplicate input detection, mempool conflicts, reorg ou concorrencia.
- Invalid block acceptance: bypass de header, parent, dificuldade, timestamp, coinbase, tx validation ou atomicidade.
- Consensus split: nao determinismo em serializacao/hashing, iteracao, tempo, recovery ou tie-breaking.
- Mempool poisoning: invalidos/conflitos/orphans/resource-heavy entrando ou sobrevivendo.
- P2P DoS/eclipse: parsing, limites, peer scoring, diversity, amplification, queues e bans.
- Wallet loss/mis-spend: chaves, change, fees, WAL, sync, recovery e broadcast retry.

## 7. Arquivos E Categorias Que Nao Podem Ser Alterados Sem Autorizacao

`audit/07_FORBIDDEN_FILES.md` ainda nao lista caminhos exatos preenchidos apos recon, mas define categorias proibidas por padrao. Nao alterar sem autorizacao explicita:

- Genesis block definitions.
- Mainnet chain parameters.
- Network identifiers.
- Checkpoints.
- Hardcoded production seeds.
- Block validation logic.
- Transaction validation logic.
- Difficulty adjustment.
- Emission schedule.
- Coinbase maturity.
- Chain selection.
- Reorg state transition.
- UTXO state mutation.
- Commitment verification.
- Range proof verification.
- Kernel signature verification.
- Hashing and serialization of consensus objects.
- Key derivation and seed handling.
- Chain database schema.
- State migration logic.
- UTXO database layout.
- Wallet database schema.
- Mainnet release scripts.
- Security CI gates.
- Production Docker/deployment files.
- Build scripts defining production binaries.

Exact-path candidates to populate during recon include, at minimum, files under:

- `crates/dom-core/`
- `crates/dom-consensus/`
- `crates/dom-chain/`
- `crates/dom-store/`
- `crates/dom-crypto/`
- `crates/dom-pmmr/`
- `crates/dom-tx/`
- `crates/dom-wallet/`
- `crates/dom-wire/`
- `crates/dom-node/`
- `crates/dom-config/`

## 8. Comandos Obrigatorios De Validacao

Baseline definido em `audit/08_VALIDATION_COMMANDS.md`:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Comandos direcionados quando relevantes:

```bash
cargo test -p dom-chain
cargo test -p dom-crypto
cargo test -p dom-node
cargo test -p dom-wallet
cargo test -p dom-mempool
cargo test -p dom-p2p
cargo test -p dom-miner
```

Buscas security-oriented:

```bash
rg "unwrap\(|expect\(|panic!\(|todo!\(|unimplemented!\(" .
rg "bypass|skip|insecure|debug|test_only|allow_invalid|disable_validation" .
rg "unsafe" .
```

Git/diff hygiene:

```bash
git status --short
git diff --stat
git diff --check
git log --oneline -n 10
```

Checks adicionais se disponiveis:

```bash
cargo test --workspace --features fuzz
cargo test --workspace --features proptest
cargo audit
cargo deny check
```

Observacao: durante este bootstrap nenhum teste foi executado, por instrucao de nao iniciar auditoria/testes antes de carregar e relatar a knowledge base.

## 9. Known Risks Iniciais

Riscos ja declarados em `audit/09_KNOWN_RISKS.md` que devem guiar a auditoria:

- Genesis immutability precisa ser confirmada.
- Difficulty adjustment precisa ser revisado.
- Emission schedule enforcement precisa ser revisado.
- Reorg/rollback behavior precisa ser revisado.
- Commitment/range proof implementation precisa ser rastreada fim a fim.
- Kernel signature domain separation precisa ser verificada.
- Serializacao usada em assinaturas e hashes precisa ser confirmada como canonica.
- Mempool conflict resolution sob reorg precisa ser verificado.
- Orphan handling precisa ser verificado.
- Resource limits precisam ser confirmados.
- P2P size/rate limits, peer scoring, ban policy e eclipse resistance precisam ser revisados.
- Wallet seed/key storage, transaction construction e reorg behavior precisam ser verificados.

## 10. Plano De Auditoria Por Prioridade

### P0 - Inventario e baseline

- Fixar commit auditado.
- Inventariar crates, arquivos, LOC, funcoes publicas, structs publicas, traits publicas, constantes consensus-critical, dependencias, RFCs referenciados e testes.
- Mapear documentacao disponivel e marcar arquivos ausentes como NAO AUDITADO.
- Rodar apenas comandos de inventario; testes entram na fase propria.

### P1 - Consenso, economia e genesis

- Auditar `dom-core`, `dom-consensus`, `dom-chain`, `dom-store`, `dom-pow`, `dom-pmmr`, `dom-tx`.
- Verificar genesis bit a bit, emission schedule, halvings, reward, fees, coinbase maturity, difficulty e chain selection.
- Rastrear block validation ate state mutation/persistence.
- Confirmar que blocos invalidos nao sao aceitos e blocos validos nao sao rejeitados.

### P2 - Persistencia, replay, restart, reorg

- Auditar atomicidade LMDB, commit/rollback/reorg, UTXO set, PMMR roots, metadata, snapshots e recovery.
- Comparar estado persistido contra replay canonico.
- Procurar NotFound silencioso, writes parciais, overlays idempotentes indevidos e reconstrucoes implicitas.

### P3 - Criptografia e serializacao

- Auditar commitments, range proofs, kernel signatures, hash domains, signing messages, canonical serialization e determinismo.
- Procurar bypasses, structural-only checks, RNG inadequado e vazamento de segredo.

### P4 - Mempool e P2P

- Auditar admissao de transacoes, conflitos, orphans, eviction, reorg reconciliation e limites.
- Auditar parsers P2P, message size, checksums, peer scoring, bans, backpressure e eclipse resistance.

### P5 - Wallet, RPC, node runtime e operacoes

- Auditar wallet seed, storage, WAL, change, fees, broadcast, recovery e reorg.
- Auditar RPC auth, endpoints, input validation e operational safety.
- Auditar node runtime, scheduler dependence, queues, shutdown/restart e deployment/mainnet configuration.

### P6 - Testes, matriz RFC e relatorio final

- Construir matriz REGRA / DOCUMENTACAO / IMPLEMENTACAO / TESTE / STATUS.
- Classificar gaps de teste por categoria: CONSENSUS, STORAGE, REORG, CRYPTO, NETWORK, MEMPOOL, WALLET, ADVERSARIAL.
- Responder as 15 perguntas adversariais obrigatorias.
- Produzir relatorio completo final com findings, evidencias, limitacoes, confianca e veredicto mainnet.

## 11. Regras Operacionais Para Proximas Fases

- Nao inventar informacoes; arquivos ausentes ficam como NAO AUDITADO.
- Toda conclusao deve citar evidencia.
- Findings HIGH/CRITICAL exigem reproducao; sem reproducao, nao classificar acima de MEDIUM.
- Nao confundir design documentado com bug.
- Nao alterar arquivos proibidos sem autorizacao explicita.
- Nao enfraquecer consenso, criptografia, validacao, dificuldade, wallet, mempool, chain ou P2P para fazer testes passarem.
- Se houver conflito entre documentacao e codigo, registrar primeiro; patch apenas apos autorizacao/scope claro.

## 12. Resultado Do Bootstrap

Status: knowledge base operacional carregada.

Pronto para iniciar a auditoria completa pre-mainnet conforme a missao recebida, mantendo relatorios parciais por fase/crate e gerando ao final um documento consolidado de auditoria completa.
