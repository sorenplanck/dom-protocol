# DOM Protocol — FABLE5 Security Audit (pré-testnet)

**Data:** 2026-06-10
**Auditor:** Fable 5 (revisão defensiva de robustez/hardening)
**Modo:** read-only em código de produção; escrita autorizada apenas em
`crates/**/tests/` (novos) e neste relatório. Nenhum arquivo de `src/` foi tocado.
**Base:** workspace de 23 crates; `git HEAD = edc4b54`, branch `main`, working tree limpo.

---

## 1. Resumo executivo e classificação de prontidão

O DOM está **substancialmente endurecido**. Reexecutei a validação de base e
revisei contra o **código real** (não contra docstrings) as três áreas de fase do
escopo. Todos os achados das auditorias anteriores (`DOM_AUDIT_REPORT.md` e
`FULL_PROTOCOL_AUDIT_REPORT.md`) que pude reverificar estão **corrigidos** ou
**mitigados e bounded**, e os três fixes herdados (Noise, genesis, Pedersen/BP)
continuam válidos com prova executável (§4).

Esta passada encontrou **1 achado novo de robustez** (ordering de admissão na
mempool, confirmado por teste — FABLE5-001) e **1 observação de defesa em
profundidade** (persistência de side-chain antes da validação contextual,
intencional e bounded — FABLE5-002). Nenhum permite inflação, double-spend ou
bypass de consenso. São de severidade **Baixa/Média**, classe DoS/CPU.

### Validação de base (executada nesta sessão)

| Comando | Resultado |
|---|---|
| `cargo build --workspace` | **OK** (exit 0) |
| `cargo test --workspace` | **OK** — agregado **1173 passed, 0 failed** |
| `cargo test -p dom-mempool --test robustness_admission_ordering` (novo) | **OK** — 3 passed |

Sem testes flaky observados nesta sessão; a suíte rodou verde de ponta a ponta
(sem os erros ambientais de LMDB/`Espaço insuficiente` que apareceram em
auditorias anteriores rodadas em sandbox read-only).

### Classificação de prontidão

| Alvo | Veredito | Justificativa |
|---|---|---|
| **Regtest** | ✅ **Pronto** | Suíte verde; isolamento por magic/chain_id; crypto ativa. |
| **Testnet privada** | ✅ **Pronto** | Invariantes monetárias fecham; fixes herdados válidos; parsers/Noise com teto. |
| **Testnet pública** | ✅ **Pronto** | FABLE5-001 **corrigido** (ver §11): gates baratos antes da crypto + short-circuit de replay no caminho P2P, validados por teste. |
| **Mainnet** | ⛔ **Ainda não** | Pré-requisito operacional fora do escopo deste agente: as constantes `GENESIS_HASH_{MAINNET,TESTNET,REGTEST}` ainda são placeholders pré-launch (ver `miner.rs:525-532`) — **PRECISA DECISÃO HUMANA** (cerimônia de genesis). Além de soak/observação em testnet. |

---

## 2. Tabela de achados

| ID | Sev. | Título | Arquivo:linha | Status |
|---|---|---|---|---|
| FABLE5-001 | Média | Validação criptográfica completa roda **antes** dos gates baratos (dedup/min-fee/chain-view); replay de tx válida é re-verificado por completo e a rejeição duplicada **não** pontua o peer | `dom-mempool/src/lib.rs:211-292`; `dom-consensus/src/lib.rs:81-116`; `dom-node/src/node.rs:1712-1731` | **CORRIGIDO** (confirmado por teste; ver §11) |
| FABLE5-002 | Baixa | Bloco side-chain é persistido (`store_known_block`) após PoW+validação estática, mas **antes** da validação contextual de inputs/maturity | `dom-chain/src/chain_state.rs:347-372` | **Confirmado por leitura** (intencional, bounded) |
| — | Info | Constantes de genesis hash ainda placeholders pré-launch | `dom-node/src/miner.rs:525-532` | **PRECISA DECISÃO HUMANA** (cerimônia) |

Reverificação dos achados anteriores (todos **fechados/mitigados**): ver §3.

---

## 3. Reverificação dos achados das auditorias anteriores

Confirmados **pelo código** (não pelo cabeçalho dos relatórios):

| Achado anterior | Estado atual | Evidência |
|---|---|---|
| DOM-AUDIT-001 (IBD self-deadlock: chain lock retido através de `purge_mempool_confirmed_inputs`) | **Corrigido** | `node.rs:~2665-2712`: guard do chain é adquirido/liberado em escopo e dropado antes de `purge_mempool_confirmed_inputs`. |
| DOM-AUDIT-003 (eviction única deixa mempool acima do cap) | **Corrigido** | `mempool/src/lib.rs:284-298`: eviction em **loop** com guarda de progresso de peso + rejeição prévia de tx acima do cap (`:266-271`). |
| DOM-AUDIT-004 (`page*limit` overflow no RPC) | **Corrigido** | `dom-rpc` usa `checked_mul` e retorna erro de cliente (reverificado pelo agente de fase 3). |
| DOM-AUDIT-006 (`/status` hardcoded mainnet) | **Corrigido** | `/status` lê `handle.network()` em runtime. |
| DOM-AUDIT-007 (parsers permissivos: Hello/Headers trailing, Addr truncado) | **Corrigido** | `message.rs`: Hello valida tamanho exato; Headers checa `pos == data.len()`; Addr (`pex.rs`) rejeita trailing. |
| FULL-AUDIT-001 (genesis state drift create vs reopen) | **Corrigido** | `miner.rs:511-521` usa `genesis_canonical_changeset` — o **mesmo** builder do reopen (`chain_state.rs:1368-1375`). Ver §4. |
| FULL-AUDIT-002 (mempool aceitava tx sem crypto completa) | **Corrigido** | `mempool/src/lib.rs:229` chama `dom_consensus::validate_transaction` (range proofs + Schnorr) na admissão de produção. |
| FULL-AUDIT-003 (coinbase não verificava Bulletproof) | **Corrigido** | `transaction.rs:378-390`: `CoinbaseTransaction::validate` chama `bp_verify` na proof da coinbase. |
| FULL-AUDIT-004 (side-chain persistida antes da validação contextual) | **Mitigado/bounded** | Persistência só após `validate_block` (PoW+crypto+balanço); retenção bounded por `prune_retained_side_chains`; promoção revalida inputs e falha fechada. Ver FABLE5-002. |

---

## 4. Fixes herdados — ainda válidos, com prova

### 4.1 Noise frame overflow → fragmentação com teto (dom-wire/src/codec.rs)
**Válido.** O codec fragmenta mensagens lógicas em frames `≤ CHUNK (65519)` e, na
recepção, **valida o tamanho total declarado contra `MAX_LOGICAL_MSG_BYTES` antes
de crescer o buffer** (`codec.rs:150-159`), além de rejeitar overrun
(`:162-170`). Não há reassemblagem infinita: o buffer cresce no máximo `CHUNK` por
frame e é capado. Timeout por frame em `IDLE_TIMEOUT_SECS` (`:125-135`).
**Prova:** testes embutidos `recv_rejects_oversized_declared_length`,
`roundtrip_max_block_size` (16 MiB), `headers_1008_roundtrip_regression`,
`recv_is_cancel_safe_across_frames` — todos verdes na suíte.

### 4.2 Genesis state drift → create == reopen (dom-chain)
**Válido.** `create_genesis_block` (`miner.rs:511-521`) persiste o changeset via
`dom_chain::genesis_canonical_changeset`, que é exatamente
`build_utxo_changeset` + `extract_kernel_excesses` — os **mesmos** helpers que o
reopen usa em `ensure_canonical_utxo_set`/`reconstruct_canonical_utxo_set`
(`chain_state.rs:1368-1375`). Logo `create == reopen` por construção, eliminando o
drift que causava risco de chain split na coinbase genesis.
**Prova:** `dom-chain/tests/corruption_detection.rs` (reopen/partial-persist) e a
suíte de `dom-node` (`create_genesis_block` ramos de create/reopen) verdes.

### 4.3 Pedersen/Bulletproof H mismatch → gerador unificado + bridge sec1↔zkp
**Válido.** Pedersen (k256) e Bulletproof (secp256k1-zkp) usam o **mesmo H**: o X
do gerador zkp (`dom_generator()`, prefixo `0x0a || H_DOM_X`) é byte-a-byte igual
ao `H_COMPRESSED_FINAL[1..]` do Pedersen. O bridge `sec1_to_zkp`/`zkp_to_sec1`
usa `is_square` via `FieldElement::sqrt`; o loop em `zkp_to_sec1` é finito (2
prefixos) e rejeita x fora da curva / prefixo zkp inválido.
**Prova:** `pedersen_and_bulletproof_use_same_generator`,
`h_generator_unification_byte_equality`, `roundtrip_sec1_zkp_sec1_100_samples`,
`edge_value_blinding_bridge_roundtrip_and_prove_verify` — verdes.

---

## 5. Resultados por fase (código real)

### FASE 1 — Integridade monetária e de consenso — **SOUND**
- **Equação agregada de balanço:** verificada em `block_full.rs` via
  `dom_crypto::verify_block_balance_equation`; todos os caminhos de aceitação
  (extensão direta, side-chain/reorg, IBD) convergem para `validate_block`. Sem
  bypass.
- **Coinbase = reward(height)+fees:** `transaction.rs:133-149`
  (`validate_explicit_value`) usa `checked_add` (overflow → erro). `total_fee`
  (`:216-221`) soma fees com `checked_add`. `block_reward` é tabela pré-computada
  (`MAX_SUPPLY_NOMS < 2^52`), sem aritmética perigosa.
- **Range proofs:** todo output confidencial passa por `bp_verify`, **incluindo a
  coinbase** (`transaction.rs:378-390`). Faixa provada `[0, 2^52)`
  (`MAX_PROVABLE_VALUE = 2^52-1`); `verify` exige `range.start == 0`.
- **Double-spend no mesmo bloco:** `block_full.rs` rejeita inputs/outputs
  duplicados no bloco e gasto de output criado no mesmo bloco (cut-through
  violation).
- **Reorg:** profundidade limitada por `MAX_REORG_DEPTH_POLICY (1000)`;
  reconstrução do UTXO set é atômica (`apply_reorg`, uma transação LMDB).
- **Overflow:** caminhos de peso/fee/difficulty usam `checked_*`/`saturating_*`;
  nada perigoso sem guarda em consenso.

### FASE 2 — Robustez criptográfica — **SOUND**
- **Schnorr:** `from_bytes` rejeita R fora da curva/identidade e `s` zero/`≥ n`
  (`schnorr.rs:56-74`, `is_scalar_valid`). Challenge inclui R(33B)+pubkey(33B)+
  **chain_id**+message — não-maleável (R vs −R dão challenges diferentes).
- **Nonce:** RFC6979 determinístico derivado de `sk` + `hash(msg||chain_id)` —
  sem risco de reuso.
- **Agregação/excess:** kernel assina com o próprio `excess` como chave; soma de
  pontos é validada; sem MuSig2 ativo → sem rogue-key. `schnorr_add_public_keys`
  rejeita resultado no infinito.
- **Bulletproof:** teto `MAX_PROOF_SIZE (6144)` checado **antes** de
  desserializar; sem alocação a partir de tamanho não validado.
- **Domain separation:** `chain_id` entra no challenge; `derive_chain_id` difere
  por `network_magic` → assinatura de uma rede não verifica em outra
  (`cross_chain_replay_prevented`).
- **Parsing de pontos:** `Commitment`/`PublicKey::from_compressed_bytes` rejeitam
  identidade, off-curve, `x ≥ p` e encoding inválido; sem `unwrap` em entrada
  adversarial.

### FASE 3 — Robustez de rede e tratamento de entrada — **SOUND (1 achado)**
- **Parsers `dom-wire`:** Hello/Headers/GetHeaders/GetBlockData/Block validam
  tamanho exato e rejeitam trailing; `Vec::with_capacity` sempre após checar a
  contagem contra limites anti-OOM.
- **Noise:** teto de reassemblagem e timeout (ver §4.1).
- **IBD:** headers validados em prefilter; deadlock DOM-AUDIT-001 corrigido;
  volume de bodies bounded por `MAX_GETBLOCKDATA_HASHES` e processamento
  incremental.
- **Mempool:** crypto completa na admissão; eviction em loop; min-fee; conflito de
  input detectado; reinjeção pós-reorg rejeita duplicatas. **Achado FABLE5-001:**
  ordering dos gates (§6).
- **Peer scoring:** invalid tx/bloco → `record_peer_violation`
  (`PROTOCOL_VIOLATION=10`, `BAN_THRESHOLD=100`). **Lacuna:** `PolicyRejected`
  (exceto "handshake timeout") **não** pontua (`node.rs:1712-1731`) — base do
  FABLE5-001.
- **Orphan/future-block:** bounded (`MAX_ORPHAN_BLOCKS=1024`,
  future queue `MAX_QUEUE_SIZE=256`).
- **RPC:** `page*limit` com `checked_mul`; `/status` com network real.

---

## 6. Achado FABLE5-001 (detalhado)

**Título:** Validação criptográfica completa precede os gates baratos de
admissão; replay de transação válida é re-verificado por inteiro e a rejeição
duplicada não é pontuada (amplificação de CPU não-banível).
**Severidade:** Média (DoS/CPU; **não** afeta consenso).
**Arquivos:** `dom-mempool/src/lib.rs:211-292`, `dom-consensus/src/lib.rs:81-116`,
`dom-node/src/node.rs:1712-1731` e `:3865-3988`.

### Descrição
`accept_tx_with_chain_view` executa, **nesta ordem**:
1. `validate_transaction` → range proofs (Bulletproof) + assinaturas Schnorr
   (caro);
2. `validate_tx_against_chain_view` → existência de input (barato);
3. `accept_validated_tx` → **dedup por hash** e **min-fee** (barato).

Ou seja, os gates baratos (dedup, min-fee, existência de input) só rodam **depois**
da criptografia cara. Pior: a rejeição de duplicata é
`DomError::PolicyRejected("transaction already in mempool")`, e
`peer_violation_score` mapeia `PolicyRejected` (que não contenha "handshake
timeout") para `None` → **nenhuma pontuação de ban**.

### Cenário
Um peer observa **uma** transação válida na rede e reenvia os mesmos bytes em
loop. Cada reenvio força o nó a refazer a verificação completa do Bulletproof +
Schnorr antes de descobrir, no passo 3, que já a possui. A rejeição não pontua o
peer → a amplificação de CPU não é contida pela defesa de scoring. O atacante
gasta ~nada (bytes já prontos); o nó gasta uma verificação de range proof por
reenvio.

### Evidência (teste que executa)
Arquivo **novo**: `crates/dom-mempool/tests/robustness_admission_ordering.rs`.
Comando e saída:

```
$ cargo test -p dom-mempool --test robustness_admission_ordering
running 3 tests
test robustness_crypto_runs_before_duplicate_check ... ok
test robustness_min_fee_gate_is_behind_crypto ... ok
test robustness_duplicate_replay_is_unscored_policy_rejection ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

- `robustness_crypto_runs_before_duplicate_check`: com uma tx já no pool sob hash
  `H`, submeter **outra** tx com assinatura corrompida mas reaproveitando `H`
  resulta em rejeição **de assinatura** (`DomError::Invalid`), e **não** em
  "already in mempool". Prova determinística de que a crypto roda antes do dedup.
- `robustness_duplicate_replay_is_unscored_policy_rejection`: 5 replays da mesma
  tx válida retornam `PolicyRejected("...already in mempool")`, cujo texto **não**
  é o único `PolicyRejected` pontuado pelo nó → não-banível.
- `robustness_min_fee_gate_is_behind_crypto`: tx com fee abaixo do piso mas
  assinatura/proof válidos só é barrada **no gate de fee**, i.e. depois que a
  crypto passou.

### Impacto
Amplificação de CPU peer-facing sem contenção por ban. Mitigantes existentes:
processamento sequencial por conexão, `IDLE_TIMEOUT`, e o atacante precisa de uma
tx válida real para o caso não-banível. Não há risco de inflação/double-spend.

### Correção (com trade-offs) — **RESOLVIDO em §11**
> Nota (2026-06-10): as opções abaixo foram a análise original (auditoria
> read-only). A correção foi desde então implementada e validada por teste —
> ver **§11 (FABLE5-001 — Resolução)**. As opções 1 e 3 foram adotadas (PASSO 2 e
> PASSO 3); a opção 2 (pontuar replay) foi **descartada** para não gerar
> falso-positivo em corridas honestas de gossip e não enfraquecer o ban de spam.

Opções (análise original):
1. **Reordenar a admissão**: checar dedup por hash e min-fee **antes** de
   `validate_transaction`. Barato e elimina o caso de replay. Trade-off: o
   `tx_hash` é suprido pelo chamador; é preciso garantir que o hash usado no dedup
   seja o hash canônico dos bytes (já é, no caminho P2P: `blake2b_256(tx_bytes)`).
   Risco baixo; **mexe na política de admissão da mempool** → confirmar com teste.
2. **Pontuar a rejeição de replay**: fazer o caminho P2P aplicar um pequeno score
   a peers que reenviam tx já conhecidas (distinto de "already in mempool" legítimo
   de corrida). Trade-off: replays honestos por corrida de gossip podem gerar
   falso-positivo; precisa de janela/threshold.
3. **Cache de tx-hash recentemente rejeitadas/conhecidas** no caminho P2P, antes
   de desserializar/validar. Mais robusto, custo de memória bounded.
**Recomendação:** opção 1 + 3. Ambas são robustez (não alteram consenso/economia),
mas como tocam a política de admissão, marco para sua decisão e validação por
teste antes de aplicar.

### Testes faltantes (após patch)
- Replay de tx válida é rejeitado **antes** de qualquer verificação de Bulletproof
  (medir que o custo cai para ~O(lookup)).
- Caminho P2P: N replays de um peer levam a score/ban dentro de um limite.

---

## 7. Achado FABLE5-002 (defesa em profundidade)

**Título:** Side-chain block persistido antes da validação contextual de inputs.
**Severidade:** Baixa. **Status:** Confirmado por leitura; **intencional e bounded**.
**Arquivo:** `dom-chain/src/chain_state.rs:347-372`.

`connect_block`, no ramo não-extensão-direta, chama `store_known_block` **após**
`validate_block` (PoW, crypto, balanço, range proofs, assinaturas, cut-through,
peso) mas **antes** de checar existência/maturity de inputs contra a UTXO da
branch — isso só ocorre na promoção (`promote_heavier_known_tip`/`apply_connect`),
que falha fechada. O custo de poluição de storage é contido por:
(a) cada bloco exige **PoW válido** (caro para o atacante);
(b) `prune_retained_side_chains` (tips e comprimento bounded).
Não há aceitação de bloco inválido. **Sem ação obrigatória pré-testnet**; vale um
teste de "storm de side-chain inválida não retém known-block além do cap" e,
opcionalmente, custo por-peer.

---

## 8. O que NÃO consegui testar (e por quê)
- **DoS de rede end-to-end real** (flood multi-peer com sockets reais): exigiria
  harness de integração de carga; aqui validei o comportamento na fronteira da
  mempool/parsers por teste unitário e leitura.
- **Custo de CPU absoluto do replay** (medição de tempo): evitei asserção por
  tempo para não introduzir teste flaky (proibido pelo princípio de integridade).
  A ordem foi provada de forma **determinística** (erro de assinatura vs.
  duplicata), que é mais forte que timing.
- **Promoção de side-chain inválida sob storage real** (FABLE5-002): provei por
  leitura o ponto de persistência; o caminho de promoção que falha fechada já é
  coberto pela suíte existente de reorg, mas não escrevi um teste novo de retenção
  bounded sob storm.
- **RandomX/LMDB sob pressão de disco**: a suíte rodou verde nesta sessão; não
  forcei condições de disco cheio.

## 9. Limitações de método
- A auditoria original foi **read-only** em produção; FABLE5-001 ficou marcado
  "PRECISA PATCH PARA CONFIRMAR". Em sessão posterior (autorizada a tocar `src/`)
  o fix foi **implementado e validado por teste** — ver §11.
- Mapeamento amplo das três fases foi feito com agentes de exploração e depois
  **reverificado no código** nos pontos críticos (genesis changeset, ordem de
  validação da mempool, codec Noise, schnorr verify, coinbase bp_verify). Onde cito
  linha, confirmei na fonte.
- Decisões de mérito (cerimônia de genesis hash; alterar política de admissão da
  mempool) estão marcadas **PRECISA DECISÃO HUMANA** e não foram tomadas.

---

## 10. Arquivos criados na auditoria original
- `crates/dom-mempool/tests/robustness_admission_ordering.rs` (testes de ordering)
- `audit/FABLE5_SECURITY_AUDIT.md` (este relatório)

---

## 11. FABLE5-001 — Resolução (2026-06-10)

A correção foi implementada e validada por teste. O escopo foi decidido pelo
**resultado do PASSO 1** (prova no caminho P2P real), não o contrário.

### PASSO 1 — Prova no caminho P2P REAL (antes de qualquer fix)
**Pergunta:** quando um peer reenvia os mesmos bytes de uma tx, o replay chega a
`validate_transaction` (Bulletproof+Schnorr) ou é cortado antes por uma camada de
inventory/gossip/dedup?

**Achado de arquitetura (código real):** o handler `Command::Tx`
(`dom-node/src/node.rs:3865`) chama `accept_tx_with_chain_view` **sem** nenhuma
consulta de inventory/cache antes. Não existe handler de `Command::Inv` (cai no
catch-all `other => ignoring`, `node.rs:4015`); o relay de tx é **push direto** de
`Command::Tx` (Dandelion fluff/stem). Ou seja, **não há camada de dedup antes da
validação** — a hipótese da revisão (de que o inventory poderia cortar o replay) é
**refutada** pelo código.

**Prova executável (determinística, não-timing):** teste novo
`crates/dom-integration-tests/tests/robustness_tx_replay_p2p.rs`
→ `robustness_p2p_tx_replay_reaches_crypto_each_time`. Sobe um node real, conecta um
peer via Noise+Hello, e reenvia 3× a MESMA tx com **range proof válido + assinatura
Schnorr corrompida** (garante que o `bp_verify` caro roda antes da rejeição por
assinatura). Observável: o ban score do peer, lido via
`PeerManager::ban_score(addr)`. Se cada replay chega à crypto, o score sobe
`PROTOCOL_VIOLATION (10)` por envio; se houvesse dedup pré-validação, estagnaria
em 10.

```
$ cargo test -p dom-integration-tests --test robustness_tx_replay_p2p -- --nocapture
PASSO 1 RESULT: replay reaches crypto on the real P2P path. ban score after 3
identical replays = 30 (= 3 × 10). No pre-validation inventory/dedup exists.
test robustness_p2p_tx_replay_reaches_crypto_each_time ... ok
```

**Conclusão PASSO 1:** o replay **PASSA até a crypto** no caminho P2P real. Isso
(a) confirma que FABLE5-001 era real no caminho real e (b) habilita o PASSO 3.

### PASSO 2 — Reordenação dos gates de admissão (higiene)
`Mempool::accept_tx_with_chain_view` agora chama
`precheck_cheap_admission_gates(&tx, &tx_hash)` **antes** de `validate_transaction`
(`dom-mempool/src/lib.rs`). Os gates hoisted são estruturais (sem crypto): dedup por
hash, min-relay-fee e teto de peso — com as **mesmas mensagens de erro** de
`accept_validated_tx` (que permanece como rede de segurança e para o caminho legado
`accept_tx`). Uma tx duplicada/abaixo-do-piso é agora rejeitada **sem pagar
Bulletproof/Schnorr**.

**Sem mudança de veredito:** os gates não dependem de validade criptográfica, logo
detectá-los mais cedo não muda o resultado binário aceita/rejeita — só a (mais
barata) razão. Provado por testes em
`crates/dom-mempool/tests/robustness_admission_ordering.rs` (reescrito para o estado
corrigido):
- `robustness_duplicate_check_runs_before_crypto` — dup-hash com assinatura quebrada
  agora é rejeitada como "already in mempool" (dedup antes da crypto).
- `robustness_min_fee_gate_runs_before_crypto` — tx abaixo do piso **com** assinatura
  inválida é rejeitada pela **fee** (min-fee antes da crypto).
- `robustness_new_invalid_tx_still_rejected_by_crypto` — tx NOVA, acima do piso,
  não-dup, com crypto inválida **continua** rejeitada por crypto (`Invalid`) →
  invalid real permanece criptograficamente rejeitada e peer-scoreável.
- `robustness_valid_new_tx_still_accepted` — tx válida nova **continua aceita**.

### PASSO 3 — Short-circuit de replay no caminho P2P (DECISÃO TÉCNICA)
Como o PASSO 1 provou que o replay passa até a crypto, o cache é justificado. Após o
PASSO 2 restava um caminho residual **não-pontuado**: um replay de tx **já no
mempool** ainda fazia, no handler, `deserialize → chain.lock() → snapshot de UTXO`
**antes** do dedup barato da mempool — i.e. contenção do `chain` lock sob flood de
replays válidos.

**Decisão (delegada ao agente):** em vez de uma estrutura de cache nova e separada
(mais superfície + risco de *orphan-starvation* se cacheasse hashes ainda-não-válidos
+ regressão de scoring se cacheasse inválidas), o handler `Command::Tx` agora faz um
**pré-check de pertinência à mempool** (`Mempool::contains`) **antes** do chain lock.
Justificativa:
- Reusa o conjunto de entradas da mempool — **já bounded** por `max_weight` — em vez
  de introduzir um LRU/anel paralelo (menos código morto, menos superfície de bug).
- **Seguro:** só faz short-circuit de tx que estão **comprovadamente** no pool
  (duplicatas certas); nunca afama um orphan (que nunca está no pool).
- **Preserva o scoring:** tx inválidas/desconhecidas **não** estão no pool → seguem
  para validação completa e peer-scoring (banimento de spam preservado). Por isso o
  teste do PASSO 1 (tx inválida) continua válido: score chega a 30.
- Observável por métrica nova `suppressed_duplicate_tx_relays` (espelha o padrão
  existente `suppressed_duplicate_block_relays`).

**Prova executável:** `robustness_p2p_known_tx_replay_is_short_circuited_before_validation`
semeia o mempool do node com uma tx (sob o hash canônico que o handler computa),
reenvia-a pelo fio e verifica que `suppressed_duplicate_tx_relays` incrementa
(replay cortado antes da validação) e que o peer **não** é pontuado (duplicata não é
violação).

```
test robustness_p2p_known_tx_replay_is_short_circuited_before_validation ... ok
test robustness_p2p_tx_replay_reaches_crypto_each_time ... ok
test result: ok. 2 passed; 0 failed; ...
```

**Residual aceito e documentado:** replays de tx **abaixo-do-piso** (que nunca entram
no mempool) ainda incorrem em `chain.lock()` + lookups de UTXO por envio (sem crypto,
graças ao PASSO 2). Custo ~O(lookup), ordens de magnitude abaixo do `bp_verify`
original; não justifica cachear hashes rejeitadas (que arriscaria scoring/orphan).

### Verificação final
- `cargo build --workspace`: **OK**.
- `cargo test --workspace`: **1180 passed, 0 failed**.
- `cargo clippy` nos crates tocados (`-D warnings`): **limpo**.
- `cargo fmt --check`: **OK**.
- Nenhuma tx muda de veredito aceita↔rejeita (testes de verdict-preservation acima).

### Arquivos tocados na resolução
- `crates/dom-mempool/src/lib.rs` — `precheck_cheap_admission_gates`, `contains`.
- `crates/dom-node/src/node.rs` — short-circuit de replay no handler `Command::Tx`.
- `crates/dom-node/src/metrics.rs` — métrica `suppressed_duplicate_tx_relays`.
- `crates/dom-mempool/tests/robustness_admission_ordering.rs` — reescrito p/ estado
  corrigido (5 testes, incl. verdict-preservation).
- `crates/dom-integration-tests/tests/robustness_tx_replay_p2p.rs` — novo (PASSO 1 +
  PASSO 3).

Decisões de mérito remanescentes inalteradas: cerimônia de `GENESIS_HASH_*` antes de
mainnet (**PRECISA DECISÃO HUMANA**).
