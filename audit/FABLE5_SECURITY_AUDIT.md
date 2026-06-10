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
| **Testnet pública** | ⚠️ **Pronto com ressalva** | Aceitável; recomenda-se tratar FABLE5-001 ( amplificação de CPU por replay de tx válida, não-banível) antes de expor a peers não confiáveis em escala. |
| **Mainnet** | ⛔ **Ainda não** | Pré-requisito operacional fora do escopo deste agente: as constantes `GENESIS_HASH_{MAINNET,TESTNET,REGTEST}` ainda são placeholders pré-launch (ver `miner.rs:525-532`) — **PRECISA DECISÃO HUMANA** (cerimônia de genesis). Além de soak/observação em testnet. |

---

## 2. Tabela de achados

| ID | Sev. | Título | Arquivo:linha | Status |
|---|---|---|---|---|
| FABLE5-001 | Média | Validação criptográfica completa roda **antes** dos gates baratos (dedup/min-fee/chain-view); replay de tx válida é re-verificado por completo e a rejeição duplicada **não** pontua o peer | `dom-mempool/src/lib.rs:211-292`; `dom-consensus/src/lib.rs:81-116`; `dom-node/src/node.rs:1712-1731` | **Confirmado por teste** |
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

### Correção (com trade-offs) — **PRECISA PATCH PARA CONFIRMAR**
Como a regra desta auditoria proíbe tocar em `src/`, deixo o fix para decisão.
Opções:
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
- Trabalho **read-only** em produção: achados cuja confirmação exigiria patch
  estão marcados "PRECISA PATCH PARA CONFIRMAR" (FABLE5-001 correção) — o **achado**
  em si está confirmado por teste; o **fix** não foi aplicado.
- Mapeamento amplo das três fases foi feito com agentes de exploração e depois
  **reverificado no código** nos pontos críticos (genesis changeset, ordem de
  validação da mempool, codec Noise, schnorr verify, coinbase bp_verify). Onde cito
  linha, confirmei na fonte.
- Decisões de mérito (cerimônia de genesis hash; alterar política de admissão da
  mempool) estão marcadas **PRECISA DECISÃO HUMANA** e não foram tomadas.

---

## 10. Arquivos criados nesta auditoria
- `crates/dom-mempool/tests/robustness_admission_ordering.rs` (novo; 3 testes verdes)
- `audit/FABLE5_SECURITY_AUDIT.md` (este relatório)

Nenhum arquivo de `src/`, `Cargo.toml`, `deploy/`, `scripts/` ou teste existente
foi modificado. Nenhum commit/push realizado.
