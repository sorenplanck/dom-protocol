# REMOTE SCAN V3 — Schema do endpoint `/chain/scan/full` e superfície de trait remota

Data: 2026-07-28. Base: wallet V3 em `redesign/restore-remote-scan`; node upstream
`sorenplanck/dom-protocol` na revisão imutável
`387b744474d2414f9d2d0e542bc654096ce2f8ed`
(`feat/chain-scan-full`).

Escopo: (1) inventário completo do trait `WalletCoreApi` com matriz de chamadores;
(2) montagem node-side de `ScanBlock` que o endpoint novo deve reusar; (3) schema
JSON de `GET /chain/scan/full`; (4) mapeamento de erros remotos → `WalletCoreError`.

---

## 1. Trait `WalletCoreApi` (dom-wallet-core-api/src/lib.rs:625-733) — inventário e matriz de chamadores

Legenda dos chamadores no wallet V3:
- **SYNC** = `CoreChainAdapter` (`crates/dom-wallet-core-sync/src/lib.rs`)
- **RESTORE** = `SeedRestoreService` (`crates/dom-wallet-core-restore/src/lib.rs`) — **não chama
  `WalletCoreApi` diretamente**: consome exclusivamente `CoreChainAdapter`
  (`dom_wallet_core_sync::{CoreChainAdapter, CoreScanBlock, ...}`), portanto herda a
  superfície de SYNC.
- **SUBMIT** = `CoreSubmissionService` (`crates/dom-wallet-core-submit/src/lib.rs` — nota: mora
  em `dom-wallet-core-submit`, não em `dom-wallet-core-protocol`)
- **FEE** = `CoreFeePolicyService` (`crates/dom-wallet-core-protocol/src/lib.rs`)
- **LIFECYCLE** = readiness do embedded core (`crates/dom-wallet-embedded-core/src/lib.rs:477,486`)

| # | Método (assinatura) | SYNC | RESTORE (via SYNC) | SUBMIT | FEE | LIFECYCLE | Remoto precisa? |
|---|---|---|---|---|---|---|---|
| 1 | `fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError>` | ✔ (`connect`, `current_identity` a cada página) | ✔ | ✔ (`require_same_chain` em toda op) | ✔ (`require_same_chain`) | — | **SIM** — `GET /chain/identity` (novo) |
| 2 | `fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError>` | ✔ (`scan_from_height`) | ✔ | — | — | — | **SIM** — `GET /chain/scan/full` |
| 3 | `fn scan_next(&self, cursor: WalletScanCursor, limit: u64) -> Result<ScanResult, WalletCoreError>` (default = delega em `scan_range` com `ScanStart::Cursor`) | ✔ (`scan_next`) | ✔ | — | — | — | **SIM** — default do trait sobre o item 2 |
| 4 | `fn validate_cursor(&self, cursor: WalletScanCursor) -> Result<CursorValidation, WalletCoreError>` | ✔ (antes de toda página e no reorg walk) | ✔ | — | — | — | **SIM** — client-side via `GET /block/:height` (público) |
| 5 | `fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8;32]>, WalletCoreError>` | ✔ (reorg walk, verificação de tip/gênese) | ✔ | — | — | — | **SIM** — `GET /block/:height` (público) |
| 6 | `fn get_utxo(&self, commitment: &[u8;33]) -> Result<Option<UtxoQueryResult>, WalletCoreError>` | — | — | — | — | — | não (nenhum call site no wallet) |
| 7 | `fn get_kernel(&self, excess: &[u8;33]) -> Result<Option<KernelQueryResult>, WalletCoreError>` | — | — | — | — | — | não (só usado internamente pelo node) |
| 8 | `fn get_block_summary(&self, selector: BlockSelector) -> Result<Option<BlockSummary>, WalletCoreError>` | — | — | — | — | — | não |
| 9 | `fn transaction_status(&self, id: TransactionIdentifier) -> Result<TransactionStatus, WalletCoreError>` | — | — | ✔ | — | — | não (spend fica no embedded) |
| 10 | `fn submit_transaction(&self, request: SubmitTransactionRequest) -> Result<SubmissionResult, WalletCoreError>` | — | — | ✔ | — | — | não |
| 11 | `fn rebroadcast_transaction(&self, id: TransactionIdentifier) -> Result<SubmissionResult, WalletCoreError>` | — | — | ✔ | — | — | não |
| 12 | `fn query_submission(&self, id: TransactionIdentifier) -> Result<SubmissionResult, WalletCoreError>` | — | — | ✔ | — | — | não |
| 13 | `fn sync_status(&self) -> Result<SyncStatus, WalletCoreError>` | — | — | ✔ (`readiness`) | — | ✔ | **derivável** (ver §5) |
| 14 | `fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError>` | — | — | ✔ (`readiness`) | — | ✔ | **derivável** (ver §5) |
| 15 | `fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError>` | — | — | ✔ (`readiness`) | — | — | não |
| 16 | `fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError>` | — | — | — | ✔ (via default `fee_policy`) | — | não |
| 17 | `fn fee_policy(&self) -> Result<FeePolicySnapshot, WalletCoreError>` (default → 16) | — | — | — | ✔ (`policy`) | — | não |
| 18 | `fn transaction_weight(&self, shape: TransactionShape) -> Result<TransactionWeight, WalletCoreError>` | — | — | — | ✔ | — | não |
| 19 | `fn minimum_fee(&self, shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError>` | — | — | — | ✔ | — | não |
| 20 | `fn estimate_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError>` | — | — | — | ✔ | — | não |
| 21 | `fn validate_fee(&self, transaction: &Transaction) -> Result<FeeValidation, WalletCoreError>` | — | — | — | ✔ | — | não |
| 22 | `fn recommended_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError>` (default → 20) | — | — | — | ✔ | — | não |

Superfície mínima que uma fonte remota tem de servir DE VERDADE (restore + sync):
**{1, 2, 3-default, 4, 5}** + readiness derivada {13, 14}. Os demais métodos devem
retornar erro tipado estável (ver §5) e a composição do app NUNCA deve ligar
`CoreSubmissionService`/`CoreFeePolicyService` numa fonte remota (spend continua no
node embedded — proibição do usuário: não quebrar o modo embedded).

### Tipos de dados relevantes (mesmo arquivo)
- `ScanRequest { network, chain_id, start: ScanStart{Height|Cursor}, max_blocks, stop_height, commitment_filters }`
  — **`commitment_filters` DEVE ser vazio no caminho remoto** (privacidade: baixar todos os
  blocos da faixa; scan seletivo é proibido). A impl remota rejeita filtro não-vazio com
  `InvalidScanRequest` ANTES de qualquer chamada de rede.
- `ScanResult { tip: BlockRef, blocks: Vec<ScanBlock>, continuation: Option<WalletScanCursor> }`
- `ScanBlock { height, block_hash, previous_block_hash, timestamp, canonical_marker, outputs, inputs, kernels, coinbase, total_fees_noms, protocol_version, range_proof_serialization_version }`
- `ScanOutput { commitment[33], range_proof: Vec<u8>, recovery_capsule: Vec<u8>, recovery_version: u16, is_coinbase, block_height, block_hash, output_position }`
- `ScanInput { spent_commitment[33] }`, `ScanKernel { excess[33], features, fee, lock_height }`,
  `CoinbaseScanMetadata { output_commitment[33], explicit_value, kernel_excess[33] }`
- `WalletScanCursor` v1: 86 bytes LE `{version:u16, network_magic:u32, chain_id[32], next_height:u64, anchor_height:u64, anchor_hash[32]}`, invariante `next_height == anchor_height + 1`.

---

## 2. Montagem node-side que o endpoint novo DEVE reusar

Há DUAS projeções de bloco no node — não confundir:

1. **V2 (insuficiente)**: `dom-node/src/wallet_scan.rs::scan_block_at` monta o
   `dom_wallet::ScanBlock` legado (só `output_commitments`, `input_commitments`,
   `total_fees_noms`). É o que alimenta o `/chain/scan` atual via
   `node_handle.rs::scan_chain` (linhas 399-440). Sem capsule/proof → inutilizável para
   o restore V3 por recovery capsule.

2. **V3 (a reusar)**: `dom-node/src/wallet_core_api.rs::EmbeddedWalletCoreApi`
   - `scan_range` (linha 476): `try_lock` no chain → `NodeNotReady("chain lock busy")`;
     identidade via `current_identity_locked`; `stop_height = min(request.stop_height|tip, tip)`;
     `to = min(start + max_blocks - 1, stop_height)`; itera `load_canonical_block_locked`
     (hash em `store.get_hash_at_height`, corpo em `store.get_block_body`,
     `Block::from_bytes`); gap ⇒ `CanonicalGap` (exceção: chain vazio no genesis ⇒ página vazia).
   - `project_block` (linha 306): coinbase primeiro (`block.coinbase.output` — fora de
     `transactions`!), depois outputs de cada tx, com `range_proof_bytes()`,
     `recovery_capsule()` (versão 0 + bytes vazios quando ausente), `output_position`
     incrementando MESMO para outputs filtrados; inputs achatados; kernels = kernel de
     coinbase (fee 0, lock 0) + kernels das txs; `canonical_marker = block_hash`;
     `protocol_version = block.header.version`;
     `range_proof_serialization_version` vindo da identidade.

**Decisão de design**: o handler do endpoint novo (em `dom-rpc` + `node_handle.rs`, no
upstream) deve chamar exatamente `load_canonical_block_locked` + `project_block` (extraídos/
reexportados de `wallet_core_api.rs`) com `filters = None`, para que embedded e remoto nunca
divirjam byte a byte. Alternativa equivalente: construir um `EmbeddedWalletCoreApi` e chamar
`scan_range` com `commitment_filters: vec![]` — mesma garantia, e ganha de graça o clamp e a
regra de ouro do `try_lock`.

---

## 3. Endpoint novo: `GET /chain/scan/full`

### Requisição
```
GET /chain/scan/full?from=<u64>&to=<u64>
Authorization: Bearer <token>      (mesma middleware require_bearer_token do /chain/scan)
Accept-Encoding: gzip              (recomendado; ver dimensionamento)
```
- **Sem parâmetro de filtro de commitment** — o servidor sempre devolve TODOS os outputs
  de TODOS os blocos da faixa (requisito de privacidade).
- Regras idênticas ao `/chain/scan` atual (dom-rpc/src/lib.rs, node_handle.rs:399):
  - `to_efetivo = min(to, tip, from + MAX_SCAN_RANGE - 1)` com `MAX_SCAN_RANGE = 1000`;
  - regra de ouro: `chain.try_lock()`; ocupado ⇒ `503` retriável imediato (nunca bloquear;
    mineração/conexão de bloco tem prioridade);
  - `from > to_efetivo` ⇒ `200` com `blocks: []` (não é erro);
  - altura canônica com corpo ausente dentro da faixa ⇒ `500` com `code: "canonical_gap"`
    (diferente do V2, que silenciosamente omitia o bloco — o V3 exige continuidade).

### Resposta `200 OK` (`application/json`)
Convenções de encoding: campos de 32/33 bytes com identidade (hashes, commitments,
excess) em **hex minúsculo** (consistente com `/chain/scan` e `/block/:height` atuais);
blobs grandes (`range_proof` ~700 B, `recovery_capsule` ~835 B) em **base64 padrão com
padding** (RFC 4648) — ~33% menor que hex num payload dominado por esses dois campos.

```jsonc
{
  "schema_version": 1,                      // versão deste contrato de wire
  "identity": {                             // espelha ChainIdentity (menos o tip, que vai abaixo)
    "network": "mainnet",                   // "mainnet" | "testnet" | "regtest" (CoreNetwork::as_str)
    "network_magic": 4276993775,            // u32
    "chain_id": "<hex 64>",
    "genesis_hash": "<hex 64>",
    "protocol_version": 1,                  // u32 (PROTOCOL_VERSION do node)
    "range_proof_serialization_version": 1, // u8
    "coinbase_maturity": 1440               // u64
  },
  "tip":  { "height": 123456, "hash": "<hex 64>" },
  "from": 1000,                             // eco do request
  "to":   1999,                             // to_efetivo após clamp
  "blocks": [
    {
      "height": 1000,
      "block_hash": "<hex 64>",
      "previous_block_hash": "<hex 64>",
      "timestamp": 1753660800,              // u64, segundos
      "canonical_marker": "<hex 64>",       // hoje == block_hash; carregar mesmo assim (futuro-proof)
      "protocol_version": 1,                // u32 = block.header.version (por bloco, não o global)
      "range_proof_serialization_version": 1,
      "total_fees_noms": 42,
      "coinbase": {
        "output_commitment": "<hex 66>",
        "explicit_value": 5000000000,       // u64 noms
        "kernel_excess": "<hex 66>"
      },
      "outputs": [
        {
          "commitment": "<hex 66>",
          "range_proof": "<base64 ~936 chars>",
          "recovery_capsule": "<base64 ~1116 chars>",  // "" quando ausente (legado)
          "recovery_version": 1,            // u16; 0 quando recovery_capsule == ""
          "is_coinbase": true,
          "output_position": 0              // u32, posição canônica no bloco
        }
      ],
      "inputs": [ "<hex 66>", ... ],        // spent_commitments achatados (ScanInput é 1 campo)
      "kernels": [
        { "excess": "<hex 66>", "features": 0, "fee": 0, "lock_height": 0 }
      ]
    }
  ]
}
```

Omissões deliberadas no wire (reconstruídas pelo cliente ao montar `ScanOutput`):
- `ScanOutput.block_height` e `ScanOutput.block_hash` são redundantes com o bloco
  envolvente — o cliente preenche com `block.height`/`block.block_hash`. Economiza
  ~100 bytes/output num payload que já é grande.

Invariantes que o CLIENTE deve validar por página (schema inválida ⇒ erro terminal, §4):
- hex/base64 decodificáveis e comprimentos exatos (32/33 bytes; capsule vazia ⇔ `recovery_version == 0`);
- `blocks` ordenados por altura consecutiva `from..=to`, `previous_block_hash` encadeando
  (primeiro bloco ancora no cursor/anchor local);
- `identity.network_magic`/`chain_id` idênticos à identidade persistida
  (`validate_same_chain` de `CoreChainAdapter` já cobre isso ao mapear para `ChainIdentity`);
- `to <= tip.height` e `to - from + 1 <= 1000`;
- `coinbase.output_commitment` presente em `outputs[0]` com `is_coinbase: true`.

### Dimensionamento e paginação
Por output: proof ~700 B (base64 ~936) + capsule ~835 B (base64 ~1116) + commitment/overhead
≈ **~2,2 KB**. Bloco só-coinbase ≈ 2,4 KB; página cheia de 1000 blocos ≥ **~2,4 MB** (mais em
blocos com txs). Recomendações: servidor mantém clamp 1000 (limite de lock-hold), mas o
cliente pagina com seu `maximum_batch_blocks` existente (bem menor) e o handler deve suportar
`gzip` (proofs/capsules comprimem pouco, mas hex/estrutura sim; ganho típico 20-35%).

### Endpoints companheiros (superfície remota completa)
- **`GET /chain/identity`** (novo, Bearer, mesma regra try_lock/503): corpo = objeto
  `identity` acima + `"tip": {height, hash}`. Implementa `chain_identity()` remoto
  (necessário para `connect`/`require_same_chain`; o `/block/:height` público não expõe
  `chain_id`/`genesis_hash`/`coinbase_maturity`/`network_magic`).
- **`GET /block/:height_or_hash`** (já existe, público, retorna header
  `{height, hash, prev_hash, timestamp, target}`): implementa
  `canonical_hash_at_height` (404 ⇒ `Ok(None)`) e a base do `validate_cursor`
  client-side: buscar header em `cursor.anchor_height`; hash ausente ⇒ `CursorReorg`;
  hash ≠ `anchor_hash` ⇒ `CursorReorg`; igual ⇒ `CursorValidation{valid: true,
  safe_rescan_anchor: anchor}` (espelho exato de `validate_cursor_locked`,
  wallet_core_api.rs:240-273).

---

## 4. Mapeamento de erros remotos → `WalletCoreError`

Regra de ouro herdada: **busy NUNCA é terminal** (proibição do usuário). O
`CoreScanError::from_core` do wallet (dom-wallet-core-sync/src/lib.rs:300-336) já colapsa
`NodeNotReady | TemporaryFailure → CoreNotReady` (retriável com backoff) e
`InternalFailure → CoreContract` (terminal). A impl remota escolhe o lado certo assim:

| Condição remota | `WalletCoreError` | Classe |
|---|---|---|
| HTTP 503 (`Overloaded` — chain busy) | `NodeNotReady("remote chain busy")` | retriável (backoff + jitter) |
| HTTP 429 | `TemporaryFailure("remote rate limited")` | retriável |
| Timeout de conexão/leitura, connection refused/reset, erro DNS/TLS transitório | `TemporaryFailure(...)` | retriável |
| HTTP 500 com corpo `{"code":"canonical_gap"}` | `CanonicalGap(...)` | terminal para a página (aciona re-validação de cursor) |
| HTTP 500 sem código estável / 502 / 504 | `TemporaryFailure(...)` | retriável (gateways são transitórios) |
| HTTP 401 / 403 (Bearer inválido/ausente) | `InternalFailure("remote unauthorized")` | **terminal** — configuração errada; nunca re-tentar em loop |
| HTTP 404 na rota `/chain/scan/full` | `InternalFailure("remote node lacks scan/full")` | **terminal** — node antigo; instruir upgrade |
| HTTP 400 (query malformada) | `InvalidScanRequest(...)` | terminal (bug do cliente) |
| JSON inválido, hex/base64 inválido, comprimento errado, `schema_version` desconhecido, invariantes de página violadas (§3) | `InternalFailure("remote schema violation: <code>")` | **terminal** — dado não confiável; nunca "aproveitar parcialmente" a página |
| `identity` da resposta ≠ identidade persistida (magic/chain_id/genesis/versões) | `CursorChainMismatch(...)` | terminal |
| Anchor do cursor não bate em `/block/:height` | `CursorReorg(...)` | tratado pelo reorg walk existente do `CoreChainAdapter` |
| `commitment_filters` não-vazio pedido à fonte remota | `InvalidScanRequest("remote source is full-scan only")` | terminal, sem chamada de rede |

Semântica derivada (métodos 13/14 do trait na fonte remota):
- `sync_status()`: última chamada de identidade OK ⇒ `Ready`; último erro retriável ⇒ `Busy`;
  nunca `Starting/Syncing` (o node remoto que responde já serve chain canônica).
- `is_ready_for_wallet_operations()`: `Ok(true)` sse a última sondagem de
  `/chain/identity` teve sucesso.
- Métodos fora da superfície (6-12, 15-22): `Err(WalletCoreError::NodeNotReady("remote
  source serves scan only"))` com mensagem estável — e o compositor do app não deve
  conectar SUBMIT/FEE a uma fonte remota (guard em tempo de composição, não de chamada).

---

## 5. Resumo das decisões de design

1. **Reuso obrigatório do `project_block`** de `EmbeddedWalletCoreApi` no handler novo —
   uma única projeção V3 no node; `wallet_scan.rs::scan_block_at` (V2) fica intocado para
   o `/chain/scan` legado.
2. **Base64 para proof/capsule, hex para identidades** — payload dominado por dois blobs
   (~1,5 KB/output); base64 poupa ~33% vs hex; hex mantém consistência com endpoints atuais
   para campos comparáveis a olho/log.
3. **Sem filtros no wire** — privacidade primeiro; a impl remota rejeita filtro localmente.
4. **`block_height`/`block_hash` de `ScanOutput` fora do wire** — redundantes, reconstruídos
   do bloco envolvente.
5. **Mesmas regras operacionais do `/chain/scan`** — Bearer, clamp `MAX_SCAN_RANGE=1000`,
   `try_lock`→503 imediato; 503/429/timeout são SEMPRE retriáveis no cliente.
6. **`/chain/identity` novo + `/block/:height` público** completam a superfície remota
   {chain_identity, scan_range, scan_next, validate_cursor, canonical_hash_at_height} sem
   tocar nos caminhos de submissão/fee, que permanecem exclusivos do node embedded.
7. **`schema_version` no topo da resposta** — permite evoluir o wire sem quebrar clientes;
   versão desconhecida é terminal no cliente.
