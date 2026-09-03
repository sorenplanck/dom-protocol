# REMOTE_SCAN_CONTRACT — contrato REAL do RPC do dom-node

Fonte da verdade: `sorenplanck/dom-protocol`, branch
`feat/chain-scan-full`, revisão imutável
`387b744474d2414f9d2d0e542bc654096ce2f8ed`, a mesma pinada pelo
`Cargo.toml` da wallet. Todas as citações são `arquivo:linha` dessa revisão,
extraídas por leitura direta do código — nada foi assumido.

Crates relevantes:

- `crates/dom-rpc/src/lib.rs` — router, handlers e DTOs (serde).
- `crates/dom-rpc/src/middleware.rs` — Bearer auth, rate limit, CORS.
- `crates/dom-rpc/src/token.rs` — origem/formato do token.
- `crates/dom-node/src/node_handle.rs` — implementação real de `scan_chain` (try_lock + clamp).
- `crates/dom-node/src/wallet_scan.rs` — extrator por bloco `scan_block_at`.

---

## 0. Propriedades globais do router (aplicam a TODOS os endpoints)

Router montado em `crates/dom-rpc/src/lib.rs:329-378` (`pub fn router`):

- **Body limit**: `RequestBodyLimitLayer::new(1_024_000)` — corpo de request
  limitado a 1.024.000 bytes (~1 MB) (`lib.rs:330`).
- **Timeout**: `TimeoutLayer::new(Duration::from_secs(30))` — 30 s por request
  (`lib.rs:331`). Estourou → resposta de timeout do tower-http (408), sem corpo JSON do app.
- **CORS**: middleware global adiciona `Access-Control-Allow-Origin: *`,
  `Allow-Methods: GET, POST, OPTIONS`, `Allow-Headers: content-type, authorization`
  (`middleware.rs:112-128`).
- **Grupos de rotas** (`lib.rs:338-373`):
  - Públicas com rate limit de leitura: `/status`, `/mempool`, `/tx/:tx_hash`,
    `/block/:height_or_hash`, `/utxo/:commitment` (`lib.rs:338-344`).
  - `/health` é pública e SEM rate limit (montada fora dos grupos, `lib.rs:370`).
  - `POST /tx/submit` pública com rate limit de submit (`lib.rs:346-348`).
  - Autenticadas (Bearer): `/wallet/balance`, `/chain/scan`, `/build-info`,
    `POST /shutdown` (com rate limit de leitura, `lib.rs:350-355`), `/peers` e
    `POST /wallet/spend` (`lib.rs:357-367`).
- **Erros tipados** (`RpcError`, `lib.rs:180-203`): mapeamento de status em
  `status_code()` (`lib.rs:195-202`):
  - `InvalidHex` / `InvalidTx` → **400**
  - `Rejected` → **409**
  - `Overloaded` → **503**
  - `Internal` → **500**
  Corpo do erro (`IntoResponse`, `lib.rs:210-221`): `{"error": "<Display do erro>"}`
  onde Display inclui o prefixo do thiserror, ex. `"overloaded: chain busy; retry"`,
  `"internal: chain scan not supported"` (formatos em `lib.rs:182-191`; pinado em
  teste `lib.rs:1919-1925`).

### Rate limits (`middleware.rs`)

- Leitura: `rate_limit_read()` — burst padrão **100 req**, refill 1/s
  (`per_second(1).burst_size(limit)`), configurável via env `DOM_RPC_RATELIMIT_READ`
  (`middleware.rs:71-87`). Chave por IP (`SmartIpKeyExtractor`, `middleware.rs:18,34`).
- Submit: `rate_limit_submit()` — burst padrão **10 req**, refill 1/s, env
  `DOM_RPC_RATELIMIT_SUBMIT` (`middleware.rs:27-43`).
- **Status quando excedido: 429 Too Many Requests**, corpo TEXTO (não JSON):
  `"Too Many Requests! Wait for {wait_time}s"` — comportamento do
  `tower_governor 0.4.3` (`~/.cargo/registry/src/.../tower_governor-0.4.3/src/errors.rs:30-37`;
  dependência declarada em `crates/dom-rpc/Cargo.toml:23`).
- Cada grupo de rota tem sua PRÓPRIA instância de layer (`lib.rs:333-336`), i.e.
  o orçamento das rotas públicas de leitura é separado do das rotas autenticadas
  de leitura — `/chain/scan` não compete com `/status`.
- Observação: `SmartIpKeyExtractor` exige `ConnectInfo<SocketAddr>`; sem ele toda
  rota rate-limitada devolve **500 "Unable To Extract Key!"** (comentário em
  `lib.rs:470-475`; erro em `tower_governor-0.4.3/src/errors.rs:38-44`).

### Autenticação Bearer

- Middleware `require_bearer_token` (`middleware.rs:139-173`):
  - Token configurado vazio → **401** sempre (`middleware.rs:144-146`).
  - Header ausente, esquema diferente de `Bearer ` (case-SENSITIVE, é
    `starts_with("Bearer ")` — `"bearer x"` minúsculo é rejeitado; teste
    `lib.rs:1713-1726`), valor vazio, ou token errado → **401** (não existe 403
    na autenticação; o único 403 do serviço é o `/shutdown` de peer não-loopback,
    `lib.rs:397-400`). Corpo do 401 é vazio (o middleware retorna `StatusCode` puro).
  - Comparação em tempo constante via `subtle::ConstantTimeEq`
    (`middleware.rs:165`).
- **Origem do token no node** (`token.rs`), precedência
  (`get_or_create_token_with_config`, `token.rs:19-31` + `get_or_create_token`,
  `token.rs:39-73`):
  1. Token explícito da config do node (caminho usado por embedders via
     `serve_with_token`, `lib.rs:440-446`);
  2. Env `DOM_RPC_TOKEN`;
  3. Arquivo `~/.dom/rpc_token` (`token_file_path`, `token.rs:79-88`);
  4. Gera novo: **32 bytes aleatórios em hex = 64 chars** (`generate_token`,
     `token.rs:7-10`) e salva em `~/.dom/rpc_token` com modo `0600` + newline
     final (`save_token_at`, `token.rs:97-124`). Cliente deve fazer `trim()` ao
     ler o arquivo (o node grava `"{token}\n"`, `token.rs:116`; e lê com `trim()`,
     `token.rs:53`).
- Header a enviar: `Authorization: Bearer <token>`.

---

## 1. GET /chain/scan?from=<u64>&to=<u64>  (AUTENTICADO)

Rota: `lib.rs:352`. Handler: `chain_scan_handler` (`lib.rs:765-795`).
Query obrigatória: `ScanQuery { from: u64, to: u64 }` (`lib.rs:732-736`) — ambos
obrigatórios; ausência/parse inválido gera rejeição de extractor do axum (400,
corpo texto do axum, não JSON do app).

### 1.1 Shape da resposta 200 (serde exato)

Structs: `ChainScanResponse` (`lib.rs:753-759`), `TipDto` (`lib.rs:738-742`),
`ScanBlockDto` (`lib.rs:744-751`). Sem renames serde — nomes de campo = nomes JSON.

```json
{
  "tip": {
    "height": 20500,
    "hash": "c2c2…c2"        // hex lowercase, 64 chars (32 bytes)
  },
  "from": 20000,               // eco do request (lib.rs:787, node_handle.rs:437)
  "to": 20499,                 // CLAMPADO (ver 1.2) — nunca o `to` pedido às cegas
  "blocks": [
    {
      "height": 20000,
      "hash": "1111…11",      // hex lowercase, 64 chars
      "output_commitments": [  // hex lowercase, 66 chars cada (33 bytes)
        "a1a1…a1"
      ],
      "input_commitments": [   // hex lowercase, 66 chars cada (33 bytes)
      ],
      "fees": 7                // u64, total de fees do bloco em noms
    }
  ]
}
```

- Encoding: `hex::encode` em tudo (`lib.rs:776-778,785`) — hex minúsculo, sem prefixo `0x`.
- Alturas SEM bloco na faixa são **omitidas** de `blocks` (doc `lib.rs:119`;
  `scan_block_at` retorna `None` para gap/pruned, `wallet_scan.rs:65-70`,
  e o loop só faz push no `Some`, `node_handle.rs:417-429`).
- Ordem de `blocks`: altura crescente (loop `for height in from..=effective_to`,
  `node_handle.rs:417`).
- `output_commitments` inclui o coinbase PRIMEIRO, depois os outputs de cada tx;
  `input_commitments` são os commitments gastos (`wallet_scan.rs:87-99`).
  Genesis mainnet (height 0) é projetado com listas vazias e fees 0
  (`wallet_scan.rs:73-81`).
- Caso-borda: se o corpo do bloco existir sem hash conhecido, `hash` sai como
  64 zeros (`sb.block_hash.unwrap_or([0u8; 32])`, `node_handle.rs:423`) — na
  prática `scan_block_at` sempre preenche `Some(hash)`.

**LIMITAÇÃO CONFIRMADA para o restore V3**: `ScanBlockDto` só carrega
`height/hash/output_commitments/input_commitments/fees` (`lib.rs:744-751`) —
NÃO há `range_proof`, `recovery_capsule`, `recovery_version`, `is_coinbase` por
output, nem `output_position`. Insuficiente para `dom-wallet-core-api::ScanOutput`;
o endpoint precisará ser estendido upstream (ou um novo criado) para o scan remoto V3.

### 1.2 Semântica do clamp

`scan_to_clamped(from, to, tip)` (`node_handle.rs:447-450`):

```rust
let cap = from.saturating_add(MAX_SCAN_RANGE - 1);   // MAX_SCAN_RANGE = 1000 (lib.rs:80)
to.min(tip).min(cap)                                  // = min(to, tip, from + 999)
```

- `to` efetivo = `min(to_pedido, tip, from + 999)` — máx. 1000 alturas por chamada.
- `from > to` ou `from > tip` → resultado `< from` → faixa vazia: `blocks: []`,
  mas a resposta ainda carrega o `tip` (doc `node_handle.rs:444-446`; guard
  `if from <= effective_to`, `node_handle.rs:416`; teste `lib.rs:1632-1648`;
  atenção: nesse caso `to` na resposta pode ser `< from`, incluindo
  `to = min(to_pedido, tip)` — não compare `to >= from` sem checar).
- Paginação do cliente: continuar de `to + 1` até `to == tip.height`
  (doc `lib.rs:107-110`).

### 1.3 Erros

- **401** sem/errado Bearer (teste `lib.rs:1561-1585`).
- **503** `{"error":"overloaded: chain busy; retry"}` — regra de ouro: o node usa
  `chain.try_lock()`; se a chain está ocupada (mineração/conexão de bloco) responde
  imediatamente `RpcError::Overloaded` (`node_handle.rs:399-407`; status em
  `lib.rs:199`). **Retriável — nunca tratar como erro terminal.**
- **500** `{"error":"internal: chain scan not supported"}` — node sem suporte a
  scan (default do trait, `lib.rs:62-64`; teste `lib.rs:1616-1630`). Também 500
  para falha de leitura do store (`node_handle.rs:419`).
- **429** texto `"Too Many Requests! Wait for Ns"` — rate limit de leitura
  autenticada (100 burst/1 rps por IP; seção 0).
- **400** do axum se `from`/`to` faltarem ou não parsearem como u64.

---

## 2. GET /block/:height_or_hash  (PÚBLICO)

Rota: `lib.rs:342`. Handler: `get_block` (`lib.rs:614-661`).

Dispatch do path param (`lib.rs:618-635`): só dígitos ASCII → tratado como altura
(`u64::parse`); qualquer outra coisa → tratado como hash hex de 32 bytes
(`parse_hash_hex`, `lib.rs:714-718`).

### 2.1 200 — `BlockHeaderResponse` (`lib.rs:297-304`, montagem `lib.rs:643-653`)

```json
{
  "height": 12345,
  "hash": "ab…cd",       // hex lowercase, 64 chars — eco do hash resolvido
  "prev_hash": "12…34",  // hex lowercase, 64 chars
  "timestamp": 1753651200, // u64, segundos (header.timestamp.0)
  "target": "00ff…",     // hex do target em big-endian (to_be_bytes), lib.rs:650
}
```

### 2.2 Erros

- **404** `{"found": false}` — altura desconhecida (`lib.rs:625-631`) ou hash sem
  header (`lib.rs:655-659`). `BlockNotFoundResponse` (`lib.rs:306-309`).
- **400** `{"error":"invalid hex: invalid height"}` — dígitos que estouram u64
  (`lib.rs:620-622`; teste `lib.rs:1834-1847`).
- **400** `{"error":"invalid hex: …"}` — não-dígitos que não sejam hex de exatamente
  32 bytes (`lib.rs:714-718`; teste `lib.rs:1851-1863`).
- **500** `{"error":"internal: corrupt header: …"}` — header corrompido (`lib.rs:641-642`).
- **429** possível (grupo público de leitura).

Útil para o wallet: confirmar `hash` de uma altura já sincronizada (detecção de
reorg) sem Bearer — mas conta no rate limit público.

---

## 3. GET /health e GET /status  (PÚBLICOS, sem auth)

### 3.1 /health — rota `lib.rs:370`, handler `lib.rs:488-490`, `HealthResponse` (`lib.rs:223-226`)

```json
{"ok": true}
```

Sempre 200 com `ok: true` se o serviço responde. **Sem rate limit** (fora dos
grupos com Governor) — heartbeat barato e seguro.

### 3.2 /status — rota `lib.rs:339`, handler `lib.rs:492-499`, `StatusResponse` (`lib.rs:228-234`)

```json
{
  "version": 1,            // dom_core::PROTOCOL_VERSION (u32)
  "chain_height": 20500,   // u64 — altura do tip do node
  "mempool_size": 3,       // usize
  "network": "mainnet"     // "mainnet" | "testnet" | "regtest" (lib.rs:25-29)
}
```

Sem auth; serve para tip (`chain_height`) e validação de rede antes de confiar em
um node remoto — mas está no rate limit público de leitura (100 burst/1 rps),
e NÃO traz o hash do tip (para o par height+hash usar `/chain/scan` ou `/block/<h>`).

---

## 4. POST /tx/submit  (PÚBLICO — documentação para envio remoto futuro)

Rota: `lib.rs:346-348` (rate limit de submit: 10 burst/1 rps). Handler:
`submit_tx` (`lib.rs:547-590`).

Request (`SubmitTxRequest`, `lib.rs:259-262`):

```json
{"tx_hex": "dede…"}   // transação serializada, hex
```

Resposta (`SubmitTxResponse`, `lib.rs:264-277`; campos `None` são omitidos —
`skip_serializing_if`):

- **200 aceita e relayada**:

```json
{"accepted": true, "relayed": true, "tx_hash": "5d…e1"}
```

- **200 aceita SEM relay** (sem peers; mempool é volátil — RFC-0012 §1, doc
  `lib.rs:152-158` — o wallet deve retransmitir):

```json
{
  "accepted": true,
  "relayed": false,
  "tx_hash": "5d…e1",
  "warning": "no peers connected; tx will be retransmitted when the node reconnects"
}
```

  (constante `WARN_ACCEPTED_NOT_RELAYED`, `lib.rs:280-281`.)

- Erros (`submit_error`, `lib.rs:696-708` — mesmo shape, com `error`):
  - **400** hex inválido / tx inválida: `{"accepted":false,"relayed":false,"error":"invalid hex: …"}`
  - **409** rejeitada (ex.: já no mempool): `{"accepted":false,"relayed":false,"error":"rejected: …"}` (teste `lib.rs:1484-1499`)
  - **503** node sobrecarregado (ex.: mempool cheio): `{"accepted":false,"relayed":false,"error":"overloaded: …"}` (teste `lib.rs:1502-1517`)
  - **500** interno.
- **429** texto se exceder 10 burst/1 rps.
- Não requer Bearer (teste `lib.rs:1398-1417`). Body limitado a ~1 MB (seção 0) —
  cabe qualquer tx normal.

---

## 5. Resumo operacional para o cliente remoto do wallet

| Endpoint | Auth | Rate limit | Sucesso | Retriáveis | Terminais |
|---|---|---|---|---|---|
| `GET /health` | não | nenhum | 200 `{"ok":true}` | timeout/conn | — |
| `GET /status` | não | 100/s IP | 200 | 429, timeout | — |
| `GET /block/:h` | não | 100/s IP | 200 header | 429, timeout | 400, 404, 500 |
| `GET /chain/scan` | Bearer | 100/s IP (pool próprio) | 200 página | **503 busy**, 429, timeout | 400, 401, 500 |
| `POST /tx/submit` | não | 10/s IP | 200 (checar `relayed`) | 503, 429, timeout | 400, 409 |

Regras que o cliente DEVE seguir:

1. `503 overloaded` em `/chain/scan` é esperado durante mineração/IBD do node —
   retry com backoff, **nunca** erro terminal (regra de ouro, `node_handle.rs:400-407`).
2. `429` vem como TEXTO, não JSON — não tentar parsear `{"error":…}` nesse caso.
3. Paginar `/chain/scan` assumindo `to` clampado: próximo `from = to_resposta + 1`;
   fim quando `to_resposta == tip.height`; tratar `blocks` com buracos (alturas
   omitidas) e faixa vazia com `to < from`.
4. Timeout de request do servidor é 30 s — timeout do cliente deve ser ≥ isso ou
   explicitamente menor com retry.
5. `/chain/scan` atual NÃO carrega recovery capsules — o restore V3 remoto exige
   extensão upstream do `ScanBlockData`/`ScanBlockDto` (seção 1.1).
