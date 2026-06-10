# DOM Protocol — Reconciliação doc↔código dos Release Blockers [MAINNET]

**Data:** 2026-06-10
**Autor:** Soren Planck
**Base:** branch `docs/blocker-reconciliation` a partir de `main` (`edc4b54`)
**Método:** leitura do CÓDIGO REAL; cada afirmação com `arquivo:linha`. Read-only —
nenhum arquivo de `crates/**/src/**` foi alterado; este relatório é o único arquivo
novo. **`docs/RELEASE_BLOCKERS.md` NÃO foi editado** (correção dele é passo separado).

> Regra aplicada: quando o doc e o código divergem, **o código é a verdade**. Onde
> há divergência, está marcado `DOC DESATUALIZADO`.

---

## 1. Tabela resumo

| Blocker | Status no doc | Status REAL | Evidência-chave (arquivo:linha) |
|---|---|---|---|
| **RB-BAN-POLICY** | 🔴 OPEN ("zero call sites") | 🔧 **PARCIAL** (largamente implementado) | `peer_violation_score` + ~14 call sites de `record_peer_violation` em `dom-node/src/node.rs:1712-1740`, `:1313/1375/1411/1468/1546/1594/3518/3540/3547/3569/3802/3968/3981/3994`; enforcement em `dom-wire/src/peer.rs:84-92` |
| **RB-HANDSHAKE-TIMEOUT** | 🔴 OPEN (linha 317) **e** ✅ RESOLVED (linha 499) | ✅ **RESOLVIDO** | `dom-wire/src/handshake.rs:20,36,116-121,163-168`; `dom-wire/src/codec.rs:125-135` |
| **RB-WALLET-SLATE** | 🔴 OPEN ("dom-wallet is empty") | 🔧 **PARCIAL** (modelo decidido + implementado + testado; falta RFC/timeout) | `dom-tx/src/slate.rs:41`; `dom-wallet/src/wallet.rs:1163/1292/1395`; testes `:2695/2756/2820` |
| **RB-IBD** | 🔧 PARTIAL ("skeleton present") | 🔧 **PARCIAL** (implementado+testado; falta RFC + checkpoints) | `dom-chain/src/ibd.rs` (867 linhas, máquina de estados completa); falta `CHECKPOINT` hardcoded (grep vazio) |
| **RB-DNS-SEEDS** | 🔴 OPEN ("no domains, no fallback IPs") | 🟠 **ABERTO (operacional)** — mecanismo pronto, dados/governança faltam | `dom-wire/src/dns_seed.rs` (resolução completa); `dom-config/src/lib.rs:88,98,100,159-162`; `dom-node/src/node.rs:1048,2302-2311` |

**Leitura rápida:** dos 5, **nenhum é "código inexistente"**. 1 está de fato
RESOLVIDO (handshake), 3 estão PARCIAIS com resíduo majoritariamente
**documental (RFC)** ou de **granularidade**, e 1 (DNS-seeds) é genuinamente um
**bloqueio operacional** (dados reais + governança), não de código.

---

## 2. Por blocker

### RB-BAN-POLICY — Peer ban scoring
**Doc afirma (RELEASE_BLOCKERS.md:298-313):** OPEN, CRITICAL — *"`add_ban_score`
defined but zero call sites. Malformed messages, invalid PoW, wrong chain_id —
none increment the ban score."*

**Código mostra:** **DOC DESATUALIZADO** — a afirmação central ("zero call sites")
é falsa.
- `record_peer_violation` / `record_pending_peer_violation` são definidos em
  `dom-node/src/node.rs:1744` e `:1772` e **chamados em ~14 pontos de rejeição**:
  handshake/hello timeout (`:1313`), falha de handshake (`:1375`), erros de
  registro de peer (`:1411/1468/1546/1594`), erro de frame/decode no message loop
  (`:3518`), segundo Hello (`:3540`), GetHeaders malformado (`:3547`), decode de
  bloco relay (`:3569`), validação de bloco (`:3802`), validação de tx relay
  (`:3968/3981`), GetBlockData malformado (`:3994`).
- O mapeamento de erro→score está em `peer_violation_score`
  (`dom-node/src/node.rs:1712-1731`): `Malformed → MALFORMED_MESSAGE(20)`;
  `Invalid("chain_id mismatch"|"network_magic mismatch") → WRONG_CHAIN_ID(100)`;
  `PolicyRejected("handshake timeout") → PROTOCOL_VIOLATION(10)`; e um **catch-all
  `DomError::Invalid(_) → PROTOCOL_VIOLATION(10)`** (`:1729`).
- Enforcement: `PeerInfo::add_ban_score` (`dom-wire/src/peer.rs:84-92`) seta
  `PeerState::Banned` ao atingir `BAN_THRESHOLD=100` e o node dropa/retorna a
  conexão quando `banned==true`.
- Persistência: `persist_peer_reputation_state` + `PEER_REPUTATION_METADATA_KEY`
  gravam o estado em LMDB e recarregam no restart.

**Resíduo exato (o que ainda falta vs. a especificação do doc):**
1. **Granularidade menor que a especificada.** Os pesos `INVALID_POW(50)`,
   `INVALID_SIGNATURE(25)` e `INVALID_TX_STRUCTURE(15)` estão **definidos**
   (`dom-wire/src/peer.rs:11,17,19`) mas **não são mapeados**: PoW/assinatura/bloco
   inválidos caem no catch-all `Invalid(_) → PROTOCOL_VIOLATION(10)`
   (`node.rs:1729`). Ou seja, **são pontuados** (refuta "none increment"), mas a
   +10 em vez de +50/+25. `Malformed(+20)` e `WRONG_CHAIN_ID(+100)` batem com o doc.
2. **ADDRESS_FLOODING(+30) não é aplicado.** `Command::Addr`/`GetAddr` não têm arm
   no message loop e caem em `other => ignoring` (`node.rs:4015`); não há rate
   limiting de ADDR. (Efeito colateral: a troca PEX via ADDR está inerte no loop.)
3. **Sem decay temporal do ban de peer registrado.** Penalidades
   *pré-registro* expiram (`PENDING_PENALTY_TTL_SECS = 15min`, bounded a 4096 —
   `dom-wire/src/manager.rs:18-21`), mas o `ban_score` de um peer **registrado** não
   tem expiração/decay — uma vez banido, permanece (inclusive após restart, por ser
   persistido). O doc pede "expire timestamp".

**Status REAL: 🔧 PARCIAL.** Enforcement + persistência funcionam e são testados
(`dom-node/src/node.rs` unit tests `malformed_message_maps_to_malformed_score`,
`wrong_network_identity_maps_to_immediate_ban_score`; `sybil_resistance.rs`,
`eclipse_resistance.rs`). Falta: granularidade de score, ADDR flooding/rate-limit,
decay de ban de peer registrado.

---

### RB-HANDSHAKE-TIMEOUT — Slowloris DoS
**Doc afirma:** **contradição interna** — `RELEASE_BLOCKERS.md:317` diz 🔴 OPEN
("`read_framed` has no timeout"), enquanto `:499-507` diz ✅ RESOLVED in v8.

**Código mostra:** **RESOLVIDO** — confirma a seção 499, refuta a 317.
- `dom-wire/src/handshake.rs:20` `HANDSHAKE_TIMEOUT_SECS = 10`; `:36`
  `IDLE_TIMEOUT_SECS = 60`.
- `perform_handshake_initiator` e `_responder` envolvem o I/O em
  `tokio::time::timeout(...)` (`:116-121` e `:163-168`), retornando
  `DomError::PolicyRejected("handshake timeout after 10s")` — **não-banível** (peer
  lento ≠ malicioso).
- `NoiseCodec::recv` aplica `tokio::time::timeout(IDLE_TIMEOUT_SECS, ...)` por frame
  (`dom-wire/src/codec.rs:125-135`), `PolicyRejected("idle timeout after 60s")`.
- Integrado no caminho de produção: `handle_inbound` e `connect_outbound` em
  `dom-node/src/node.rs` aplicam o handshake sob `tokio::select!` com o timeout.

**DOC DESATUALIZADO:** a entrada `[MAINNET]` 🔴 OPEN (`:317`) está obsoleta; o
próprio doc já a reclassificou para `[TESTNET]` ✅ RESOLVED (`:499`). Resíduo = a
**entrada duplicada/contraditória** no doc (a remover na correção do doc).

**Status REAL: ✅ RESOLVIDO** (código). Nada falta no código.

---

### RB-WALLET-SLATE — Protocolo de slate da wallet
**Doc afirma (RELEASE_BLOCKERS.md:342-350):** OPEN — *"dom-wallet is empty. No RFC
for slate format, rounds, replay protection, timeout. Required: Decision between
Grin-style interactive vs ECDH stealth addresses, then RFC + implementation."*

**Código mostra:** **DOC DESATUALIZADO** em vários pontos.
- **dom-wallet NÃO está vazio.** `dom-wallet/src/wallet.rs` tem ~2.925 linhas, mais
  módulos (`hd_wallet.rs`, `journal.rs`, `store.rs`, `coin_selection.rs`, etc.):
  seed BIP39 + HD derivation, scan/coinbase recovery, build de spend, journal/rollback.
- **A decisão interactive-vs-stealth JÁ foi tomada: INTERACTIVE (estilo Grin).**
  Provado pelo fluxo de partial-sigs em rounds (não há ECDH/stealth address).
- **Slate existe e é tipado:** `dom-tx/src/slate.rs:41` `pub struct Slate` com
  `version, chain_id, amount, fee, lock_height`, inputs/change/output do sender e
  recipient, `*_public_excess`, `*_public_nonce`, `*_partial_sig`.
- **Fluxo de 3 passos implementado:** `create_send_slate`
  (`wallet.rs:1163`) → `receive_slate` (`:1292`) → `finalize_slate` (`:1395`).
  Agregação Schnorr via `schnorr_partial_sign` / `schnorr_aggregate_sigs` /
  `schnorr_add_public_keys` (`dom-crypto/src/schnorr.rs`); replay protection com
  `chain_id` no challenge.
- **Testes e2e + adversariais:**
  `finalize_slate_end_to_end_builds_valid_aggregate_transaction` (`wallet.rs:2695`)
  monta uma tx agregada que passa estrutura+balanço+`schnorr_verify`;
  `adversarial_cross_chain_slate_is_rejected_*` (`:2756`),
  `adversarial_non_owned_slate_is_rejected_by_finalize` (`:2820`), além de tamper de
  amount/fee/output e partial-sig inválida.

**Resíduo exato:**
1. **RFC formal ausente** (documento). Não há `docs/DOM_RFC_*` do slate — só
   doc-comments no código. (Resíduo documental, não de código.)
2. **Sem timeout/expiração de slate.** Inputs ficam reservados até `cancel_tx`
   manual; não há auto-expiração. (Resíduo de código, pequeno; UX.)
3. **Transporte/UX assíncrona** (troca de arquivo/QR/endpoint entre sender e
   recipient) fora do escopo do slate em si; a relay de rede valida a tx final pelo
   caminho normal de tx.

**Status REAL: 🔧 PARCIAL.** Modelo decidido, implementado e testado e2e. Falta:
RFC documental + timeout de slate + camada de transporte.

---

### RB-IBD — Initial Block Download
**Doc afirma (RELEASE_BLOCKERS.md:354-360):** PARTIAL — *"ibd.rs skeleton present,
RFC missing."*

**Código mostra:** **DOC DESATUALIZADO** quanto a "skeleton" — é implementação real.
- `dom-chain/src/ibd.rs` tem **867 linhas**: `IbdPhase` (`:24`), `IbdInterruption`
  (`:47`), `IbdControl` (`:60`), `PersistedIbdState` com `save/load/clear`
  (`:77,112,117,125`) e `IbdState` com `from_persisted` (`:377`), `process_headers`
  (headers-first, `:433`), `note_round_progress`/`note_empty_response`
  (stalling/timeout, `:526/545`). Constantes `MAX_HEADERS_PER_REQUEST=2000` (`:14`),
  `MAX_IBD_RETRY_ATTEMPTS=3` (`:18`).
- Stateful/resumível e persistido em LMDB; download em lotes via
  `MAX_GETBLOCKDATA_HASHES` no `dom-node/src/node.rs` (`resume_ibd_block_sync`,
  `continue_ibd_header_sync`, `validate_ibd_headers_batch`).
- Testes: `dom-chain/tests/ibd_adversarial.rs` (headers inválidos/fora de ordem,
  flood, crescimento de memória), `dom-chain/tests/ibd_persistence.rs` (resume),
  `dom-integration-tests/tests/ibd_two_node.rs` (2 nós, env-gated por RandomX).

**Resíduo exato:**
1. **RFC formal de IBD ausente** (o que o doc de fato aponta). Não existe
   `docs/DOM_RFC_*IBD*`.
2. **Sem checkpoints hardcoded / minimum-work checkpoint.** Grep por `CHECKPOINT`
   em `dom-core/src`, `dom-config/src` e `ibd.rs` é vazio; `checkpoint_tip_hash`
   (`ibd.rs:93`) é **âncora de resume da sessão local**, não um checkpoint de
   confiança global. O doc pede "hardcoded checkpoints" — genuinamente não existe.
3. Download é em lotes **sequenciais** (não confirmei download paralelo entre
   múltiplos peers) — marcar como "não verificado" se for requisito.

**Status REAL: 🔧 PARCIAL.** Código implementado e testado; falta RFC documental +
checkpoints hardcoded (código pequeno) + eventual download paralelo multi-peer.

---

### RB-DNS-SEEDS — Bootstrap discovery
**Doc afirma (RELEASE_BLOCKERS.md:330-338):** OPEN — *"No domains specified, no
governance, no hardcoded fallback IPs."*

**Código mostra:** **PARCIALMENTE DESATUALIZADO** — o mecanismo existe e está ligado
ao bootstrap; o que falta são **dados reais + governança**.
- `dom-wire/src/dns_seed.rs`: `resolve_seeds(mainnet, port, custom_seeds)` faz
  resolução via `tokio::net::lookup_host`, aceita seeds custom, e cai em IPs de
  fallback. `MAINNET_DNS_SEEDS` lista **5 domínios** (`seed1..seed5.dom-protocol.org`)
  e `TESTNET_DNS_SEEDS` **2**.
- `NodeConfig` **tem** os campos (refuta "undefined"): `dns_seeds`,
  `disable_dns_seeds`, `seed_peers` (`dom-config/src/lib.rs:88,98,100`); default
  mainnet lista 2 domínios (`:159-162`), testnet 1 (`:184`).
- Ligado ao bootstrap: `resolve_configured_dns_seeds` (`dom-node/src/node.rs:2302`)
  é chamado no startup (`:1048`) e estendido com `seed_peers` (`:1051`).

**Resíduo exato (genuinamente aberto — operacional, não código):**
1. **Domínios são placeholders.** `seed*.dom-protocol.org` ainda não são operados /
   publicados em DNS por operadores independentes.
2. **`MAINNET_SEED_IPS` está vazio** — `dns_seed.rs` traz o comentário literal
   *"To be filled after genesis"*; não há IP de fallback hardcoded.
3. **Governança** (≥5 operadores independentes) e **DNSSEC guidance** = decisão
   operacional/RFC, não implementadas.
4. **Rate limiting de ADDR** ausente (cruza com RB-BAN-POLICY resíduo #2).

**Status REAL: 🟠 ABERTO (operacional).** O mecanismo de código é o componente mais
completo; o que bloqueia é **dados reais + governança**, por design pós-genesis.
É o único dos 5 que continua legitimamente "aberto", mas como **tarefa de
lançamento**, não de engenharia.

---

## 3. Caminho real até testnet pública

Reconciliado o mapa, o que de fato resta (curto e priorizado) para uma **testnet
pública** estável:

1. **(Operacional, bloqueante) Bootstrap discovery — RB-DNS-SEEDS.** Para uma
   testnet pública é preciso **pelo menos**: subir 1–2 seeds reais (DNS ou IP) e
   povoar `dns_seeds`/`seed_peers` (ou `MAINNET_SEED_IPS`/equivalente de testnet) com
   endereços que resolvem. Sem isso, nós novos não se encontram. É o único item que
   genuinamente impede a testnet pública hoje. (Governança formal de 5 operadores +
   DNSSEC podem vir depois.)
2. **(Código, pequeno) ADDR/PEX no message loop + rate limiting** — hoje
   `Command::Addr` é ignorado (`node.rs:4015`); sem PEX, a descoberta depende só dos
   seeds. Ligar o handler de ADDR (com `ADDRESS_FLOODING` score + rate-limit) melhora
   muito a robustez de descoberta numa rede pública.
3. **(Código, opcional p/ testnet) Granularidade de ban + decay** — mapear
   `INVALID_POW/INVALID_SIGNATURE` para seus pesos e adicionar expiração ao ban de
   peer registrado. Não bloqueia testnet (o enforcement coarse já funciona), mas é
   higiene anti-DoS antes de exposição prolongada.
4. **(Documental, não bloqueia testnet) RFCs de IBD e de Slate** — o código está
   implementado e testado; faltam os documentos formais. Importam para auditoria
   externa e mainnet, não para subir a testnet.
5. **Já fora do caminho de testnet:** RB-HANDSHAKE-TIMEOUT está **resolvido**; o
   slate interactive está implementado e testado (timeout de slate é UX, não
   bloqueia rede). A cerimônia de `GENESIS_HASH_*` (ver auditoria FABLE5) é
   pré-requisito de **mainnet**, não de testnet.

**Conclusão:** o repositório está substancialmente mais avançado do que o
`RELEASE_BLOCKERS.md` sugere. Para **testnet pública**, o gargalo real é
**operacional (seeds reais)** + um pequeno trabalho de **PEX/ADDR**; o restante dos
"[MAINNET] OPEN" é documentação (RFC) ou polimento que não impede subir a rede.

---

## 4. Limitações de método
- Cada veredito acima foi confirmado no código nos pontos citados. Onde não abri o
  arquivo pessoalmente para um número de linha interno, citei a função/arquivo
  verificado e marquei suposições como tais (ex.: download paralelo multi-peer no
  IBD — **não verificado**).
- `docs/RELEASE_BLOCKERS.md` **não foi editado** (correção é passo separado após sua
  revisão). Há também itens fora do escopo desta tarefa no doc (RB-MUSIG2,
  RB-GENESIS-ANCHOR, etc.) que não foram reconciliados aqui.
- WIP local não-commitado de wallet (`confirm_receive_request`) foi **ignorado** na
  análise, conforme instruído; conclusões refletem apenas código commitado.
