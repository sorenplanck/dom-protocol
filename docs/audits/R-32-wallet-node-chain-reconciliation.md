# R-32 — Reconciliação de chain entre wallet v2 e nó

**Status:** ABERTO (documentação; nenhuma alteração de `src/` nesta etapa)
**Componente:** `dom-wallet2` (scan/submit) ↔ `dom-rpc` (`/status`, `/tx/submit`)
**Severidade:** baixa (defensivo/diagnóstico) — **não é bug de consenso**
**Tipo:** hardening + 1 decisão de mérito (ver Camada 2)

---

## Contexto / evidência

O `chain_id` da wallet v2 é um `[u8; 32]` guardado em `WalletV2State`
(`crates/dom-wallet2/src/wallet_state.rs:41`), fixado em
`WalletV2State::new(network, chain_id)` (`wallet_state.rs:58`). O valor canônico
é `derive_n(network_magic, genesis_hash)` = `Blake2b-256(network_magic ||
genesis_hash)` — ou seja, **derivado do hash do genesis**. O nó calcula o mesmo
valor via `n_for(config)` em `crates/dom-node/src/miner.rs`.

A ligação **slate ↔ slate** já é sólida e está coberta:

- `build_send(…, state.chain_id)` grava `slate.chain_id`
  (`crates/dom-wallet2/src/payment.rs:157`);
- `respond_receive(slate, &state.chain_id)` verifica e falha com `SlateError`
  se diferir (`payment.rs:257`; check em `crates/dom-slate/src/lib.rs:222`);
- `slate_finalize(…, &state.chain_id)` verifica de novo (`payment.rs:355`);
- o `chain_id` entra no domínio da **assinatura do kernel**
  (`schnorr_verify(…, chain_id, …)` em `crates/dom-slate/src/lib.rs:377`), logo
  uma tx construída para uma chain é **criptograficamente inválida** em outra.

### Lacuna observada

Não existe nenhuma reconciliação entre a wallet e o **nó** ao qual ela se conecta:

- `submit_tx` (`crates/dom-wallet2/src/rpc_source.rs:270`) apenas serializa a tx
  e faz `POST /tx/submit`; **não** compara chain alguma.
- O nó **não expõe** seu `chain_id`/genesis por RPC. `/status` devolve só
  `version`, `chain_height`, `mempool_size` e `network`
  (`crates/dom-rpc/src/lib.rs:219-224`). `/chain/scan` devolve `tip` +
  commitments por bloco, **sem** `chain_id` (`lib.rs:697-703`).
- A wallet também **não** compara seu próprio `network` com o `network` de
  `/status` antes de escanear/submeter.

### Por que não é bug de consenso

A rede de segurança real existe: como o `chain_id` está no kernel **assinado**,
uma tx de chain errada é **rejeitada pelo nó** (a assinatura não verifica contra
o `chain_id` do nó) — falha segura, não aplica errado.

O custo é de **diagnóstico**: uma wallet apontada para o nó da rede errada
escaneia commitments irrelevantes e só descobre o problema num *submit reject*
opaco (`409`), em vez de falhar cedo com uma mensagem clara.

---

## Camada 1 — Check leve imediato (sem mudar a superfície RPC)

**O que:** antes de scan e antes de submit, a wallet busca `GET /status` e
compara `status.network` contra `state.network`. Se diferirem, aborta cedo com
erro claro do tipo `"wallet na chain errada: configurada para <X>, nó reporta
<Y>"`.

**Por que é seguro/barato:**
- usa apenas o que `/status` **já expõe** (`network`, `lib.rs:223`);
- não altera consenso, nem formato de tx, nem superfície RPC;
- transforma uma rejeição opaca tardia numa falha precoce e legível;
- granularidade é de **rede** (regtest/testnet/mainnet), não de `chain_id` —
  suficiente para o erro operacional mais comum (apontar a wallet para o nó
  errado), insuficiente para distinguir duas chains da **mesma** rede (ex.: dois
  regtests com genesis diferentes). Esse caso residual é coberto pela Camada 2.

**Pontos de inserção (quando for implementado):**
- caminho de scan via `RpcChainSource` (`crates/dom-wallet2/src/rpc_source.rs`);
- caminho de submit `submit_tx` (`rpc_source.rs:270`).

**Não implementar nesta etapa.**

---

## Camada 2 — Reconciliação forte por `chain_id`/`genesis_hash`

> **PRECISA DECISÃO HUMANA**

**O que:** expor o `chain_id` (= `derive_n`) e/ou o `genesis_hash` no corpo de
`GET /status`, e fazer a wallet comparar `status.chain_id == state.chain_id`
antes de scan/submit. Isso fecha o caso residual da Camada 1 (mesma rede, chains
distintas) com uma comparação exata de 32 bytes.

**Por que é decisão de mérito (não do agente):**
- **altera a superfície RPC pública** (`StatusResponse`,
  `crates/dom-rpc/src/lib.rs:219`) — mudança aditiva, mas é contrato externo;
- precisa decidir **o que** expor: `chain_id` derivado, `genesis_hash` cru, ou
  ambos; e se entra também em `/chain/scan` (para amarrar cada scan à chain);
- toca a fronteira nó↔ferramentas externas e merece revisão humana de
  compatibilidade e de exposição de informação.

**Opções (com trade-offs):**

| Opção | O que expõe | Prós | Contras |
|-------|-------------|------|---------|
| 2a | `chain_id` (`derive_n`) em `/status` | comparação direta com `state.chain_id`; 32 bytes | novo campo no contrato `/status` |
| 2b | `genesis_hash` cru em `/status` | wallet recomputa `derive_n` e valida a derivação inteira | wallet precisa do `network_magic` para derivar; mais lógica no cliente |
| 2c | `chain_id` em `/status` **e** em `/chain/scan` | amarra cada resultado de scan à chain, não só o handshake | duplica o campo; mais superfície |

**Recomendação para a decisão humana:** 2a (campo `chain_id` aditivo em
`/status`) cobre o handshake com custo mínimo; 2c só se quisermos que cada scan
seja auto-verificável. Decidir antes de qualquer implementação.

**Não implementar nesta etapa.**

---

## Resumo

- Camada 1: hardening puro, sem decisão de mérito — pode ser agendado para
  implementação assim que priorizado.
- Camada 2: **bloqueada em decisão humana** (muda contrato RPC público).
- Nenhuma das duas é pré-requisito de segurança de consenso; ambas são melhoria
  de diagnóstico/robustez operacional antes da testnet.
