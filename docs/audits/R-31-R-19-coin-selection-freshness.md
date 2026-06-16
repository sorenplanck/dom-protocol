# R-31 / R-19 — Frescura do UTXO na seleção de inputs (wallet v2)

**Status:** camada (c) IMPLEMENTADA (release da reserva no reject do submit em
`submit_finalized`); camada (b) ABERTA (frescura antes do send)
**Componente:** `dom-wallet2` — `create_send` / coin selection (`payment.rs`) ↔
camada de orquestração (caller send→submit) ↔ reconciliador (`reconcile.rs`,
`transport.rs`)
**Severidade:** baixa-média — **correção/UX** e **input reservado preso**;
**NÃO é consenso, NÃO há perda de fundos nem inflação** (o nó é a autoridade e
rejeita uma tx sobre input não-canônico)
**Tipo:** hardening (arquitetura em camadas) + 1 ponto de coordenação com a UI

---

## Contexto / evidência

`create_send` é, por design, uma **pure state transition** sobre `WalletV2State`
(`crates/dom-wallet2/src/payment.rs:3`): seleciona inputs, cria o change em C0,
reserva os inputs e monta o slate — **sem I/O de disco e sem falar com o nó**.

A seleção de inputs confia **exclusivamente no estado persistido** no store e num
**tip persistido** (cursor da última reconciliação), nunca no estado ao vivo do nó:

- Exige `OutputStatus::Confirmed` e não-reservado; `Unconfirmed`/`Reorged`/`Spent`
  são excluídos:
  - `payment.rs:75` — `if out.status != OutputStatus::Confirmed || out.is_reserved() { return false; }`
  - variantes de estado em `crates/dom-wallet2/src/types.rs:97-106`
- O "tip" usado na maturidade de coinbase **não é o tip ao vivo** — é o cursor
  persistido `meta.last_reconciled_tip`:
  - `payment.rs:93` — `let tip = state.meta.last_reconciled_tip;`
  - `payment.rs:78-83` — `Some(b) => tip.saturating_sub(b.height) >= maturity`
- `is_spendable` decide só por campos persistidos (`out.status`, `out.is_coinbase`,
  `out.origin_block`) — **nenhuma** verificação de que o commitment ainda está no
  UTXO set canônico (`payment.rs:74-86`).
- `create_send` (`payment.rs:132-206`): `select_inputs` → `build_send`
  (`payment.rs:157`) → muta o store e reserva os inputs (`payment.rs:196-200`).
  Em nenhum ponto consulta o nó nem revalida o UTXO contra o tip atual antes de
  reservar/montar.

### Sem reconcile como pré-condição

`create_send` **não** chama reconcile/sync, nem o exige. O reconciliador é um
driver **separado** (`tip → scan → reconcile`):

- `crates/dom-wallet2/src/reconcile.rs` — `pub fn reconcile(store, view, now)`
- `crates/dom-wallet2/src/transport.rs` — `pub fn sync(...)` = `tip()` →
  `scan_range(from, tip)` → `reconcile`
- `crates/dom-wallet2/src/wallet_state.rs` — avança `meta.last_reconciled_tip` /
  `last_reconciled_hash` após o scan/reconcile

Neste branch os únicos chamadores de `create_send` são **testes**; não há fiação
de produção que garanta "reconcile antes de send". A frescura do store antes de
um send é, hoje, **responsabilidade do chamador** — e nada em `create_send` a
garante ou impõe.

### Consequência (por que NÃO é consenso)

Se o store estiver desatualizado — uma saída foi gasta por outra
instância/dispositivo, ou saiu num reorg ainda não reconciliado — `create_send`
seleciona, reserva e monta a tx sobre uma entrada **já não-canônica**. A tx só
falha mais tarde, no **submit** (o nó rejeita). O dano é:

1. **UX/correção:** o usuário monta um pagamento que será rejeitado.
2. **Input reservado preso:** o input fica `reserved_for` um slate que nunca
   confirma, reduzindo o saldo gastável até uma liberação explícita.

Não há perda de fundos nem inflação: a tx inválida não entra na cadeia.

### Mitigações que JÁ existem

- Exige `Confirmed` (`payment.rs:75`) — não gasta saída ainda não canônica
  **segundo o store**.
- A reserva impede double-spend **local** concorrente (`payment.rs:196-200`;
  teste `reservation_prevents_double_spend`, `payment.rs:516-526`).
- Maturidade de coinbase vs tip persistido (`payment.rs:78-83`).

Todas dependem de o store refletir a verdade — exatamente a lacuna acima.

---

## Arquitetura recomendada (em camadas, sem quebrar a pureza)

A correção **não** deve ir para dentro de `create_send`: manter a transição pura
preserva testabilidade, atomicidade e ausência de I/O. A frescura é
responsabilidade da **camada de orquestração** (o caller que conduz
send → submit).

**Invariante de design:** `create_send` permanece *pure state transition* — sem
rede, sem disco (`payment.rs:3`).

### Camada (b) — mínimo barato: frescura ANTES do send

Antes de chamar `create_send`, a orquestração:
- roda um `sync` (`transport.rs::sync`), ou
- checa a **idade** de `meta.last_reconciled_tip` (e/ou `last_reconciled_hash`) e
  recusa/avisa se o store estiver velho além de um limite.

Custo mínimo, fecha o caso comum (store simplesmente atrasado). Não cobre um
reorg que aconteça **entre** a montagem e o submit.

### Camada (c) — robusto: revalidar e tratar o reject no submit — IMPLEMENTADA

No caminho de submit (orquestração sobre `submit_finalized`):
- tratar a **rejeição do nó** como sinal de input não-canônico;
- **liberar o input reservado** (release da reserva), devolvendo o saldo
  gastável;
- opcionalmente revalidar os inputs selecionados contra o nó imediatamente antes
  do submit.

Cobre o reorg-durante-montagem (a janela que (b) não fecha) e resolve o "input
preso".

**Status: IMPLEMENTADO.** `submit_finalized` agora recebe `now: u64` e, no
**reject do `submit_tx`**, libera a reserva de cada input do slate
(`out.release_reservation(now)`) antes de propagar o erro. O slate é mantido
`Finalized` de propósito — **NÃO** vira `Failed`/`Canceled`: uma rejeição não
prova que a tx morreu (pode ter entrado no mempool de outra forma); o próximo
`reconcile` estabelece a verdade (`Spent` se entrou, `Confirmed` se não). A
reserva é só um guard local de double-spend e é seguro liberá-la aqui. Coberto
pelo teste `reserved_input_released_on_submit_reject`. Os chamadores do desktop
(`wallet_manager::submit_finalized` e `resubmit_pending`, e os callers em
`lib.rs`) passam `now_secs()`.

**Recomendação:** (b) é o piso barato; (c) é o que dá robustez real contra reorg
durante a montagem. Idealmente ambos — (b) reduz a frequência, (c) cobre o resto.

---

## Ponto de coordenação

> **PRECISA DECISÃO / coordenação com o branch da UI**

As camadas (b) e (c) vivem na **orquestração**, que é justamente a fiação
wallet-desktop do engine v2 (ver `[[wallet-v2-desktop-integration]]`, em branch
próprio, fora de `main`). Definir:

- onde mora a política de frescura (idade-limite do `last_reconciled_tip`) e seu
  valor;
- a semântica de UX do reject (liberar input + avisar vs. retry automático);
- se (c) deve revalidar inputs **proativamente** antes do submit (custo de rede
  extra) ou só **reativamente** ao reject.

Nenhum desses é decisão do agente isolado — toca contrato do módulo e a UX do
desktop. **Não implementar antes de coordenar com o branch da UI.**

---

## Resumo

- (1) Seleção exige `Confirmed` + não-reservado (`payment.rs:75`); coinbase vs
  tip persistido (`payment.rs:78-83`).
- (2) Sem verificação ao vivo do UTXO/tip: confia 100% no estado persistido e no
  cursor `meta.last_reconciled_tip` (`payment.rs:93`); `create_send` nunca fala
  com o nó (`payment.rs:132-206`).
- (3) Nenhum reconcile/sync antes/dentro de `create_send`; driver separado
  (`reconcile.rs`/`transport.rs`); frescura é do chamador.
- Severidade: correção/UX + input reservado preso — **não** consenso, **não**
  perda de fundos.
- Fix em camadas na orquestração: (b) frescura antes do send (mínimo, **ABERTO**),
  (c) liberar input + tratar reject no submit (robusto contra reorg,
  **IMPLEMENTADO** em `submit_finalized`).
- (b)/(c) tocam a fiação do desktop → **coordenar com o branch da UI**.

Relacionado: [[wallet-v2-desktop-integration]].
