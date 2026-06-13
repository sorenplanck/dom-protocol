# Wallet Desktop Slate Flow Audit

Date: 2026-06-13
Branch: `release/wallet-v0.3.1`
Scope: `wallet-desktop`, `dom-wallet`, `dom-wallet-app`, wallet RPC client, `dom-rpc`, `dom-node` submit/rescan/reorg surfaces.

## 1. Resumo Executivo

O fluxo oficial Tauri da `wallet-desktop` usa Slate para envio real de usuario: `slate_create_send` -> `slate_receive` -> `slate_finalize`. Os comandos antigos `wallet_send` / `wallet_create_receive` nao estao expostos no handler Tauri, e a UI web chama somente os comandos Slate.

O fluxo basico A -> B -> A funciona no core da wallet ate construir uma transacao agregada valida, persistir pending state do sender, confirmar output do receiver em bloco canonico e marcar submitted sob a chave correta do sender slate. O node tambem rejeita/aceita tx via validacao real de mempool antes de retornar sucesso ao RPC.

Porem, a wallet nao esta pronta para testnet publica nem mainnet. Ha falhas confirmadas por testes defensivos locais pre-existentes: o `Repair` rescan e o rollback/reorg removem outputs confirmados com blinding aleatorio que nao sao re-derivaveis, incluindo output recebido via Slate e change confirmado. Isso pode fazer saldo desaparecer apos rescan automatico do desktop ou apos reorg com a mesma tx re-minerada.

Classificacao:

| Alvo | Veredito |
|---|---|
| Regtest local | Parcial, com risco de perda de saldo visual/persistido apos rescan/reorg |
| Testnet privada | Nao recomendado sem patch de persistencia de non-derivable outputs |
| Testnet publica | Bloqueado |
| Mainnet | Bloqueado |

## 2. Call Graph Real

### Wallet A cria slate

UI web: `wallet-desktop/ui/src/screens.js:598`
-> API: `wallet-desktop/ui/src/api.js:69`
-> Tauri command: `wallet-desktop/src-tauri/src/lib.rs:779`
-> `WalletManager::slate_create_send`: `wallet-desktop/src-tauri/src/wallet_manager.rs:253`
-> node status height via `NodeRpcClient::status`
-> `Wallet::create_send_slate`: `crates/dom-wallet/src/wallet.rs:1358`
-> mature coin selection, random change blinding, sender excess, sender nonce
-> journal `Built` under sender slate hash: `wallet.rs:1440-1452`
-> reserve inputs under `slate_hash`: `wallet.rs:1454-1456`
-> persist `PendingTx` with `send_slate`, `send_slate_secrets`: `wallet.rs:1458-1475`.

### Wallet B responde

UI web: `wallet-desktop/ui/src/screens.js:641`
-> API: `wallet-desktop/ui/src/api.js:71`
-> Tauri command: `wallet-desktop/src-tauri/src/lib.rs:796`
-> `WalletManager::slate_receive`: `wallet_manager.rs:274`
-> node status height
-> `Wallet::receive_slate`: `wallet.rs:1487`
-> validates chain id and empty recipient fields
-> creates random recipient output blinding/rangeproof and partial sig
-> stores pending receive under hash of responded slate bytes: `wallet.rs:1558-1577`.

### Wallet A finaliza

UI web: `wallet-desktop/ui/src/screens.js:632`
-> API: `wallet-desktop/ui/src/api.js:72`
-> Tauri command: `wallet-desktop/src-tauri/src/lib.rs:807`
-> `WalletManager::slate_finalize`: `wallet_manager.rs:291`
-> `Wallet::finalize_slate`: `wallet.rs:1590`
-> reconstructs sender phase slate and `sender_slate_hash`: `wallet.rs:1617-1624`
-> verifies stored sender slate and inputs
-> verifies recipient sig, aggregates final sig, validates tx structure and balance: `wallet.rs:1652-1715`
-> stores final tx bytes on pending sender slate and clears sender secrets: `wallet.rs:1717-1724`
-> returns `FinalizedSlate { tx, pending_key: sender_slate_hash }`.

### Submit

`WalletManager::slate_finalize`
-> `NodeRpcClient::submit_tx`: `crates/dom-wallet/src/rpc_client.rs:426`
-> `POST /tx/submit`: `crates/dom-rpc/src/lib.rs:431`
-> `NodeHandle::submit_tx`: `crates/dom-node/src/node_handle.rs:47`
-> tx decode, canonical chain view, mempool admission, metrics, relay attempt
-> RPC returns accepted with `tx_hash` and `relayed` flag.

On `Ok`, desktop calls `mark_submitted(pending_key)`: `wallet_manager.rs:314-330`.
On explicit/safe failures, it may `cancel_tx(pending_key)`: `wallet_manager.rs:332-349`.
On ambiguous read/transport failure, it keeps pending to avoid double-spend.

### Confirmation

Node/miner applies canonical block to wallet via `apply_canonical_block_with_hash`: `crates/dom-wallet/src/wallet.rs:2093`.
Sender side: consumed pending input causes journal `Confirmed`, inputs marked spent, reservation released, change registered.
Receiver side: created output matching pending receive candidate causes `ReceiveConfirmed` journal, pending receive removal, confirmed output registration: `wallet.rs:2148-2159`.

### Restart

`WalletDir::open` attaches journal and calls wallet reconcile paths. `Wallet::reconcile_with_journal` can heal submitted/building sender pending records and terminal sender confirms. It can only reconstruct `Received` entries if encrypted pending receive secrets still exist: `wallet.rs:384-407`.

### Rescan / rollback

Desktop background rescan calls `WalletManager::rescan_against_node`: `wallet-desktop/src-tauri/src/lib.rs:1186-1241`
-> `DomNode::rescan_wallet_dir`
-> `Wallet::rescan_canonical_chain(Repair)`: `wallet.rs:1011`.

`rollback_to` removes outputs above the ancestor and explicitly says received outputs must be re-received: `wallet.rs:696-700`. That is the root of the confirmed receiver reorg failure.

## 3. Tabela de Testes Existentes

| Arquivo | Teste | Cobre | Lacuna | Deterministico | Peso |
|---|---|---|---|---|---|
| `crates/dom-wallet/src/wallet.rs` | `create_send_slate_reserves_inputs_and_keeps_secrets_out_of_slate` | Slate step 1, reserva, segredo fora do slate | Sem node real | Sim | Rapido |
| `crates/dom-wallet/src/wallet.rs` | `finalize_slate_end_to_end_builds_valid_aggregate_transaction` | A->B->A, tx agregada valida | Sem RPC/node/bloco | Sim | Rapido |
| `crates/dom-wallet/src/wallet.rs` | `finalize_marks_submitted_under_slate_hash_key_and_advances_journal` | `slate_hash` vs `tx_hash` no core | Nao exercita Tauri/RPC | Sim | Rapido |
| `crates/dom-wallet/src/wallet.rs` | `apply_canonical_block_confirms_received_slate_output` | Receiver reconhece output em bloco | Sem restart/reorg | Sim | Rapido |
| `crates/dom-wallet/src/wallet.rs` | `canonical_rescan_confirms_received_slate_output_after_restart` | Pending receive sobrevive restart antes de confirmacao | Nao cobre receive ja terminal | Sim | Rapido |
| `crates/dom-wallet/tests/tx_lifecycle.rs` | lifecycle/reconcile tests | WAL, submitted, failed, reopen, pending bytes | Legacy spend, nao Slate completo | Sim | Rapido |
| `crates/dom-wallet/tests/tx_rollback.rs` | rollback tests | Sender spend reorg/reinstate | Nao receiver Slate | Sim | Medio |
| `crates/dom-wallet/tests/canonical_rescan.rs` | rescan tests | coinbase, spent, pending drop, restart digest | Nao non-derivable confirmed outputs | Sim | Medio |
| `crates/dom-wallet/tests/rpc_client.rs` | submit tests | accepted/rejected/409/decode/client errors | Mock HTTP, sem node real | Sim | Rapido |
| `crates/dom-wallet-app/src/runtime.rs` | pending resubmit tests | app resubmit, 409, failed, retry later | Legacy app, nao Tauri Slate | Sim | Rapido |
| `crates/dom-node/src/node_handle.rs` | `submit_tx_*` | real mempool admission, relay flag, reject invalid inputs | Sem wallet-desktop UI | Sim | Rapido |
| `crates/dom-integration-tests/tests/wallet_flow.rs` | wallet coinbase/restart | wallet/node restart basico | Ignorado no ambiente atual | N/A | Pesado |
| `crates/dom-integration-tests/tests/spend_e2e.rs` | cross-node spend | node propagation | Ignorado no ambiente atual, legacy spend | N/A | Pesado |

## 4. Tabela de Testes Novos / Defensivos

Nao criei novos testes nesta execucao para respeitar o limite de escrita e porque dois arquivos defensivos ja existiam como untracked antes da auditoria. Eles foram executados como evidencia.

| Arquivo | Teste | Resultado | Cobre | Achado |
|---|---|---|---|---|
| `crates/dom-wallet/tests/robustness_reorg_slate_receive.rs` | `robustness_slate_receive_survives_reorg_when_tx_is_remined` | FAIL | receive Slate confirmado -> rollback -> mesma tx re-minerada | WDSF-001 |
| `crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs` | `robustness_confirmed_slate_receive_survives_subsequent_repair_rescan` | FAIL | receive Slate confirmado -> segundo Repair rescan | WDSF-002 |
| `crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs` | `robustness_confirmed_change_survives_repair_rescan` | FAIL | change confirmado -> Repair rescan | WDSF-002 |

## 5. Achados

### WDSF-001 — Receiver Slate confirmado se perde apos reorg e re-mineracao da mesma tx

Severity: High
Status: confirmado por teste
Affected files:
- `crates/dom-wallet/src/wallet.rs:600`
- `crates/dom-wallet/src/wallet.rs:696`
- `crates/dom-wallet/src/wallet.rs:2148`
- `crates/dom-wallet/tests/robustness_reorg_slate_receive.rs:24`

Descricao: `apply_canonical_block_with_hash` transforma o pending receive em output confirmado e remove o pending. `rollback_to(1)` remove outputs com `block_height > 1`. Quando a mesma transacao e re-minerada, nao ha mais pending receive candidate nem blinding persistido no journal para re-registrar o output.

Impacto: destinatario pode perder reconhecimento local de fundos recebidos apos reorg normal, mesmo que a tx sobreviva na chain vencedora.

Exploitabilidade: media. Reorgs curtos sao esperados em testnet/public networks; um atacante/miner pode aumentar probabilidade.

Evidencia: `cargo test -p dom-wallet --test robustness_reorg_slate_receive` falha com output ausente apos re-mineracao.

Correcao minima: persistir material suficiente do receive confirmado para rollback/replay seguro, ou manter terminal receive records capazes de reconstruir output sem depender do pending.

Correcao arquitetural: separar journal publico de um store criptografado de wallet-owned non-derivable outputs, com status canonico/reorged e bloco de origem, e fazer `rollback_to` reativar um receive candidate ou preservar segredo ate finality.

Teste recomendado: manter o teste existente e adicionar variante com restart entre rollback e re-mineracao.

Decisao humana: sim, definir politica de finality/persistencia para outputs com blinding aleatorio.

### WDSF-002 — Repair rescan apaga outputs confirmados nao re-derivaveis

Severity: High
Status: confirmado por testes
Affected files:
- `crates/dom-wallet/src/wallet.rs:1011`
- `crates/dom-wallet/src/wallet.rs:1095`
- `crates/dom-wallet/src/wallet.rs:1213`
- `crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs:51`
- `crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs:152`

Descricao: `rescan_canonical_chain(Repair)` reconstrui outputs por coinbase deterministica, receive requests deterministicos e pending receives. Outputs ja confirmados via Slate e change confirmado usam blindings aleatorios e deixam de existir como pending; no proximo rescan Repair, o conjunto reconstruido nao os inclui.

Impacto: o background rescan da `wallet-desktop` pode apagar saldo recebido via Slate ou change confirmado apos um novo bloco, sem reorg.

Exploitabilidade: alta em uso normal, pois o desktop executa rescan automatico quando a chain avanca.

Evidencia: `cargo test -p dom-wallet --test robustness_rescan_nonderivable_outputs` falha nos dois testes.

Correcao minima: durante `Repair`, preservar outputs confirmados nao re-derivaveis que ainda aparecem no conjunto canonico de `output_commitments` e nao foram gastos por `canonical_inputs`.

Correcao arquitetural: introduzir indice persistente criptografado para outputs wallet-owned non-derivable, reconciliado por commitment contra a chain canonica, sem depender de pending state.

Teste recomendado: os dois testes existentes, mais variante com `WalletDir::open` antes do segundo rescan.

Decisao humana: sim, porque altera semantica de rescan/reorg da wallet, embora nao consenso.

### WDSF-003 — `dom-wallet-app` ainda expoe fluxo legado ativo por payment request

Severity: Medium
Status: confirmado por leitura
Affected files:
- `crates/dom-wallet-app/src/app.rs:336`
- `crates/dom-wallet-app/src/app.rs:395`
- `crates/dom-wallet-app/src/runtime.rs:1101`
- `crates/dom-wallet/src/wallet.rs:1732`

Descricao: a wallet oficial Tauri usa Slate, mas o crate `dom-wallet-app` ainda tem UI ativa de receive/send baseada em payment request e chama `Wallet::build_spend`. Esse caminho nao e o fluxo oficial da `wallet-desktop` web/Tauri, mas permanece compilado e testado.

Impacto: usuarios ou builds que lancem `dom-wallet-app` podem operar o caminho non-Slate, com semantica diferente de receiver/change/persistencia.

Exploitabilidade: depende de distribuicao. Se `dom-wallet-app` for empacotado como wallet oficial, e caminho publico.

Evidencia: `render_send` chama `submit_payment_request`, que chama `build_spend`.

Correcao minima: rotular `dom-wallet-app` como legacy/test-only ou remover do release oficial.

Correcao arquitetural: unificar UI em comandos Slate ou criar wallet v2 minima sem payment-request legacy.

Teste recomendado: teste de release/packaging garantindo que so `wallet-desktop` Tauri e distribuida.

Decisao humana: sim, produto/release.

### WDSF-004 — Falta teste E2E real dois-wallet Slate com node/miner nao ignorado

Severity: Medium
Status: confirmado por ausencia de cobertura
Affected files:
- `crates/dom-integration-tests/tests/wallet_flow.rs`
- `crates/dom-integration-tests/tests/spend_e2e.rs`
- `wallet-desktop/src-tauri/src/wallet_manager.rs:291`

Descricao: o core tem testes unitarios Slate, e o node tem testes de submit/mempool, mas nao ha teste de integracao nao-ignorado que execute A cria slate, B responde, A finaliza, node aceita, bloco confirma, balances convergem e restart preserva tudo.

Impacto: regressao entre wallet-desktop, RPC e node pode passar em CI local por falta de costura fim-a-fim.

Exploitabilidade: operacional; aumenta risco de releases com fluxo quebrado.

Evidencia: testes E2E wallet em `dom-integration-tests` estao ignorados no ambiente atual por `env-blocked-wsl` e/ou cobrem legacy spend/coinbase, nao Slate completo.

Correcao minima: adicionar teste em `crates/dom-integration-tests/tests/` que use node regtest real com fast mining e duas `WalletDir`.

Correcao arquitetural: criar harness oficial wallet/node para fluxos de produto, executado em CI dedicado com recursos adequados.

Teste recomendado: `two_wallet_slate_happy_path`, `restart_after_submitted_before_confirmation`, `rpc_failure_does_not_mark_submitted`.

Decisao humana: nao para teste; sim para provisionar CI pesado.

## 6. Legacy Path Assessment

| Pergunta | Resposta |
|---|---|
| `build_spend` ainda e acessivel pela wallet oficial? | Nao pela UI Tauri `wallet-desktop`; sim por `dom-wallet-app` e por RPC `wallet_spend` do node/miner sweep. |
| UI chama fluxo legado? | `wallet-desktop/ui` nao; `dom-wallet-app` sim. |
| Fluxo legado pode afetar testnet? | Sim se `dom-wallet-app` ou RPC `wallet_spend` forem distribuidos/usados. O auto-sweep do desktop tambem usa receive request + node wallet spend para miner rewards, nao Slate usuario-a-usuario. |
| Remover, esconder ou manter test-only? | Para testnet publica, esconder/remover do produto oficial ou marcar explicitamente como legacy/test-only. |

Classificacao:

| Fluxo | Classificacao |
|---|---|
| `wallet-desktop` `slate_create_send/receive/finalize` | ACTIVE OFFICIAL |
| `dom-wallet` `create_send_slate/receive_slate/finalize_slate` | ACTIVE OFFICIAL core |
| `dom-wallet-app` payment request + `build_spend` | ACTIVE LEGACY / RISKY PUBLIC PATH se distribuido |
| `Wallet::build_spend` unit/integration tests | ACTIVE LEGACY and TEST SUPPORT |
| `wallet_send` / `wallet_create_receive` Tauri commands | DEAD in Tauri surface |
| node `wallet_spend` | ACTIVE INTERNAL/MINER RPC path |

## 7. Restart / Replay Assessment

| Invariante | Resultado |
|---|---|
| Pending sender slate sobrevive restart antes de finalize | Parcialmente coberto por persistencia de `PendingTx` e tests unitarios; sem E2E node |
| Finalize antes de submit sobrevive restart | Provavel via `pending.tx_bytes`, precisa teste Tauri/core especifico |
| Submitted sobrevive restart | Coberto por journal/resubmit tests em `dom-wallet-app`; Tauri equivalente por leitura |
| Confirmed sender spend sobrevive restart | Coberto por lifecycle/reconcile tests |
| Receiver pending output sobrevive restart antes de confirmacao | Coberto por `canonical_rescan_confirms_received_slate_output_after_restart` |
| Receiver confirmed output sobrevive restart + rescan | Falha por WDSF-002 |
| Replay de receive slate duplicado nao duplica output | Nao comprovado; `receive_slate` rejeita slates ja respondidos, mas replay da mesma sender slate inicial cria nova resposta com novo blinding/hash |
| Reorg reconcilia saldo receiver | Falha por WDSF-001 |

## 8. Balance Accounting

`Wallet::balance` soma outputs nao gastos por confirmed/immature/reserved e subtrai reserved de spendable. Isso esta correto para outputs existentes no index, mas WDSF-001/WDSF-002 removem outputs do index. Portanto o problema nao e a formula de balance; e perda de tracking/persistencia do output.

Estados:

| Estado | Avaliacao |
|---|---|
| immature coinbase | Coberto por coinbase/rescan/maturity tests |
| spendable | Coberto para outputs persistidos |
| locked/reserved outgoing | Coberto por pending lifecycle |
| pending incoming | Coberto enquanto pending receive existe |
| submitted | Coberto por journal/resubmit |
| confirmed incoming Slate | Bloqueado por Repair/reorg |
| failed/cancelled | Coberto para sender pending |
| reorged receiver | Bloqueado |

## 9. Adversarial Inputs

Cobertura confirmada:

| Entrada adversarial | Resultado |
|---|---|
| Slate truncado / hex invalido | `slate_from_hex` rejeita decode/deserialize; UI limita leitura de arquivo |
| Chain id errado | Testes `receive_slate_rejects_wrong_chain_id` e `adversarial_cross_chain_slate...` |
| Amount/fee adulterado | Testes adversariais em `wallet.rs` |
| Recipient fields ausentes | Teste `adversarial_finalize_requires_all_recipient_fields` |
| Output/signature adulterados | Testes adversariais em `wallet.rs` |
| Slate de outra wallet | Teste `adversarial_non_owned_slate_is_rejected_by_finalize` |
| Submit duplicado | RPC client cobre 409; app resubmit trata 409 como sucesso |
| RPC falha | Tauri nao marca submitted em Err; app retry/failed coberto |

Precisa patch/teste adicional:

| Entrada | Status |
|---|---|
| duplicate receive_slate da mesma sender slate | PRECISA PATCH/TESTE PARA CONFIRMAR idempotencia desejada |
| duplicate finalize_slate | PRECISA TESTE; atual finalize remove secrets, segunda chamada deve falhar segura |
| node accepted not relayed | Leitura confirma warning; precisa E2E wallet state |
| tx ja confirmada submetida de novo | PRECISA TESTE node/wallet |
| commitment/kernel features inconsistente no Slate | Parcial em validate tx; precisa casos direcionados |

## 10. Validacao

Baseline solicitada:

```bash
git status --short
git branch --show-current
cargo build --workspace
cargo test -p dom-wallet
cargo test -p dom-wallet-app
cargo test -p dom-node
cargo test -p dom-integration-tests
cargo test -p dom-wallet --test robustness_rescan_nonderivable_outputs
cargo fmt --check
git diff --check
```

Resultados:

```text
git status --short:
 M audit/FABLE5_SECURITY_AUDIT.md
?? crates/dom-wallet/tests/robustness_reorg_slate_receive.rs
?? crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs

git branch --show-current:
release/wallet-v0.3.1

cargo build --workspace:
PASS

cargo test -p dom-wallet:
FAIL. Unit tests and earlier integration tests passed, then
crates/dom-wallet/tests/robustness_reorg_slate_receive.rs failed.
This file was already untracked before this audit.

cargo test -p dom-wallet-app:
PASS. 30 passed.

cargo test -p dom-node:
PASS. 214 passed, 1 ignored in lib tests; integration tests passed.

cargo test -p dom-integration-tests:
PASS. Heavy IBD two-node test passed in 480.34s. Several tests are explicitly ignored as env-blocked-wsl.

cargo test -p dom-wallet --test robustness_rescan_nonderivable_outputs:
FAIL. Both defensive tests failed, confirming WDSF-002.

cargo fmt --check:
FAIL only on pre-existing untracked files:
crates/dom-wallet/tests/robustness_reorg_slate_receive.rs and
crates/dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs.
The report is Markdown and unaffected.

git diff --check:
PASS.
```

## 11. Final Verdict

| Pergunta | Resposta |
|---|---|
| A wallet-desktop oficial usa apenas Slate para envio real? | Sim para a UI Tauri/web auditada. |
| Ainda existe caminho legado acessivel? | Sim em `dom-wallet-app` e node/miner RPC; nao como comando Tauri usuario-a-usuario. |
| Bug `slate_hash` vs `tx_hash` esta resolvido? | Para `slate_finalize` Tauri/core, sim por leitura e teste `finalize_marks_submitted_under_slate_hash_key_and_advances_journal`. |
| Fluxo A->B->A->node->block->restart funciona? | Parcial. A->B->A e node submit funcionam por componentes; falta E2E real nao ignorado e receiver confirmed falha apos rescan/reorg. |
| Bugs sao UI, wallet core, RPC ou node? | Principais bugs confirmados sao wallet core persistence/rescan/reorg. UI/RPC/node submit parecem coerentes por leitura/testes. |
| Vale corrigir wallet atual ou criar wallet v2 minima? | Corrigir wallet atual se o objetivo e preservar releases; para testnet publica, uma wallet v2 minima com store explicito de non-derivable outputs reduziria risco arquitetural. |
| Ha blocker para testnet publica? | Sim: WDSF-001 e WDSF-002. |
| Ha blocker para mainnet? | Sim. |

## 12. Limitacoes

- Nao alterei producao, consenso, PoW, RandomX, PMMR, `Cargo.toml` ou `Cargo.lock`.
- Nao criei novos testes porque os testes defensivos locais ja existentes confirmaram os blockers.
- Nao executei uma wallet-desktop GUI manual.
- Nao ha E2E nao-ignorado que prove duas wallets Slate contra node real com bloco, rescan e restart.
- Testes ignorados em `dom-integration-tests` exigem ambiente dedicado/VPS conforme anotacoes existentes.
- Achados de duplicate receive/finalize e tx confirmada resubmetida precisam testes adicionais.

## 13. Arquivos Alterados

- `audit/WALLET_DESKTOP_SLATE_FLOW_AUDIT.md`: novo relatorio de auditoria solicitado.

## 14. Forbidden File Compliance

Nenhum arquivo de producao ou arquivo proibido foi modificado. O unico arquivo criado foi o relatorio permitido pelo prompt.
