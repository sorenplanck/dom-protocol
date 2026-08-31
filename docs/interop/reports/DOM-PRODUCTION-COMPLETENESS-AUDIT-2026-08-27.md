# Auditoria de completude operacional da DOM Interop

Data: 2026-08-27

Branch: `feat/domv2-interop-absorption`

Snapshot auditado: `166b55299d5642200e0f5b7e384b14cf8bcbd17f`

Método: código, manifests, alvos compiláveis e testes; documentos não foram
usados para transformar uma capacidade ausente em capacidade existente.

## Veredito direto

**NO-GO para dinheiro real.** O snapshot contém um conjunto avançado de
bibliotecas de interoperabilidade, mas não contém o produto que as dirige.
Não existe um executor durável da rota, não existe um daemon de
interoperabilidade e não existe uma integração completa entre rota, carteiras,
signers, relay, solver e chains.

A classificação correta é:

> SDK/protocolo e autoridades de segurança parcialmente operacionais, com bons
> testes de componentes, mas ainda sem uma rede que conclua autonomamente uma
> rota com fundos reais.

O registro machine-readable desta conclusão está em
`DOM-PRODUCTION-READINESS-MANIFEST-2026-08-27.json`. Ele contém 37 requisitos:
22 ausentes, 14 parciais e uma exclusão intencional de mainnet. Trinta são P0;
35 bloqueiam a release operacional que lhes corresponde.

Esta auditoria complementa, e não substitui,
`DOM-CODE-FIRST-ABSORPTION-AUDIT-2026-08-27.md`. O relatório anterior responde
“o que absorver de Cipher, Kaystra, Kael e Keystone”. Este responde “o que deve
existir para a DOM produzir uma operação completa”.

## Separação obrigatória: snapshot e worktree

Há uma diferença material entre o commit fixado e os arquivos locais:

| Superfície | No commit `166b552…` | No worktree da auditoria | Classificação |
|---|---:|---:|---|
| `contracts/` | Não | Sim, não rastreado | Worktree-only |
| `ConditionLockV2` e `ConditionLockERC20V2` | Não | Sim | Não são entrega da branch |
| job CI de Foundry/Anvil | Não | Sim, modificação local | Não é gate da branch |
| `scripts/e2e_anvil.sh` | Não | Sim, não rastreado | Não é gate da branch |
| `RouteExecutor` | Não | Não | Ausente |
| `dom-interopd` | Não | Não | Ausente |

`git ls-tree -r --name-only 166b552… contracts` não devolve nenhum arquivo.
Logo, no snapshot, os contratos EVM não estão apenas “sem deployment”: seus
sources, testes e artefatos tampouco pertencem à árvore Git.

As alterações locais são úteis e foram preservadas, mas não foram contadas
como funcionalidade publicada. Nenhum commit ou push foi realizado nesta
auditoria.

## O que o código realmente entrega

| Capacidade | Estado | Evidência no código |
|---|---|---|
| Máquina durável por settlement | Presente | `kaystra-core/src/settlement_engine.rs:239,612`; journal/CAS/cursor/outbox em `store/src/settlement.rs` |
| Binding estático de duas pernas | Presente | `route-composer/src/lib.rs:208` |
| Ordem segura de funding | Presente como recusa | `route-composer/src/lib.rs:425` |
| Verificação `t·G == T` | Presente | `route-composer/src/lib.rs:389` |
| Contracts Store durável | Presente em Linux | `dom-scriptless-store/src/runtime/linux/session_store.rs:2042` |
| Relay durável | Presente como biblioteca Linux | `relay/src/production.rs:1,386` |
| Adaptador DOM real | Presente como `ChainSourceV1`/`EffectSinkV1` | `adapters/dom-real/src/lib.rs:930,1115` |
| Adaptador EVM | Observa e prepara chamada sem assinatura | `adapters/evm/src/adapter.rs:1,245` |
| Autoridade Bitcoin Core | Biblioteca concreta, sem runtime dono | `adapters/btc-live/src/lib.rs:1` |
| Perfil de chain | Schema validado e digestado | `chain-profile/src/lib.rs:96,217` |
| RFQ/seleção/binding | Presente como mecanismo | `rfq`, `f6-engine` |
| Solver | Referência com rate/spread estáticos | `solver/src/lib.rs:1,111` |
| Carteira DOM comum | Spend, reserva e journal comuns | `dom-wallet/src/wallet.rs:1564,1680` |
| Contratos EVM na branch | Ausentes | árvore Git do snapshot |
| Executor/daemon | Ausentes | nenhum alvo binário correspondente em `cargo metadata` |

O comentário do próprio workspace classifica os membros F2–F7 como
“Test scaffolding, never a product binary” (`Cargo.toml:75`). Isso é coerente
com o inventário:

- `f7-e2e` apenas reexporta a autoridade de anchors
  (`f7-e2e/src/lib.rs:1`);
- `f5-e2e` é um CLI manual com chaves fixas de teste
  (`f5-e2e/src/main.rs:1`);
- todas as chamadas encontradas a `SettlementEngine::tick` estão em testes e
  harnesses, não em um processo de produção;
- `route-composer` afirma que não acopla os dois engines e que o chamador deve
  dirigi-los (`route-composer/src/lib.rs:15,425`).

## O bloqueador principal: `RouteExecutorV1`

O executor deve ser uma máquina pura de rota sobre duas máquinas de
settlement. Ele não pode ser um script que chama funções em sequência nem um
wrapper que considera “erro” como terminal enquanto ainda há dinheiro preso.

A solução deve separar cinco dimensões persistidas:

| Dimensão | Exemplos |
|---|---|
| Fase de coordenação | `Negotiating`, `TermsFrozen`, `RefundsArmed`, `Funding`, `Settling`, `Recovery` |
| Progresso upstream | estado econômico, tx preparada/broadcast/final, refund executável |
| Progresso downstream | estado econômico, tx preparada/broadcast/final, refund executável |
| Visibilidade do segredo | `Private` ou `Public { first_exposure }` |
| Saúde | `Running`, `Degraded`, `RecoveryOnly`, `ManualIntervention` |

Uma enumeração linear única é insuficiente. Por exemplo, uma rota pode estar
com downstream reorged, upstream claim pendente e `t` já público. Reorg deve
regredir a observação econômica, mas jamais a visibilidade do segredo.

### Invariantes do executor

1. Nenhum funding deixa a custódia antes de ambos os refunds estarem armados.
2. Downstream só financia depois de upstream atingir a finality congelada.
3. Nenhum reveal sai sem revalidação fresca de todas as pernas.
4. Todo efeito externo nasce da mesma transação durável que registrou a decisão.
5. Todo retry conserva a identidade semântica e a chave de idempotência.
6. `SecretVisibility::Public` é monotônico e sobrevive a reorg, restart e
   restore.
7. Depois de `t` público, upstream claim tem prioridade sobre trabalho novo,
   quotes, manutenção e retries comuns.
8. “Fail closed” desabilita avanço inseguro, mas não desabilita claim/refund de
   fundos já presos.
9. Uma rota só é terminal quando as duas pernas têm resultado econômico
   terminal reconciliado.
10. Nenhum participante entrega ao executor as chaves do outro participante.

### Fluxo positivo mínimo

```text
RouteCreated
  -> TermsFrozen(profile/deployment/fee/bond digests)
  -> BothRefundsArmed
  -> UpstreamFundingCommitted
  -> UpstreamFundingBroadcast
  -> UpstreamFundingFinal
  -> DownstreamFundingCommitted
  -> DownstreamFundingBroadcast
  -> DownstreamFundingFinal
  -> RevealAuthorizationIssued
  -> DownstreamSecretBearingActionExternalized
  -> SecretPublic
  -> t re-extracted and t*G == T verified
  -> UpstreamClaimCommitted/Broadcast
  -> both outcomes reconciled terminal
```

Cada seta deve ser uma transição por evento, com revision/CAS, journal,
snapshot e comandos atômicos. O executor nunca chama uma chain diretamente a
partir do reducer.

### Saídas negativas obrigatórias

- abort antes de qualquer funding;
- upstream funded e downstream nunca financiado;
- ambas financiadas e downstream nunca claimed;
- refund de cada perna e cascade de refunds;
- RPC indisponível ou contraditório;
- funding/claim/refund preso em mempool;
- reorg antes de finality;
- reorg depois de `t` público;
- signer temporariamente indisponível;
- crash antes/depois de persist, assinatura, entrega externa e broadcast;
- rota assumida por uma nova fencing generation;
- `RecoveryOnly` ou `ManualIntervention` sem perder os timers e autoridades de
  saída.

## Handoff de `t`: a fronteira mais perigosa

O ponto mais importante não é apenas:

```rust
let t = downstream.extract_secret(evidence)?;
let t = binding.verify_revealed_scalar(&t)?;
upstream.claim(t)?;
```

O conhecimento é irreversível antes da finality. Em EVM, `t` aparece no
calldata de `claim`; em Bitcoin, pode ser extraído da assinatura final. Assim,
o estado crítico nasce quando bytes válidos saem da autoridade ou aparecem no
mempool/bloco, não quando o claim fica finalizado.

O desenho seguro é:

1. Preparar upstream claim e todos os refunds enquanto `t` ainda é privado.
2. Obter `RevealAuthorizationV1` curta, one-shot, vinculada a rota, termos,
   perfis, `T`, snapshots finalizados, ação exata, ator e orçamento restante.
3. Persistir a autorização/commitment antes de entregar a ação secret-bearing
   à carteira externa.
4. A carteira assina/transmite e devolve somente identidade pública e receipt;
   o route store não precisa guardar `t` plaintext.
5. Um watcher de urgência observa também mempool/raw transactions. Se houver
   crash entre broadcast e receipt local, ele redescobre a exposição.
6. Reextrair `t` em memória `Zeroizing`, verificar `t·G == T` e executar o
   upstream claim imediatamente.
7. Reorg do downstream não volta para `Private`; o daemon continua ambos os
   rebroadcasts porque o segredo já não pode ser recolhido.

Estado/alerta operacional obrigatório:

```text
SecretPublicButUpstreamUnclaimed
```

Ele deve ter a menor janela de retry, impedir shutdown comum sem handoff seguro
e disparar alerta máximo. Métrica, log e alerta carregam somente `route_id`,
deadlines e digests; nunca `t`.

## Persistência e concorrência da rota

As peças atuais já fornecem padrões bons de SQLite/WAL, `synchronous=FULL`,
CAS, outbox e locks. O que falta é aplicá-los à entidade rota.

`DurableRouteStoreV1` deve persistir:

- bundle/terms/profile/deployment digests congelados;
- snapshot multidimensional da rota;
- journal encadeado e revisionado;
- referências de evidência e anchors, não interpretações livres;
- comandos/outbox com bytes exatos ou commitment de custódia externa;
- timers e action-budget;
- tentativas, receipts, txids e replacement lineage;
- lease da rota e fencing epoch;
- resultado terminal de cada perna.

Não deve persistir:

- seed, private key, signing share ou secret nonce;
- `t` standalone;
- token RPC/cookie;
- payload secreto em log ou mensagem de erro.

Os stores de Contracts, Relay, BTC live e BTC vault já têm locks de processo
fortes. Isso não equivale a ownership da rota: dois composition roots podem
abrir raízes diferentes e agir sobre o mesmo lock on-chain. Por isso cada
efeito deve carregar `(route_id, fencing_epoch, effect_id)`, e cada signer deve
recusar um epoch antigo.

## O daemon de produção

O produto mínimo deve conter um binário Linux `dom-interopd`. Cada usuário ou
solver opera a própria instância; não existe um serviço central com todas as
chaves.

```text
Wallet/UI do participante
        | IPC autenticado / mTLS com capabilities
        v
dom-interopd (Linux, autoridade local)
  +-- RouteSupervisor / RouteExecutorV1
  +-- DurableRouteStoreV1 + timers + fencing
  +-- ContractsStore worker
  +-- Relay inbox/outbox worker
  +-- DOM observer/actuator
  +-- EVM observer + wallet authority
  +-- Bitcoin observer + Core wallet authority
  +-- Recovery scheduler + metrics/alerts
        |
        +--> DOM node RPC
        +--> EVM RPCs
        +--> Bitcoin Core
        +--> relay não confiável
```

Ordem de startup:

1. verificar build attestation e registro assinado;
2. adquirir lock da raiz/instância;
3. abrir stores/vaults e conferir identidades;
4. replayar e verificar snapshots;
5. reconciliar ações de custódia externa;
6. iniciar observers;
7. recuperar primeiro rotas funded e `SecretPublic`;
8. somente então aceitar RFQs/rotas novas.

O shutdown deve fazer o inverso, mas workers de urgent claim/refund só param
depois de commitarem o handoff ou de outra fencing generation assumir.

## Workers de chain

Cada chain precisa de duas superfícies distintas.

### Observer

- lê blocos/mempool dentro de limites;
- ancora cursor em hash e altura;
- diferencia “nenhum evento” de “não consegui observar”;
- produz fatos neutros e referências de evidência;
- detecta reorg e revalida;
- mantém finality econômica separada de exposição pública do segredo.

### Actuator

- prepara e faz preflight;
- solicita autorização à carteira;
- registra commitment/bytes antes de envio;
- transmite, rebroadcasta e reconcilia;
- aplica fee caps e replacement policy congelados;
- nunca reconstrói silenciosamente uma transação diferente em retry.

Regras específicas:

- EVM: nonce serializado por conta; replacement usa o mesmo nonce e conserva
  `to`, `value` e calldata, alterando somente campos de fee permitidos.
- Bitcoin: uma substituição de funding que muda txid/outpoint invalida refund
  presigned. Ela é proibida depois de armar o refund, salvo se toda a rota for
  rearmada antes do primeiro broadcast. CPFP/anchors ou uma ladder
  pré-autorizada precisam de desenho explícito.
- DOM: rebroadcast usa bytes duráveis; qualquer fee bump que muda template
  exige nova autoridade, novo nonce e nova validação do contrato.

## Carteiras e signers

### DOM

A carteira comum já seleciona/reserva inputs e guarda pending transactions.
Falta `DomInteropAuthorityV1` para:

- reservar outputs exclusivamente por `route_id`;
- derivar a share correta sem exportar seed;
- participar do shared output e Bulletproof colaborativo;
- assinar refund e claim adaptor somente sob purpose/template exatos;
- produzir o output confidencial de treasury para a chave congelada;
- reconciliar reservations, pending txs e contract sessions após restart;
- permitir claim/refund de emergência mesmo quando novas rotas estão pausadas.

### EVM

`UnsignedEvmCall` é deliberadamente correto e não custodial, mas precisa de uma
autoridade que faça:

- validação de chain/profile/address/extcodehash;
- account nonce e EIP-1559;
- assinatura, broadcast e receipt;
- replacement semanticamente idêntico;
- `approve` exato/limitado ou permit previamente vinculado;
- reconciliação depois de crash sem assinar calldata arbitrário.

### Bitcoin

`adapter-btc-live` já possui a fronteira mais próxima de produção: seleciona
UTXOs via Bitcoin Core, prepara funding sem publicar e retém bytes até refund
durável. O gap é o ownership do ciclo inteiro pelo daemon, incluindo fee,
rebroadcast, Core restart e deadlines.

### Protocolo comum de capability

Cada signer deve receber uma capability opaca com:

```text
route_id + leg_id + action_kind + exact_digest + terms/profile digest
+ fencing_epoch + expiry + one_shot_counter
```

Não deve existir método genérico `sign(bytes)` ou `broadcast(command)` no
product path.

## A parte dos contratos

### Contratos mínimos necessários

| Componente | Necessidade | Situação |
|---|---|---|
| `ConditionLockV2` nativo | Necessário para DOM↔EVM nativo | Só no worktree local |
| `ConditionLockERC20V2` | Necessário apenas para perfil ERC-20 | Só no worktree local |
| Lock de bond F4 | Pode reutilizar `ConditionLockV2/ERC20V2`; não exige novo escrow | Máquina/adapter existem, worker live não |
| Contrato Bitcoin | Não há deployment; Taproot é construído por rota | Primitivas existem |
| “Contrato DOM” novo | Não necessário; a perna usa transações DOM/adaptor off-chain | Não alterar consenso |
| Registry on-chain | Opcional; manifesto assinado off-chain é suficiente no v1 | Não criar por reflexo |
| Factory determinística | Útil, não bloqueia o primeiro deployment pinado | P1/P2 |
| Contrato de AMM/venue | Não necessário para solver com inventário próprio | P2 |

O caminho correto não é adicionar um `RouteCoordinator` on-chain. Nenhum
contrato EVM pode observar com confiança DOM e Bitcoin sem introduzir oracle,
comitê ou settlement otimista. A atomicidade continua criptográfica e cada
participante a aplica localmente.

### O que falta para os locks virarem produto

1. Sources, testes e lockfiles rastreados na branch.
2. Build Foundry reproduzível com versões e settings fixos.
3. ABI e bindings Rust gerados/pinados.
4. Manifesto por rede com chain ID, endereço, start block, runtime code hash,
   compiler/settings e tx de deployment.
5. Verificação de `extcodehash` no startup e antes de abrir rota.
6. Deployments reais nas redes habilitadas e source verification.
7. Auditoria independente sobre o bytecode final.
8. Invariants/fuzz/differential tests contra tokens e receivers hostis.
9. Monitoramento de payout deferido e gas headroom.
10. Política de asset que impeça um caller de transformar “contrato aceita” em
    “protocolo suporta”.

O v1 deve começar com native asset. ERC-20 só deve ser habilitado por entrada
de profile explícita, token/implementation revisado, decimals congelados,
allowance limitada e testes contra upgrades/retornos/balance mentiroso. Uma
instância por asset pode ser considerada para reduzir domínio de falha, mas não
é necessária para fechar o primeiro caminho nativo.

### Bond

`f4-harness` já modela bond como outro `ConditionLock`; `f6-engine` apenas
journala o identificador da reserva. Portanto o gap não é obrigatoriamente um
novo `SolverBondEscrow.sol`. É um `BondAuthority` operacional que:

- prova collateral real antes de atestar a quote;
- reserva capacidade sem double booking;
- financia o lock;
- observa release/slash;
- executa compensation;
- reconcilia tudo após restart e relay loss.

Um vault de bond reutilizável pode ser projetado depois, se a economia exigir
capital compartilhado. Ele não deve ser apresentado como requisito de
atomicidade do v1.

### Treasury

`rfq::fee_policy` calcula o valor do share confidencial, mas a superfície
encontrada verifica apenas números (`fee_policy.rs:144`). O runtime/wallet deve
vincular também a chave/output de treasury correta. Não é um contrato Solidity
e não exige mudança de consenso DOM.

## Relay até Contracts Store

`route-transport` preserva os bytes DSC1, verifica envelope/role/transcript e
devolve o payload aceito. O próprio código diz que entregar esses bytes a
`ContractsSessionStoreV1::accept_transport_message` continua sendo obrigação
do caller (`route-transport/src/lib.rs:243-256`). O caller produtivo não existe.

`RelayWorkerV1` deve:

1. puxar mailbox durável;
2. executar uma única pipeline autenticada;
3. compartilhar o mesmo `TranscriptStateV1` durável entre F6 e route messages;
4. entregar route payload byte-identicamente ao Contracts Store;
5. persistir outcome/ACK antes de avançar watermark;
6. manter foreign-kind payload disponível ao consumidor correto;
7. aplicar retry/backpressure sem perder equivocation evidence.

O relay atual tem store durável, mas nenhuma network face. `dom-relayd` precisa
de autenticação, quotas, mailbox retention, rate limit, reconnect, discovery e
rotação de identidade. O relay continua incapaz de claim/refund, por desenho.

## Solver e liquidez

`ReferenceSolverV1` transforma policy estática em quote assinada. O código diz
explicitamente que não inventa market data. `f6-engine` garante exclusividade
do identificador de reserva, não congela moedas/UTXOs reais.

O solver operacional precisa de:

- serviço de RFQ/mailbox;
- inventário por chain/asset;
- reserva transacional de outputs, UTXOs, saldo/nonce e bond;
- pricing com proveniência, staleness e exposure caps;
- quote signing e expiry;
- participação nas duas pernas até terminal;
- liberação/reconciliação de reservas;
- rebalanceamento.

AMM, agregador e exchange são venues opcionais. Eles não bloqueiam um solver
bilateral financiado com inventário próprio. Entram depois que atomicidade,
crash recovery e contabilidade de inventário estiverem fechadas.

## Registry operacional e build de produção

`ChainProfileV1` já liga timing, finality, assets, deployment address e code
hash. Falta o sistema que o torna configuração operacional:

- codec/arquivo canônico e assinado;
- versão monotônica, expiração e política de rollback;
- distribuição e cache;
- genesis/RPC identity preflight;
- rollout e revogação com semântica de rotas já abertas;
- digest congelado em cada route bundle;
- attestation no binário e nos artifacts de release.

Feature closure também é bloqueador:

- `dom-leg` usa `default = []` e o caminho disabled retorna
  `CryptoBackendDisabled`;
- `adapter-evm` deixa `rpc-http` fora do default;
- stores/relay produtivos são Linux-only;
- os gates atuais recusam `evidence-only` e relay fault injection, mas testam
  componentes separados.

`dom-interopd` deve ter um feature `production` fechado por construção, com
dependências reais não opcionais. O CI deve buildar exatamente:

```text
cargo build --release -p dom-interopd --no-default-features --features production
```

e executar `dom-interopd self-check --json`. O self-check deve provar DOM real,
EVM HTTP, Bitcoin live, stores de produção, target Linux, ausência de test
keys/mocks/failpoints e digests de registry/contratos.

## Linux e autocustódia

O Contracts Store e o relay durável são Linux-only. Isso não é uma falha se o
produto declarar a topologia correta:

- autoridade `dom-interopd` em Linux;
- app desktop/mobile como cliente;
- IPC local owner-only ou canal remoto mutuamente autenticado;
- capabilities por rota/método;
- daemon continua recovery mesmo se a UI fechar.

O canal remoto não pode transformar o daemon em custodiante central. O usuário
deve controlar a instância/keys ou usar hardware/external signer com policy
verificável.

## Semântica de restart do `ContractStateV1`

A suspeita é real no tipo isolado:

- `ContractStateV1::resume` restaura stage, transcript e sequências;
- reinicializa `session_id`, últimos digests por papel e equivocation evidence
  (`dom-adaptor/src/contract_session.rs:557`);
- o próprio teste aceita que o duplicate pós-restart vira `Replay` ou
  `ForkedTranscript`, não `DuplicateAck` (`contract_session.rs:1017`).

Mas há uma nuance essencial: `ContractsSessionStoreV1` possui outra pipeline
durável e seus testes preservam duplicate/equivocation após reopen
(`session_store.rs:13474`) e em crash cuts (`session_store.rs:13743`). Portanto:

- não é prova de exploit em um runtime atual — esse runtime não existe;
- é uma armadilha latente para o futuro composition root;
- o daemon deve ser proibido de usar `ContractStateV1::resume` diretamente.

Dois fechamentos aceitáveis:

1. usar exclusivamente o Contracts Store como autoridade e tornar o resume
   isolado inacessível ao product path; ou
2. criar `ContractCheckpointV2` autenticado com session ID, últimos
   `(sequence,digest)` e equivocation evidence.

Em ambos os casos os testes devem cobrir accept → restart → duplicate,
accept → restart → conflict, troca de session ID e preservação de
`FailedClosed`/evidence.

## E2E que existe versus o que falta

| Cenário | Cobertura atual | Gate de produto |
|---|---|---|
| Dois engines, mesmo `T` | Simulado, handoff manual | Daemon dirige ambos |
| EVM + Bitcoin reais | Harness ignorado, DOM fixture | DOM real + processos separados |
| DOM↔EVM claim/refund | Componentes/Anvil local | Carteiras e daemon reais |
| DOM↔BTC claim/refund | BTC Core real isolado | DOM real e daemon |
| Crash de settlement | Forte por componente | Crash em cada fronteira da rota |
| Duplicate/equivocation | Forte no Contracts Store | Atravessar relay worker e daemon |
| Relay loss | Forte em harness | Relay em processo/rede separado |
| Reorg pré-finality | Adaptadores | Rota recompõe decisões |
| Reorg após `t` público | Sem reação produtiva | `SecretPublic` não regride; claim urgente |
| Crash entre os dois claims | Ausente | Restart extrai evidência e claim upstream |
| Funding preso/fee bump | Ausente na rota | Policy específica por chain |
| RPC indisponível | Testes de adapter | Health/backoff sem avançar cursor |
| Dois executores | Locks de componente | Lease/fencing de route ID |
| Restore durante rota | Backups isolados | Restore coordenado + reconciliação |
| Signer/hardware offline | Ausente | Recovery lane e action-budget |
| Profile/deployment trocado | Validações isoladas | Startup/route/reveal revalidation |

O E2E final deve iniciar processos separados:

```text
initiator wallet + initiator interopd
solver wallet/inventory + solver interopd
dom-relayd
DOM node(s)
Anvil ou EVM testnet node
Bitcoin Core regtest/custom signet
contratos rastreados e deployment pinado
```

Além do estado final, deve provar:

- zero funding sem refund;
- zero reuse de nonce/share;
- zero efeito econômico duplicado;
- zero cursor avançado sem consequência durável;
- zero `t` standalone em stores/logs/artifacts;
- nenhum reorg torna `t` privado de novo;
- toda perna funded termina claimed ou refunded;
- nenhum segundo executor ultrapassa fencing;
- nenhuma restauração aceita trabalho novo antes da reconciliação.

## Operação que falta

Os componentes têm bastante engenharia de backup e lock. A lacuna é
coordenação de produto, não ausência absoluta dessas primitivas.

Antes de fundos reais são obrigatórios:

- metrics/readiness por rota;
- alerta `SecretPublicButUpstreamUnclaimed`;
- alertas de deadline budget, observer lag, RPC disagreement, outbox backlog,
  mailbox gap, signer loss, fee cap e backup stale;
- backup consistente de route store, Contracts Store, vaults, wallet e
  identities;
- cópia off-host criptografada e restore drill;
- RPO/RTO explícitos;
- schema migration/upgrade N/N−1;
- drain sem abandonar recovery;
- transferência de ownership com fencing;
- rotação de chaves/identidades sem reescrever roster de rota aberta;
- secret scanner read-only sobre logs, SQLite/WAL, crash dumps e evidence
  exports.

A DOM node já expõe Prometheus, mas a camada interop não possui daemon nem
métricas de rota. Backup/restore forte existe no Contracts Store, porém partes
da criação/publicação são `evidence-only`; não há backup coordenado do sistema
inteiro.

## Como as absorções entram nesta solução

| Fonte | Absorção | Onde entra |
|---|---|---|
| Cipher | reviewer independente e fixtures reais | evidence workers e E2E |
| Kaystra | guard multi-leg, margin calibration, watcher e sanitizer | reveal authority, actuator, policy e release gate |
| Kael | kernel puro, revalidação anti-TOCTOU e signer preflight | RouteExecutor e SignerBoundary |
| Keystone | consenso Bitcoin/checkpoints/differential testing | Bitcoin observer/evidence; perfil otimista continua opcional |

Nenhuma dessas absorções substitui o `RouteExecutor`. Elas endurecem decisões
que só passam a ter efeito quando o runtime existe.

## Ordem de implementação

### M0 — runtime durável, ainda sem valor real

- `crates/route-executor` com reducer/eventos/invariantes;
- route store, outbox, timers, leases e fencing;
- `dom-interopd` Linux;
- relay-to-store worker com transcript único;
- reveal authority e signer capabilities;
- registry loader e feature closure;
- claim/refund/crash com chains simuladas dirigidos pelo binário.

Saída: o daemon, e não o teste, é o dono da rota.

### M1 — duas rotas verticais

1. DOM↔EVM em DOM regtest + Anvil, após rastrear os contratos.
2. DOM↔Bitcoin em DOM regtest + Bitcoin Core regtest/custom signet.

Inclui carteiras, actuators, deployments e restore. Claim e refund devem ser
automáticos; nenhuma chave fixa ou comando manual pertence ao product path.

### M2 — rota composta e solver financiado

- mesmo `T` nas duas pernas;
- handoff automático e urgent lane;
- solver de inventário fixo;
- reservas reais e bond live;
- EVM→DOM→Bitcoin multiprocesso.

Saída: a rota completa converge após crash entre downstream reveal e upstream
claim.

### M3 — gate adversarial de produção

- network relay/admission;
- fault matrix completa;
- dois executores/fencing;
- backup/restore disaster drill;
- observabilidade e alertas;
- auditoria independente dos contratos e release artifact;
- sanitizer/evidence gate.

Somente depois disso faz sentido discutir venues externos ou mainnet. Bitcoin
mainnet é hoje intencionalmente irrepresentável e Ethereum chain ID 1 é
recusado; removê-los é uma decisão de segurança separada, não um flag de
deployment.

## Critério final de GO

A DOM Interop só pode ser chamada de operacional quando o artefato exato de
release provar, de forma automatizada:

1. um processo produtivo dirige a rota inteira;
2. cada participante conserva autocustódia;
3. contratos e deployments pertencem à branch e são code-hash pinned;
4. refund existe antes de funding;
5. reveal depende de snapshot fresco e one-shot capability;
6. `t` público dispara upstream claim imediato e nunca regride após reorg;
7. crash/restart/duplicate/reorg/replacement/restore convergem;
8. solver reserva fundos e bond reais sem overbooking;
9. build não contém backend disabled, mocks ou fault surfaces;
10. operação detecta e recupera rotas em risco.

Até todos esses gates passarem, a frase tecnicamente honesta é: **a DOM possui
o motor e várias autoridades, mas ainda não possui o veículo que executa a
interoperabilidade.**
