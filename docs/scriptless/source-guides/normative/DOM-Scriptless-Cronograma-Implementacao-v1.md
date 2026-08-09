# DOM Scriptless Contracts — Cronograma de Implementação
## Do estado atual ao primeiro contrato rodando

Data: 2026-08-04
Escopo: V1 estrito — **2-de-2, funding / claim por adaptor / refund por timelock absoluto**.
Fora do escopo V1: n-de-n, threshold, camada declarativa, swap cross-chain, canais.

Regra que ordena tudo: **cada fase termina com um artefato demonstrável em regtest**
antes de a seguinte começar. Durações são ordens de grandeza, não compromissos.

---

## FASE 0 — Gates de viabilidade · **PAGA**

Não é trabalho futuro; é o que já foi provado e sustenta o resto.

| Gate | Resultado | Evidência |
|---|---|---|
| O-01 · paridade do adaptor | VERDE, sem fator de sinal | 10.017/10.017 casos, 16 combinações de paridade; o verificador da DOM usa SEC1 de 33 bytes, sem normalização x-only |
| O-03 · timelock ponta a ponta | VERDE | rejeição `TemporarilyInvalid` sem punir reputação, aceite exato na altura, refund pré-assinado guardado 20 blocos e aceito de primeira |
| BP colaborativa × 2 commits | VERDE | 739 bytes, mesmo verificador, `wire_differences_outside_proof = 0` |
| O-02 · recuperação do output compartilhado | DECIDIDO: C2 (decoy canônica) | C1 inviável por aritmética (déficit ≥16 bytes); corpus 100k+100k, 2.891 testes, menor p 118× acima do limiar |
| B1 · inputs congelados | CORRIGIDO | tombstone terminal + expiração segura + cancelamento na UI |

Artefatos já no repositório: **8 vetores canônicos do adaptor** (commit `7698225`),
**builder HEIGHT_LOCKED** (`19c191f`), **RPC expondo features/lock_height** (`76597c6`).

---

## FASE 1 — Fundação criptográfica (`dom-adaptor`)

**Objetivo:** transformar o que foi provado em laboratório em biblioteca de produção.

**Entregáveis**
1. Crate novo `dom-adaptor` (isolado, para facilitar revisão externa), com:
   - `presign(x, k, T, msg) -> ŝ` · `verify_presign(ŝ, R̂, X, T, msg)` ·
     `adapt(ŝ, t) -> s` · `extract(s, ŝ) -> t`;
   - canonicidade: rejeição de `T` = identidade, escalar 0 ou ≥ n, pontos não canônicos.
2. **Esquema de dois nonces com binding** (`R_i = R_i1 + b·R_i2`), que é a defesa contra
   ataques de sessões paralelas (Wagner/ROS) — o aggsig atual é de 2 rounds sem binding.
3. **Nonce Vault** com consume-before-export: o nonce é marcado como consumido e
   *persistido* ANTES de sair da máquina. Crash matrix implementada: falha em cada ponto
   do ciclo nunca resulta em reuso.
4. Testes contra as **fixtures canônicas** já congeladas (V01..V08) — usando o
   verificador real de consenso, nunca reimplementação.

**Gate de saída (G1):** o crate reproduz os 8 vetores byte a byte; property test de ciclo
fechado (`extract(adapt(presign)) == t`) em ≥10.000 casos aleatórios; teste de crash
provando ausência de reuso de nonce em cada ponto de falha.

**Risco:** baixo. A matemática está provada; é engenharia de tradução.
**Ordem de grandeza:** semanas.

---

## FASE 2 — Output compartilhado (a peça dura)

**Objetivo:** duas partes criam um output `C = v·H + (r_A + r_B)·G` sem que nenhuma
conheça `r`, com range proof válido e indistinguível.

**Entregáveis**
1. Protocolo de blinding conjunto: cada parte contribui `r_j`, ninguém aprende a soma.
2. **Bulletproof colaborativa** integrada ao caminho real de construção de output —
   três fases sobre o mesmo FFI que a DOM já linka (`tau_x`/`t_one`/`t_two` deixam de ser
   NULL), com `n_commits = 2`, `value_gen = H_DOM` e o extra-commit da capsule.
3. **Decoy canônica determinística**: framing `01 00 || nonce[12] || 50 00 || body[80]`,
   com os 92 bytes variáveis gerados por commit-reveal bilateral **e contribuição
   derivada deterministicamente** de (segredo de longo prazo ‖ id de sessão) — para que
   abortar e reiniciar não gere sorteio novo (fecha o canal por grinding).
4. **PoK do commitment parcial** da contraparte (assinatura Schnorr sobre `C_j` com `r_j`)
   — lacuna do mwc que a DOM não deve herdar.

**Gate de saída (G2):** em regtest, duas wallets constroem e publicam um output
compartilhado; o output é aceito pelo consenso; mede 872 bytes no wire; nenhum
participante isolado consegue gastá-lo; `HugePages`/perf sem regressão.

**Risco: ALTO — é o único marco sem precedente direto em produção.** O teste isolado
passou, mas a integração ao slate real, sob crash e reorg, é onde estimativa estoura.
**Ordem de grandeza:** semanas a um mês.

---

## FASE 3 — Sessão, transporte e estado

**Objetivo:** a coreografia sobrevive a mundo real — crash, reinício, contraparte lenta.

**Entregáveis**
1. Envelope off-chain de contrato (formato próprio, versionado, com id de sessão,
   papéis, transcript e anti-replay).
2. **Máquina de estados do contrato**, estendendo o `TransactionLifecycle` que já existe
   na wallet v3, com evidência por transição e retomada após restart.
3. Persistência atômica dos bytes finalizados (o padrão já estabelecido na Missão 2:
   o envelope é descartável, os bytes são a autoridade).
4. Política de deadlines derivada, não arbitrária — margens em **altura de bloco**,
   calculadas a partir de propagação e profundidade de reorg observadas na mainnet.

**Gate de saída (G3):** teste de interrupção em **cada** passo do protocolo; em todos os
cortes, ou o contrato prossegue corretamente, ou aborta liberando reservas com segurança.
Nenhum estado intermediário perde fundos ou trava input indefinidamente.

**Risco:** médio. É onde mora a maior parte do trabalho de engenharia.
**Ordem de grandeza:** semanas.

---

## FASE 4 — Funding com refund pré-assinado

**Objetivo:** o dinheiro entra no contrato **só depois** de existir saída garantida.

**Entregáveis**
1. Ordem inviolável (é a propriedade de segurança central):
   (a) partes montam o funding **sem assinar**;
   (b) co-assinam o **refund** gastando o output compartilhado, com
       `KERNEL_FEAT_HEIGHT_LOCKED` e `lock_height = H_refund`;
   (c) **só então** assinam e publicam o funding.
2. **Gate de backup bilateral**: dois ACKs verificados de roundtrip do share
   (exportar → reimportar → conferir contra `share·G`) antes de qualquer funding.
   Consequência assumida do C2: o output compartilhado é irrecuperável da chain.
3. Escada de refunds com fees escalonadas (MW não tem RBF; a fee está congelada na
   mensagem assinada e pode envelhecer abaixo do mínimo de relay).

**Gate de saída (G4):** abandono simulado em cada passo; em todos, ou ninguém perde
fundos, ou o refund destrava em `H_refund` e é aceito de primeira — reproduzindo o
resultado já obtido no gate O-03, agora sobre output compartilhado.

**Risco:** médio. As peças existem; o risco é de ordenação e de estado.
**Ordem de grandeza:** semanas.

---

## FASE 5 — Claim condicional por adaptor

**Objetivo:** a saída pela **condição**, complementar à saída por timeout.

**Entregáveis**
1. Claim pré-assinada deslocada por `T`; ao publicar, `t` fica extraível do kernel.
2. Extração pelo observador e verificação `t·G == T`.
3. Análise de timing: `t` é extraível do mempool **antes** da confirmação. Sem timelock
   relativo na DOM, a única proteção é a margem `H_refund − altura_do_claim` — definir
   piso de claim e estudar a interação com Dandelion++ (fase stem).

**Gate de saída (G5):** ciclo completo em regtest com os **dois** terminais obrigatórios:
(i) caminho feliz com extração verificada byte a byte; (ii) refund sem revelação.
Mais um caso adversarial de claim próximo ao deadline.

**Risco:** médio.
**Ordem de grandeza:** semanas.

---

## FASE 6 — Primeiro contrato rodando

**Definição de pronto — a propriedade existe quando isto for verdade:**

> Duas wallets independentes, em regtest, criam um escrow 2-de-2 com timeout; o contrato
> resolve pelas duas vias (condição e timeout) em execuções distintas; **e um observador
> com acesso total à chain não consegue distinguir nenhuma dessas transações de
> transações comuns** — mesmo tamanho de kernel (115 bytes), mesmo peso, mesmo envelope
> de output (872 bytes), capsule presente e indistinguível.

**Entregáveis**
1. Suíte E2E integrada rodando os dois terminais ponta a ponta.
2. **Gate de indistinguibilidade** como teste permanente: um script que, dado um bloco,
   tenta separar transações de contrato das comuns e **falha em fazê-lo**.
3. Documentação pública do desenho, para revisão externa.

**Ordem de grandeza:** dias, se as fases anteriores estiverem verdes — é integração.

---

## TRANSVERSAIS (correm em paralelo, não bloqueiam)

**T1 — Anonymity set do refund (começar JÁ, precisa de calendário).**
Hoje nenhuma wallet emite `lock_height` — o primeiro refund real seria um farol.
Decisão pendente: `N` **sorteado** numa faixa, não fixo. Um `N = 6` fixo cria assinatura
própria (transação comum entraria em `lock_height + ~6`; refund em `lock_height + ~0-2`),
e a distância vira o distinguidor. Faixa sorteada que sobreponha as duas distribuições.
**Custa duas linhas de código e meses de calendário — por isso é o item mais urgente
dos transversais.**

**T2 — MuSig2 / anti rogue-key.**
A agregação atual é soma plana de chaves; o próprio repositório reconhece o risco
(`fix008_rogue_key_aggregation.rs`). Para 2-de-2 com funding co-construído e verificação
mútua o risco prático é menor, mas é **pré-requisito antes de mainnet**, não antes do
demo em regtest. Especificação já existe (RFC-0009), tags de domínio já reservadas.

**T3 — Revisão externa.**
Convidar quem gosta de quebrar assim que houver crate concreto (fim da Fase 1).
A segurança da **composição** — adaptor + dois nonces + excess MW + BP colaborativa na
mesma sessão — é consistente mas não provada, e nenhum gate interno fecha isso.

**T4 — Validação de regressão pesada.**
`ibd_two_node` não roda na máquina atual. Antes de qualquer release binária do nó,
executar em hardware adequado (o `node.rs` foi tocado na Missão 2).

---

## CAMINHO CRÍTICO, EM UMA LINHA

`Fase 1 (adaptor) → Fase 2 (output compartilhado) → Fase 3 (sessão) → Fase 4 (funding+refund) → Fase 5 (claim) → Fase 6 (E2E)`

A **Fase 2 é o gargalo** e concentra o risco de cronograma. As Fases 1 e 3 podem ter
trabalho paralelizado por agentes distintos (crates diferentes); as 4 e 5 dependem
estritamente da 2.

## O QUE NÃO ESTÁ NESTE CRONOGRAMA (deliberado)

n-de-n e threshold · árbitro 2-de-3 · camada declarativa de contratos ·
swap atômico cross-chain · canais de pagamento (exigiria timelock **relativo**, que não
existe na DOM e seria hard fork) · auditoria externa paga.

Nada disso é necessário para a DOM passar a ter a propriedade. Tudo isso é o que vem
**depois** de ela existir.
