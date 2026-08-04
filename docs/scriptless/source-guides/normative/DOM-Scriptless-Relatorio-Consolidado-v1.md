# DOM Scriptless Contracts — Relatório Consolidado de Viabilidade
## O que foi alterado no código e o que os testes comprovam

Data: 2026-08-04
Repositórios: `dom-release` (branch `release/mainnet`) e `dom-wallet-v3`
(branch `redesign/restore-remote-scan`)

Disciplina do documento: **CONFIRMADO** exige evidência executada (arquivo:linha, saída
real de teste ou hash de artefato). Tudo o mais está na seção final, declarado como não
provado.

---

# 1. RESUMO EXECUTIVO

Quatro perguntas de viabilidade foram levantadas antes de qualquer implementação de
contratos privados na DOM. As quatro foram respondidas com experimento, não com
argumento:

| Pergunta | Resposta | Como foi provado |
|---|---|---|
| O adaptor Schnorr fecha contra o verificador real da DOM? | **Sim, sem fator de sinal** | 10.017/10.017 casos, 16 combinações de paridade |
| Um kernel com timelock atravessa a pilha inteira? | **Sim** | rejeição, aceite exato na altura, refund guardado 20 blocos e aceito de primeira |
| Um Bulletproof pode ser gerado a várias mãos no formato da DOM? | **Sim** | 739 bytes, mesmo verificador, zero diferenças de wire |
| Um output compartilhado pode ser recuperável sem virar marcador? | **Sim, por decoy canônica** | 200.000 amostras, 2.891 testes, nenhum distinguiu |

**Consequência:** a DOM tem, hoje, todas as primitivas necessárias para contratos
multisig privados que finalizam na chain como transações comuns. Nenhuma exige mudança
de consenso. O que falta é engenharia de integração, não descoberta.

---

# 2. PROVAS DE VIABILIDADE

## 2.1 Gate SC-AD0 — Adaptor signatures sobre o kernel da DOM

**Pergunta:** o esquema `R̂ = R + T`, `ŝ = k + e·x`, `s = ŝ + t`, `t = s − ŝ` fecha
contra o verificador de consenso, em todas as combinações de paridade de pontos?

**Método:** probe que executa o ciclo completo verify → adapt → verify → extract,
verificando a assinatura final com o **verificador real de consenso**, não com uma
reimplementação de teste.

**Resultado — CONFIRMADO**
- 10.017 de 10.017 casos com `t' == t` exato;
- 16 combinações de paridade cobertas (prefixos 0x02/0x03 de R, X, T e R̂);
- zero extrações de `−t`, zero rejeições indevidas;
- causa estrutural: **o verificador da DOM usa SEC1 completo de 33 bytes para R e X, sem
  normalização BIP340/x-only** — é essa divergência de projeto em relação ao Bitcoin que
  elimina a classe inteira de bugs de sinal que atormenta adaptors sobre BIP340;
- subproduto: uma assinatura construída com `k` e `x` escolhidos foi aceita pelo wrapper
  real de consenso.

**Artefatos:** relatório com SHA-256 `037e2126…a1b17`; extrato de 8 vetores com SHA-256
`e99ad8a3…eaa4b`; probe em `crates/dom-node/src/bin/adaptor_parity_probe.rs`
(mantido não rastreado, fora do repositório).

## 2.2 Gate O-03 — Kernel HEIGHT_LOCKED de ponta a ponta

**Método:** dois nós regtest reais, com P2P, mempool, relay Dandelion++ e mineração —
não simulação em memória.

**Resultado — CONFIRMADO**

| Caso | Observado |
|---|---|
| Transmitir antes da altura | rejeitado com `TemporarilyInvalid: kernel locked until height 24, current 4` |
| O peer pune o remetente? | **Não** — `ban_score` 0 → 0 após relay Fluff real pelo fio |
| O mempool retém para depois? | **Não** — não existe fila para transação futura (existe `FutureBlockQueue` para blocos, não para tx) |
| Mineração até H+19 | nenhum bloco pôde incluir a transação |
| Na altura exata (H = lock_height) | **aceita** — os mesmos bytes rejeitados em 23 foram aceitos em 24, sem reconstrução |
| **Refund pré-assinado** | assinado em H=25 com lock=45, guardado 20 blocos **sem tocar a rede**, transmitido uma única vez em 45 → aceito de primeira, propagado e minerado. **Zero retransmissões** |
| Invariante de malleabilidade | bidirecional e fechada: `(0x02, 0)` e `(0x00, ≠0)` ambos rejeitados |

**Semântica firmada:** `lock_height` é a **primeira** altura válida (a condição de
consenso é `lock_height > current`), não a última bloqueada.

**Achado de privacidade — CONFIRMADO:** um kernel HEIGHT_LOCKED tem **exatamente** o
mesmo tamanho (115 bytes) e o mesmo peso (3) de um kernel comum, porque `lock_height`
é um `u64` sempre presente no fio. Sem penalidade de taxa, sem sinal de tamanho.
Diferem apenas 9 dos 115 bytes.

## 2.3 Bulletproof colaborativo no formato da DOM

**Pergunta:** a prova agregada de 2 commitments (739 bytes, gerador H custom, extra-commit
da recovery capsule) sobrevive à geração a várias mãos?

**Resultado — CONFIRMADO**
- o protocolo multiparte **já está compilado e linkado** no binário da DOM: é o mesmo
  entry point C `secp256k1_bulletproof_rangeproof_prove` que ela já chama, com os três
  parâmetros de fase (`tau_x`, `t_one`, `t_two`) hoje passados como NULL — e a declaração
  FFI da DOM em `bulletproof_bp.rs:154-175` **já os inclui**;
- o C vendorizado é **byte-idêntico** ao de referência (diff recursivo: zero diferenças);
- o `H_DOM` custom entra como `value_gen`, o 14º parâmetro, lido **antes** de qualquer
  bifurcação de fase;
- o extra-commit da capsule é absorvido no transcript antes do early-return da fase 1;
- teste executado com `n_commits = 2`: **739 bytes, mesmo verificador,
  `wire_differences_outside_proof = 0`**;
- **indistinguibilidade estrutural:** não existe bifurcação no código de serialização —
  prova multiparte e de parte única saem do mesmo bloco, com forma algébrica idêntica.

## 2.4 Gate O-02 — Recuperação do output compartilhado sem virar marcador

**Problema:** uma capsule que devolva o blinding completo permitiria gasto unilateral;
uma capsule ausente seria um marcador on-chain.

**Aritmética que eliminou a alternativa (C1, duas capsules por-share) — CONFIRMADO**
```
96 bytes totais − 2 (version) − 12 (nonce) − 2 (length) = 80 de payload
seção mínima por share: 32 (share) + 16 (tag AEAD) = 48
2 × 48 = 96 > 80  →  déficit de 16 bytes, no melhor caso
com value e domínio: 104 a 160 bytes  →  não cabe
```

**Evidência empírica do marcador — CONFIRMADO** (varredura da chain local, altura 14.522):
entre outputs **regulares**, 4 de 4 têm capsule. A ausência global (41% do total) é
efeito de coinbases, que são publicamente distinguíveis. Um output regular sem capsule
seria o primeiro da história da chain.

**Solução adotada (C2) e validada — CONFIRMADO**
- decoy canônica: `01 00 || CSPRNG[12] || 50 00 || CSPRNG[80]` — 96 bytes aleatórios
  **não** serviriam, porque o parser exige o header fixo e falharia com erro em vez de
  `Ok(None)`;
- gerada por **commit-reveal bilateral**: nenhuma parte fixa unilateralmente qualquer
  byte (teste `neither_party_unilaterally_fixes_any_variable_byte` altera cada um dos 92
  bytes de uma parte e comprova que o byte on-chain correspondente muda);
- para seed de terceiro, capsule real alheia e decoy percorrem o **mesmo caminho de falha
  AEAD** e retornam `Ok(None)`.

**Corpus estatístico — CONFIRMADO**
- 100.000 capsules reais (pelo construtor de produção `create_recovery_capsule`) e
  100.000 decoys;
- 2.891 testes **pré-registrados**, alfa familiar 0,01, correção de Bonferroni
  (limiar 3,459 × 10⁻⁶);
- bateria: qui-quadrado por posição, entropia de Shannon, frequência de bits (736
  posições), autocorrelação (lags 1..16), janelas de 4 bytes com 4.096 buckets
  equiprováveis;
- **menor p-valor de toda a bateria: 4,109 × 10⁻⁴ — cerca de 118 vezes acima do limiar**;
- **2.891/2.891 passaram. Nenhum teste distinguiu os conjuntos.**
- artefatos com SHA-256 publicados (corpora de 9,6 MB cada, tabela completa de p-valores).

---

# 3. CÓDIGO ALTERADO E COMMITADO

## 3.1 `dom-release` — três commits

**`19c191f` — `feat(tx): build height-locked kernels`** (2 arquivos, +136 −32)
O hardcode de `lock_height = 0` existia em **cinco** pontos, não dois:

| Ponto | O que era |
|---|---|
| `dom-slate/src/lib.rs:303` | literal `lock_height: 0` no Slate |
| `dom-slate/src/lib.rs:620` | `finalize` fixava `KERNEL_FEAT_PLAIN` |
| `dom-slate/src/lib.rs:696` | `plain_kernel_message` estampava PLAIN na **mensagem assinada** |
| `dom-tx/src/lib.rs:307` | literal no `TransactionKernel` |
| `dom-tx/src/lib.rs:339-343` | guard fail-closed: *"SpendBuilder currently emits plain kernels"* |

Correção: a feature passa a ser **derivada** de `lock_height` num único ponto, tornando
o builder estruturalmente incapaz de emitir os pares proibidos. API aditiva
(`build_send_with_lock_height`); o caminho PLAIN permanece byte-idêntico.

**`76597c6` — `feat(rpc): expose kernel height locks`** (3 arquivos, +183 −3)
`features` e `lock_height` passam a aparecer em `/tx/:tx_hash`, `/block/:height_or_hash`
e `/mempool`. Antes, **nenhuma superfície** os expunha — só a `ScanKernel` da wallet-core.
Um pagamento travado por altura era indiagnosticável para usuário e operador.
Mudança aditiva; consumidores atuais não quebram.

**`7698225` — `test(consensus): freeze SCAD0 adaptor vectors`** (2 arquivos novos, +162)
Os 8 vetores do gate SC-AD0 viram fixtures canônicas permanentes, com teste que
reexecuta cada um contra o verificador real de consenso.

## 3.2 `dom-wallet-v3` — quatro commits

**`fa2f3e7` + `767788b` — correção do B1 (inputs congelados)**

O bug: um envio abandonado no round 1 imobilizava o **input inteiro** para sempre. A
reserva sobrevivia a `kill -9`, não havia TTL nem varredura de órfãos, e o
`dom-wallet-rescan` **não resolvia** — ele *reaplicava* a reserva
(`wallet.rs:1113-1130`, comprovado com `pending_retained: 2, pending_dropped: 0`).
A única saída (`slate_cancel`) existia, funcionava, e estava marcada `#[allow(dead_code)]`
**fora** do `generate_handler!` do Tauri: o usuário não tinha affordance nenhuma.

Correção:
- `slate_cancel` registrado como comando Tauri, com botão na UI;
- `TransactionLifecycle::Cancelled` como **tombstone terminal** que o rescan respeita;
- expiração automática **somente** quando o envelope expirou **e** não existe transação
  finalizada persistida;
- pós-finalize **nunca** libera automaticamente — só manual, com aviso de risco de gasto
  duplo, porque a contraparte ainda pode transmitir;
- rollback de reorg restaura a reserva sem duplicar;
- defaults retrocompatíveis para estados criptografados antigos.

**`b4847f2` — `feat(wallet): plumb height-locked sender kernels`** (3 arquivos, +105 −36)
`build_sender` aceita `kernel_features` e `lock_height` opcionais; `None/None` preserva
PLAIN/0; pares explícitos inconsistentes falham fechados.

**`abb5731` — `fix(wallet): decouple finalized tx from slate expiry`** (3 arquivos, +23 −20)
Decisão de desenho: **o envelope é descartável após a assinatura**. O `expires_at_height`
governa a vida da *negociação*; `lock_height` governa a validade *consensual* — e pode
excedê-lo legitimamente. O submit/rebroadcast passa a ler os bytes finalizados
persistidos sem revalidar o envelope. Sem isso, um refund travado além do teto de 1.440
blocos da wallet ficaria inutilizável.

---

# 4. TESTES QUE COMPROVAM

## 4.1 `dom-release`

| Suíte | Resultado |
|---|---|
| `dom-slate` + `dom-tx` + `dom-rpc` | **139 passaram, 0 falharam** |
| `dom-consensus` | **117 passaram, 0 falharam** |
| Fixtures SCAD0 (isolado) | **1/1 verde, cobrindo 8/8 vetores** |
| KAVs de congelamento de bytes | **4/4 verdes** — provam que o caminho PLAIN não se moveu |
| `cargo check -p dom-node` · `fmt` · `clippy -D warnings` | verdes |

Testes específicos que sustentam a viabilidade:
- fronteira de timelock em `lock_height − 1`, `lock_height` e `lock_height + 1`;
- assinatura sobre a tripla `(features, fee, lock_height)` — prova que remetente e
  destinatário assinaram a **mesma mensagem** contendo o byte de feature;
- ausência de downgrade para PLAIN;
- canonicidade bidirecional (os dois pares proibidos rejeitados, cada um com sua mensagem);
- ciclo adaptor completo por vetor: verify → adapt → verify (consenso) → extract →
  `t' == t` e `t'·G == T`.

## 4.2 `dom-wallet-v3`

| Suíte | Resultado |
|---|---|
| `dom-wallet-core` | 22 |
| `dom-wallet-core-restore` | 12 |
| `dom-wallet-domain` | 12 |
| `dom-wallet-storage` | 16 |
| `dom-wallet-core-sync` | 41 |
| Frontend | 46 |
| Production cutover | 3 |
| `protocol` + `core` + `storage` (missão 2) | 45 |

Destaques:
- `kill -9` real (SIGKILL de processo filho, sem destrutor) → reabertura → cancelamento →
  input disponível → rescan **não** reaplica;
- transação finalizada com `features = HEIGHT_LOCKED` e `lock_height = 4242`, com
  verificação dos bytes decodificados;
- bytes finalizados **exatos** sobrevivem ao restart do armazenamento criptografado.

## 4.3 Laboratório C2

6 testes verdes, mais a bateria estatística completa executada em perfil release.

---

# 5. O QUE AINDA **NÃO** ESTÁ PROVADO

Esta seção existe porque um relatório sem ela não merece confiança.

1. **A segurança da composição.** Cada peça isolada tem literatura sólida (adaptor de
   identification schemes, binding do MuSig2, sigma-protocols). A composição —
   adaptor + dois nonces + excess MW + Bulletproof colaborativa na mesma sessão — é
   consistente, mas **não está coberta por prova publicada**. Exige revisão de
   criptógrafo externo; nenhum gate interno substitui isso.

2. **Ataques de sessões paralelas (Wagner/ROS).** O aggsig atual é de 2 rounds sem
   binding de nonce. Com uma sessão por vez o risco é contornável; uma biblioteca de
   contratos abre muitas sessões concorrentes. Mitigação estrutural: o esquema de dois
   nonces (Fase 1) e o MuSig2 do RFC-0009.

3. **Rogue-key.** A agregação é soma plana de chaves; o próprio repositório reconhece o
   risco em `fix008_rogue_key_aggregation.rs`. Para 2-de-2 com verificação mútua o risco
   prático é menor, mas é **pré-requisito antes de mainnet**.

4. **Grinding por abort na decoy.** O commit-reveal impede escolha adaptativa e controle
   unilateral, mas uma parte pode abortar depois de ver o resultado e repetir a sessão
   até obter bytes que lhe agradem. Correção prevista: contribuição derivada
   deterministicamente de (segredo de longo prazo ‖ id de sessão).

5. **Não distinção estatística não é prova de indistinguibilidade.** A bateria confirma
   ausência de sinal nos testes, corpus e limiar descritos. Não exclui um distinguidor
   diferente ou um corpus adversarial maior.

6. **Anonymity set inexistente hoje.** Nenhuma wallet emite `lock_height` — o primeiro
   refund real seria um farol. Requer política de emissão rotineira **com N sorteado**
   (um N fixo cria assinatura própria) e meses de calendário para o conjunto se formar.

7. **Nada disso foi integrado ao fluxo de produção.** As etapas do C2 são laboratório.
   O que está commitado é a fundação (builder, RPC, fixtures, correção do B1).

8. **Regressão pesada pendente.** A suíte `ibd_two_node` não foi executada nesta máquina;
   o `node.rs` foi tocado na exposição do RPC. Validação em hardware adequado é
   pré-requisito da próxima release binária do nó.

---

# 6. CONCLUSÃO

Todos os bloqueadores de viabilidade foram testados e nenhum reprovou. A matemática
fecha contra o verificador de produção, o timelock atravessa a pilha, a prova colaborativa
compõe no formato da DOM e a recuperação do output compartilhado tem solução
indistinguível.

O que separa este ponto do primeiro contrato rodando é **engenharia de integração** —
biblioteca de adaptor em produção, output compartilhado no fluxo real, sessão com
estado, funding com refund pré-assinado e claim condicional — e não mais nenhuma
pergunta de "isso é possível na DOM?".
