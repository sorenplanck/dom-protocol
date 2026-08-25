# DOCUMENTO DE FUNDAÇÃO — DOM INTEROP
## Sistema de Interoperabilidade DOM-Cêntrico (Projeto DOM v2)

> **SUPERSEDED (2026-08-09).** Esta v0.2 foi substituída pela **v0.3** (`DOM-Interop-Documento-de-Fundacao-v0.3.md`) e saiu de circulação de agentes (§12.2). Mantida apenas como histórico; nenhuma seção aqui é autoridade de contexto.


```text
Versão:              0.2 (rascunho para ratificação)
Data:                2026-08-05
Responsável:         Soren Planck (operador e autoridade de ratificação)
Executor principal:  Desenvolvedor parceiro (a definir formalmente)
Estado:              RASCUNHO — nenhuma seção é canônica antes da ratificação
Nome do produto:     "DOM Interop" é nome de trabalho [PROPOSTA]
Substitui:           v0.1 e o "KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE v1.0.1"
                     (o v1.0.1 fica SUPERSEDED como autoridade de contexto;
                     seus blocos de USPE, envelope e governança foram
                     portados para cá, adaptados à topologia DOM-cêntrica)
```

---

## P. PREÂMBULO

### P.1 Taxonomia obrigatória

- **[DECIDIDO]** — confirmado pelo operador; direcionamento atual.
- **[PROPOSTA]** — introduzido para completar a engenharia; exige ratificação.
- **[ABERTO]** — não definido.
- **[BLOQUEADO]** — depende de evidência, implementação ou decisão externa.
- **[FORA DE ESCOPO]** — não pertence a este roadmap.

Todo trecho de código neste documento é **[PROPOSTA]**, exceto onde marcado
**[AUTORIDADE: dom-adaptor 180b731]** — nesses casos o código é transcrição
da API real do crate no rev fixado e não pode ser alterado pelo projeto.

### P.2 Hierarquia de autoridade e regra de não-inferência

1. Código no rev pinado do `dom-adaptor` (autoridade criptográfica DOM).
2. Ratificações registradas na seção 12 deste documento.
3. O corpo deste documento.
4. Documentos anteriores (v0.1, v1.0.1) — apenas histórico.

Regra de não-inferência: nenhum agente ou colaborador pode inferir que um
repositório, formato, API, contrato ou teste existe sem verificá-lo; mocks e
exemplos não são promovidos a implementação; item [ABERTO] só vira decisão
por ratificação registrada.

### P.3 Cápsula de realinhamento de contexto

Todo agente ou colaborador deve internalizar antes de qualquer trabalho:

1. **[DECIDIDO]** Projeto ÚNICO: consolida Kaystra, Keystone, GStar,
   Kael/HTLC e o futuro USPE em um único produto.
2. **[DECIDIDO]** Desenvolvimento SEPARADO e independente da DOM durante todo
   o ciclo. Nenhum componente altera `dom-protocol`, DOM Wallet,
   `dom-contracts` ou consenso.
3. **[DECIDIDO]** Topologia DOM-cêntrica: todo fluxo tem a forma **DOM ↔ X**.
   A DOM é sempre uma das pernas. O produto NÃO é interoperabilidade genérica
   entre terceiros (ex.: BTC↔ETH sem DOM).
4. **[DECIDIDO]** Ao fim, o produto será INTEGRADO à DOM como evolução —
   **DOM v2**. Não é L2, rollup nem sidechain com ponte custodial.
5. **[DECIDIDO]** Vínculo com a DOM durante o desenvolvimento:

   ```text
   DOM_PROTOCOL_REPOSITORY = https://github.com/sorenplanck/dom-protocol
   DOM_ADAPTOR_REV  = 180b731a6aeba37f03a74fb49e985bf8741d0885
   DOM_ADAPTOR_TREE = a45ef6fc0f8db0a01decb210b234fae9daf111cc
   Branch de origem: feat/scriptless-phase1-dom-adaptor-v1
   Crate:            crates/dom-adaptor
   ```

   Pin sempre por `rev`; nunca por branch ou path local.
6. **[DECIDIDO]** DOM v2 é evolução ACIMA DO CONSENSO (nó + serviços +
   wallet). Componente que "exigir" mudança de consenso é defeituoso.
7. **[DECIDIDO]** Autocustódia absoluta; nenhum componente custodia seeds,
   chaves, nonce shares ou segredos.
8. **[DECIDIDO]** Antipoder: nenhum admin key, guardian, founder path ou
   endpoint administrativo — com grep-gate em CI.
9. **[DECIDIDO]** DL2P FORA do roadmap. CIPHER (VWE) e Kaystra Lend FORA
   da v1.
10. **[DECIDIDO]** Mocks e `dom-sim` nunca satisfazem gate final.

---

## 1. MISSÃO E TOPOLOGIA

### 1.1 Missão

Construir o sistema que dá à DOM interoperabilidade soberana com outras
chains — swaps, pagamentos e settlement DOM↔X — preservando autocustódia,
privacidade da DOM (indistinguibilidade on-chain) e ausência de terceiros de
confiança, para incorporação final à DOM como DOM v2.

### 1.2 Topologia assimétrica (hub DOM) — [DECIDIDO]

```text
        ┌──────────────────────────────────────────────┐
        │                 KAYSTRA CORE                 │
        │   intents · RFQ · solver · settlement engine │
        └──────────┬──────────────────────┬────────────┘
                   │                      │
        ┌──────────▼─────────┐   ┌────────▼───────────────┐
        │   PERNA DOM        │   │  PERNA CONTRAPARTE      │
        │   (nativa, fixa)   │   │  (CounterpartyAdapter)  │
        │   dom-adaptor pin  │   ├─ dom-sim (harness)      │
        │   180b731          │   ├─ EVM (ConditionVM)      │
        └────────────────────┘   ├─ Bitcoin (taproot)      │
                                 └─ HTLC fallback (Kael)   │
```

- A perna DOM é componente **nativo** do motor; o trait neutro existe apenas
  para o lado contraparte. Crescimento em N adapters, não N² pares.
- Regra de desempate de design: entre uma solução confortável para chains de
  estado público e uma que funciona em chain confidencial, **a segunda vence,
  sempre**.

### 1.3 Fluxo canônico do segredo — [DECIDIDO]

```text
Setup:    partes fixam terms_hash, session_id, roster.
          t nasce com quem fará o claim condicionado; T = t·G é publicado.
Perna DOM: contrato 2-de-2 (refund-before-funding quando o perfil exigir).
Perna X:   lock condicionado a T (ConditionVM / taproot adaptor / HTLC).
Amarração: uma pre-signature de adaptor liga as pernas.
Claim:     executar o claim em uma perna revela (ou permite extrair) t,
           que destrava a outra perna.
Saída:     claim XOR refund por perna; timelocks garantem saída unilateral.
```

A matemática da amarração (forma Schnorr, idêntica em espírito na DOM e no
BIP340):

```text
Pre-signature:  R̂ = k·G          (nonce agregado sem o ponto de adaptor)
                e  = H(R̂+T ‖ P ‖ m)   (challenge computado sobre R = R̂+T)
                ŝ  = k + e·d          (escalar "quase-assinatura")
Verificação:    ŝ·G == R̂ + e·P
Adaptação:      s  = ŝ + t   →  (R̂+T, s) é assinatura Schnorr válida
Extração:       t  = s − ŝ   (quem tem a pre-signature e vê s na chain
                              recupera o segredo)
```

---

## 2. FUNDAÇÕES CRIPTOGRÁFICAS

### 2.1 Base comum — [DECIDIDO]

- Curva secp256k1; Schnorr no formato DOM, verificado pelo verificador
  **normal e inalterado** da DOM.
- Pins imutáveis sem ratificação: `grin_secp256k1zkp = "=0.7.15"` e a
  `secp256k1-zkp` pinada do workspace DOM.
- Hash, parsing canônico, challenge e aritmética vêm de `dom-crypto`
  **através do dom-adaptor**. O projeto **nunca** reimplementa primitivas,
  challenge ou verificador — nem para teste (I15).
- Serialização canônica de largura fixa; rejeição de ponto identidade,
  encoding não canônico e trailing bytes.

### 2.2 Perna DOM — [AUTORIDADE: dom-adaptor 180b731]

Tudo nesta seção é API existente no rev fixado. O dev deve tratá-la como
contrato: o crate compila apenas dentro do workspace DOM, por isso a
dependência é por git+rev (§4.3).

**2.2.1 Purposes fechados (`messages.rs`):**

```rust
pub enum PurposeV1 {
    Refund       = 0x01,
    ClaimAdaptor = 0x02, // exige ponto de adaptor T
    Funding      = 0x03,
    Sponsor      = 0x04, // codec reservado; execução NÃO autorizada na Fase 1
}
```

`ClaimAdaptor` sem ponto, ou `Funding`/`Refund` com ponto, são rejeitados
pelo próprio crate. Não criar purposes novos sem ratificação + versão.

**2.2.2 Sessão e transcript (`session.rs`, `context.rs`):**

```rust
pub struct TrustedChainIdV1([u8; 32]);
pub struct ParticipantIdentityV1 { /* id, papel, chave */ }
pub struct ParticipantRosterV1(Vec<ParticipantIdentityV1>); // ordenado
pub enum   ContractKindV1 { /* registro fechado */ }

// session_id nunca é escolhido pelo chamador:
pub trait SessionIdRegistryV1 { /* dedupe durável */ }
pub fn generate_session_id_v1<R: SessionIdRegistryV1>(...) -> ...;

// template canônico da transação DOM + hash:
pub fn canonical_template_v1(tx: &dom_consensus::Transaction)
    -> Result<(Vec<u8>, [u8; 32])>;

// transcript congelado, evolui apenas por:
pub fn initial_transcript_hash_v1(...) -> ...;
pub fn advance_transcript_hash_v1(...) -> ...;
pub fn session_message_digest_v1(unsigned_message_bytes: &[u8]) -> [u8; 32];
```

`SessionContextV1` amarra chain_id, session_id, roster, `ContractKindV1`,
`PurposeV1`, `DirectionV1` (X→DOM / DOM→X), `SigningPhaseV1` e termos, com
codificação canônica exata. Divergência de contexto = abort fail-closed.

**2.2.3 Nonces one-shot e Vault (`nonce.rs`, `nonce_vault.rs`):**

- KDF ratificada de dois nonces por uso; `AuthorizedSecretNoncePairV1` é
  consumido no uso (o crate impede por `compile_fail` importar par
  reutilizável ou derivação crua).
- Contrato `NonceVaultV1` (storage-independent — a implementação durável é
  do projeto, entregável F1): reservas (`NonceReservation`,
  `ReservationState`, `RestoreState`), permits (`ExposurePermitBindingV1`,
  `ExposureKindV1`), identidade (`NonceIdentityV1`), retomada
  (`ReservationResumeResultV1`), **reenvio byte-idêntico** por
  `ResendRequestV1` sobre `SpentArtifactDescriptorV1`, digest de saída por
  `exposure_outbound_digest_v1(kind, bytes)`.
- Restore é leitura delegada; abort consome todo estado vivo. Zeroização
  obrigatória; nenhum segredo em Debug/Display/log/erro/dump.

**2.2.4 Assinatura 2-de-2 — assinaturas reais:**

```rust
// Rodadas: NonceCommitmentV1 → NonceRevealV1 → PartialSignatureV1
pub fn aggregate_public_nonces_v1(nonces: &[PublicKey]) -> Result<PublicKey>;

pub fn aggregate_partial_signatures_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,
    template_hash: &[u8; 32],
) -> Result<PartialSig>;
// valida: purpose estrito Fase 1, binding de template, sem duplicata.

pub fn finalize_plain_signature_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,              // apenas Funding | Refund
    template_hash: &[u8; 32],
    aggregate_nonce: &PublicKey,
    aggregate_signing_key: &PublicKey,
    chain_id: &[u8; 32],
    kernel_message_digest: &[u8; 32],
) -> Result<SchnorrSignature>;       // 65 bytes; verificada pelo
                                     // verificador normal da DOM antes de
                                     // retornar.
```

**2.2.5 Adaptor — o trio que amarra as pernas (`adaptor.rs`):**

```rust
pub struct AdaptorSecret(SecretScalar);
impl AdaptorSecret {
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self>;
    pub fn public_point(&self) -> Result<PublicKey>; // T = t·G
}

pub struct AdaptorPreSignatureV1 {
    // encoding canônico de 162 bytes:
    //   [0..32]    claim_template_hash
    //   [32..65]   adaptor_point T (comprimido, 33)
    //   [65..98]   aggregate_nonce_hat R̂ (comprimido, 33)
    //   [98..130]  scalar_hat ŝ
    //   [130..162] transcript_hash
}
impl AdaptorPreSignatureV1 {
    pub fn from_bytes_for_session(bytes: &[u8], context: &SessionContextV1)
        -> Result<Self>;

    pub fn verify(
        &self,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<bool>;

    pub fn adapt(       // verify + adapta + re-verifica a final
        &self,
        secret: &AdaptorSecret,
        /* mesmos bindings de verify */
    ) -> Result<SchnorrSignature>;

    pub fn extract(     // verifica ambas e extrai t validado
        &self,
        final_signature: &SchnorrSignature,
        /* mesmos bindings de verify */
    ) -> Result<AdaptorSecret>;
}
```

Observação de segurança embutida no crate: `adapt` recusa segredo cujo
`public_point()` difira do `adaptor_point` comprometido; `verify` recusa
template/transcript divergentes ANTES de tocar a equação. O motor herda esse
fail-closed de graça — não o contorne com wrappers "convenientes".

**2.2.6 PoK de share (`share_pop.rs`):**

```rust
pub fn prove_share_knowledge_v1(
    statement: &SharePoPStatementV1,   // vincula sessão/participante/papel
    signing_share: &SigningShareV1,
) -> Result<ShareProofV1>;             // nonce via OsRng, canônico

pub fn verify_share_knowledge_v1(
    statement: &SharePoPStatementV1,
    proof: &ShareProofV1,
) -> Result<bool>;
```

Toda agregação de pontos públicos (nonces, futuros blinds) exige PoK
verificada da contraparte antes da soma — sem exceção.

**2.2.7 Outputs compartilhados / Bulletproof colaborativa — [BLOQUEADO].**
`BpStatementV1` e `BpRound1ShareV1` existem no rev; os segredos
(`BpCommonNonceShareV1`, `BpLocalBlindingV1`, `BpRound2ShareV1`) estão
selados até autorização das fases DOM posteriores. A construção
`C = v·H_DOM + (r_A + r_B)·G` com proof aceita pelo verificador normal é
entrega da missão DOM-SCRIPTLESS-PHASE2-G2 (lado DOM). Este projeto a
consome quando o G2 fechar; até lá, perna DOM = cripto real de
sessão/nonce/assinatura/adaptor sobre `dom-sim` (§4.5).

**2.2.8 Conformidade obrigatória — [DECIDIDO].** A CI do projeto executa,
contra o pin, a suíte do próprio crate: fixtures assinadas, comparação com o
conjunto de referência independente (**311 intermediários**,
`independent_vector_comparison`) e os testes G1a. Divergência de um byte é
falha de build. Este é o significado executável de "base compatível com a
DOM". (Job de CI na §9.)

### 2.3 Perna EVM — [DECIDIDO como primeira contraparte real]

Mecanismo primário: contrato de condição estilo ConditionVM. O truque
central é computar `address(t·G)` on-chain com `ecrecover`, custo ~3k gas:

```text
ecrecover(h, v, r, s) retorna address( r⁻¹·(s·R − h·G) ).
Com h = 0, R = G  (r = Gx, v = 27 pois Gy é par):
    ecrecover(0, 27, Gx, t·Gx mod n)  ==  address(t·G)
```

Esqueleto da v2 endurecida **[PROPOSTA — entregável F3]**:

```solidity
// SPDX-License-Identifier: TBD (A2)
pragma solidity ^0.8.24;

/// Perna EVM de um settlement DOM↔EVM. Lock condicionado ao segredo t
/// cujo ponto T foi fixado no setup. O claim REVELA t on-chain — é o
/// evento que a perna DOM consome via AdaptorPreSignatureV1::extract.
contract ConditionLockV2 {
    uint256 internal constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    struct Lock {
        address funder;          // quem depositou (refund)
        address beneficiary;     // quem faz claim(t)
        address adaptorAddress;  // address(T) — fixado no setup
        uint96  amount;
        uint64  deadline;        // bloco/timestamp de refund
        bytes32 binding;         // keccak256(chain_id_dom, session_id,
                                 //           terms_hash) — domain separation
        bool    settled;
    }
    mapping(bytes32 => Lock) public locks;

    event Claimed(bytes32 indexed lockId, uint256 t); // t revelado
    event Refunded(bytes32 indexed lockId);

    function open(
        bytes32 lockId, address beneficiary, address adaptorAddress,
        uint64 deadline, bytes32 binding
    ) external payable {
        require(locks[lockId].funder == address(0), "exists");
        require(msg.value > 0 && msg.value <= type(uint96).max, "amount");
        require(deadline > block.timestamp, "deadline");
        locks[lockId] = Lock(msg.sender, beneficiary, adaptorAddress,
                             uint96(msg.value), deadline, binding, false);
    }

    function claim(bytes32 lockId, uint256 t) external {
        Lock storage l = locks[lockId];
        require(!l.settled, "settled");
        require(msg.sender == l.beneficiary, "beneficiary");
        require(block.timestamp < l.deadline, "expired");
        require(t != 0 && t < N, "scalar");            // canônico
        address recovered = ecrecover(
            bytes32(0), 27, bytes32(GX), bytes32(mulmod(t, GX, N))
        );
        require(recovered != address(0) &&
                recovered == l.adaptorAddress, "wrong secret");
        l.settled = true;
        emit Claimed(lockId, t);                        // revelação pública
        (bool ok, ) = l.beneficiary.call{value: l.amount}("");
        require(ok, "push-pay");                        // reverte se falhar
    }

    function refund(bytes32 lockId) external {
        Lock storage l = locks[lockId];
        require(!l.settled, "settled");
        require(block.timestamp >= l.deadline, "not yet");
        l.settled = true;
        emit Refunded(lockId);
        (bool ok, ) = l.funder.call{value: l.amount}("");
        require(ok, "push-pay");
    }
}
```

Regras F3 sobre esse esqueleto: suíte Foundry completa (claim válido, t
inválido/zero/≥n, claim após deadline, refund antes do deadline, reentrância,
lockId duplicado, binding divergente); `binding` DEVE incluir o
`session_id`/`terms_hash` da perna DOM; ERC-20 via variante com
`safeTransfer`; ECDSA-adaptor do GStar continua experimental e fora da v1.
Fallback HTLC (Kael `newSwap`/`redeem`/`refund`) só onde ConditionLock não
se aplique — com o custo declarado de linkability por hashlock igual.

### 2.4 Perna Bitcoin — [DECIDIDO como segunda contraparte]

Adaptor Schnorr **BIP340** em taproot key-path (claim indistinguível de
gasto comum); refund por script-path com CSV/CLTV. Espelho da §1.3:

```rust
// [PROPOSTA — entregável F5] pseudocódigo da ponte BIP340
// pre-sign (quem trava): R̂ = k·G ; e = tagged_hash("BIP0340/challenge",
//     xonly(R̂+T) ‖ xonly(P) ‖ sighash) ; ŝ = k + e·d  (mod n)
// adapt   (quem conhece t): s = ŝ + t  → witness (xonly(R̂+T), s)
// extract (quem pre-assinou, ao ver a tx no mempool/bloco): t = s − ŝ
//
// Cuidados obrigatórios F5:
// - paridade x-only: se y(R̂+T) for ímpar, negar k e t coerentemente
//   ANTES de ŝ — regra congelada em vetor de teste, não em comentário;
// - sighash: SIGHASH_DEFAULT sobre template congelado (equivalente ao
//   claim_template_hash da perna DOM);
// - refund: tapleaf `<delta> OP_CSV OP_DROP <refund_pk> OP_CHECKSIG`.
```

**[ABERTO A8]** A ponte formal challenge-DOM ↔ challenge-BIP340 (formatos
distintos, mesma curva) é entregável F5, com vetores próprios, sem tocar
nenhuma das duas autoridades. Keystone entra como evidência verificável de
eventos BTC para o USPE e observação (§3.3) — nunca como custodiante.

### 2.5 Regra transversal do segredo — [DECIDIDO]

- `t` nasce com quem fará o claim; `T = t·G` publicado no setup; `t` só se
  torna conhecível por claim legítimo (revelação on-chain em X, ou
  `extract` na DOM).
- Nenhum transporte, relay, banco ou log carrega `t`, nonces secretos,
  shares ou seeds; transporte carrega apenas artefatos opacos autenticados.
- Reuso de nonce entre PoK, assinatura, adaptor e (futura) bulletproof é
  proibido por construção (domínios do dom-adaptor).

### 2.6 Trilha de pesquisa — [FORA DA V1]

CIPHER (witness encryption verificável, EVM→BTC sem contato) permanece
laboratório; nenhum gate depende dele; nenhuma API pública o expõe.

---

## 3. INTEGRAÇÃO DE CADA PRODUTO

### 3.1 Kaystra → Núcleo (settlement engine) — [DECIDIDO]
Intents, RFQ, seleção de solver, máquina de estados (§6), coordenação das
duas pernas, consumo de evidência verificada. O `kaystra_watcherd` Python
vira referência de comportamento (preflight de ações irreversíveis,
validação de RPC sem credenciais); implementação de produto é Rust.
Economics de solver: [ABERTO A5], ratificar na F6.

### 3.2 GStar → Contratos EVM — [DECIDIDO]
ConditionVM/Foundry absorvidos como perna EVM (§2.3, ConditionLockV2).
Taxonomia G/G′/H36–H39 vai para `docs/research/`, separada de interface
executável.

### 3.3 Keystone → Evidência e observação Bitcoin — [DECIDIDO]
O Keystone real (verificador BTC trust-minimized, ZK SP1/Groth16 fechado)
integra como módulo de evidência verificável de eventos Bitcoin, consumível
pelo USPE e pelo motor. **[PROPOSTA]** Transporte é componente próprio
"Relay" (§4.6); Keystone mantém identidade Bitcoin. **[ABERTO A2]** BUSL:
relicenciar ou reescrever a parte que migra — resolver na F0, por escrito,
junto da cessão de PI do parceiro.

### 3.4 USPE → Garantia econômica (do zero)
Portado do Documento Mestre v1.0.1 e adaptado à restrição DOM v2.

**Papel [DECIDIDO]:** USPE não cria simultaneidade entre chains; transforma
obrigação falhada em consequência econômica verificável: liberação ou
retenção de bond, punição e, quando a policy determinar, compensação.

**Restrição inegociável de DOM v2 [DECIDIDO]:** toda punição e compensação é
executável por criptografia e timelock (bond em ConditionLock/2-de-2 cujo
gasto de penalidade é destravado por evidência verificável ou extração de
segredo) — **nunca por operador, árbitro, comitê ou admin key**.

**Objetos mínimos [PROPOSTA]:**

```rust
pub struct AssurancePolicyV1 {
    pub policy_id: PolicyId,
    pub version: u32,
    pub protected_obligations: Vec<ObligationId>,
    pub required_collateral: AssetAmount,
    pub settlement_deadline: Deadline,   // unidade do adapter; NUNCA
    pub claim_deadline: Deadline,        // convertida silenciosamente
    pub compensation_cap: AssetAmount,   // altura ↔ relógio
    pub evidence_rules: Vec<EvidenceRule>,
    pub terminal_policy: TerminalPolicy,
}

pub struct AssuranceCertificateV1 {
    pub certificate_id: CertificateId,
    pub settlement_id: SettlementId,
    pub terms_hash: Digest32,            // terms divergente invalida
    pub solver_id: SolverId,
    pub policy_id: PolicyId,
    pub collateral_evidence: EvidenceRef, // sem evidência não há emissão
    pub issued_at: LogicalTime,
    pub expires_at: Deadline,
}

/// Abstrações que impedem a primeira implementação de virar dependência:
pub trait BondAdapter      { /* lock, release, slash — cripto-only */ }
pub trait EvidenceVerifier { /* evidência bruta → VerifiedOutcome */ }
```

**Estados [PROPOSTA — adaptado: EVIDENCE_REVIEW é verificação mecânica de
evidência pelos adapters, não revisão humana; sem estado ACTION_REQUIRED,
que implicaria intervenção — timeout resolve pela terminal_policy]:**

```rust
pub enum AssuranceState {
    NotRequired,
    BondRequired, BondLocking, Protected,
    ReleasePending, Released,
    ClaimWindow, EvidenceVerification,
    Slashed, Compensated,
    ClaimRejected, // evidência não satisfaz as regras → Released
}
```

**Invariantes USPE [REQUISITO]:** nenhum certificado sem evidência
verificada do collateral; `terms_hash` diferente invalida o certificado;
release/slash/compensação dependem de policy + evidência (nunca de
declaração do Relay); uma obrigação não gera compensações duplicadas;
`SETTLED`, `REFUNDED` e `COMPENSATED` são mutuamente exclusivos para a
mesma obrigação (salvo policy explícita de decomposição parcial); valor
compensado nunca excede o cap; deadlines mantêm a unidade do adapter; toda
decisão preserva evidência para auditoria. Model checking obrigatório na
F4: dupla compensação, release+slash simultâneos, timeout, evidência
tardia, crash em transição.

**[ABERTO A6]** Onde vivem os bonds na v1 (EVM primeiro; DOM quando o
Scriptless amadurecer), assets aceitos, sizing.

### 3.5 Kael/HTLC → Fallback e biblioteca EVM — [DECIDIDO]
HTLC core + `OrderLib` EIP-712 como fallback e biblioteca de termos.
Orderbook/coordinator experimental FORA da v1 (RFQ do núcleo o substitui).

### 3.6 CIPHER → pesquisa [FORA DA V1].
### 3.7 Lend v2 e KaystraPay → consumidores futuros [FORA DA V1].
### 3.8 DL2P → [FORA DE ESCOPO] integral.

---

## 4. ARQUITETURA E CÓDIGO DE REFERÊNCIA

### 4.1 Componentes

```text
kaystra-core        motor: intents, termos, state machine, coordenação
dom-leg             perna DOM nativa (único crate que importa dom-adaptor)
counterparty-api    trait CounterpartyAdapter + tipos neutros
adapters/dom-sim    chain DOM simulada (dev/test; nunca gate F7+)
adapters/evm        ConditionLockV2 + observador EVM
adapters/btc        taproot adaptor + observador BTC (+ Keystone evidence)
adapters/htlc       fallback Kael
uspe                bonds, deadlines, compensação criptográfica
relay               transporte autenticado de artefatos opacos (opcional)
store               persistência local autoritativa, journal, idempotência
```

### 4.2 Workspace e pins — [PROPOSTA de layout; pins DECIDIDOS]

```toml
# Cargo.toml (raiz do monorepo)
[workspace]
members = [
  "crates/kaystra-core", "crates/dom-leg", "crates/counterparty-api",
  "crates/adapters/dom-sim", "crates/adapters/evm", "crates/adapters/btc",
  "crates/uspe", "crates/relay", "crates/store",
]
resolver = "2"

[workspace.dependencies]
# ÚNICA porta para a DOM. Pin por rev; PROIBIDO branch/path/cargo update global.
dom-adaptor = { git = "https://github.com/sorenplanck/dom-protocol",
                rev = "180b731a6aeba37f03a74fb49e985bf8741d0885",
                package = "dom-adaptor" }
thiserror = "1"
zeroize   = { version = "1", features = ["derive"] }
```

Regra de dependência (grep-gate em CI): apenas `crates/dom-leg` pode conter
`use dom_adaptor` / `dom-adaptor` no Cargo.toml. `kaystra-core` e `uspe`
importam somente `dom-leg` e `counterparty-api`.

### 4.3 counterparty-api — trait neutro — [PROPOSTA]

```rust
// crates/counterparty-api/src/lib.rs
use core::future::Future;

pub struct CounterpartyChainId(pub [u8; 32]);
pub struct ChainCursor(pub Vec<u8>);        // opaco, persistível
pub struct AdaptorPointBytes(pub [u8; 33]); // T comprimido, vindo do dom-leg
pub struct RevealedSecretBytes(pub [u8; 32]); // t revelado on-chain (X)

pub struct ChainCapabilities {
    pub supports_condition_lock: bool,   // revelação de t on-chain (EVM)
    pub supports_schnorr_adaptor: bool,  // key-path adaptor (BTC)
    pub supports_hashlock_fallback: bool,
    pub timelock_domain: TimelockDomain, // BlockHeight | Timestamp
    pub finality: FinalityPolicy,        // [ABERTO A4] por chain
}

pub enum ObservedEvent {
    LockOpened   { lock_id: [u8; 32], height: u64 },
    LockClaimed  { lock_id: [u8; 32], revealed: RevealedSecretBytes,
                   height: u64 },
    LockRefunded { lock_id: [u8; 32], height: u64 },
    Reorged      { from_height: u64 }, // invalida observações ≥ altura (I11)
}

pub enum AdapterError {
    UnsupportedCapability, InvalidState, PreconditionUnsatisfied,
    EvidenceInvalid, ReorgDetected, StaleCursor, VersionMismatch,
    AdapterUnavailable, NonCanonicalRetransmission,
}

/// Assíncrono por decisão (RPCs remotos); trait com métodos async nativos
/// (Rust ≥1.75) — dyn-compat via enum de adapters ou wrapper, decidir na F0.
pub trait CounterpartyAdapter: Send + Sync {
    fn chain_id(&self) -> CounterpartyChainId;
    fn capabilities(&self) -> ChainCapabilities;

    /// Prepara o lock condicionado a T. Retorna artefato opaco pronto
    /// para autorização/broadcast pelo agente local (sem custódia aqui).
    fn prepare_lock(&self, terms: &NeutralTerms, t: &AdaptorPointBytes)
        -> impl Future<Output = Result<OpaqueArtifact, AdapterError>> + Send;

    /// Observação por cursor persistível; reorg é evento, não pânico.
    fn observe(&self, cursor: &ChainCursor, max: usize)
        -> impl Future<Output = Result<(Vec<ObservedEvent>, ChainCursor),
                                       AdapterError>> + Send;

    /// Evidência bruta da chain → resultado verificado neutro (I9).
    fn verify_evidence(&self, evidence: &[u8])
        -> impl Future<Output = Result<VerifiedOutcome, AdapterError>> + Send;
}
```

Regras da interface: idempotência; versionamento explícito; binding
chain/perfil; limites de tamanho antes de alocar; erros estáveis; cursor
persistível; capacidade desconhecida = falha fechada (I10).

### 4.4 dom-leg — uso canônico do dom-adaptor — [PROPOSTA sobre AUTORIDADE]

Fluxo claim DOM→X visto do motor (nomes reais do crate):

```rust
// crates/dom-leg/src/claim_flow.rs — esqueleto ilustrativo
use dom_adaptor::{
    AdaptorPreSignatureV1, AdaptorSecret, PurposeV1,
    aggregate_public_nonces_v1, finalize_plain_signature_v1,
};

pub struct DomLegSession { /* SessionContextV1 + vault handle + template */ }

impl DomLegSession {
    /// Contraparte revelou t no claim EVM (ObservedEvent::LockClaimed)
    /// OU nós vimos a assinatura final na DOM e extraímos t:
    pub fn extract_secret(
        &self,
        pre: &AdaptorPreSignatureV1,
        final_sig: &dom_adaptor::SchnorrSignature,
    ) -> Result<AdaptorSecret, LegError> {
        pre.extract(
            final_sig,
            &self.claim_template_hash,
            &self.transcript_hash,
            &self.aggregate_signing_key,
            &self.chain_id,
            &self.kernel_message,
        ).map_err(Into::into)
    }

    /// Nós conhecemos t (viemos do claim na outra perna) e finalizamos
    /// a assinatura DOM do claim:
    pub fn adapt_claim(
        &self,
        pre: &AdaptorPreSignatureV1,
        t: &AdaptorSecret,
    ) -> Result<dom_adaptor::SchnorrSignature, LegError> {
        pre.adapt(t, &self.claim_template_hash, &self.transcript_hash,
                  &self.aggregate_signing_key, &self.chain_id,
                  &self.kernel_message).map_err(Into::into)
    }
}
```

Proibições no dom-leg: nenhum wrapper que aceite template/transcript "de
fora" sem revalidar contra a sessão; nenhum caminho que finalize
`ClaimAdaptor` por `finalize_plain_signature_v1` (o crate já rejeita —
não "conserte" isso); nenhum armazenamento de `AdaptorSecret` fora do
fluxo (I1).

### 4.5 dom-sim — chain DOM simulada — [DECIDIDO em papel; API PROPOSTA]

```rust
pub trait SimChain {
    fn height(&self) -> u64;
    fn advance(&mut self, blocks: u64);
    fn submit(&mut self, artifact: OpaqueArtifact) -> SubmitResult;
    fn confirmations(&self, id: &[u8; 32]) -> Option<u64>;
    fn inject_reorg(&mut self, depth: u64);       // I11 testável
    fn scan(&self, cursor: &ChainCursor) -> (Vec<ObservedEvent>, ChainCursor);
}
```

Declaração obrigatória em todo relatório: *dom-sim não é a DOM; não confere
compatibilidade de rede; a troca pelo nó real ocorre na F7 sob gate de
elegibilidade.* A criptografia sobre ele é sempre a real (dom-adaptor).

### 4.6 Relay — transporte — [PROPOSTA, portado do v1.0.1 §9.3–9.5]

```rust
pub struct RelayEnvelopeV1 {
    pub protocol_version: u16,
    pub service: ServiceKind,
    pub message_kind: u16,
    pub settlement_id: SettlementId,
    pub message_id: MessageId,
    pub sender_id: ParticipantId,
    pub recipient_id: ParticipantId,
    pub sequence: u64,
    pub previous_digest: Digest32,
    pub payload_codec: CodecId,
    pub payload_hash: Digest32,
    pub payload: BoundedBytes,   // opaco; Relay NUNCA decodifica
    pub authentication: AuthTag, // [ABERTO A10]
}
```

Semântica de entrega [REQUISITO]: at-least-once no transporte; exactly-once
na camada de efeitos por idempotência com chave
`(settlement_id, sender_id, message_id | sequence)`. Mesmo id + mesmos
bytes ⇒ mesmo ACK; mesmo id + bytes diferentes ⇒ equivocation, falha
fechada. Reenvio usa os bytes persistidos do envelope — nunca recalcula
assinatura, nonce ou payload (espelha `ResendRequestV1` do dom-adaptor).

Indisponibilidade [REQUISITO, testado na F6]: sessão continua por outro
transporte; artefatos finais existem localmente; observers alternativos
reconciliam a chain; claim/refund/compensação não dependem de banco do
Relay; ao voltar, o Relay reconcilia por digests e idempotency keys sem
repetir efeitos.

### 4.7 store — persistência — [princípio DECIDIDO; tecnologia ABERTA A7]

Sessão autoritativa local; journal append-only de decisões; idempotency
keys; cursores por chain; revisão monotônica/CAS; outbox durável; retomada
pós-crash; reconciliação com as chains; implementação durável do contrato
`NonceVaultV1` (fail-closed quando witness/rollback incompleto — regra do
próprio crate).

---

## 5. INVARIANTES NORMATIVAS

```text
I1  Autocustódia: nenhum componente guarda seed, chave privada, share ou t.
I2  Antipoder: nenhum admin key, guardian, founder path, endpoint
    administrativo, pausa global ou upgrade unilateral. Grep-gate em CI.
I3  Acima do consenso: nenhuma mudança em consenso, wire, genesis, mempool
    ou encoding da DOM; dom-protocol/dom-contracts/DOM Wallet intocados.
I4  Claim e refund são desfechos mutuamente exclusivos por perna.
I5  Refund-before-funding onde o perfil exigir: nenhum funding antes do
    refund finalizado, validado e persistido.
I6  Nonces one-shot; domínios separados; zeroização; nenhum segredo em
    Debug/Display/log/erro/dump/telemetria.
I7  Retransmissão byte-idêntica; mesma idempotency key nunca produz
    artefatos semanticamente diferentes.
I8  Indistinguibilidade DOM preservada: nenhum marcador de colaboração em
    nada que vá à chain DOM.
I9  Evidência de chain só é interpretada pelo adapter daquela chain.
I10 Capacidade desconhecida ou versão divergente: falha fechada.
I11 Reorg invalida decisões derivadas da observação afetada até
    revalidação; um único efeito econômico terminal por settlement.
I12 USPE: sem dupla compensação; release e slash mutuamente exclusivos;
    execução puramente criptográfica.
I13 Mock/dom-sim nunca satisfaz gate final; F7+ exige DOM real.
I14 Caminho de produção: sem unwrap/expect em input não confiável, sem
    panic como classificação, sem unsafe fora de wrapper FFI mínimo, sem
    float em valor, sem serde como wire criptográfico, sem trailing bytes
    ignorados, alocação só após validar cap.
I15 Nenhuma reimplementação de primitiva, challenge ou verificador DOM.
```

---

## 6. MÁQUINA DE ESTADOS DE SETTLEMENT

**[PROPOSTA]** Função de transição pura, table-driven, sem efeitos — os
efeitos moram no motor, que consome o resultado:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettlementState {
    Preparing, ReadyToFund, Confirming, Settling, Settled, Refunded,
}

pub enum SettlementEvent {
    RefundArmed,            // refund pré-assinado finalizado+persistido (I5)
    FundingObserved { height: u64 },
    FundingConfirmed,
    SecretRevealed(RevealedSecretBytes),
    ClaimConfirmed,
    TimelockExpired,
    RefundConfirmed,
    ReorgInvalidated { from_height: u64 },
}

pub enum TransitionError { IllegalEvent, TerminalState }

pub fn transition(s: SettlementState, e: &SettlementEvent)
    -> Result<SettlementState, TransitionError>
{
    use SettlementState::*; use SettlementEvent::*;
    Ok(match (s, e) {
        (Preparing,   RefundArmed)            => ReadyToFund,
        (ReadyToFund, FundingObserved { .. }) => Confirming,
        (Confirming,  FundingConfirmed)       => Settling,
        (Settling,    SecretRevealed(_))      => Settling, // aguarda claim
        (Settling,    ClaimConfirmed)         => Settled,
        (Confirming | Settling, TimelockExpired) => s,     // arma refund
        (Confirming | Settling, RefundConfirmed) => Refunded,
        // Reorg NÃO é terminal: regride a observação, não o dinheiro (I11)
        (Confirming,  ReorgInvalidated { .. }) => ReadyToFund,
        (Settling,    ReorgInvalidated { .. }) => Confirming,
        (Settled | Refunded, _) => return Err(TransitionError::TerminalState),
        _ => return Err(TransitionError::IllegalEvent),
    })
}
```

Obrigações F2 sobre esse esqueleto: tabela completa (entrada, operações
permitidas, eventos emitidos, dados persistidos, pós-crash, efeito de
reorg, terminal econômico) por estado; property tests de que `Settled` e
`Refunded` são inalcançáveis simultaneamente; crash injetado em CADA
transição com retomada pelo journal.

---

## 7. FASES E GATES

Nenhuma fase inicia sem o gate anterior PASS ou dispensa ratificada por
escrito. Cada fase lista o "primeiro código" para o dev não começar pelo
lado errado.

### F0 — Fundação (sem código de protocolo)
Entregas: repositório e workspace (§4.2); CI com fmt/clippy/test +
conformidade dom-adaptor (§9) + grep-gates de I2/I6/I14/§4.2; acordo
escrito de licença e cessão de PI; decisão BUSL do Keystone (A2); nome (A1);
decisão dyn-compat do trait async (§4.3).
Gate G-F0: `VECTORS_GREEN + IP_SIGNED + LICENSES_DECIDED`.

### F1 — Perna DOM (cripto real sobre dom-sim)
Primeiro código: implementação durável do contrato `NonceVaultV1` no
`store`, depois `DomLegSession`.
Entregas: sessão/roster/transcript; vault durável; rodadas 2-de-2 dos três
purposes; `verify/adapt/extract`; `dom-sim` (§4.5) com reorg injetável.
Gate G-F1: funding→claim e funding→refund abstratos com criptografia real;
extração de `t` correta; "spend unilateral" criptograficamente impossível
(o teste chega ao verificador real do pin, não a um mock);
crash/restore/resend byte-idêntico; conformidade de vetores mantida.

### F2 — Núcleo Kaystra
Primeiro código: `transition()` (§6) + tabela completa + property tests;
depois termos canônicos e `terms_hash` (ratificar A3 aqui).
Gate G-F2: E2E contra dom-sim com injeção de falhas (crash em cada
transição, duplicação, reorder, reorg, evidência tardia).

### F3 — Perna EVM (primeira contraparte real)
Primeiro código: `ConditionLockV2` (§2.3) + suíte Foundry adversarial.
Entregas: adapter EVM (`observe` por eventos + cursores; finality A4).
Gate G-F3: primeiro E2E real DOM(dom-sim)↔EVM em testnet, DUAS direções,
com `t` extraído de `Claimed` on-chain real e refund por deadline real;
relatório com tx hashes.

### F4 — USPE mínimo
Primeiro código: `AssuranceState` + invariantes como property tests +
model checking (§3.4); `BondAdapter` sobre ConditionLock.
Gate G-F4: `NO_DOUBLE_COMPENSATION + NO_RELEASE_AND_SLASH + TIMEOUT_SAFE`
demonstrados; compensação executada em testnet sem qualquer ação
privilegiada.

### F5 — Perna Bitcoin
Primeiro código: ponte BIP340 (§2.4) com vetores de paridade x-only
congelados ANTES de qualquer fluxo.
Gate G-F5: E2E DOM(dom-sim)↔BTC em regtest e signet, duas direções;
refund CSV real; evidência Keystone consumida pelo USPE.

### F6 — RFQ, solver e Relay
Entregas: RFQ/quotes/seleção (A5); Relay (§4.6).
Gate G-F6: settlement completo com solver; perda total do Relay e do seu
banco não impede claim nem refund locais; ACK/dedup/retransmissão
byte-idêntica aprovados.

### F7 — DOM real — [BLOQUEADO por dependência externa]
Pré-condição (lado DOM, fora deste projeto): Scriptless Fases 2–6 (G2
output compartilhado + BP colaborativa; sessão/transporte; funding com
refund pré-assinado; claim por adaptor; E2E).
Entregas: substituir dom-sim pelo nó DOM real (regtest → rede de teste),
usando builder, RPC, mempool, verificador e scanner reais.
Gate G-F7 (gate de elegibilidade DOM): formatos canônicos congelados;
identificadores de sessão/transação; política de timelock/confirmação/
reorg; vetores E2E publicados; versão DOM congelada e pinada; conformance
verde contra a DOM real; comparação dom-sim × DOM real documentada.

### F8 — Auditoria e Merge DOM v2
Entregas: auditoria externa de composição; empacotamento como distribuição
DOM v2 (nó + serviços + wallet); plano de migração de repositório.
Gate G-F8: auditoria sem findings pendentes; I1–I15 verificados no pacote;
ratificação explícita do operador. Só então existe "DOM v2".

Paralelismo: F1→F2 seriais; F3 inicia com G-F2 parcial (máquina estável);
F4 paralelo a F3/F5; o lado DOM (Scriptless P2–P6) corre em paralelo e só
acopla na F7.

---

## 8. TESTES ADVERSARIAIS TRANSVERSAIS

Além dos gates por fase, a suíte permanente cobre, em todo fluxo:

crash em cada transição; ACK perdido; duplicação; replay; equivocation
(mesmo id, bytes diferentes); reorder; reorg em cada perna; perda do Relay;
perda do banco do Relay; adapter indisponível; evidência inválida;
evidência tardia; timeout em cada deadline; retomada após restart em cada
fase de assinatura; resend byte-idêntico após restart; `t` inválido
(zero, ≥n, não canônico); ponto identidade; PoK inválida; participante
duplicado/omitido/reordenado; template ou transcript divergente; secret
scan de todo artefato e log.

Ferramentas: property tests (proptest), fuzz targets nos parsers de
envelope/artefato/evidência, differential tests contra os vetores do pin,
model checking do USPE e da máquina de estados.

---

## 9. CONFORMIDADE E CI

### 9.1 Job de conformidade DOM — [DECIDIDO]

```yaml
# .github/workflows/ci.yml (trecho)
jobs:
  dom-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Clone DOM no rev pinado
        run: |
          git clone https://github.com/sorenplanck/dom-protocol dom
          git -C dom checkout 180b731a6aeba37f03a74fb49e985bf8741d0885
      - name: Vetores do dom-adaptor (311 intermediários + G1a + fixtures)
        run: cargo test -p dom-adaptor --locked --manifest-path dom/Cargo.toml
      - name: Testes do dom-leg contra o pin
        run: cargo test -p dom-leg --locked
  guards:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Fronteira dom-adaptor (só dom-leg importa)
        run: |
          ! grep -rn "dom_adaptor\|dom-adaptor" crates \
              --include="*.rs" --include="*.toml" \
              | grep -v "^crates/dom-leg/"
      - name: Antipoder (I2)
        run: |
          ! grep -rniE "admin_key|onlyOwner|guardian|pause_all|upgradeTo" \
              crates contracts/src
      - name: I14 (amostra)
        run: |
          ! grep -rn "\.unwrap()\|\.expect(" crates --include="*.rs" \
              | grep -v "/tests/\|/fuzz/\|#\[cfg(test)\]"
```

(Os grep-gates são a versão mínima; a F0 os converte em lints/xtask com
allowlist explícita e justificada por linha.)

### 9.2 Regra de atualização do pin

Atualizar `DOM_ADAPTOR_REV` é evento de ratificação (seção 12): exige
changelog do delta, re-execução completa da conformidade e nova versão
deste documento. `cargo update` global é proibido; lockfile commitado.

---

## 10. GATE DE INTEGRAÇÃO DOM v2 (checklist consolidado)

Cumulativamente: G-F0…G-F8 PASS; nenhum NOT_CONFIRMED convertido em PASS
por inferência documental; nenhuma mudança de consenso pendente ou
proposta; auditoria externa entregue; licenças compatíveis com a
distribuição DOM; declaração assinada de que dom-protocol, dom-contracts e
DOM Wallet permaneceram intocados durante todo o desenvolvimento.

---

## 11. QUESTÕES ABERTAS

```text
A1  Nome do produto.
A2  Licença do produto; relicenciamento/reescrita do Keystone (BUSL).
A3  Formato canônico de termos e terms_hash (ratificar na F2).
A4  Política de finality/confirmação por chain contraparte (F3/F5).
A5  Economics de solver, fees e bond sizing do USPE (F4/F6).
A6  Onde vivem os bonds v1 (EVM) e migração futura para a DOM.
A7  Tecnologia de persistência do store.
A8  Ponte formal DOM-Schnorr ↔ BIP340, incl. paridade x-only (F5).
A9  Testnets escolhidas (EVM; signet BTC).
A10 Autenticação dos envelopes do Relay.
A11 Destino do orderbook experimental do Kael (pós-v1).
A12 Dyn-compat do trait async do CounterpartyAdapter (F0).
```

---

## 12. REGISTRO DE DECISÕES E PROTOCOLO DE ATUALIZAÇÃO

### 12.1 Registro

Cada ratificação registra: ID, data, problema, decisão, alternativas
rejeitadas, impacto, componentes afetados, decisão substituída, status.

```text
D-000  2026-08-05  Fundação: cápsula P.3 itens 1–10        RATIFICAÇÃO PENDENTE
D-001  2026-08-05  v1.0.1 SUPERSEDED como autoridade        RATIFICAÇÃO PENDENTE
```

### 12.2 Protocolo de atualização deste documento
(portado do v1.0.1 §26, adaptado)

- Existe UMA autoridade de contexto por vez. Ao ratificar uma versão nova,
  a anterior recebe a marca SUPERSEDED na primeira página e sai de
  circulação de agentes.
- Mudança editorial → incrementa patch; mudança de [PROPOSTA]→[DECIDIDO] ou
  novo [ABERTO] → incrementa minor; mudança de decisão já ratificada ou de
  topologia → incrementa major e exige entrada D-xxx com a decisão
  substituída.
- Mudança em `counterparty-api`, em formato canônico ou no pin DOM exige
  nova versão do documento; mudança interna de adapter, não.
- Todo agente que receber este documento responde primeiro com a cápsula
  P.3 nas próprias palavras; se a reprodução divergir, o operador corrige
  antes de qualquer código.

---

*Esta v0.2 substitui a v0.1 e o "KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE
v1.0.1". A disciplina de taxonomia, gates e anti-teatro permanece
integralmente em vigor. Código marcado [AUTORIDADE: dom-adaptor 180b731] é
transcrição do crate real e não pode ser alterado pelo projeto; todo o
restante do código é [PROPOSTA] até ratificação.*
