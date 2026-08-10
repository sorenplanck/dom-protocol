# DOM Scriptless — Hash Domain Registry

Status: **PROPOSTO — não congelado** (§3.4 do
`DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`).

§3.4 exige que toda tag de domínio Scriptless seja "registrada e congelada em um
único módulo", e que `DomainTag` seja "um enum fechado gerado do registro
`docs/HASH_DOMAINS.md`". Este é esse registro. Ele é a fonte única da qual o enum
fechado deve ser gerado; nenhuma tag pode ser instanciada como string literal
arbitrária em runtime.

## Precondição normativa do congelamento

§3.4 é explícito: as tags **só podem ser congeladas depois** que o Gate G0
localizar a função BLAKE2b-256 canônica usada pela DOM em challenges e derivações
e expuser um adapter byte-idêntico. Enquanto o G0 não produzir esse registro
(caminho `arquivo:função`, digest de 32 bytes, framing exato da tag,
personalization/salt/key, endianness, redução hash→scalar, preimage e digest
esperado de cada vetor), estas tags permanecem **PROPOSTAS**.

Proibições que valem desde já (§3.4):

- proibido `SHA256(tag) || SHA256(tag) || mensagem` (construção BIP340);
- proibido trocar apenas SHA256 por BLAKE2b mantendo a duplicação;
- proibido instanciar diretamente uma biblioteca BLAKE2b genérica no módulo
  Scriptless — personalization, framing, comprimento, ordem de campos e
  endianness devem ser exatamente os do backend DOM mapeado;
- o challenge de assinatura/adaptor do kernel **não** ganha tag Scriptless: deve
  chamar o `dom_kernel_challenge` nativo byte a byte.

Tags são ASCII, case-sensitive, sem NUL, sem Unicode, sem normalização e sem
concatenação em runtime. Alterar algoritmo, framing ou tag depois do freeze
exige versão de domínio nova e vetores novos; nunca se sobrescreve um vetor
publicado.

## A — Tags do registro normativo §3.4

Estas constam da tabela da especificação mestra.

| Tag ASCII | Uso | Em uso no código |
| --- | --- | --- |
| `DOM:scriptless-session-id:v1` | Identificador de sessão derivado de entropia e participantes | sim |
| `DOM:scriptless-message:v1` | Assinatura/autenticação de mensagem off-chain | sim |
| `DOM:scriptless-transcript:v1` | Hash acumulado do transcript | sim |
| `DOM:scriptless-participant:v1` | ID de participante | sim |
| `DOM:scriptless-share-pop:v1` | PoK do share de blinding/chave (§4.2) | sim |
| `DOM:scriptless-nonce-commit:v1` | Commitment de nonce público | sim |
| `DOM:scriptless-sig-nonce-bind:v1` | Binding factor dos dois nonces Schnorr agregados | sim |
| `DOM:scriptless-bp-common-commit:v1` | Commitment da contribuição secreta do common nonce BP | sim |
| `DOM:scriptless-bp-common-joint:v1` | Combinação ordenada das contribuições secretas BP | sim |
| `DOM:scriptless-bp-common-nonce:v1` | Nonce comum Bulletproof MPC | sim |
| `DOM:scriptless-contract-id:v1` | Identificador local do contrato | não |
| `DOM:scriptless-template:v1` | Commitment a template de transação | sim |
| `DOM:scriptless-chain-id:v1` | Identificador de rede (Apêndice E) | não |
| `DOM:scriptless-terms:v1` | Commitment aos termos finais aceitos | não |

## B — Tags adicionais em uso, ainda não na tabela §3.4

Estas existem no código e **precisam ser ratificadas na tabela normativa** antes
do freeze, ou renomeadas para tags já registradas. Estão listadas aqui para que o
registro reflita a realidade do código e nenhuma tag viva fique fora dele.

| Tag ASCII | Uso | Módulo |
| --- | --- | --- |
| `DOM:scriptless-share-pop-challenge:v1` | Challenge derivado da PoK §4.2 | `share_pop.rs` |
| `DOM:scriptless-transcript-init:v1` | Âncora inicial do transcript de assinatura | `transcript.rs` |
| `DOM:scriptless-bp-statement:v1` | Hash do `BpStatementV1` congelado (§5.2) | `bulletproof_mpc.rs` |
| `DOM:scriptless-bp-round1-commit:v1` | Commitment de rodada 0B (§5.4) | `bulletproof_mpc.rs` |
| `DOM:scriptless-bp-no-recovery:v1` | Sentinel de `recovery_binding_hash` sem capsule (§5.2) | `bulletproof_mpc.rs` |
| `DOM:scriptless-contract-envelope:v1` | Digest do envelope de contrato (Fase 3.1) | `contract_session.rs` |
| `DOM:scriptless-contract-transition:v1` | Transcript de transição do contrato (Fase 3.2) | `contract_session.rs` |
| `DOM:scriptless-decoy-contribution:v1` | Contribuição determinística da decoy (Fase 2.3) | `decoy_capsule.rs` |
| `DOM:scriptless-decoy-commit:v1` | Commitment da contribuição da decoy | `decoy_capsule.rs` |
| `DOM:scriptless-decoy-share-seed:v1` | Seed da decoy derivada do share | `signing_share.rs` |
| `DOM:scriptless-partial-commit-pop-context:v1` | Contexto da PoK de commitment parcial | `partial_commitment_pop.rs` |
| `DOM:scriptless-partial-commit-pop-challenge:v1` | Challenge da PoK de commitment parcial | `partial_commitment_pop.rs` |
| `DOM:scriptless-vault-outbound:v1` | Vault: material de saída | `vault_signer.rs` |
| `DOM:scriptless-vault-counterparty:v1` | Vault: binding de contraparte | `vault_signer.rs` |
| `DOM:scriptless-vault-budget-key:v1` | Vault: chave de orçamento | `vault_signer.rs` |
| `DOM:scriptless-vault-computation-input:v1` | Vault: input de computação | `vault_signer.rs` |
| `DOM:scriptless-vault-exposure-permit:v1` | Vault: permit de exposição | `vault_operation.rs` |

Nota sobre `partial-commit-pop`: essa PoK é **redundante** com a §4.2
(`share_pop.rs`), que é a primitiva normativa do registro. Ver
`docs/scriptless/AUDIT-SELF-WRITTEN-MODULES.md`. Se ela for removida em favor da
§4.2, as duas tags saem deste registro em vez de serem ratificadas.

## C — Labels de KDF/AEAD (registro separado, §3.4)

Estas **não** são automaticamente chamadas de `H_tag`:

| Label ASCII | Em uso |
| --- | --- |
| `DOM:scriptless-secret-nonce:v1` | via `-seed`/`-wide`/`-aux` |
| `DOM:scriptless-store:v1` | store |
| `DOM:scriptless-store-record:v1` | store |
| `DOM:scriptless-store-tombstone:v1` | store |
| `DOM:scriptless-store-backup:v1` | store |

Em uso no código como derivações do label de nonce secreto:
`DOM:scriptless-secret-nonce-seed:v1`, `DOM:scriptless-secret-nonce-wide:v1`,
`DOM:scriptless-secret-nonce-aux:v1`.

## Trabalho pendente para o freeze (§3.4)

1. **G0**: registrar a função BLAKE2b-256 canônica da DOM e expor o adapter
   byte-idêntico, com o registro completo de framing/endianness/hash→scalar.
2. **Ratificar** as tags da seção B na tabela normativa, ou removê-las.
3. **Gerar `DomainTag`** como enum fechado a partir deste registro, com
   `as_ascii()` devolvendo exatamente os bytes registrados, e substituir todas as
   constantes string literais dos módulos por variantes do enum.
4. **Teste diferencial** `every_scriptless_domain_matches_dom_blake2b_backend`
   contra o backend DOM, e regra de CI que falhe se `Sha256`, `SHA256(tag)` ou
   duplicação de `tag_hash` aparecerem no adapter `H_tag`.

```text
REGISTRY = PROPOSED_NOT_FROZEN
FREEZE_BLOCKED_BY = G0_CANONICAL_BLAKE2B_ADAPTER
DOMAIN_TAG_ENUM = NOT_YET_GENERATED
TAGS_IN_SPEC_TABLE = 14
TAGS_PENDING_RATIFICATION = 17
```
