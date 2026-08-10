# DOM Scriptless — Hash Domain Registry

Status: **CONGELADO** (§3.4 do
`DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`), gerado como o enum
fechado `DomainTag` em `crates/dom-adaptor/src/domain_tag.rs`.

§3.4 exige que toda tag de domínio Scriptless seja "registrada e congelada em um
único módulo", e que `DomainTag` seja "um enum fechado gerado do registro
`docs/HASH_DOMAINS.md`". Este é esse registro, e o enum é a fonte única da qual
nenhuma tag pode ser instanciada como string literal arbitrária em runtime: os
`const` de tag de cada módulo são definidos a partir de `DomainTag::X.as_str()`,
e o gate de CI `scripts/check-hash-domains.sh` recusa qualquer literal de tag
Scriptless fora do enum (salvo os labels KDF/AEAD da seção C).

## Função canônica H_tag (a substância §3.4 / G0)

Localizada in-repo — não precisa da cerimônia G0 (revogada pelo coordenador):

- **arquivo:função** — `crates/dom-crypto/src/hash.rs :: blake2b_256_tagged`
- **algoritmo/digest** — BLAKE2b configurado nativamente para 32 bytes
  (`Blake2b256`); BLAKE2s-256 e BLAKE2b-512 truncado são dialetos diferentes
- **framing exato da tag** — `len(tag) as u16 little-endian || tag_ascii || data`
- **personalization/salt/key** — nenhum; o toolkit não instancia BLAKE2b genérico
  próprio, só delega a esta função
- **endianness** — little-endian no prefixo de comprimento
- **hash→scalar** — `scalar_from_wide_be` sobre BLAKE2b-wide com rejection
  sampling e tratamento de zero do backend DOM (não presumido: pertence a este
  registro)

É uma **única** função — o "um H_tag canônico" que a §3.4 exige — logo não há
segundo dialeto. O teste diferencial
`every_scriptless_domain_matches_dom_blake2b_backend` prova que cada domínio
passa exatamente por ela; o gate de CI recusa `Sha256`, `SHA256(tag)` e `sha2::`
na superfície H_tag.

## Proibições permanentes (§3.4)

- proibido `SHA256(tag) || SHA256(tag) || mensagem` (construção BIP340);
- proibido trocar apenas SHA256 por BLAKE2b mantendo a duplicação;
- proibido instanciar BLAKE2b genérico no módulo Scriptless;
- o challenge de assinatura/adaptor do kernel **não** ganha tag Scriptless: chama
  o `dom_kernel_challenge` nativo byte a byte.

Tags são ASCII, case-sensitive, sem NUL, sem Unicode, sem normalização, sem
concatenação em runtime. **Alterar algoritmo, framing ou tag depois do freeze
exige versão de domínio nova e vetores novos; nunca se sobrescreve um vetor
publicado.**

## A — Domínios normativos §3.4 (congelados)

`DomainTag` variante ← tag ASCII. Todas na tabela da especificação mestra.

| Variante | Tag ASCII |
| --- | --- |
| `SessionId` | `DOM:scriptless-session-id:v1` |
| `Message` | `DOM:scriptless-message:v1` |
| `Transcript` | `DOM:scriptless-transcript:v1` |
| `Participant` | `DOM:scriptless-participant:v1` |
| `SharePop` | `DOM:scriptless-share-pop:v1` |
| `NonceCommit` | `DOM:scriptless-nonce-commit:v1` |
| `SigNonceBind` | `DOM:scriptless-sig-nonce-bind:v1` |
| `BpCommonCommit` | `DOM:scriptless-bp-common-commit:v1` |
| `BpCommonJoint` | `DOM:scriptless-bp-common-joint:v1` |
| `BpCommonNonce` | `DOM:scriptless-bp-common-nonce:v1` |
| `ContractId` | `DOM:scriptless-contract-id:v1` |
| `Template` | `DOM:scriptless-template:v1` |
| `ChainId` | `DOM:scriptless-chain-id:v1` |
| `Terms` | `DOM:scriptless-terms:v1` |

## B — Domínios adicionais em uso, ratificados neste freeze

| Variante | Tag ASCII | Módulo |
| --- | --- | --- |
| `SharePopChallenge` | `DOM:scriptless-share-pop-challenge:v1` | `share_pop.rs` |
| `TranscriptInit` | `DOM:scriptless-transcript-init:v1` | `session.rs` |
| `BpStatement` | `DOM:scriptless-bp-statement:v1` | `bulletproof_mpc.rs` |
| `BpRound1Commit` | `DOM:scriptless-bp-round1-commit:v1` | `bulletproof_mpc.rs` |
| `BpNoRecovery` | `DOM:scriptless-bp-no-recovery:v1` | `bulletproof_mpc.rs` |
| `ContractEnvelope` | `DOM:scriptless-contract-envelope:v1` | `contract_session.rs` |
| `ContractTransition` | `DOM:scriptless-contract-transition:v1` | `contract_session.rs` |
| `DecoyContribution` | `DOM:scriptless-decoy-contribution:v1` | `decoy_capsule.rs` |
| `DecoyCommit` | `DOM:scriptless-decoy-commit:v1` | `decoy_capsule.rs` |
| `DecoyShareSeed` | `DOM:scriptless-decoy-share-seed:v1` | `signing_share.rs` |
| `PartialCommitPopContext` | `DOM:scriptless-partial-commit-pop-context:v1` | `partial_commitment_pop.rs` |
| `PartialCommitPopChallenge` | `DOM:scriptless-partial-commit-pop-challenge:v1` | `partial_commitment_pop.rs` |
| `VaultExposurePermit` | `DOM:scriptless-vault-exposure-permit:v1` | `permit.rs` |
| `VaultOutbound` | `DOM:scriptless-vault-outbound:v1` | `permit.rs` |
| `VaultBudgetKey` | `DOM:scriptless-vault-budget-key:v1` | `reservation_binding.rs` |
| `VaultCounterparty` | `DOM:scriptless-vault-counterparty:v1` | `reservation_binding.rs` |
| `VaultComputationInput` | `DOM:scriptless-vault-computation-input:v1` | `vault_operation.rs` |

Nota: `PartialCommitPopContext`/`PartialCommitPopChallenge` são de uma PoK
redundante com a §4.2 (`share_pop.rs`); permanecem registradas enquanto o módulo
existir (ver `docs/scriptless/AUDIT-SELF-WRITTEN-MODULES.md`).

## C — Labels de KDF/AEAD (registro separado, §3.4 — NÃO são `DomainTag`)

Não são automaticamente `H_tag`; ficam fora do enum fechado por decisão da spec,
mesmo usando a mesma primitiva BLAKE2b como KDF.

| Label ASCII | Uso |
| --- | --- |
| `DOM:scriptless-secret-nonce-seed:v1` | derivação de nonce secreto |
| `DOM:scriptless-secret-nonce-wide:v1` | derivação de nonce secreto |
| `DOM:scriptless-secret-nonce-aux:v1` | derivação de nonce secreto |
| `DOM:scriptless-store:v1` … `-store-backup:v1` | store (dom-contracts) |

## Vetores congelados

Digest exato de `blake2b_256_tagged(tag, msg)`, pinado em
`domain_tag.rs::frozen_vectors_pin_the_exact_canonical_digests`. Nunca
sobrescrever.

| Domínio | mensagem | digest BLAKE2b-256 (hex) |
| --- | --- | --- |
| `SessionId` | `""` | `69f51cb9f8853a4ed7e65d8a255dbe0cc09fc52b390ac1481d2c82fa0f7f9bfc` |
| `SharePop` | `""` | `4376c43a143b10bc4946d88224df2d163f8c9b0834ff0d28d546badae99a6a0f` |
| `BpStatement` | `"abc"` | `ef7f0ba1c87a06504282f37b235c22374dcb11ced50940d78f5043c130d6b857` |

A estabilidade byte-a-byte de todo o registro é ainda ancorada pelos vetores
congelados de prova/assinatura (`g1a_*`) e pela prova colaborativa de 739 bytes:
a migração dos `const` para o enum foi verificada preservando esses vetores.

```text
REGISTRY = FROZEN
CANONICAL_HTAG = dom-crypto/src/hash.rs::blake2b_256_tagged (BLAKE2b-256 native, len_u16_le||tag||data)
DOMAIN_TAG_ENUM = crates/dom-adaptor/src/domain_tag.rs (31 domains)
DIFFERENTIAL_TEST = every_scriptless_domain_matches_dom_blake2b_backend
CI_GATE = scripts/check-hash-domains.sh
KDF_AEAD_LABELS = SEPARATE_REGISTRY_NOT_DOMAINTAG
```
