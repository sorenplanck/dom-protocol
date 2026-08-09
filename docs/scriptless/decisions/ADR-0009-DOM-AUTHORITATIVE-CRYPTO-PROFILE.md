# ADR-0009 — perfil criptográfico autoritativo da DOM

Status: **ACEITA** para o perfil já implementado pela DOM; não aprova G1a.

## Contexto

G1a precisa interoperar com assinaturas de kernel existentes sem criar outro
dialeto criptográfico.

## Evidência

- **DOCUMENTO NORMATIVO:** Especificação Mestra (EM) §§3.1–3.4 e 6.1–6.3;
  Relatório Consolidado (RC) §2.1.
- **CÓDIGO DOM AUTORITATIVO:** `dom-crypto/src/hash.rs::{blake2b_256,
  blake2b_256_tagged,DomHasher}`, `keys.rs::{Scalar,SecretKey,PublicKey}` e
  `schnorr.rs::{schnorr_challenge,schnorr_verify,SchnorrSignature}` no commit
  `769822562565f18ef55423dc992e7aa661206b4a`.
- **FIXTURE OU TESTE CONGELADO:** `dom-crypto/tests/conformance_kav.rs`,
  `negative_kav.rs` e `dom-consensus/tests/scad0_adaptor_fixtures.rs`.

## Decisão

O perfil é secp256k1, pontos SEC1 comprimidos de 33 bytes, escalares Schnorr em
32 bytes big-endian, assinaturas `R33 || s32`, BLAKE2b nativo de 256 bits e
challenge/verificação exclusivamente por `dom-crypto`. `dom-adaptor` não terá
backend ou hash criptográfico paralelo. Novos tipos secretos são opacos, não
`Debug`/`Clone`/serde, usam `ZeroizeOnDrop` e comparam material secreto somente
por operações constant-time baseadas em `subtle`, seguindo os helpers DOM.

## Alternativas consideradas

- `k256` diretamente no crate: rejeitada como backend de produção duplicado.
- BIP-340/x-only: rejeitada; a DOM preserva a paridade SEC1 completa.
- nova primitiva de hash: rejeitada.

## Consequências

A implementação exigirá uma API estreita e revisada em `dom-crypto` para a
aritmética ainda privada. Probes podem usar outro backend apenas para
verificação independente, nunca como caminho de produção.

## Compatibilidade

Não muda consenso, wire, kernel, challenge ou assinatura persistida.

## Riscos

Confundir `keys::Scalar` little-endian com escalares Schnorr big-endian ou
contornar APIs privadas com outro backend produziria incompatibilidade.
