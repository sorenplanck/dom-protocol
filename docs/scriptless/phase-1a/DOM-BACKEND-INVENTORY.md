# Inventário do backend criptográfico DOM

Baseline inspecionada: `769822562565f18ef55423dc992e7aa661206b4a`
em `/home/leonardov/dom-release` e no clone isolado. Origem de cada conclusão:
**CÓDIGO DOM AUTORITATIVO**, salvo indicação diferente.

| Responsabilidade | Crate, arquivo e símbolo | Tipo/formato | Rejeição e dependências | Testes existentes | Reuso por `dom-adaptor` e risco |
|---|---|---|---|---|---|
| Curva/grupo | `dom-crypto`; `keys.rs`, `schnorr.rs` | secp256k1; ordem `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` | `secp256k1 0.28`, `k256 0.13`, `secp256k1-zkp` rev `264e84ad…` | `keys.rs`, `negative_kav.rs`, `schnorr.rs` | Perfil reutilizável; aritmética geral ainda não é pública. Não usar `k256` em produção no adaptor. |
| Scalar validado geral | `dom-crypto::keys::Scalar` | 32 bytes armazenados **LE**, faixa `[1,n-1]`; `from_be_bytes` faz conversão explícita | zero e `>=n` rejeitados por `secp256k1::SecretKey` | `keys.rs`; `negative_kav.rs` | Reutilizável nas fronteiras, mas LE interno não é wire Schnorr. |
| Chave secreta | `dom-crypto::keys::SecretKey` | 32 bytes **BE**, `[1,n-1]` | tamanho, zero e `>=n` rejeitados | `keys.rs` | Tipo zeroizável, mas é `Clone` e exporta cópia raw; tipos de nonce G1a precisarão wrapper mais restrito. |
| Ponto/chave pública | `dom-crypto::keys::PublicKey` | SEC1 comprimido, 33 bytes, prefixo `02/03` | tamanho/prefixo antes do parser; fora da curva e infinito rejeitados por `secp256k1` | roundtrip, prefixo, uncompressed e comprimento em `keys.rs` | Parser/serializer diretamente reutilizáveis. `inner()` é crate-private, impedindo aritmética externa segura. |
| Hash BLAKE2b-256 | `dom-crypto::hash::blake2b_256` | `Blake2b<U32>`, digest nativo 32 bytes | sem key, salt ou personalization | `conformance_kav.rs`: empty/`abc` | Reutilizar exclusivamente. Não instanciar `blake2` no adaptor. |
| Hash tagged | `dom-crypto::hash::{blake2b_256_tagged,DomHasher}` | `u16_le(tag_len) || tag UTF-8 || data`; digest 32 | `&str`; comprimento precisa caber em `u16` | `dom-test-vectors/hash_vectors.rs` | Reutilizável com enum fechado de tags ASCII. Não aceitar string do chamador. |
| Challenge Schnorr | `dom-crypto::schnorr::schnorr_challenge` | tag `DOM:kernel-sig:v1`; corpo `R33 || X33 || chain_id32 || message` | digest é interpretado como scalar **BE**, sem redução; zero/`>=n` falham na operação seguinte | `schnorr.rs`; SCAD0 | Chamar diretamente. Não criar challenge Scriptless. |
| Assinatura Schnorr | `dom-crypto::schnorr::{schnorr_sign,schnorr_partial_sign,schnorr_aggregate_sigs}` | partial `s32` BE; assinatura `R33 || s32`, 65 bytes | pontos/scalars canônicos; soma zero falha | KAVs em `schnorr.rs` | Helpers existentes comprovam a convenção aditiva, mas não implementam dois nonces/binding. |
| Verificador primitivo | `dom-crypto::schnorr::schnorr_verify` | `sG == R + eX` | parser canônico e challenge DOM | `schnorr.rs`; SCAD0 | Reuso obrigatório. |
| Verificador real de kernel | `dom-consensus::validate_kernel_signatures` | mensagem `H_tag(TAG_KERNEL_MSG, features_u8 || fee_u64_le || lock_height_u64_le)`; kernel 115 bytes | parseia assinatura e excess; rejeita falha como consenso | `kav_byte_freeze.rs`; `scad0_adaptor_fixtures.rs` | Gate deve chamar este wrapper além do verificador primitivo. |
| Serialização | `dom-consensus::transaction::{TransactionKernel,DomSerialize,DomDeserialize}` | `features1 || fee8 || lock_height8 || excess33 || signature65`; inteiros do writer são LE | tamanhos fixos e parsers de `Amount`/`Commitment` | roundtrips e KAVs de consenso | Reuso obrigatório; G1a não altera wire. |
| Nonce Schnorr atual | `dom-crypto::schnorr::{schnorr_sign,rfc6979_nonce}` | RFC6979/HMAC-SHA256 sobre `BLAKE2b(message || chain_id)` | rejection sampling constante; função privada | vetor RFC6979 e teste de divergência de prehash | Não serve como vault nem como construção de dois nonces. API G1a de produção não aceitará nonce livre da aplicação. |
| Constant-time | `keys.rs::Scalar::ct_eq`; `schnorr.rs::{is_scalar_valid,bytes_lt_ct}` | `subtle::Choice` | percorre todos os 32 bytes | testes unitários/negativos | Reutilizar padrões; comparisons de novos secrets precisam auditoria própria. |
| Zeroização | `keys.rs::{Scalar,SecretKey}` | `Zeroize` + `ZeroizeOnDrop` | `PublicKey` não é secreto | testes de traits não constituem cobertura de todos os caminhos | Base útil; `Clone` e cópias `[u8;32]` exigem wrapper G1a não clonável/não serializável. |

## Lacuna de API que bloqueia a implementação

`PublicKey::inner`, `schnorr::is_scalar_valid` e as operações escalares/pontos
necessárias a `R_i1 + bR_i2`, `R+T` e verificação de partial são privadas. A
solução segura é uma extensão mínima, revisada e testada em `dom-crypto`, não
uma dependência de produção direta em `k256` dentro de `dom-adaptor`. A forma
dessa extensão só deve ser implementada depois da revisão da derivação secreta e
com vetores independentes; o mapping de binding já está congelado na ADR-0013.

## Evidência laboratorial não autoritativa

O arquivo oficial não rastreado
`crates/dom-node/src/bin/adaptor_parity_probe.rs` (14.421 bytes, SHA-256
`e036be3b8ae8f081a214958ed47e0d311c14e91277cbc57797f7276ef8c66064`)
foi lido sem alteração. Ele usa DOM para challenge/verificação e `k256` para
cross-check, confirmando `s=s_hat+t` sem fator de sinal. Nenhum byte de código
foi importado; os testes rastreados SCAD0 são a evidência executável usada aqui.
