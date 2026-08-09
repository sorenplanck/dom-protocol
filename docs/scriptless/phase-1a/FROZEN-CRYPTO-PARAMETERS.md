# Parâmetros criptográficos congelados antes de G1a

Congelamento não significa implementação nem aprovação do gate. As origens são
indicadas por **DOCUMENTO NORMATIVO**, **CÓDIGO DOM AUTORITATIVO**, **FIXTURE OU
TESTE CONGELADO**, **ADR DE ENGENHARIA** ou **AINDA BLOQUEADO**.

| Parâmetro | Valor congelado | Origem | Estado |
|---|---|---|---|
| Grupo | secp256k1 | EM §§3.1–3.2; `dom-crypto` | CONGELADO |
| Ordem `n` | `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` | `schnorr.rs::SECP256K1_N`; `secp256k1::constants::CURVE_ORDER` nos KAVs | CONGELADO |
| Scalar de protocolo | 32 bytes BE, `1 <= s < n` | ADR-0010; `PartialSig`/`SchnorrSignature` | CONGELADO |
| Scalar `keys::Scalar` | armazenamento LE; conversão BE explícita | `keys.rs::Scalar` | CONGELADO, não é wire |
| Ponto | SEC1 comprimido 33 bytes, prefixo `02/03` | EM §3.2; `keys.rs::PublicKey` | CONGELADO |
| Identidade/infinito | rejeitar | EM §3.2; parser `secp256k1` | CONGELADO |
| Subgrupo | validado pelo parser secp256k1; cofactor 1 | backend DOM | CONGELADO |
| Hash | BLAKE2b com parâmetro de saída nativo de 32 bytes | EM §3.4; `Blake2b<U32>`; KAV empty/abc | CONGELADO |
| Key/salt/personalization | nenhum | `hash.rs` e KAV | CONGELADO |
| Framing tagged | `u16_le(tag_len) || tag_ascii || data` | `blake2b_256_tagged`/`DomHasher` | CONGELADO |
| Challenge | `H_tag("DOM:kernel-sig:v1",R33||X33||chain_id32||message)` | `schnorr_challenge` | CONGELADO |
| Digest challenge → scalar | bytes BE, sem redução; inválido se zero ou `>=n` | `schnorr.rs` | CONGELADO |
| Assinatura | `R33 || s32_be`, 65 bytes; `sG=R+eX` | `SchnorrSignature`; `schnorr_verify` | CONGELADO |
| Adaptor | `R_hat=R+T`; `s=s_hat+t`; `t=s-s_hat`; `tG=T` | EM §§1.1/6.3; RC §2.1; SCAD0 | CONGELADO |
| Fator de sinal | nenhum; SEC1 completo preserva paridade | RC §2.1; SCAD0 | CONGELADO |
| Hash de binding → scalar | digest BE direto; aceitar `[1,n-1]`; sem redução/retry; inválido aposenta sessão | código challenge DOM + ADR-0013 | CONGELADO |
| Geração de dois nonces | contexto/derivação final e API vault não congelados | EM §§3.3/6.6; ADR-0013 | **BLOQUEADO** |

## Fronteiras secretas

- Novos nonces/shares devem ser tipos opacos, sem `Debug`, `Clone`, serde ou
  exportação genérica; origem **DOCUMENTO NORMATIVO** (EM §§3.1, 5.5, 19–20) e
  **ADR DE ENGENHARIA**.
- Memória temporária precisa de `ZeroizeOnDrop`; comparações secretas usam
  `subtle`; origem **CÓDIGO DOM AUTORITATIVO** e requisito local G1a.
- `SecretKey`/`Scalar` existentes são `Clone`; isso é uma diferença consciente,
  não licença para os tipos G1a clonarem segredos.
