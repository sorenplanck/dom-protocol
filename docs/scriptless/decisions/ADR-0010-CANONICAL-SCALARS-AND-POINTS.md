# ADR-0010 — representação canônica de escalares e pontos

Status: **ACEITA** para os formatos DOM e reutilizada pelo binding da ADR-0013.

## Contexto

A DOM possui duas representações de bytes que não podem ser tratadas como uma
só.

## Evidência

- **CÓDIGO DOM AUTORITATIVO:** `dom-crypto/src/keys.rs::Scalar` armazena LE e
  converte explicitamente; `schnorr.rs::{PartialSig,SchnorrSignature,
  schnorr_challenge}` usa escalares BE; `keys.rs::PublicKey` aceita somente SEC1
  comprimido.
- **FIXTURE OU TESTE CONGELADO:** `dom-crypto/tests/negative_kav.rs` cobre zero,
  `n`, `n+1` e `n-1`; SCAD0 cobre ambas as paridades.
- **DOCUMENTO NORMATIVO:** EM §§3.1–3.2 e 15.2.

## Decisão

No transcript e formatos de G1a, todo escalar criptográfico é exatamente 32
bytes big-endian no intervalo `[1,n-1]`. O tipo legado `keys::Scalar` pode ser
reutilizado somente com `from_be_bytes`/`to_be_bytes`; sua forma interna LE não
é wire. Pontos são exatamente SEC1 comprimido `02/03 || x32`, 33 bytes. Tamanho,
prefixo, curva e canonicidade são validados por `PublicKey` e a reserialização
deve ser byte-idêntica. Identidade/infinito, ponto fora da curva e encoding
alternativo são rejeitados.

## Alternativas consideradas

LE no protocolo, redução modular e x-only foram rejeitados por divergirem das
assinaturas DOM. Aceitar encodings e normalizá-los foi rejeitado por
malleability.

## Consequências

Conversões de fronteira serão nomeadas e testadas. ADR-0013 reutiliza no binding
o mapeamento observado no challenge DOM, sem redução/retry.

## Compatibilidade

Preserva `SchnorrSignature` e `PartialSig` existentes.

## Riscos

Reversão dupla de bytes e redução silenciosa; ambas são proibidas e vetorizadas.
