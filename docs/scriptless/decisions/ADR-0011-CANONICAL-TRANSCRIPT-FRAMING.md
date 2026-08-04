# ADR-0011 — framing do transcript canônico

Status: **ACEITA** para o framing DOM e payloads G1a explicitamente listados;
transcript cumulativo completo continua **BLOQUEADO**.

## Contexto

A EM fornece fórmulas e layouts candidatos, mas marca o Apêndice E como
proposto para freeze e não define todos os discriminantes.

## Evidência

- **DOCUMENTO NORMATIVO:** EM §§3.4, 6.6, 8.4, 15.2 e Apêndice E.
- **CÓDIGO DOM AUTORITATIVO:** `blake2b_256_tagged` fixa apenas o framing comum
  `tag_len_u16_le || tag_ascii || data`.

## Decisão

Congelam-se o framing comum da DOM, a disciplina `fixed`/`u32_le length`/`u32_le
count` da EM §3.4 e as sequências de campos G1a que a EM declara explicitamente,
descritas em `CANONICAL-TRANSCRIPT.md` e `SERIALIZATION-PROFILE.md`. Não se
atribuem bytes para estado inicial, direção, enum completo de fases ou
presença/ausência de adaptor point. Nenhuma estrutura Rust de produção será
criada para partes bloqueadas até esses bytes serem decididos e vetorizados.

## Alternativas consideradas

Usar serde/CBOR, concatenação ad hoc ou copiar envelopes DL2P: rejeitadas.
Escolher discriminantes convenientes: rejeitada por falta de evidência.

## Consequências

O hash tagged e alguns subtranscripts ficam rastreáveis; o transcript completo
e o esquema de dois nonces continuam bloqueados.

## Compatibilidade

Não altera nenhum formato DOM existente.

## Riscos

Ambiguidade de concatenação e cross-purpose se a implementação ultrapassar a
parte congelada.
