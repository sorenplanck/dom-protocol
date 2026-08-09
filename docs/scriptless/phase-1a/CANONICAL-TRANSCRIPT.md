# Transcript canônico — parte congelada e bloqueios

## Framing comum DOM

Toda ocorrência abaixo de `H_tag(tag, body)` significa, byte a byte:

| Ordem | Campo | Tamanho | Tipo/codificação | Origem | Validação |
|---:|---|---:|---|---|---|
| 1 | `tag_len` | 2 | `u16` little-endian | `dom-crypto::blake2b_256_tagged` | tamanho exato do ASCII |
| 2 | `tag` | variável | ASCII case-sensitive, sem NUL/Unicode runtime | EM §3.4 + ADR-0004 | enum fechado/versionado |
| 3 | `body` | conforme tabela | concatenação exata | documento/ADR específico | sem serde/bincode |

O digest é BLAKE2b nativo de 32 bytes, sem key, salt ou personalization.

## Challenge do kernel DOM — congelado

| Ordem | Campo | Tamanho | Codificação | Origem | Validação |
|---:|---|---:|---|---|---|
| 1 | `R_hat` | 33 | SEC1 comprimido | `schnorr_challenge` | `PublicKey` canônico |
| 2 | `X` | 33 | SEC1 comprimido | `schnorr_challenge` | `PublicKey` canônico |
| 3 | `chain_id` | 32 | bytes opacos DOM | `schnorr_challenge` | tamanho exato |
| 4 | `kernel_message` | 32 em consenso | digest de `TAG_KERNEL_MSG` | `validate_kernel_signatures` | mensagem real do kernel |

Tag: `DOM:kernel-sig:v1`. O digest é scalar BE sem redução.

## Commitment de dois nonces — layout documental congelado

Tag: `DOM:scriptless-nonce-commit:v1`.

| Ordem | Campo | Tamanho | Codificação | Origem | Validação |
|---:|---|---:|---|---|---|
| 1 | `chain_id` | 32 | bytes | EM §6.6 | exato |
| 2 | `session_id` | 32 | bytes | EM §§3.3/6.6/Ap. F | exato |
| 3 | `participant_id` | 32 | bytes | EM §§3.3/6.6/Ap. F | exato |
| 4 | `purpose` | 1 | ADR-0012 | EM Ap. E §E.6 | `01..03` em G1a |
| 5 | `template_hash` | 32 | digest | EM §6.6 | exato |
| 6 | `R_i1` | 33 | SEC1 comprimido | EM §6.6 | ponto canônico |
| 7 | `R_i2` | 33 | SEC1 comprimido | EM §6.6 | ponto canônico |
| 8 | `adaptor_point` | 33 no Claim | SEC1 comprimido | EM §6.6 | não identidade |

Para Funding/Refund, ADR-0013 congela uma produção condicional de **zero bytes**
para `adaptor_point`: o body termina em `R_i2`. Não se serializa identity nem um
sentinel de zeros. O purpose anterior seleciona a gramática.

## Binding coletivo — campos congelados, conversão bloqueada

Tag: `DOM:scriptless-sig-nonce-bind:v1`.

| Ordem | Campo | Tamanho | Codificação | Origem | Validação |
|---:|---|---:|---|---|---|
| 1–4 | `chain_id`, `session_id`, `purpose`, `template_hash` | 97 | como acima | EM §6.6 | exato |
| 5 | quantidade de `X_i` | 4 | `u32` LE | EM §3.4 disciplina de listas | limitada |
| 6 | `ordered(X_i)` | `33*n` | participant index crescente | EM §§3.4/6.6 | pontos canônicos, sem duplicata |
| 7 | quantidade de pares | 4 | `u32` LE | EM §3.4 | igual a `n` |
| 8 | `ordered(R_i1||R_i2)` | `66*n` | mesma ordem dos `X_i` | EM §6.6 | pontos canônicos |
| 9 | `adaptor_point` | 33 no Claim; 0 em Funding/Refund | SEC1 ou ausente por purpose | EM §6.6 + ADR-0013 | não identidade no Claim |

O body fica inequívoco pelo count, tamanhos fixos e purpose. ADR-0013 congela
`b` como o digest tagged interpretado diretamente em BE, aceito somente em
`[1,n-1]`, sem redução/retry; um valor inválido aposenta a sessão.

## Hash acumulado da sessão — ainda bloqueado

A EM §8.4 fornece
`previous_hash32 || message_digest32 || direction_u8 || accepted_phase_u16_le`
sob `DOM:scriptless-transcript:v1`. Não define o hash inicial nem os códigos de
direção/fase. Estes pertencem à Fase 3-SM e não podem ser inventados por G1a.
