# Registro de domínios e purposes de G1a

O framing de todas as tags é o de `dom_crypto::blake2b_256_tagged`; nenhuma
instância BLAKE2b paralela é permitida.

| Tag ASCII exata | Uso | Origem | Estado |
|---|---|---|---|
| `DOM:kernel-sig:v1` | challenge final DOM | código `TAG_KERNEL_SIG` + EM | CONGELADO |
| `DOM:kernel-msg:v1` | mensagem de kernel | código `TAG_KERNEL_MSG` | CONGELADO |
| `DOM:scriptless-nonce-commit:v1` | commitment de nonces públicos | EM §§3.4/6.6 + ADR-0011 | CONGELADO para o layout descrito |
| `DOM:scriptless-sig-nonce-bind:v1` | binding coletivo | EM §§3.4/6.6 + ADR-0011/0013 | CONGELADO |
| `DOM:scriptless-transcript:v1` | hash acumulado de sessão | EM §§3.4/8.4 | tag/fórmula conhecidos; discriminantes BLOQUEADOS |

Tags candidatas de Bulletproof, transporte, autenticação e sessão presentes na
EM não são promovidas por esta missão porque não pertencem ao núcleo G1a
imediato.

## Purposes v1

| Nome canônico | Byte | Uso | Origem | Estado |
|---|---:|---|---|---|
| `RefundV1` | `0x01` | assinatura de refund | EM Ap. E §E.6 + ADR-0012 | CONGELADO |
| `ClaimAdaptorV1` | `0x02` | pré-assinatura adaptor de claim | EM Ap. E §E.6 + ADR-0012 | CONGELADO |
| `FundingV1` | `0x03` | assinatura de funding | EM Ap. E §E.6 + ADR-0012 | CONGELADO |
| Sponsor | `0x04` | reservado, fora de G1a | EM Ap. E §E.6 | NÃO IMPLEMENTAR |

Outros bytes são inválidos. A separação entre os três purposes ocorre pelo
discriminante obrigatório dentro do preimage de uma tag versionada, não por
tags improvisadas. Famílias de nonce são distintas por `(key, purpose)`.

## Bloqueios

- derivação byte-exata dos dois nonces secretos;
- códigos do transcript de Fase 3-SM;
- vetores independentes do esquema completo.
