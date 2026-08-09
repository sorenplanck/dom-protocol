# Inputs do protocolo da testemunha remota

Baseline portátil: ADR-0006. Privacidade: ADR-0007. Conectividade: ADR-0008.
Este documento não escolhe algoritmo de assinatura, wire ou timeout.

## Informação máxima permitida

| Campo lógico | Propriedade | Observação |
|---|---|---|
| `protocol_version` | público | fechado antes da implementação |
| `epoch_pseudonym` | pseudônimo e rotacionável | não é wallet/session/user ID |
| `request_id` | idempotency key opaca | não derivada de tx/contrato |
| `previous_anchor` | digest/contador opaco | encadeia atualizações |
| `next_anchor` | digest/contador opaco | monotônico |
| `client_auth` | autentica época, não identidade civil | construção ainda bloqueada |
| `receipt` | assinado pela witness e persistível | algoritmo/wire ainda bloqueados |

É proibido enviar identidade, contrato, valor, endereço, purpose, hash de
transação, template hash, session ID ou contraparte. A witness ainda observa a
cadeia pseudônima de atualizações e horários; esse vazamento residual é
inevitável na baseline e deve ser documentado/testado.

## Semântica necessária

- advance/lookup idempotente por `request_id`;
- rejeição de regressão, fork e predecessor desconhecido;
- receipt assinado cobre versão, pseudônimo de época, request e transição;
- rotação/encerramento de época preserva prova de monotonicidade;
- modo auto-hospedado possui o mesmo protocolo e testes;
- TPM/Secure Enclave são backends opcionais, nunca fallback silencioso.

O algoritmo de assinatura, formato byte a byte, política de rotação e retenção
são **AINDA BLOQUEADOS** por revisão de protocolo e threat model.
