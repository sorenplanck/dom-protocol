# Modelo de crash, retry, rollback e restauração

| Ponto de crash | Estado seguro após reabertura | Ação permitida |
|---|---|---|
| antes da reserva durável | nenhuma reserva | nova tentativa com novo fluxo lógico |
| após reserva/budget, antes dos bytes | slot continua gasto | completar ou abortar consumindo |
| após bytes duráveis, antes do witness | bytes não exportáveis | retry idempotente do avanço remoto |
| após witness aceitar, antes de receipt local | estado incerto | consultar por `RequestId`; nunca avançar com novo nonce |
| após receipt durável, antes da exportação | exposição autorizada | retornar bytes persistidos |
| durante/depois da exportação | tratar como exposto | retry byte-idêntico ou consumir |
| durante consumo/tombstone | reconciliar journal/store/witness | escolher estado monotonicamente mais avançado |
| backup antigo/restauração | `RESTORE_QUARANTINED` | reconciliar com witness; nenhuma sessão adaptor |
| witness/store em fork | divergência | quarentena/fail-closed; intervenção auditável |

## Regra de merge

Restore é união de tombstones e máximo monotônico comprovado por receipts, nunca
substituição cega por snapshot. Ausência local não prova que um nonce/budget não
foi consumido. Uma restauração incapaz de obter evidência remota permanece em
quarentena; não existe fallback para arquivo local.

## Parâmetros não escolhidos

Número de retries, backoff, timeout, retenção do journal/tombstones e duração de
quarentena permanecem parametrizados para medição. A propriedade de segurança
não pode depender de um valor default não congelado.
