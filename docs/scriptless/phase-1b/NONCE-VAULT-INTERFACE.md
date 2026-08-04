# Contrato futuro do Nonce Vault

Este é um contrato semântico, não código nem API pronta. A trait será declarada
no `dom-adaptor`; a implementação de produção ficará na Wallet V3.

## Tipos opacos mínimos

- `VaultKeyId`, `SessionId`, `CounterpartyBucket`, `NonceSlotId` e `RequestId`;
- `PurposeV1` (Funding/Claim/Refund), sem revelar purpose à testemunha;
- `ReservationReceipt`, `ExposureBytes` e `WitnessReceipt`;
- erros tipados: conflito, budget, indisponibilidade, rollback, divergência,
  quarentena e corrupção.

IDs enviados à testemunha são pseudônimos específicos da época, não IDs de
wallet/sessão/contrato. Segredos não implementam `Debug`, `Clone` ou serde comum.

## Operações semânticas

| Operação | Pré-condição | Efeito durável | Idempotência |
|---|---|---|---|
| reservar | wallet normal, key/purpose/context válidos, budgets disponíveis | aloca slots, debita budgets e journaliza | mesmo `RequestId` retorna mesma reserva |
| comprometer bytes públicos | reserva ativa | fixa digest e bytes exatos antes de qualquer envio | mesmos bytes retornam receipt; diferentes falham |
| autorizar exposição | âncora avançada e receipt remoto durável | marca `EXPOSURE_AUTHORIZED` | repete o mesmo receipt |
| obter bytes de retry | exposição já autorizada | nenhuma nova alocação | retorna bytes byte-idênticos |
| consumir | uso, sucesso ou transição irreversível | remove secret, cria tombstone e avança journal/âncora | repetir confirma mesmo estado |
| abortar | qualquer reserva não terminal | consome slots e budget; nunca devolve | repetir confirma tombstone |
| reabrir/reconciliar | startup/crash | valida journal, store, receipt e witness | fail-closed em divergência |
| restaurar | backup em dispositivo/estado potencialmente antigo | inicia `RESTORE_QUARANTINED` | nenhuma exportação até reconciliação |

O contrato não escolhe timeout, retries, retenção, limites ou janelas. Eles são
parâmetros medidos/versionados e não podem ter default silencioso.
