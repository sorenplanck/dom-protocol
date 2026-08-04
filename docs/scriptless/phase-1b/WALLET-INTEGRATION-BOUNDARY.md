# Fronteira de integração com a Wallet V3

## Pontos de integração futuros

| Camada Wallet | Evidência existente | Extensão futura |
|---|---|---|
| `dom-wallet-storage::WalletDirectory` | gerações cifradas, lock, CAS por geração, staging/fsync/publish | namespace/transação do vault, journal e receipts |
| `dom-wallet-domain::WalletState` | generation, intents, private context redigido | referência opaca a estado adaptor; não serializar nonce cru no modelo comum |
| `dom-wallet-core` | persiste reserva/contexto antes de request e reusa bytes em retry | chamar trait do vault em fluxos adaptor somente |
| recovery/restore | staging e validação existentes | iniciar `RESTORE_QUARANTINED` para capability adaptor |
| frontend/Tauri | comandos com redaction | nunca expor secret, receipt bruto ou metadados internos |

## Isolamento obrigatório

Transações comuns da Wallet continuam pelo fluxo atual. Elas não:

- debitam budget adaptor;
- avançam journal/âncora adaptor;
- contatam witness;
- entram em quarentena apenas por indisponibilidade da witness.

Somente criar/revelar/assinar uma sessão adaptor exige conectividade e receipt
antes da exportação. A Wallet pode continuar recebendo, enviando e sincronizando
transações comuns quando a witness estiver offline.

## Interfaces com Fase 3-SM

A máquina de estados recebe apenas resultados tipados da trait: reservado,
commitment persistido, exposição autorizada, bytes de retry, consumido,
quarentena ou erro. Ela não escolhe nonces, não atualiza contadores diretamente e
não trata timeout como autorização para fallback.
