# ADR-0007 — minimização de metadados da testemunha

Status: aceito como requisito de privacidade; formato pendente.

## Decisão

A testemunha observa uma cadeia pseudônima de atualizações monotônicas e seus horários. Ela não recebe identidade, contrato, valor, endereço, purpose ou hash de transação. Também não recebe preimagem, chave de gasto ou conteúdo de sessão.

O vazamento residual de sequência/horários e eventual metadado de rede deve ser documentado, medido e tratado antes de produção. Rotação e encerramento de época devem reduzir correlação sem permitir rollback.
