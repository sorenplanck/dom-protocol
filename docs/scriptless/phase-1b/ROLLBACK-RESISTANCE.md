# Resistência a rollback de G1b

O estado local combina journal append-only encadeado com âncora monotônica mantida por testemunha remota independente do backup. Receipts assinados vinculam avanço e identidade pseudônima/época sem transportar dados do contrato.

Rollback local, backup antigo, divergência, receipt inválido, cadeia remota incompatível ou restauração em outro dispositivo levam a falha fechada. Quando a reconciliação segura não é comprovada, o estado é `RESTORE_QUARANTINED`.

A matriz de evidências deve cobrir crash antes/depois de cada boundary, retry idempotente, perda de resposta, restauração, fork, divergência, rotação e encerramento de época. Nenhuma sequência pode ressuscitar nonce ou orçamento.
