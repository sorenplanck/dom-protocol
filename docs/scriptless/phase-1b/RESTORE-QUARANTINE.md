# Quarentena de restauração

Toda restauração em outro dispositivo começa em `RESTORE_QUARANTINED`. Nesse estado, a Wallet não abre nem exporta material de sessão adaptor até reconciliar journal, época, âncora e receipts com a testemunha.

Backup local não é autoridade para reduzir contador, restaurar orçamento ou reviver nonce. Divergência, ausência de receipt verificável ou cadeia remota incompatível mantêm a quarentena.

Transações comuns permanecem isoladas: elas não consultam orçamento, âncora ou testemunha. A política exata de saída da quarentena requer especificação e testes G1b; não é definida nesta missão.
