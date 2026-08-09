# Gate G1b — vault, orçamento e rollback

Estado: **NÃO APROVADO**. Este checklist controla exclusivamente G1b. Documentação não constitui implementação ou evidência de fechamento. Nenhum valor numérico de orçamento é escolhido aqui.

- [ ] Trait do Nonce Vault definido no `dom-adaptor` sem dependência da Wallet V3.
- [ ] Implementação transacional e persistente localizada na Wallet V3.
- [ ] Reserva de nonces durável antes de qualquer exposição de material de sessão.
- [ ] Consumo de nonces durável e irreversível em sucesso, aborto, crash e retry.
- [ ] Orçamento global por chave medido, congelado e aplicado.
- [ ] Orçamento secundário por contraparte medido, congelado e aplicado.
- [ ] Limite de sessões concorrentes medido, congelado e aplicado.
- [ ] Limite por janela medido, congelado e aplicado.
- [ ] Abortos consomem orçamento e nunca o devolvem.
- [ ] Journal append-only encadeado e validado em reabertura.
- [ ] Âncora monotônica independente de backup e estado restaurável.
- [ ] Testemunha remota adotada como baseline portátil, sem fallback silencioso local.
- [ ] Receipts assinados validados e persistidos antes da exportação de material.
- [ ] Retry idempotente comprovado para reserva, avanço e receipt.
- [ ] Crash recovery comprovado em todos os boundaries duráveis.
- [ ] Rollback, fork e divergência detectados e tratados sem ressurreição.
- [ ] Restauração incapaz de ressuscitar nonce, sessão ou orçamento consumido.
- [ ] Restauração em outro dispositivo começa em `RESTORE_QUARANTINED`.
- [ ] Rotação de chave/identidade pseudônima e encerramento de época especificados e testados.
- [ ] Matriz Windows, Linux e macOS executada para persistência, crash e restore.
- [ ] Modo de testemunha auto-hospedada entregue como requisito do produto.
- [ ] Testemunha recebe somente cadeia pseudônima, atualização monotônica e dados mínimos de receipt.
- [ ] Testemunha não recebe identidade, contrato, valor, endereço, purpose ou hash de transação.
- [ ] Vazamento residual de cadeia pseudônima de atualizações e horários documentado e testado.
- [ ] Sessões adaptor bloqueiam exportação enquanto conectividade/receipt não estiverem disponíveis.
- [ ] Demonstração de que transações comuns não consultam orçamento, âncora ou testemunha.

Fechar G1b não fecha G1a. Produção exige ambos formalmente aprovados.

## Estado do freeze versus estado do gate

| Área | Contrato documentado | Implementação | Testes/matriz |
|---|---|---|---|
| Direção de dependência/trait | sim, ADR-0002/0016 e interface semântica | pendente | pendente |
| Store transacional/journal | modelo consolidado | pendente na Wallet | crash matrix pendente |
| Budgets | semântica congelada; números não escolhidos | pendente | medição pendente |
| Witness/receipt | baseline e metadados permitidos definidos | protocolo byte a byte pendente | interoperabilidade pendente |
| Restore/quarentena | comportamento fail-closed definido | pendente | rollback/restore pendente |
| Isolamento de transações comuns | boundary definido | demonstração pendente | teste de ausência de chamadas pendente |

Documentação de fronteira não fecha caixas. Consulte
[`IMPLEMENTATION-BOUNDARY.md`](IMPLEMENTATION-BOUNDARY.md) e
[`CRASH-RECOVERY-MODEL.md`](CRASH-RECOVERY-MODEL.md).
