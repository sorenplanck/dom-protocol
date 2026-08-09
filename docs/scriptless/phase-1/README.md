# Fase 1 — índice de compatibilidade

A Fase 1 foi dividida formalmente em dois gates independentes pelo [ADR-0005](../decisions/ADR-0005-PHASE-1-SPLIT.md):

- [Fase 1a — criptografia pura](../phase-1a/SCOPE.md), controlada por [GATE-G1A](../phase-1a/GATE-G1A.md).
- [Fase 1b — vault e resistência operacional](../phase-1b/SCOPE.md), controlada por [GATE-G1B](../phase-1b/GATE-G1B.md).

Produção exige G1a **e** G1b. A Fase 2 pode avançar após G1a somente em regtest e sem fundos reais.

A colisão de nomenclatura normativa está resolvida pelo
[ADR-0015](../decisions/ADR-0015-PHASE-3-NOMENCLATURE.md):

- **Fase 3-SNV/G1b** = Store e Nonce Vault da Especificação Mestra;
- **Fase 3-SM** = sessão, transporte e máquina de estados do Cronograma.

Novos documentos não usam “Fase 3” sem o sufixo.

Os arquivos restantes nesta pasta são índices/redirecionamentos mantidos para compatibilidade com links do bootstrap. Eles não são fontes normativas concorrentes.

| Caminho legado | Fonte autoritativa atual |
|---|---|
| `GATE-G1.md` | `phase-1a/GATE-G1A.md` + `phase-1b/GATE-G1B.md` |
| `SCOPE.md` | `phase-1a/SCOPE.md` + `phase-1b/SCOPE.md` |
| `HASH-DOMAINS-AND-PURPOSES.md` | `phase-1a/HASH-DOMAINS-AND-PURPOSES.md` |
| `NONCE-VAULT-ARCHITECTURE.md` | `phase-1b/NONCE-VAULT-ARCHITECTURE.md` |
| `SESSION-BUDGET.md` | `phase-1b/SESSION-BUDGET.md` |
| `ROLLBACK-RESISTANCE.md` | `phase-1b/ROLLBACK-RESISTANCE.md` |
