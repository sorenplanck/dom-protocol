# ADR-0005 — divisão da Fase 1 em G1a e G1b

Status: aceito.

## Decisão

G1a (criptografia pura) e G1b (vault e resistência operacional) são gates independentes, com checklists e evidências separados.

Após aprovação formal de G1a, a Fase 2 pode avançar somente em regtest e sem fundos reais. Esse avanço não implica aprovação de G1b nem prontidão para produção. Produção exige G1a **e** G1b aprovados.

## Consequências

`phase-1a/` e `phase-1b/` são as fontes autoritativas. `phase-1/` permanece como índice de compatibilidade e status agregado, sem checklist normativo duplicado.
