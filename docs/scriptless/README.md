# DOM Scriptless Contracts

Esta árvore documenta e controla o desenvolvimento isolado do DOM Scriptless Contracts. O bootstrap cria apenas isolamento, baseline, documentação, fixtures importadas e o esqueleto compilável de `dom-adaptor`; nenhuma criptografia da Fase 1 está implementada.

## Hierarquia normativa

1. Especificação Mestra DOM Scriptless Contracts v1.0.
2. Relatório Consolidado.
3. Cronograma de Implementação.
4. Código, fixtures e testes congelados.

Os três primeiros documentos foram fornecidos pelo operador e estão registrados, com proveniência, cópias byte-idênticas e SHA-256, em [`source-guides/NORMATIVE-SOURCES.md`](source-guides/NORMATIVE-SOURCES.md). A [revisão comparativa](reports/phase-1/NORMATIVE-REVIEW.md) e a [matriz de inputs G1a](phase-1a/NORMATIVE-INPUT-MATRIX.md) distinguem decisões congeladas de propostas, ambiguidades e ausências.

## Gates

- **[G1a](phase-1a/GATE-G1A.md):** criptografia pura, incluindo vetores, transcript, dois nonces, adaptação, extração e verificação real DOM.
- **[G1b](phase-1b/GATE-G1B.md):** Nonce Vault, orçamento, journal, testemunha remota, restauração e resistência a rollback.

O [índice da Fase 1](phase-1/README.md) preserva os caminhos legados sem duplicar a autoridade normativa. Produção exige G1a e G1b aprovados. Fase 2 pode avançar após G1a somente em regtest e sem fundos reais. Esta execução não aprova nenhum gate.
