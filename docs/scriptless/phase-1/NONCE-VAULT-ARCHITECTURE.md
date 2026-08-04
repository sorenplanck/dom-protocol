# Arquitetura do Nonce Vault

O contrato/trait do vault será definido em `dom-adaptor` somente depois do congelamento normativo. A implementação persistente pertence à Wallet V3. A direção permitida é Wallet V3 → `dom-adaptor`; a direção `dom-adaptor` → Wallet V3 é proibida.

O vault deverá coordenar alocação de sessão, consumo irreversível de nonces e orçamento, journal append-only, avanço de âncora remota, receipt durável, crash/retry e restauração em quarentena. Nenhuma exportação de material de sessão pode preceder o receipt durável.

A testemunha remota é a baseline portátil e o desenho deve oferecer testemunha auto-hospedada. Sessões adaptor requerem conectividade para a âncora; pagamentos e transações comuns permanecem independentes dela.

Este documento define somente limites de dependência e invariantes. Nenhuma API, storage schema, transporte, formato de receipt ou política numérica é escolhido no bootstrap.
