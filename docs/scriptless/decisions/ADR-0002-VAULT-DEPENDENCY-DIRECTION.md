# ADR-0002 — direção da dependência do vault

Status: aceito como invariante arquitetural.

O trait do Nonce Vault pertence ao `dom-adaptor`; sua implementação persistente pertence à Wallet V3. A Wallet pode depender de `dom-adaptor`. `dom-adaptor` não pode depender da Wallet, impedindo inversão de camadas e acoplamento da criptografia pura ao armazenamento.
