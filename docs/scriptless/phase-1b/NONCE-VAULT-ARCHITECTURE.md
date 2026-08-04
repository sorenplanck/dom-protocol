# Arquitetura do Nonce Vault de G1b

O trait pertence ao `dom-adaptor`; a implementação transacional persistente pertence à Wallet V3. A dependência permitida é Wallet V3 → `dom-adaptor`. A direção `dom-adaptor` → Wallet V3 é proibida.

Uma sessão adaptor precisa reservar nonce e orçamento de forma durável antes de expor material. Sucesso, aborto e falhas posteriores à reserva consomem o nonce e o orçamento. O journal append-only encadeado registra transições; a âncora monotônica externa impede que backup/restore retroceda o estado aceito.

Nenhuma exportação ocorre antes do receipt assinado e duravelmente persistido. Retry precisa ser idempotente. Crash recovery jamais pode criar uma segunda reserva, reutilizar nonce ou devolver orçamento.

Esta missão não define trait, schema, formato, algoritmo de assinatura do receipt ou transporte.
