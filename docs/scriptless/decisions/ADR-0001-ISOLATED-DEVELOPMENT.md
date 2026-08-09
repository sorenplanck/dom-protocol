# ADR-0001 — desenvolvimento isolado

Status: aceito para bootstrap.

DOM e Wallet oficiais permanecem somente leitura. Desenvolvimento ocorre em clones locais completos, sem hardlinks, com branches/tags de baseline, pushes bloqueados e sem `origin`. Integração oficial só pode ocorrer em processo futuro, após implementação completa e gates aprovados.
