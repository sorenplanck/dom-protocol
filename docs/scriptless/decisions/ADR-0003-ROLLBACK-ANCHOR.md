# ADR-0003 — âncora contra rollback

Status: baseline arquitetural; formatos pendentes.

G1b usa testemunha remota como baseline portátil e exige uma opção auto-hospedada no desenho. Journal local encadeado e âncora monotônica independente do backup impedem ressurreição de nonce/orçamento. Exportação requer receipt durável. Divergência produz `RESTORE_QUARANTINED`.

A âncora é avançada somente por sessões adaptor. Transações comuns não dependem dela. Transporte, encoding, identidade, autenticação e formato do receipt permanecem pendentes da norma.
