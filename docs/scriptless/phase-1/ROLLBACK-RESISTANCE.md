# Resistência a rollback

O estado local deve usar journal append-only encadeado e uma âncora monotônica independente do backup. A testemunha remota é a baseline portátil; uma implantação auto-hospedada deve existir no desenho.

Antes de exportar qualquer material de uma sessão adaptor, o avanço da âncora precisa produzir receipt durável. Retrocesso, fork ou divergência levam a `RESTORE_QUARANTINED`, sem reutilização de nonce ou recuperação de orçamento.

A validação G1b deve congelar uma matriz que cubra crash em cada boundary, retry idempotente, rollback local, backup anterior, restauração, indisponibilidade/divergência da testemunha e recuperação sem ressurreição. A obrigação online se limita a sessões adaptor; transações comuns não leem nem avançam a âncora.
