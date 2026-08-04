# Escopo da Fase 1

A Fase 1 cria `dom-adaptor` sem modificar consenso ou wire. Ela é dividida em dois gates inseparáveis para produção:

## G1a — criptografia pura

Integração com primitivas DOM autoritativas, esquema de dois nonces, transcript/binding, partials, agregação, adaptação, extração, fixtures independentes e verificação final pelo verificador real da DOM.

## G1b — vault e resistência operacional

Trait do Nonce Vault no `dom-adaptor`; implementação persistente na Wallet V3; orçamentos globais e por contraparte; concorrência/janelas; journal encadeado; testemunha remota; âncora monotônica; receipts duráveis; crash/retry/backup/restore/rollback e quarentena.

A testemunha remota é a baseline portátil. O desenho também deve incluir testemunha auto-hospedada obrigatória. Conectividade online é exigida somente ao abrir/avançar sessões adaptor. Transações DOM comuns não consultam nem avançam a âncora.

Fora do escopo: DL2P, mudanças de consenso, genesis, network magic, formatos persistidos, protocolo, wire, criptografia provisória e qualquer valor normativo inventado.
