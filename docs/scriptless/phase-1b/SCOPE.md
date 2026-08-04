# Escopo da Fase 1b — vault e resistência operacional

Este documento é a fonte autoritativa para o escopo de G1b. G1b cobre Nonce Vault, persistência transacional na Wallet V3, consumo durável, orçamento, journal, âncora, testemunha remota, receipts, retry/crash/rollback, restauração, plataformas e modo auto-hospedado.

G1a e G1b são gates independentes. G1b não redefine a criptografia de G1a. Produção exige aprovação formal de G1a **e** G1b. A possibilidade de Fase 2 em regtest após G1a não permite fundos reais nem dispensa G1b.

Sessões adaptor exigem conectividade e receipt durável da testemunha antes da exportação de material. Transações comuns da Wallet não usam orçamento, âncora ou testemunha e não podem ser bloqueadas pela indisponibilidade desse serviço.

Fora do escopo: valores numéricos arbitrários, fallback silencioso para arquivo local, mudança de consenso/wire e qualquer componente DL2P.
