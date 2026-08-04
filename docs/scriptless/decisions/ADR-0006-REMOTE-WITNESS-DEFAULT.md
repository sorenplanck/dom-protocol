# ADR-0006 — testemunha remota como baseline portátil

Status: aceito como baseline arquitetural; protocolo pendente.

## Decisão

A testemunha remota é a baseline portátil de G1b para Windows, Linux e macOS. TPM, Secure Enclave e equivalentes são backends opcionais de reforço. Não existe fallback silencioso para arquivo local.

O produto deve incluir modo de testemunha auto-hospedada. Indisponibilidade da testemunha falha fechada para novas sessões adaptor, sem bloquear transações comuns.

## Limites

Transporte, assinatura, encoding, autenticação, operação e deployment não são definidos nesta missão.
