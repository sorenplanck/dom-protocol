# Matriz de plataformas de G1b

| Plataforma | Baseline obrigatória | Backend local opcional | Evidência pendente |
|---|---|---|---|
| Windows | testemunha remota + receipts assinados | TPM quando disponível | atomicidade, crash, retry, restore e auto-hospedagem |
| Linux | testemunha remota + receipts assinados | TPM/serviço protegido quando disponível | atomicidade, crash, retry, restore e auto-hospedagem |
| macOS | testemunha remota + receipts assinados | Secure Enclave/Keychain protegido quando aplicável | atomicidade, crash, retry, restore e auto-hospedagem |

Backends locais são reforços opcionais. Ausência ou falha deles não autoriza fallback silencioso para arquivo local; a baseline portátil continua sendo a testemunha remota.

A matriz deverá demonstrar também que indisponibilidade da testemunha bloqueia apenas sessões adaptor e não afeta transações comuns da Wallet.
