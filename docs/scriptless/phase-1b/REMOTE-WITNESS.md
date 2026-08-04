# Testemunha remota de G1b

A testemunha remota é a baseline portátil para Windows, Linux e macOS. TPM, Secure Enclave e equivalentes são backends opcionais de reforço; não substituem a baseline e não existe fallback silencioso para arquivo local.

Para uma sessão adaptor, a Wallet obtém e persiste um receipt assinado de avanço monotônico antes de exportar qualquer material. Retry da mesma operação deve ser idempotente. Falta de conectividade impede somente a sessão adaptor.

Uma testemunha auto-hospedada é requisito do produto, não uma extensão opcional. O protocolo e os formatos permanecem pendentes de congelamento normativo; esta missão não os inventa nem implementa.
