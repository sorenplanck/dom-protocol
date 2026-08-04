# Invariantes de segurança

- Usar exclusivamente primitivas, parser de pontos, challenge, Schnorr, serialização e verificador autoritativos da DOM.
- Não criar BLAKE2b paralelo; hashes do projeto devem passar pelo `blake2b_256_tagged` autoritativo e por um registro canônico congelado.
- Separar domínios e purposes versionados para Funding, Claim e Refund sem inventar valores antes da norma.
- Comparar material secreto em constant time e zeroizar nonces, shares e segredos.
- Tipos secretos não podem expor `Debug`, clonagem ou serialização genérica indevida.
- Nonces e orçamento consumidos não podem ser ressuscitados por crash, retry, backup ou restauração.
- Nenhuma exportação ocorre antes de receipt durável da âncora independente.
- O vault persistente pertence à Wallet V3; `dom-adaptor` não depende da Wallet.
- A testemunha remota é a baseline portátil e uma testemunha auto-hospedada é obrigatória no desenho.
- O requisito online vale apenas para sessões adaptor; transações comuns não usam nem avançam a âncora.
- Fase 1 não altera consenso, genesis, network magic, wire, serialização, protocolo ou blocos persistidos.
