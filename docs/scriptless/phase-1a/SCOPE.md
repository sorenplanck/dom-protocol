# Escopo da Fase 1a — criptografia pura

Este documento é a fonte autoritativa para o escopo de G1a. G1a cobre somente a construção e a validação criptográfica de adaptor signatures no `dom-adaptor`, sem persistência, orçamento, testemunha remota ou integração Wallet.

Inclui o esquema de dois nonces com binding, transcript canônico, purposes Funding/Claim/Refund, domínios de hash, partials, agregação, adaptação, extração, vetores independentes, entradas malformadas, mutações, fuzz e verificação final pelo verificador real da DOM.

G1a e G1b são gates independentes. Depois da aprovação formal de G1a, a Fase 2 pode avançar somente em regtest e sem fundos reais. G1a isoladamente nunca autoriza produção; produção exige G1a **e** G1b aprovados.

Fora do escopo: Nonce Vault, armazenamento, orçamento, journal, âncora, testemunha, restauração, consenso, wire e qualquer implementação DL2P.
