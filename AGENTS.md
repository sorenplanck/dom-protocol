# DOM Scriptless Contracts — regras do fork isolado

- Este repositório é o fork local de desenvolvimento do DOM Scriptless Contracts.
- `/home/leonardov/dom-release` e `/home/leonardov/dom-wallet-v3` são fontes oficiais somente para leitura. Todo desenvolvimento ocorre nos clones sob `/home/leonardov/dom-scriptless-dev`.
- DL2P, arquivos `DL2P-*`, modelos `rfc000*.py`, especificações L2 antigas e mudanças de consenso DL2P estão fora deste projeto.
- A integração em repositórios oficiais só pode ser considerada após implementação completa e testes aprovados; push, merge, release e publicação estão proibidos neste ambiente.
- A Fase 1 corresponde ao crate `dom-adaptor` e não pode alterar consenso, genesis, network magic, serialização, protocolo, wire ou blocos persistidos.
- O laboratório fornece evidência e fixtures candidatas, nunca implementação autoritativa.
- Commits devem ser pequenos, auditáveis e restritos ao escopo.
- Fixtures congeladas não podem ser regeneradas pelo mesmo código sob teste.
- Não inventar formatos, tags de hash, purposes, políticas ou limites numéricos.
- Não duplicar Schnorr, BLAKE2b, parser de pontos, challenge ou verificador autoritativo da DOM.
- Não usar `unsafe`, `todo!()`, `unimplemented!()` nem mocks confundíveis com produção.
- Produção exige aprovação de G1a e G1b; o bootstrap não autoriza implementação criptográfica.
