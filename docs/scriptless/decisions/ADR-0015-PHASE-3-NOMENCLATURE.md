# ADR-0015 — nomenclatura inequívoca da Fase 3

Status: **ACEITA** como resolução editorial, sem alterar as fontes importadas.

## Contexto

A Especificação Mestra chama Store/Nonce Vault de Fase 3; o Cronograma chama a
máquina de estados da sessão de Fase 3.

## Evidência

- **DOCUMENTO NORMATIVO:** EM §18, “Fase 3 — Store e Nonce Vault”; Cronograma
  “FASE 3 — Sessão, transporte e estado”.
- **ADR DE ENGENHARIA:** sufixos evitam colisão sem renumerar documentos.

## Decisão

- `Fase 1/G1a`: núcleo criptográfico `dom-adaptor`.
- `Fase 3-SNV/G1b`: Store e Nonce Vault da EM; escopo do segundo agente.
- `Fase 3-SM`: máquina de estados e transporte do Cronograma.

G1a e o contrato de G1b podem avançar em paralelo. A implementação de 3-SNV
depende da trait estável de `dom-adaptor`; 3-SM consome operações do vault e
artefatos G1a. Integra-se primeiro a API criptográfica e a trait, depois a
persistência da Wallet, e por último a máquina de estados/E2E.

## Alternativas consideradas

Renumerar uma fonte ou escolher uma como “errada”: rejeitadas. “Fase 3” sem
sufixo: proibida em novos documentos técnicos.

## Consequências

As duas frentes podem ser entregues sem ambiguidade.

## Compatibilidade

É somente nomenclatura; documentos importados ficam byte-idênticos.

## Riscos

Ferramentas externas podem continuar usando o nome curto; índices devem apontar
esta ADR.
