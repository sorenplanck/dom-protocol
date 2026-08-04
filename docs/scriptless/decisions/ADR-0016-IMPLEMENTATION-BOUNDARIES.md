# ADR-0016 — fronteiras entre dom-adaptor, Store, Wallet e máquina de estados

Status: **ACEITA** para direção de dependências; protocolos concretos pendem de
G1a/G1b.

## Contexto

O vault precisa ser abstraído pelo núcleo, persistido pela Wallet e orquestrado
pela sessão sem criar dependência circular.

## Evidência

- **DOCUMENTO NORMATIVO:** EM §§5.5, 6.6, 8, 10 e 18.
- **CÓDIGO DOM AUTORITATIVO:** `dom-wallet-storage::WalletDirectory` já oferece
  writer lock, geração esperada, staging, `fsync` e publicação; não é ainda um
  Nonce Vault nem uma âncora antirrollback.
- **ADR DE ENGENHARIA:** ADR-0002, ADR-0003 e ADR-0006–0008.

## Decisão

`dom-adaptor` possui tipos opacos, erros e a futura trait do Nonce Vault; depende
de `dom-crypto`, nunca da Wallet. A implementação transacional, journal e cliente
da testemunha ficam em crates da Wallet V3. Fase 3-SM orquestra a trait e não
acessa arquivos do vault. Transações comuns usam seu caminho atual e não chamam
orçamento, âncora ou testemunha.

## Alternativas consideradas

Vault dentro de `dom-adaptor`, trait na Wallet e fallback em arquivo local:
rejeitados por acoplamento, inversão de dependência ou rollback silencioso.

## Consequências

O contrato pode ser testado com implementações de teste explicitamente tipadas;
o backend de produção só existe na Wallet. Exportação exige receipt durável.

## Compatibilidade

Nenhuma mudança no wallet/consensus wire. Integração futura será aditiva.

## Riscos

A publicação por gerações da Wallet, isoladamente, não impede restauração de
backup antigo. A testemunha e a quarentena continuam obrigatórias.
