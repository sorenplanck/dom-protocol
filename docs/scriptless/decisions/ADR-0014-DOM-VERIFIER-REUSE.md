# ADR-0014 — reutilização do verificador DOM

Status: **ACEITA**.

## Contexto

Uma assinatura adaptada só tem valor se for aceita pelo caminho real de
consenso.

## Evidência

- **CÓDIGO DOM AUTORITATIVO:** `dom-consensus::validate_kernel_signatures`
  constrói `kernel_message`, parseia `SchnorrSignature`/`PublicKey` e chama
  `dom_crypto::schnorr_verify`; `dom-tx::kernel_message` usa o mesmo layout.
- **FIXTURE OU TESTE CONGELADO:** `scad0_adaptor_fixtures.rs` verifica os oito
  kernels por ambos os caminhos.
- **DOCUMENTO NORMATIVO:** EM §§6.1–6.3 e 14.1; RC §2.1.

## Decisão

G1a chamará `dom_crypto::schnorr_challenge` e `schnorr_verify`; o teste de gate
também passará a assinatura final por
`dom_consensus::validate_kernel_signatures`. Não haverá challenge ou verificador
Scriptless alternativo.

## Alternativas consideradas

Verificação somente por equação em `k256` ou mock: rejeitadas como evidência de
gate. Podem existir apenas como cross-check de teste.

## Consequências

Testes G1a precisam construir um kernel canônico de 115 bytes e usar a mensagem
real de kernel.

## Compatibilidade

Alinha-se exatamente ao consenso atual, sem alterá-lo.

## Riscos

Um teste que use mensagem arbitrária pode validar a primitiva e ainda não provar
aceitação do kernel; ambos os níveis são obrigatórios.
