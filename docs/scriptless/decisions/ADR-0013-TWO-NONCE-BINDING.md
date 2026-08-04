# ADR-0013 — esquema de dois nonces e binding

Status: **ACEITA** para equações, binding e gramática v1; derivação secreta de
nonces e validação independente continuam **BLOQUEADAS**.

## Contexto

Dois nonces com binding são obrigatórios contra sessões paralelas, mas a DOM
atual oferece apenas Schnorr aditivo de nonce único.

## Evidência

- **DOCUMENTO NORMATIVO:** EM §6.6 define `R_i=R_i1+bR_i2`, os preimages de
  commitment/binding e `s_i_hat=k_i1+b k_i2+e x_i`, explicitamente sujeitos a
  validação DOM; RC §5 e Cronograma Fase 1 mantêm a prova pendente.
- **CÓDIGO DOM AUTORITATIVO:** `dom-crypto::schnorr_partial_sign` implementa
  somente `k+ex`; não há hash-to-scalar público para `b` nem aritmética pública
  suficiente.

## Decisão

As equações da EM §6.6 são o esquema v1. O binding usa o mesmo mapeamento do
challenge DOM: digest tagged de 32 bytes interpretado diretamente como inteiro
BE; aceitar somente `[1,n-1]`, sem redução e sem retry. Um digest inválido aborta
e consome a sessão/nonces. Para `ClaimAdaptorV1`, o preimage termina em `T33`;
para `FundingV1` e `RefundV1`, termina após as listas e **zero bytes** de adaptor
point são anexados. O purpose torna a gramática inequívoca e identidade não é
usada como sentinel.

A implementação ainda não começa nesta missão. Antes do caminho produtivo,
faltam a derivação exata de `k_i1/k_i2`, vetores independentes e a extensão
estreita em `dom-crypto`; esses itens não alteram os bytes já congelados.

## Alternativas consideradas

Redução módulo `n` e retry com contador foram rejeitados por divergirem do
challenge DOM e criarem outro dialeto. Rejeição/aposentadoria da sessão foi
escolhida. Um sentinel de identidade/zeros e uso direto de `k256` foram
rejeitados.

## Consequências

G1a permanece aberto. O segundo agente pode implementar o contrato do vault,
mas não deve exportar material antes de G1a/G1b.

## Compatibilidade

Evita criar um dialeto incompatível.

## Riscos

Nonce reuse, last-mover e divergência entre backends. A rejeição de digest é
fail-closed e consome budget, impedindo retry/grinding gratuito.
