# ADR-0012 — códigos e versionamento de purposes

Status: **ACEITA** para G1a v1; Sponsor fica reservado e fora de escopo.

## Contexto

Funding, Claim e Refund precisam de discriminantes binários estáveis. A EM
propõe uma tabela inequívoca; esta ADR formaliza os três valores necessários.

## Evidência

- **DOCUMENTO NORMATIVO:** EM Apêndice E §E.6 propõe `refund=1`,
  `claim_adaptor=2`, `funding=3`, `sponsor=4`; EM §§3.4 e 6.6 exige purpose no
  binding; Cronograma Fase 1 exige famílias separadas.
- **ADR DE ENGENHARIA:** esta ADR promove somente os três valores de G1a para o
  perfil versionado v1.

## Decisão

`RefundV1=0x01`, `ClaimAdaptorV1=0x02` e `FundingV1=0x03`. `0x04` é reservado a
Sponsor, não implementado por G1a. Demais valores são inválidos. O byte purpose
é obrigatório nos preimages indicados; valores distintos fornecem separação
lógica dentro da tag versionada. Alterar a tabela exige nova versão/domínio.

## Alternativas consideradas

Strings, ordem alfabética e três tags sem discriminante foram rejeitadas por
não corresponderem ao layout proposto e ampliarem o registro.

## Consequências

Há bytes fechados para os três purposes, mas a ausência de adaptor point em
Funding/Refund continua bloqueada no transcript geral.

## Compatibilidade

Não toca wire/consenso; é formato off-chain novo e versionado.

## Riscos

Confundir Claim genérico com `claim_adaptor` ou ativar Sponsor implicitamente.
