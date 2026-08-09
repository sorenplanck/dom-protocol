# Gate G1a — criptografia pura

Estado: **NÃO APROVADO**. Este checklist controla exclusivamente G1a. A existência de documentação, esqueleto ou fixture candidata não conclui item algum; cada fechamento exige evidência independente congelada e revisão formal.

- [ ] Adaptor signatures especificadas e implementadas somente sobre primitivas autoritativas da DOM.
- [ ] Esquema de dois nonces com binding especificado e congelado.
- [ ] Transcript canônico, incluindo binding, partials e agregação, congelado byte a byte.
- [ ] Purposes Funding, Claim e Refund fechados e versionados.
- [ ] Separação de domínio comprovada entre os três purposes.
- [ ] Registro canônico e versionado de domínios de hash congelado.
- [ ] Uso exclusivo do hash autoritativo da DOM por meio de `blake2b_256_tagged`.
- [ ] Ausência comprovada de BLAKE2b, challenge, parser ou verificador paralelo.
- [ ] Comparações constant-time aplicadas a todo material secreto relevante.
- [ ] Zeroização comprovada de nonces, shares e segredos em todos os caminhos.
- [ ] Tipos secretos sem `Debug`, clonagem ou serialização genérica indevida.
- [ ] Oito vetores SCAD0 congelados e revisados byte a byte.
- [ ] Vetores independentes congelados para o esquema de dois nonces.
- [ ] Adaptação e extração congeladas em vetores independentes.
- [ ] Assinatura final verificada pelo verificador real da DOM.
- [ ] Scalars malformados e de fronteira rejeitados sem ambiguity ou panic.
- [ ] Pontos malformados, identidade e encodings não canônicos rejeitados.
- [ ] Mutação de todos os campos críticos coberta por testes negativos.
- [ ] Fuzz dos parsers e operações de G1a concluído sem panic.

Fechar G1a não fecha G1b e não autoriza fundos reais ou produção.

## Estado do freeze versus estado do gate

| Área | Input | Implementação | Teste DOM | Validação independente |
|---|---|---|---|---|
| Perfil DOM, scalar/ponto/hash | congelado por ADR-0009/0010 | pendente | backend existente mapeado | parcial em KAVs |
| Purpose Funding/Claim/Refund | congelado por ADR-0012 | pendente | pendente | pendente |
| Adaptor `s=s_hat+t` | congelado por EM/RC/SCAD0 | pendente em `dom-adaptor` | 8 kernels passam no teste rastreado DOM | vetores externos pendentes |
| Transcript de challenge | congelado por código DOM/ADR-0014 | pendente | backend existente | KAVs DOM existentes |
| Transcript de dois nonces | construção/binding congelados; derivação bloqueada | não iniciado | pendente | pendente |
| Binding/hash-to-scalar | congelado por ADR-0013 | não iniciado | AUTO-CHECK parcial | esquema independente pendente |
| Tipos secretos/CT/zeroização | política congelada | pendente | pendente | auditoria pendente |

Nenhuma caixa acima é marcada porque nenhum requisito completo reúne input,
implementação, teste correspondente e validação exigida. Consulte
[`NORMATIVE-INPUT-MATRIX.md`](NORMATIVE-INPUT-MATRIX.md) e
[`FROZEN-CRYPTO-PARAMETERS.md`](FROZEN-CRYPTO-PARAMETERS.md).
