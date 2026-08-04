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
