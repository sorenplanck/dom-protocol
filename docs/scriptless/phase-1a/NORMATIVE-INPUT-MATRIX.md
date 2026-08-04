# Matriz de inputs normativos de G1a

Data: 2026-08-04
Resultado: inputs classificados; **nenhum item de G1a aprovado por esta matriz**.

## Estados

- **CONGELADO** — decisão normativa explícita e inequívoca no seu escopo indicado.
- **CONSISTENTE** — fontes concordam na direção/requisito, mas ainda falta evidência de freeze byte a byte.
- **AMBÍGUO** — o item agrega partes com graus diferentes de definição ou admite mais de uma leitura.
- **AUSENTE** — as três fontes importadas não especificam o requisito.
- **CONFLITANTE** — fontes dão instruções incompatíveis.
- **EXIGE DECISÃO** — a própria fonte marca proposta, bloqueio ou dependência de medição/evidência antes do freeze.

Abreviações: **EM** = Especificação Mestra v1.0 R1; **RC** = Relatório Consolidado; **CR** = Cronograma. Consulte a [revisão completa](../reports/phase-1/NORMATIVE-REVIEW.md).

## Matriz

| Input | Estado | O que os documentos permitem afirmar | Pendência antes do freeze/implementação | Fonte identificável |
|---|---|---|---|---|
| Curva | CONSISTENTE | usar exclusivamente o grupo/backend já autoritativo da DOM; evidências referem secp256k1/SEC1 | localizar e congelar crate, tipos e funções reais no commit-base; nenhuma biblioteca paralela | EM §§3.1–3.2, 6.1; RC §2.1 |
| Codificação de pontos | CONSISTENTE | SEC1 comprimido de 33 bytes, ambas paridades, rejeição de identidade e reserialização idêntica | congelar parser/funções reais e vetores completos no crate DOM | EM §3.2; RC §2.1 |
| Representação de scalars | EXIGE DECISÃO | zero e não canônicos são rejeitados | endianness, bytes canônicos, conversão interna, ordem `q`, redução e zero/retry dependem do backend real | EM §§3.1, 3.4 e 15.2 |
| Hash | CONGELADO | BLAKE2b nativo com saída de 32 bytes; não BLAKE2s nem BLAKE2b-512 truncado; sem dialeto paralelo | identificar adapter autoritativo e comprovar equivalência; este freeze não cobre framing | EM §3.4 |
| Tags e domínios | EXIGE DECISÃO | tags ASCII, case-sensitive, versionadas e centralizadas são exigidas; lista candidata existe | framing, personalization, salt/key, registro final e vetores diferenciais; lista ainda é proposta | EM §3.4 e §21/O-10 |
| Purposes | EXIGE DECISÃO | Funding, Claim e Refund precisam de famílias de nonce separadas | congelar enum/bytes/versão e resolver o `sponsor` proposto fora do escopo G1a | EM Apêndice E §E.6; CR “FASE 1” |
| Transcript | EXIGE DECISÃO | evolução vincula hash anterior, digest, direção e fase; lotes ordenam por participante | encoding completo, transcript inicial, todos os campos e vetores byte a byte | EM §8.4 e §15.2 |
| Ordem dos campos | EXIGE DECISÃO | campos fixos/variáveis e listas têm disciplina proposta; participantes usam ordem estável | layouts do Apêndice E são explicitamente propostos para freeze | EM §3.4 e Apêndice E, introdução |
| Esquema de dois nonces | EXIGE DECISÃO | dois nonces com binding são defesa obrigatória contra sessões paralelas | validar composição e equações contra DOM, congelar vetores independentes | EM §6.6; RC §5; CR “FASE 1” |
| Nonce binding | EXIGE DECISÃO | deve vincular chain, sessão, purpose, template, chaves/nonces ordenados e adaptor point | tag, preimage, hash→scalar, comportamento de zero e vetores não congelados | EM §§3.4 e 6.6 |
| Challenge | CONSISTENTE | usar byte a byte o challenge nativo do kernel DOM sobre a mensagem real; nenhuma tag Scriptless | congelar arquivo:função, inputs exatos e vetores diferenciais no commit-base | EM §§3.4, 6.2–6.3; RC §2.1 |
| Equações de assinatura | AMBÍGUO | convenção adaptor simples é explícita; equação parcial de dois nonces é proposta | separar formalmente equação adaptor já confirmada da composição agregada ainda bloqueada | EM §§1.1, 6.3 e 6.6; RC §§2.1 e 5 |
| Adaptação | CONGELADO | `R_hat=R+T`, `s=s_hat+t`, segredo deve satisfazer `tG=T`, assinatura final passa no verificador DOM | implementar somente após os demais inputs e vetores; gate continua aberto | EM §§1.1 e 6.3; RC §2.1 |
| Extração | CONGELADO | `t=s−s_hat`, exigir nonce byte-idêntico, assinatura final válida e `tG=T` | implementar/testar casos de fronteira e paridade no crate isolado | EM §6.3 e Apêndice E §E.6; RC §2.1 |
| Rejeição de entradas malformadas | CONSISTENTE | tamanhos exatos; ponto inválido/identidade/não canônico e scalar zero/fora da ordem falham fechados | vincular erros e parser ao backend DOM e congelar corpus/mutações | EM §§3.1–3.2 e 15.2 |
| Zeroização | CONSISTENTE | nonces, shares e segredos temporários são zeroizados; consumo/tombstone precede exportação | provar cobertura de todos os caminhos, inclusive erro/crash | EM §§3.1, 5.5, 6.1, 10.2 e 20 |
| Constant-time | AUSENTE | nenhuma regra explícita encontrada nas três fontes | decisão normativa e comprovação para comparações de material secreto; requisito local de G1a permanece | revisão integral de EM/RC/CR |
| Restrições de tipos secretos | CONSISTENTE | secrets não devem expor bytes crus; `Debug`, `Clone`, serde/log são proibidos para material secreto salvo fronteira explícita | congelar tipos e auditoria de traits no crate | EM §§3.1, 5.5, 19 e 20 |
| Vetores independentes | AUSENTE | SCAD0 de oito vetores é identificado e correlacionado por hash; vetores canônicos são exigidos | fonte independente para dois nonces, binding, transcript, partials e agregação não foi fornecida | EM §15.2; RC §§2.1/4.1; CR “FASE 1” |
| Integração com verificador DOM | CONGELADO | assinatura final deve usar o formato/challenge/verificador real da DOM, sem reimplementação | criar adapter e testes no crate; a evidência de laboratório não conclui G1a | EM §§6.1–6.3 e 14.1; RC §2.1 |

## Resultado de prontidão

Os inputs já congelados/consistentes delimitam o trabalho, mas os itens `EXIGE DECISÃO`, `AMBÍGUO` e `AUSENTE` impedem iniciar uma implementação criptográfica sem inventar bytes ou políticas. A próxima missão normativa deve:

1. mapear as funções autoritativas DOM no commit-base;
2. congelar scalar encoding e hash/tag framing por vetores diferenciais;
3. fechar purposes e transcript;
4. obter vetores independentes do esquema de dois nonces;
5. formalizar constant-time;
6. registrar errata/versionamento que incorpore a divisão G1a/G1b.

Até lá, [`GATE-G1A.md`](GATE-G1A.md) permanece integralmente aberto.
