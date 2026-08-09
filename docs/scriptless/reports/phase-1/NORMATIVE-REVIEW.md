# Revisão normativa comparativa — DOM Scriptless Contracts

Data da revisão: 2026-08-04
Escopo: leitura e comparação documental; nenhuma implementação ou decisão criptográfica nova.

## Fontes e método

Identificadores usados nas citações:

- **EM** — `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx`, título interno “DOM Scriptless Contracts”, subtítulo “Especificação Mestra de Engenharia e Implementação v1.0 — Revisão R1”, datada de 3 de agosto de 2026.
- **RC** — `DOM-Scriptless-Relatorio-Consolidado-v1.md`, título interno “DOM Scriptless Contracts — Relatório Consolidado de Viabilidade”, datado de 2026-08-04; o conteúdo não declara uma versão documental, embora o nome do arquivo indique `v1`.
- **CR** — `DOM-Scriptless-Cronograma-Implementacao-v1.md`, título interno “DOM Scriptless Contracts — Cronograma de Implementação”, datado de 2026-08-04; declara escopo V1 estrito, mas não uma versão documental explícita, embora o nome do arquivo indique `v1`.

O DOCX foi aberto como pacote OOXML e seu texto foi extraído somente em memória a partir de `word/document.xml`; nenhuma conversão ou gravação foi feita no original ou na cópia. Os dois Markdown foram lidos diretamente. Proveniência, metadados e hashes estão em [`NORMATIVE-SOURCES.md`](../../source-guides/NORMATIVE-SOURCES.md).

## Escopo de cada documento

| Fonte | Escopo declarado | Papel na hierarquia |
|---|---|---|
| EM | arquitetura, primitivas, protocolo, formatos binários propostos, APIs, storage, testes e gates do toolkit; sem mudança silenciosa de consenso | especificação superior; distingue `CONFIRMADO`, `NORMATIVO V1`, `PROPOSTO`, `BLOQUEADO` e `FUTURO` (EM, “Controle do documento”) |
| RC | evidência executada de viabilidade e inventário do que permanece não provado | evidência posterior para adaptor, timelock, Bulletproof e recovery output (RC §§1–5) |
| CR | sequência de entrega até o primeiro contrato 2-de-2 em regtest | dependências e gates de implementação (CR, “FASE 0” a “FASE 6”) |

O V1 comum é 2-de-2 com funding, claim por adaptor e refund por timelock absoluto; n-de-n, threshold, camada declarativa, cross-chain e canais ficam fora do primeiro produto (EM §1.4; CR, abertura e “O QUE NÃO ESTÁ NESTE CRONOGRAMA”).

## Decisões criptográficas explícitas

### Curva, pontos, scalars e primitivas

- A assinatura final, o parser, o challenge, o codec e o verificador devem ser os já autoritativos da DOM; substituir o esquema/kernel por biblioteca externa alteraria a verificabilidade e é proibido pelo desenho (EM §§3.2, 3.4, 6.1 e 6.3).
- O material disponível é consistente com o grupo usado pela DOM e encoding SEC1 comprimido de 33 bytes. Pontos recebidos devem ter tamanho exato, prefixo permitido, pertencer ao grupo, não ser identidade e reserializar para os mesmos bytes (EM §3.2). O probe posterior relata que o verificador real usa SEC1 completo de 33 bytes, sem normalização BIP340/x-only, cobrindo 16 combinações de paridade (RC §2.1).
- A representação byte a byte de scalars e sua endianness **não estão congeladas pelos documentos**. A EM chama explicitamente o exemplo de wrapper de `PROPOSTO`, exige adaptação ao backend real e proíbe presumir equivalência entre bibliotecas (EM §3.1). O mesmo vale para redução hash→scalar, rejeição/zero e retry (EM §3.4 e §21, O-10).
- Segredos devem usar wrappers específicos e zeroização; tipos locais da Bulletproof não devem implementar `Clone`, `Debug` ou serialização (EM §§3.1 e 5.5). A proibição geral de `Debug`/`Clone`/serde para secrets aparece também como pergunta obrigatória de revisão (EM §19) e checklist de release (EM §20, “Criptografia”).
- Os três documentos não estabelecem explicitamente uma API/estratégia constant-time para comparações de material secreto. Esse requisito existe no controle local de G1a, mas é uma lacuna nas três fontes importadas.

### Hash e separação de domínios

- O algoritmo-base está explícito: BLAKE2b configurado nativamente para digest de 32 bytes. BLAKE2s-256 e truncamento de BLAKE2b-512 são dialetos distintos e devem aparecer em vetores negativos (EM §3.4).
- É normativo não criar um segundo dialeto de hash: o adapter deve delegar ao backend canônico da DOM. BIP340/SHA-256, duplicação de `tag_hash` e instanciação direta de BLAKE2b genérico no módulo Scriptless são proibidos (EM §3.4). O RC não contradiz essa regra; o CR exige o novo crate sobre as primitivas existentes (CR, “FASE 1”).
- O framing da tag, personalization, salt/key, endianness, redução hash→scalar e API streaming são declarados **não congelados**. A EM exige localizar a função real, registrar `arquivo:função` e produzir vetores diferenciais antes do freeze (EM §3.4 e §21, O-10).
- A EM lista tags ASCII propostas para sessão, mensagem, transcript, participante, PoK, nonce commitment, binding, Bulletproof, contrato, template, chain e terms. Elas são case-sensitive e versionadas, mas o próprio texto condiciona seu congelamento ao gate do backend canônico (EM §3.4). Portanto o registro ainda não pode ser tratado como fechado.

### Purposes, transcript e dois nonces

- A separação entre famílias de nonce por finalidade é explícita. O Apêndice E propõe `1=refund`, `2=claim_adaptor`, `3=funding`, `4=sponsor`, enquanto G1a local controla somente Funding, Claim e Refund (EM Apêndice E §E.6; [`GATE-G1A.md`](../../phase-1a/GATE-G1A.md)). Como os códigos/tamanhos do Apêndice E são rotulados `PROPOSTOS para freeze`, esses bytes não estão congelados. A presença de `sponsor` requer delimitação formal de escopo e não autoriza ampliar G1a.
- O transcript é acumulado sobre hash anterior, digest da mensagem, direção e fase aceita; rodadas coletivas ordenam por `participant_index`, nunca por relógio/ordem de chegada (EM §8.4). Porém os layouts do Apêndice E e os vetores byte a byte permanecem propostos, logo a ordem completa de todos os campos ainda exige freeze.
- Dois nonces com binding são requisito consistente para mitigar sessões paralelas/Wagner/ROS (EM §§6.1 e 6.6; RC §5, itens 1–2; CR, “FASE 1”, entregável 2). A construção sugerida usa `R_i = R_i1 + b·R_i2` e vincula chain, sessão, purpose, template, chaves, nonces e adaptor point (EM §6.6).
- A própria EM classifica a construção aditiva de dois nonces como bloqueada até validação contra a DOM. O RC confirma o adaptor simples, mas declara que a composição adaptor + dois nonces + excess MW + Bulletproof não está coberta por prova publicada (RC §5, itens 1–2). Não existem vetores independentes congelados do binding/transcript/partials nos três documentos.

### Adaptor, challenge, adaptação e extração

- A convenção normativa é `R_hat = R + T`, pré-assinatura verificada por `s_hat·G = R_hat + e·X − T`, adaptação `s = s_hat + t` e extração `t = s − s_hat`, sempre verificando `t·G = T` (EM §§1.1 e 6.3).
- O challenge da assinatura/adaptor não recebe tag Scriptless: deve chamar byte a byte o challenge nativo do kernel sobre a mensagem exata aceita pelo verificador DOM, incluindo fee/lock height/excesso conforme o codec real (EM §§3.4, 6.2 e 6.3).
- O RC apresenta evidência posterior do ciclo verify → adapt → verify → extract em 10.017/10.017 casos, 16 combinações de paridade e zero extrações de `−t`, usando o verificador real (RC §2.1). Isso torna a convenção consistente e resolve a pergunta de viabilidade, mas não implementa nem aprova o crate G1a.
- A extração só pode ocorrer depois de a assinatura final passar no verificador real e o nonce `R` ser byte-idêntico ao da pré-assinatura (EM §6.3 e Apêndice E §E.6).

## Serialização, rejeição e vetores

- Campos on-chain continuam no codec DOM existente; nenhum campo Scriptless/DL2P pode aparecer em funding, claim ou refund (EM, “Decisões arquiteturais”, §14.3 e conclusão normativa). Não há mudança de consenso ou wire nesta fase.
- Pontos malformados, identidade e encodings que não reserializam de forma idêntica devem ser rejeitados. Scalars zero, `q`, valores fora da ordem e representações não canônicas integram os vetores mínimos (EM §§3.1–3.2 e 15.2).
- Codecs propostos usam tamanhos exatos, inteiros little-endian e reserved bytes zero, mas a EM marca os layouts/códigos do Apêndice E como propostos para freeze. Isso não congela automaticamente a representação interna do scalar nem um wire novo (EM Apêndice E, introdução).
- A EM exige vetores de tags, IDs, scalars/pontos de fronteira, adaptor/paridade, transcript, journal e serialização DOM, além de property tests, differential tests, fuzzing e fault injection (EM §§15.1–15.5).
- O RC identifica oito fixtures SCAD0 pelo SHA abreviado `e99ad8a3…eaa4b` e relata sua execução no verificador real (RC §§2.1 e 4.1). A fixture local corresponde ao hash completo `e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b`. Não há, nas fontes, vetor independente congelado para o esquema completo de dois nonces.

## Critérios de G1a

As fontes sustentam como entradas de G1a: wrappers canônicos; reutilização do backend DOM; adaptor verify/adapt/extract; dois nonces com binding; transcript/template; purposes separados; oito SCAD0; entradas malformadas; vetores diferenciais; property tests; fuzz; e verificação final real (EM §§3, 6, 8.4 e 15; RC §§2.1 e 5; CR, “FASE 1”).

Situação após esta revisão: **G1a NÃO APROVADO, 19 pendências abertas**. Documentação e evidência de laboratório não constituem implementação, vetores completos independentes ou auditoria. O script de gate continua sendo a fonte mecânica de contagem.

## Critérios de G1b, Wallet e Nonce Vault

- A EM separa estado criptográfico irreversível, estado monotônico de protocolo e projeção reversível da chain; reorg só pode alterar a última categoria (EM §10.1).
- O Nonce Vault possui transições monotônicas. Depois de commitment público o nonce não retorna ao pool; consume-before-export persiste bytes, marca consumo/tombstone, faz commit+sync e só então cria autorização de exportação. Retry apenas reenvia bytes idênticos (EM §§10.2 e 10.5).
- A persistência exige CAS, transação atômica, journal/tombstones monotônicos e fault injection em cada fronteira persist/send. Restore mescla tombstones por união/máximo, troca a época e queima qualquer nonce de exposição ambígua (EM §§10.3–10.5, §15.4 e Apêndice F §§F.1–F.3).
- O CR coloca o Nonce Vault dentro da sua “FASE 1”, enquanto a EM o agenda em “Fase 3 — Store e Nonce Vault”. Ambos exigem o mecanismo, mas divergem no nome/agrupamento da fase.
- Nenhum dos três documentos define orçamento global por chave, orçamento por contraparte, limites concorrentes/por janela ou valores numéricos. Nenhum valor pode ser escolhido nesta revisão.

Situação após esta revisão: **G1b NÃO APROVADO, 26 pendências abertas**. Os requisitos locais de G1b são mais recentes e deliberadamente mais fortes que os três documentos importados.

## Testemunha remota, restauração e rollback

Os três documentos importados tratam journal local, tombstones, backup/restore e rollback, mas **não especificam testemunha remota, recibos assinados, cadeia remota monotônica, modo auto-hospedado, metadados observáveis, requisito online ou `RESTORE_QUARANTINED`** (EM §10, §15.4 e Apêndice F; RC §5; CR, “FASE 1”).

Essas decisões foram registradas posteriormente no controle local:

- testemunha remota como baseline portátil, sem fallback silencioso, e auto-hospedagem obrigatória ([ADR-0006](../../decisions/ADR-0006-REMOTE-WITNESS-DEFAULT.md));
- exposição apenas de cadeia pseudônima de atualizações/horários, nunca identidade, contrato, valor, endereço, purpose ou tx hash ([ADR-0007](../../decisions/ADR-0007-WITNESS-METADATA.md));
- conectividade e receipt durável somente para sessões adaptor; transações comuns não usam orçamento/âncora/testemunha; restore em outro dispositivo começa em quarentena ([ADR-0008](../../decisions/ADR-0008-ONLINE-CONTRACT-REQUIREMENT.md)).

Esses ADRs governam o bootstrap atual, mas a ausência nos três documentos superiores requer incorporação por revisão/errata normativa antes de congelar o protocolo G1b.

## Dependências entre fases

- A EM organiza baseline/G0, crypto lab, types/wire, store/vault, shared output, funding/refund e claim em fases sucessivas (EM §18).
- O CR organiza adaptor+dois nonces+vault em Fase 1, shared output em Fase 2, sessão em Fase 3, funding/refund em Fase 4 e claim em Fase 5 (CR, “FASE 1” a “FASE 5”).
- A divisão vigente do clone é G1a (criptografia pura) e G1b (vault/resistência operacional), independentes; Fase 2 pode avançar após G1a somente em regtest e sem fundos reais, enquanto produção exige G1a e G1b ([ADR-0005](../../decisions/ADR-0005-PHASE-1-SPLIT.md)).

## Contradições, ambiguidades e lacunas

| Tema | Estado | Evidência e consequência |
|---|---|---|
| Status O-01/O-03/O-02 | ambiguidade temporal | EM §21 registra gates bloqueados; RC §§2.1–2.4 relata evidência posterior que resolve viabilidade. É necessário erratum/status versionado na fonte superior; não é conflito matemático. |
| Nome e conteúdo da Fase 1 | conflitante | EM §18 separa vault na Fase 3; CR inclui vault na Fase 1; ADR-0005 cria G1a/G1b. O clone está operacionalmente resolvido pelo ADR, mas as fontes importadas não refletem a divisão. |
| Curva/backend | consistente, não totalmente congelado | uso do backend DOM/secp256k1 e SEC1 é consistente (EM §§3/6; RC §2.1), mas crate/API e representação interna não são definidos pelas fontes. |
| Scalars e hash→scalar | exige decisão | endianness, redução, zero/retry e conversões são explicitamente dependentes do backend real (EM §§3.1/3.4). |
| Tags/framing | exige decisão | BLAKE2b-256 é explícito; framing, personalization, parâmetros e registro final aguardam G0/vetores (EM §3.4 e O-10). |
| Purposes | exige decisão | três purposes de G1a precisam fechamento; Apêndice E propõe códigos e inclui `sponsor`, mas rotula layouts como propostos. |
| Transcript/ordem completa | exige decisão | regra acumulativa e ordenação existem (EM §8.4), mas bytes completos e vetores não estão congelados. |
| Dois nonces | exige decisão | requisito é consistente; equações são desenho bloqueado e faltam vetores independentes (EM §6.6; RC §5). |
| Constant-time | ausente | não há requisito explícito correspondente nas três fontes; permanece requisito local de G1a. |
| Orçamentos de sessão | ausente | não há política nem medição nas fontes; G1b proíbe escolher números sem medição/freeze. |
| Testemunha remota e quarentena | ausente | cobertas apenas por ADR-0006–0008/G1b local; precisam consolidação normativa superior. |
| DL2P | fora de escopo | a EM contém referências e uma integração opcional; nenhum artefato DL2P foi importado e tais seções não governam a implementação Scriptless isolada. |

## Conclusão

Os documentos permitem preparar o freeze formal de G1a porque fecham a direção arquitetural, a convenção adaptor, o algoritmo-base de hash, o uso do verificador real e os invariantes de nonce. Eles **não** autorizam implementação ainda: framing/tags, scalar encoding, purposes, transcript completo e esquema de dois nonces precisam de decisão e vetores independentes.

G1b possui uma base local de persistência/restore na EM, mas seus requisitos atuais de orçamento, testemunha remota, receipt, privacidade e quarentena não aparecem nas três fontes importadas. G1a e G1b permanecem individualmente não aprovados.
