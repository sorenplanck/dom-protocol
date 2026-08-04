# Gate G1 — requisitos obrigatórios

Estado do bootstrap: **NÃO APROVADO**. Todos os itens abaixo precisam de evidência congelada. Caixas abertas são bloqueios reais; valores numéricos de orçamento continuam pendentes de medição e congelamento normativo.

## G1a — criptografia pura

- [ ] Oito fixtures SCAD0 congeladas byte a byte.
- [ ] Vetores independentes congelados para o esquema de dois nonces.
- [ ] Transcript, binding, partials e agregação congelados.
- [ ] Adaptação e extração congeladas.
- [ ] Assinatura final verificada pelo verificador real da DOM.
- [ ] `purpose` fechado e versionado para Funding, Claim e Refund.
- [ ] Separação de domínio entre os purposes.
- [ ] Registro canônico de domínios de hash.
- [ ] Uso exclusivo de `blake2b_256_tagged`.
- [ ] Ausência de implementação BLAKE2b paralela.
- [ ] Comparações constant-time para material secreto.
- [ ] Zeroização de nonces, shares e segredos.
- [ ] Tipos secretos sem `Debug`, clonagem ou serialização genérica indevida.
- [ ] Fuzz sem panic.
- [ ] Testes de scalars e pontos malformados.
- [ ] Mutação de todos os campos críticos.

## G1b — vault, orçamento e rollback

- [ ] Trait do Nonce Vault definido no `dom-adaptor`.
- [ ] Implementação persistente localizada na Wallet V3.
- [ ] Proibição verificada da dependência `dom-adaptor → dom-wallet-v3`.
- [ ] Orçamento global de sessões por chave, medido e congelado.
- [ ] Orçamento secundário por contraparte, medido e congelado.
- [ ] Limite de sessões concorrentes, medido e congelado.
- [ ] Limite por janela, medido e congelado.
- [ ] Abortos contabilizados sem devolver orçamento.
- [ ] Journal append-only encadeado.
- [ ] Âncora monotônica independente do backup.
- [ ] Testemunha remota adotada como baseline portátil.
- [ ] Testemunha auto-hospedada incluída obrigatoriamente no desenho.
- [ ] Requisito online limitado às sessões adaptor.
- [ ] Transações comuns não usam nem avançam a âncora.
- [ ] Detecção de retrocesso e divergência.
- [ ] Estado `RESTORE_QUARANTINED`.
- [ ] Nenhuma exportação antes do receipt durável da âncora.
- [ ] Matriz de crash, retry, rollback e restauração.
- [ ] Restauração incapaz de ressuscitar nonce ou orçamento consumido.

## Limite de protocolo

- [ ] Evidência de nenhuma mudança de consenso ou wire na Fase 1.
- [ ] G1a aprovado.
- [ ] G1b aprovado.

Somente a aprovação conjunta de G1a e G1b permite considerar produção.
