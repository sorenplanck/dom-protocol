# Auditoria code-first de absorção para DOM v2

Data: 2026-08-27

Branch DOM: `feat/domv2-interop-absorption`

Base DOM: `166b55299d5642200e0f5b7e384b14cf8bcbd17f`

Método: código executável, testes e comportamento observado; documentação só foi aceita quando confirmada pelo código.

> **Limite deste documento.** Esta auditoria responde estritamente “o que a DOM
> deve absorver dos quatro projetos”. Ela não certifica que a branch possui um
> produto operacional ponta a ponta. A avaliação complementar — incluindo
> executor de rota, daemon, carteiras, contratos, solver, deployments, operação
> e E2E multiprocesso — está em
> [`DOM-PRODUCTION-COMPLETENESS-AUDIT-2026-08-27.md`](DOM-PRODUCTION-COMPLETENESS-AUDIT-2026-08-27.md).
> No snapshot fixado, `contracts/` não pertence à árvore Git; os contratos
> atualmente visíveis existem somente no worktree local da auditoria.

## Resultado executivo

A DOM já tem a melhor base dos cinco projetos para liquidação atômica centrada na DOM: composição de duas liquidações com o mesmo ponto adaptador `T`, conservação do valor de trânsito, ordem segura de funding, refund armado antes de funding, seleção RFQ determinística, relay autenticado/durável e adaptadores que só promovem fatos finalizados. Substituir essa base por HTLC público, pelo orderbook Kael ou pelo contrato otimista Keystone seria regressão.

Há, contudo, seis absorções que melhoram materialmente a segurança:

1. **P0 — consenso Bitcoin completo no verificador portátil de evidências.** A DOM verifica PoW contra o `nBits` declarado pelo próprio header e verifica encadeamento, mas não prova que o `nBits` era o esperado segundo checkpoint, retarget e median-time-past. Keystone cobre esse espaço.
2. **P0 — autorização de revelação ao vivo, multi-leg e de uso único.** A DOM valida a rota estaticamente e ordena funding com segurança, mas o seam `submit_claim` da execução EVM ainda aceita o artefato de claim sem exigir ali uma fotografia finalizada recente de todas as pernas. Kaystra fornece a ideia de guarda; Kael fornece o padrão anti-TOCTOU. Nenhuma das duas implementações deve ser copiada literalmente.
3. **P0 — pipeline independente de evidência com `PASS`/`FAIL`/`INCONCLUSIVE`.** Cipher separa coleta de julgamento. A DOM deve acrescentar manifesto assinado, hashes e proveniência para não herdar a fragilidade do JSON não autenticado de Cipher.
4. **P0 — gate de vazamento de segredos para artefatos.** O sanitizer Kaystra mostra a necessidade, mas precisa ser refeito como verificador não destrutivo, tipado e consciente de stores binários.
5. **P0 — vetores diferenciais Bitcoin.** Os mesmos casos devem concordar entre a implementação DOM, Bitcoin Core e uma implementação independente; retarget, MTP, SegWit e Merkle ímpar são obrigatórios.
6. **P1 — identidade Bitcoin única e vinculada ao settlement.** A derivação BIP86 de Keystone é uma boa referência conceitual, desde que a DOM trate colisão de índice, vincule o resultado de forma verificável e preserve seu perfil scriptless.

O manifesto normativo e validável desta auditoria está em `DOM-CODE-FIRST-ABSORPTION-MANIFEST-2026-08-27.json`. Ele registra cada decisão, destino, política de cópia e teste de aceitação.

## Escopo realmente inspecionado

| Projeto | Código fixado | Branches consideradas | Licença efetiva para absorção |
|---|---|---|---|
| Cipher | `fbf49ba4f394cf4b3b7739dad159745ad17282c1` | `main` | Nenhuma licença encontrada. Tratar como todos os direitos reservados; estudar e reimplementar conceitos, sem copiar para produção. |
| Kaystra | `5f3a39464b4cc038f44a46da07a502db850b7534` | `main` e `audit/sanitize-evidence-artifacts` | Repositório declara licença pendente/todos os direitos reservados; apenas `KaystraRevealGuard.sol` declara MIT. |
| Kael | `f7e022974b19935e105a01bbeb4c257e358606d3` | `main`, `audit/30-node-market-testnet-sim` e branches remotas antigas | Workspace Rust e contratos MIT. A branch de auditoria acrescenta a simulação; as outras branches não contêm mecanismo mais novo que `main`. |
| Keystone | `56535d28f100dfb6aa42145239b5a8b54eaa9e44` | `main` | BUSL-1.1: desenvolvimento, teste, auditoria, pesquisa e testnet são permitidos; produção com valor real exige acordo até 2028-07-02, quando muda para MIT. |

Isto impõe uma fronteira simples: ideias de Cipher/Kaystra devem ser reimplementadas; código Keystone só pode entrar em produção após relicenciamento/acordo ou por uma implementação independente baseada em especificações públicas do Bitcoin; Kael é compatível com MIT, ainda sujeito a revisão técnica.

## Evidência de execução

| Projeto | Resultado reproduzido | Limite observado |
|---|---|---|
| Cipher | 54 testes Python passaram: 30 do harness, 20 do modelo ideal e 4 de pesquisa; bytecode compilou. | `compileall` altera bytecode Python versionado pelo projeto; esses artefatos foram restaurados após o teste. Os cenários reais dependem de Bitcoin Core e não transformam coleta ausente em `PASS`. |
| Kaystra | 4 testes Foundry passaram; módulos Python compilaram. | Cobertura do guard é pequena: não há fuzz, chamadas hostis, reverts, boundary de `tCut` nem teste Bitcoin multi-leg. |
| Kael | 49 testes Foundry e 109 testes Rust passaram, incluindo Anvil, propriedades anti-vazamento e a simulação de mercado. | Rust depende do artefato Foundry já compilado; build Rust isolado falha se `contracts/out` não existir. `forge fmt --check` falha no código do repositório. |
| Keystone | 120 testes Rust, 61 testes da lib verifier sem features e 100 testes Foundry passaram; o invariant executou 128.000 chamadas. | `cargo test -p keystone-verifier --no-default-features` com todos os integration targets falha porque `real_chain.rs` não é feature-gated. `forge fmt --check` falha. O ZK é interface/mock, não um prover/verificador de produção. |

Falha de formatação ou feature-gating não invalida a lógica testada, mas impede chamar esses repositórios de release-clean. Nenhum resultado sintético foi contado como teste de rede real.

O gate final da DOM executou `cargo test --all-targets` para `route-composer`, `kaystra-core`, `btc-evidence`, `adapter-btc-live`, `adapter-evm`, `rfq`, `intent-book`, `solver`, `relay`, `dom-adaptor` e `f3-harness`: todos os testes executados passaram. A propriedade `crash_prefix_recovery_converges` completou todos os casos com store real e `fsync` em 2.633,99 segundos; a propriedade criptográfica de 10.000 ciclos também passou. Dois alvos permaneceram intencionalmente ignorados pelo próprio código: o soak manual de 10.000 Bulletproofs e o regenerador que escreve fixtures. O e2e Anvil condicionado por feature compilou, mas não foi executado nesse comando offline. `cargo fmt --all --check`, o gate do manifesto e seus quatro testes negativos também passaram.

## Baseline de segurança que a DOM deve preservar

Antes de absorver, é crucial reconhecer o que já está melhor na DOM:

- `route-composer` exige duas sessões diferentes, um único hub DOM, o mesmo ponto adaptador, conservação do montante DOM, uma única taxa e ladders de deadline por domínio. Ambas as rotas precisam ter refund armado; upstream confirma antes de downstream financiar (`crates/route-composer/src/lib.rs:46-62`, `415-444`).
- `kaystra-core` já é uma máquina de estados pura, persistente, com efeitos depois de commit, terminais imutáveis e regressão explícita após reorg. Isso é superior ao cursor monotônico de Kaystra e Kael.
- `rfq` vincula o digest do conjunto de candidatos e faz seleção exata/determinística (`crates/rfq/src/selection.rs:340`). Isso é superior ao orderbook volátil de Kael.
- `relay` autentica envelopes, protege replay/gap/equivocação e conserva bytes persistidos (`crates/relay/src/auth.rs:117`, `541-563`).
- O adaptador BTC usa claim scriptless em key-path MuSig/adaptor e refund CSV. O Taproot CLTV de Cipher é útil como oracle de laboratório, não como substituto.
- `btc-live` coleta uma fotografia local revalidada, com identidade de rede, ancestralidade e bytes de blocos. `btc-evidence` é corretamente não custodial e não conhece `t`.
- O adaptador EVM exige fatos finalizados e detecta reorg. A fraqueza residual está no último passo de autorização do segredo, não na regra de finality do observador.

Qualquer absorção que reintroduza hashlock público correlacionável, segredo no verificador, chave dentro do adapter, decisão baseada em tip não finalizado ou side effect antes de persistência deve ser recusada.

## Cipher: o que absorver

### 1. Revisor independente e classificação tri-state — absorver agora

O coletor declara no próprio código que nunca emite `PASS`/`FAIL` (`original_harness/bitcoin/regtest/run_s12.py:2`). O revisor separado devolve `INCONCLUSIVE` quando faltam fatos e só produz `PASS` depois de conferir cadeia ativa, conflitos, destinatário, valor, outpoint e timing (`review_artifacts.py:155-263`). Testes também impedem que os cenários de coleta contenham lógica de classificação.

Aplicação na DOM:

- `CollectorArtifactV1`: bytes brutos, endpoints, chain identity, bloco/tx e digest do coletor; nenhum veredito.
- `ReviewManifestV1`: versão, digest de todos os artefatos, commit do verificador, policy digest, resultado tri-state e assinatura do revisor.
- `INCONCLUSIVE` nunca deve virar evento USPE e nunca deve autorizar claim, refund ou funding.
- Dois revisores independentes devem conseguir reproduzir o mesmo resultado a partir do mesmo manifesto.

Cipher não autentica criptograficamente o JSON. Portanto a DOM deve absorver a separação, não o formato frágil.

### 2. Harness Bitcoin Core fresco e cross-check de descriptor — adaptar

O fixture cria wallets descriptor novas, deriva o Taproot de duas maneiras, compara output key, scriptPubKey, folhas e control blocks e executa conflitos reais de claim/refund. Isso é excelente como oracle independente contra o adapter DOM.

Adaptação segura: manter o contrato DOM scriptless atual e usar o harness apenas para validar transações reais, política de mempool, maturidade CSV, anexos proibidos, sighash e dupla despesa. Um perfil NUMS/duas folhas pode permanecer isolado como teste negativo ou compatibilidade futura.

### 3. Enumeração completa do instance binding — absorver como schema, não como criptografia

O modelo ideal liga chain ID, genesis, versão de fork, política/checkpoint de finality, contrato/code hash, SID, destinatário, valor, outpoint, deadlines e transação. Essa lista é uma boa matriz de mutação para `SettlementTermsV2` e `RouteBundleV1`.

O mecanismo `IDEAL_SIG|secret|tx` em `cipher-vwe-ideal/cipher_vwe_ideal/crypto.py:32` é apenas SHA-256 determinístico. Ele não fornece witness encryption. O módulo de pesquisa acerta ao não promover WE geral, signature-WE sem construção concreta ou comitê com autoridade externa. Manter tudo isso em quarentena até haver construção, prova, implementação constante, auditoria e vetores adaptativos.

### O que não absorver de Cipher

- a primitiva VWE ideal como segurança real;
- comitê de decriptação, pois adiciona autoridade externa;
- Taproot CLTV de duas folhas como perfil padrão;
- evidência JSON sem assinatura/hash de árvore;
- qualquer arquivo de backup ou relatório que contradiga o código atual.

## Kaystra: o que absorver

### 1. Guard multi-leg pré-reveal — absorver o requisito, reescrever a implementação

`KaystraRevealGuard` verifica bundle, `tCut`, margem e estado/deadlines de várias liquidações (`contracts/src/KaystraRevealGuard.sol:71-85`). O orchestrator equivalente falha fechado em erros RPC. É a ideia certa: um segredo com efeito em várias pernas só pode ser publicado quando todas permanecem executáveis.

O contrato atual, porém, ignora exatamente `t` e `caller` na função `canReveal(bytes32,bytes32,address)`. Também deixa chamada externa hostil reverter a consulta, só enxerga estado EVM e não ancora uma fotografia Bitcoin. Copiá-lo daria uma falsa sensação de segurança.

A versão DOM deve emitir uma `RevealAuthorizationV1` opaca e de uso único, vinculada a:

- `route_bundle_hash`, `terms_hash` de cada perna e ponto `T`;
- `H(t*G)` ou comprovação interna de que `t*G == T`, sem gravar `t` no artefato;
- identidade do executor/broadcaster autorizado;
- para cada chain: block hash, altura/timestamp finalizado, policy digest e snapshot digest;
- estados ao vivo: refund armado, funding canônico/finalizado, não refundado, não claimed e não reorged;
- orçamento restante para observar, assinar, substituir, confirmar e ainda exercer o upstream claim/refund;
- expiração curta, nonce de consumo e digest dos bytes exatos a transmitir.

O broadcaster deve consumir essa capability na mesma transação durável que registra os bytes. Erro, timeout, revert, dado ausente ou snapshot velho equivale a `DENY`.

### 2. Calibração de margem e caps — adaptar

`kaystra_calibrate.py` calcula `M` usando propagação + maior finality + cadência do watcher + censura + failover RPC, multiplicado por fator de segurança (`tools/kaystra_calibrate.py:59-60`). A decomposição é boa e deve alimentar a policy da rota.

O cálculo atual usa percentil simples sem tamanho mínimo, intervalo de confiança, rejeição de schema ou disciplina de outliers. A DOM deve produzir um artefato assinado contendo dataset hash, algoritmo, versão, janela temporal, N, percentis, pior caso observado e caps. Mudança de policy invalida capabilities ainda não consumidas.

### 3. Bundle operacional único — adaptar

`kaystra_bundle.py` valida ordem de deadlines e reúne pernas, margem e policy. A DOM deve estender o seu binding para um bundle consumível por composer, watcher, signer e reviewer, evitando configurações divergentes entre processos.

### 4. Watcher — absorção seletiva

São úteis: preflight antes da ação, `testmempoolaccept` para Bitcoin, PSBT finalize/decode, RBF, substituição EIP-1559/legacy, limites de fee/bounty, idempotência e terminal checks.

Não copiar: cursor que apenas cresce com o safe tip, chave de journal sem block hash, ações por comandos genéricos e inferência do tipo de ação por assinatura textual. A DOM deve conservar store autenticado, bytes exatos e rollback por âncora canônica.

### 5. Sanitizer de evidência — reimplementar como gate não destrutivo

O script da branch de auditoria só edita texto, usa regex ampla e chega a apagar SID público. Isso perde proveniência e ainda não encontra segredo em SQLite, CBOR, logs comprimidos ou variantes de chave.

A solução DOM precisa de dois modos:

- `check`: somente leitura, falha CI e aponta classe/localização sem ecoar o segredo;
- `export`: cria cópia sanitizada separada e um mapa de integridade que liga cada arquivo exportado ao digest do original.

O classificador deve distinguir secreto (private key, seed, mnemonic, nonce secreto, adaptor scalar `t`, token RPC) de identificador público (SID, txid, pubkey, point `T`). O artefato canônico nunca é alterado.

### O que não absorver de Kaystra

- `canReveal` atual como autoridade final;
- margem fixa ou percentil sem qualidade estatística;
- cursor monotônico sem block hash;
- sanitizer destrutivo;
- confiança em somente EVM para uma rota BTC/EVM/DOM.

## Kael: o que absorver

### 1. Kernel puro + revalidação anti-TOCTOU — absorver agora

`swapkit` separa observação, decisão e execução. `verify_counterparty_leg` confere existência, hashlock, token, valor, recipient e timelocks. A máquina só permite `RedeemCounterpartyLeg` quando o snapshot é `Safe`; depois de lock, `Unsafe` conduz a refund e o segredo não é exposto (`swapkit/src/sm.rs:223-293`). O executor reexecuta a decisão imediatamente antes de lock/redeem e há testes específicos em `swapkit/src/exec/mod.rs:506-521`.

Na DOM, isso deve compor com o guard Kaystra: o guard avalia todas as pernas e cria capability curta; o executor refaz a leitura finalizada e só então consome a capability com os bytes persistidos. A máquina pura nunca recebe chave de assinatura ou cliente RPC.

### 2. Signer allowlist e preflight que não transmite — absorver

O signer recusa mainnet/chain desconhecida antes de criar o signer (`swapkit/src/exec/signer.rs:111-144`) e o preflight comprova zero transações. Esse padrão deve existir em todos os e2e que carregam chave de desenvolvimento.

### 3. Vetores Rust/Solidity — adaptar, corrigindo o domínio

O cross-check EIP-712 é bom como técnica. O tipo atual, entretanto, usa domínio somente `name/version` (`contracts/src/Order.sol:17`) e omite `chainId`/`verifyingContract`. Além disso, `created_at` não é assinado, mas decide prioridade e papel; o próprio integration test registra que ele é ignorado no payload assinado. Isso permite replay de deployment e manipulação da ordem/roles pelo relay.

Se a DOM criar gateway EIP-712, ele deve assinar toda semântica econômica, usar domínio completo, separar timestamp autenticado do servidor de dados do maker e manter candidate-set digest. Não substituir o RFQ DOM pelo orderbook Kael.

### 4. Testes vivos e taxonomia de cenários — absorver como teste

São valiosos os testes Anvil de rollback sem vazamento, mutação de cada campo, gap no limite, recipient errado e preflight. A simulação “30-node”, porém, é um processo determinístico com participantes sintéticos e métricas geradas; ela serve como gerador de cenários/JSONL, não como evidência de rede, consenso ou reorg de 30 nós.

### Falhas Kael que a DOM deve usar como testes negativos

- replay EIP-712 entre chain/contrato;
- `created_at` mutável alterando maker/taker e price-time;
- orderbook em memória sem cancel/fill/partial fill durável;
- comparação de preço baseada em valor bruto em vez de razão normalizada fora do perfil estreito;
- `authorizeLeg` chamável por qualquer conta consumindo nonce do maker, o que permite griefing de ordem assinada;
- HTLC público correlacionando pernas e reduzindo privacidade;
- ERC-20 fee-on-transfer sem contabilidade por saldo recebido;
- observer com `next_block` monotônico que não representa rollback canônico completo.

Esses mecanismos não devem entrar na DOM.

## Keystone: o que absorver

### 1. Verificação completa de consenso de headers Bitcoin — P0

Este é o maior ganho técnico. `crates/verifier/src/chain.rs` caminha a partir de checkpoint confiável, exige contexto MTP exato, calcula o `nBits` esperado, aplica retarget/clamps, valida PoW e MTP. O Solidity possui implementação diferencial e testes em boundary real.

Hoje `btc-evidence` da DOM faz:

```text
parse header -> target = header.target() -> validate_pow(target)
link next.prev_blockhash -> validate_pow(next.target())
```

Isso prova que cada header satisfaz o target que ele mesmo declara, não que aquele target era permitido pelo consenso. Um atacante que controla o bundle pode declarar target mais fácil, minerar uma cadeia barata e obter uma falsa profundidade portátil. Quando o bundle vem diretamente de Bitcoin Core autenticado, o nó reduz o risco; quando a evidência é verificada de forma independente/offline, a lacuna é real.

Criar `KeystoneBitcoinEvidenceV2` na DOM, sem mudar silenciosamente V1, com:

- network params explícitos e limitados;
- checkpoint hash/height/bits/time/epoch start e exatamente 11 timestamps recentes;
- headers contíguos com altura implícita e cap estrito;
- expected-bits por altura, retarget e testnet/signet special rules quando aplicável;
- MTP, PoW, merkle, txid/wtxid e outcome existentes;
- policy que define confiança do checkpoint e profundidade/accumulated work exigidos.

O V1 não deve autorizar produção em perfis que requerem verificação trust-minimized; pode permanecer para regtest ou evidência originada por nó explicitamente confiado.

### 2. Script Bitcoin único por settlement — P1

Keystone deriva BIP86 a partir de material que inclui chain, contrato, solver, beneficiary, checkpoint, valores, deadlines, bond/deposit, asset e salt. A propriedade de field sensitivity é excelente.

Para DOM, adaptar o conceito ao descriptor scriptless existente: settlement/session/terms/route/chain e policy devem participar de uma derivação determinística e verificável. O índice BIP32 de 31 bits pode colidir; por isso, colisão deve causar retry com salt comprometido, nunca reuse silencioso. O contrato Keystone guarda somente um commitment informacional dessa derivação; a DOM deve tornar a verificação parte da autoridade que aceita funding/evidência.

### 3. Checkpoint registry — P1, com fork choice explícito

O registry impede overwrite, usa ownership em duas etapas e permite extensão após verificar headers. Ele não seleciona sozinho a cadeia de maior trabalho. A DOM deve manter forks, accumulated work, política de confirmação e governança da raiz; uma extensão válida não é automaticamente a cadeia canônica.

### 4. Settlement otimista — perfil opcional, não substituição

O `Settler` aceita claims paralelos por commitment e expõe challenges concretos para PoW, linkage, bits, timestamp, confirmations, Merkle, payment e late payment. Garbage claim não bloqueia honest claim. Bond com burn desincentiva self-challenge, depósito do payee precifica free option e push-then-pull evita receiver hostil travar finalização.

Isto pode virar um adapter USPE separado para aplicações que escolhem explicitamente:

- challenger honesto e economicamente motivado;
- liveness EVM/L2 durante a janela;
- checkpoint governance;
- challenge window e custo máximo;
- probabilidade/custo de censura.

Não deve substituir o swap adaptor atômico. O caminho otimista muda o modelo de confiança e introduz capital, janela e watcher obrigatório.

### 5. Padrões contratuais genéricos — absorver

- claims paralelos em vez de “first garbage wins”;
- payout push-then-pull;
- contabilidade ERC-20 pelo delta realmente recebido;
- deadlines de pagamento e claim separados;
- depósito contra free option;
- bond mínimo derivado do pior custo de challenge;
- burn parcial para tornar self-challenge caro;
- cada fraude aceita deve ter um challenge positivo, pequeno e determinístico.

### 6. Differential testing — absorver agora

Reaproveitar a metodologia, gerando vetores independentes de dados públicos do Bitcoin: parser limitado, CompactSize canônico, txid SegWit calculado sobre serialização legacy, Merkle com duplicação ímpar, retarget e MTP. O corpus deve rodar em DOM Rust, uma segunda implementação e Bitcoin Core; Solidity somente se o perfil otimista for criado.

### Limites que não podem ser escondidos

- BUSL bloqueia cópia em produção sem acordo/relicenciamento até a change date.
- O checkpoint é raiz confiável e o registry não prova sozinho “most work”.
- A derivação BIP86 é majoritariamente verificada off-chain; commitment on-chain não prova a derivação.
- O watcher é referência operacional e seu journal append-only não substitui o store DOM autenticado.
- Binaries usam `expect`/argumentos de chave adequados a referência, não a produção.
- `IZkClaimVerifier` e o mock dos testes não são uma implementação ZK. Manter em pesquisa.
- Tokens ERC-20 patológicos ainda exigem policy/allowlist; retorno falso depois de efeito e callbacks não padronizados precisam de threat model explícito.

## Arquitetura unificada proposta

```text
coletores sem veredito
        |
        v
manifesto de evidência assinado e hash-pinned
        |
        v
verificadores independentes (BTC consenso V2 / EVM finalizado / DOM canônico)
        |
        v
VerifiedOutcome + snapshot finalizado por perna
        |
        v
RouteRevealReadinessV1 (função pura, fail-closed)
        |
        v
RevealAuthorizationV1 curta, one-shot, vinculada aos bytes
        |
        v
store: persistir + fsync + consumir capability
        |
        v
broadcaster: revalidar âncoras e transmitir bytes idênticos
```

As seis regras centrais são:

1. Nenhum coletor julga a própria evidência.
2. Nenhum verificador recebe `t`, nonce secreto ou chave.
3. Nenhuma decisão usa tip quando a policy exige finalized/canonical.
4. Nenhum segredo chega ao broadcaster sem capability one-shot ainda fresca.
5. Nenhum side effect ocorre antes de persistência durável dos bytes exatos.
6. Ausência, contradição, erro RPC, reorg ou orçamento insuficiente sempre nega; nunca degrada para caminho permissivo.

## Plano de implementação em ondas

### Onda 0 — testes que demonstram as lacunas

Adicionar primeiro, sem mudar comportamento produtivo:

- header com `nBits` artificialmente fácil e PoW válido para esse target: V1 demonstra aceitação; V2 deve rejeitar;
- retarget de mainnet nos blocos 2015/2016 e vetor de span negativo/clamped;
- violação de MTP com linkage/PoW válidos;
- reorg após preparar claim e antes de broadcast: nenhum `t` transmitido;
- estado executável que expira dentro do action budget;
- guard externo que reverte e RPC que retorna dado parcial;
- secret/caller/bundle/terms trocados;
- crash entre emissão, persistência e broadcast, comprovando one-shot e byte identity;
- artefato contendo mnemonic/private key/nonce/adaptor scalar em texto e store estruturado;
- coletor incompleto produzindo `INCONCLUSIVE`, nunca `PASS`.

### Onda 1 — `btc-evidence` V2

Destino: `crates/adapters/btc-evidence` e `btc-live`.

Implementar o walker completo por especificação pública Bitcoin, com vetores independentes. Não importar código Keystone BUSL para o path MIT sem autorização de licença. Conservar o bridge USPE recebendo somente outcome público verificado.

Gate de saída: corpus diferencial, fuzz de parser/caps, real-chain boundary, no-default-features e revisão independente.

### Onda 2 — autoridade de revelação

Destino: `route-composer`, `kaystra-core`, `store` e executores reais.

Criar tipos opacos `FinalizedLegSnapshotV1`, `RouteRevealReadinessV1` e `RevealAuthorizationV1`. A função de decisão é pura. A emissão e o consumo são persistentes/CAS. O broadcaster exige a capability e recusa bytes diferentes.

Gate de saída: propriedades anti-TOCTOU, reorg, restart e “Unsafe never exposes secret” em simulação e Anvil.

### Onda 3 — proveniência e higiene da evidência

Destino: tooling, CI e codecs de evidência.

Introduzir collector/reviewer separado, tri-state, assinatura, content tree e scanner não destrutivo. Artefatos sanitizados são exports derivados, nunca a fonte canônica.

### Onda 4 — binding único e policy calibrada

Destino: settlement terms/descriptor Bitcoin, route bundle e deployment preflight.

Adicionar derivação única com collision retry, bundle versionado e policy de action budget construída de amostras autenticadas. Revalidar o mesmo digest em todos os serviços.

### Onda 5 — adapter otimista opcional

Somente após ondas 1–4, decisão explícita de produto e resolução BUSL. Ele deve ser um perfil separado com trust assumptions visíveis, não um bypass do core adaptor.

## Gates de release

A DOM não deve chamar o perfil interoperável de production-ready enquanto qualquer item abaixo falhar:

- P0 do manifesto sem implementação e teste adversarial;
- evidência BTC portátil aceitando target autodeclarado sem expected-bits;
- claim secret-bearing sem capability ao vivo e one-shot;
- qualquer caminho em que `INCONCLUSIVE` gere outcome;
- key/test tooling capaz de assinar chain não allowlisted;
- artifact export sem secret scan e integrity map;
- código Cipher/Kaystra/Keystone copiado fora da política de licença;
- teste “30-node” sintético apresentado como evidência de rede real;
- interface ZK apresentada como prova implementada.

## Decisão final por projeto

| Projeto | Absorver | Adaptar com correção | Não absorver/promover |
|---|---|---|---|
| Cipher | separação collector/reviewer; tri-state; cross-check real | instance binding; harness descriptor | VWE ideal, committee, JSON não autenticado, Taproot CLTV como default |
| Kaystra | requisitos de guarda live; decomposição do action budget | guard multi-chain/capability; bundle; watcher ops; sanitizer | contrato atual como autoridade, cursor monotônico, redaction destrutiva |
| Kael | anti-TOCTOU; secret non-leak tests; allowlist/preflight | vetores EIP-712 e cenários | orderbook como core, HTLC público default, nonce-grief contract, simulação como prova real |
| Keystone | metodologia de consenso/differential; padrões econômicos e pull payout | BTC verifier V2; script único; checkpoints; adapter otimista | cópia BUSL não autorizada, most-work implícito, ZK mock como produção |

## Conclusão

A solução correta é **absorver invariantes e mecanismos, não importar arquiteturas inteiras**. A DOM permanece o centro de liquidação e conserva seu caminho adaptor/scriptless como default. Keystone fortalece a verdade Bitcoin; Kaystra e Kael fecham a janela entre decisão e revelação do segredo; Cipher fortalece a independência e a honestidade da evidência. Juntos, esses elementos formam uma fronteira coerente: fatos externos completos e reproduzíveis entram, uma capability curta autoriza o único efeito sensível, e somente outcomes públicos verificados chegam ao core DOM.

O manifesto associado torna essa conclusão verificável por CI e impede que itens em quarentena, mecanismos com licença restrita ou decisões sem testes de aceitação sejam promovidos por acidente.
