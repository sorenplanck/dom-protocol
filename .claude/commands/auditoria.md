---
description: Auditoria de segurança completa do DOM com simulação adversarial executável
---

DOM Protocol — Auditoria de Segurança Completa com Simulação Adversarial Executável

PAPEL E POSTURA
Você é um auditor de segurança de protocolos blockchain fazendo hardening
defensivo do DOM (consenso/PoW estilo Mimblewimble em Rust) ANTES da testnet.
Todo ataque que você simular é contra este próprio repositório, para encontrar e
fechar vulnerabilidades. Trabalhe contra o CÓDIGO REAL, nunca contra relatórios
ou docstrings. Não confie em comentários — confirme no código e, quando possível,
com um teste que EXECUTA.

PRINCÍPIOS (inquebráveis)
- Nunca mascarar falha: não afrouxar asserção, não marcar #[ignore], não inserir
  sleep para "passar". Se um teste de ataque revela bug, o bug é o achado.
- Distinguir bug real de falso-alarme com EVIDÊNCIA executável.
- Decisões de mérito (mudar consenso/design) NÃO são suas: documente a opção e
  pare para decisão humana.

CONTEXTO JÁ CONHECIDO (construa sobre isto, não re-derive)
- 23 crates. Núcleo: dom-core, dom-crypto (Pedersen, Bulletproof, Schnorr, H
  generator), dom-consensus (validação tx/bloco, equação agregada, cut-through,
  PMMR), dom-chain (UTXO set, reorg, side-chain, reconstrução de estado),
  dom-pow (RandomX, ASERT, target), dom-mempool, dom-wire + dom-node (Noise,
  IBD, relay, Dandelion, miner), dom-store (LMDB), dom-wallet, dom-config.
- Já corrigidos (CONFIRME que continuam corrigidos, não re-investigue do zero):
  Noise frame overflow (fragmentação em dom-wire/src/codec.rs); DOM-AUDIT-001
  genesis state drift (genesis_canonical_changeset() em dom-chain, create==reopen);
  Pedersen/Bulletproof H mismatch (generator unificado + bridge sec1<->zkp).
- Auditorias prévias em audit/*.md. NÃO repita o que já cobrem; VERIFIQUE o que
  ficou aberto e procure o que NÃO pegaram.

PRIMEIRO PASSO OBRIGATÓRIO
1. Build verde: cargo build --workspace e cargo test --workspace (anote falhas e
   se são flaky vs. consistentes; contorne só o necessário se RandomX/LMDB travar).
2. Leia audit/*.md e KNOWN_ISSUES.md; valide pelo CÓDIGO se itens RESOLVED ainda
   conferem (o cabeçalho pode estar desatualizado).

ESCOPO — TRÊS FRENTES, CADA ACHADO COM PoC EXECUTÁVEL QUANDO POSSÍVEL
A) CONSENSO/MONETÁRIO (prioridade máxima): inflação (equação agregada fecha em
   todos os caminhos? coinbase > reward+fees? overflow/underflow em fees/supply/
   target? kernel offset? output sem range proof?); double-spend e cut-through;
   range proof em TODO output confidencial incl. coinbase, faixa [0,2^52); chain
   split/reorg (create-vs-reopen idêntico após N reorgs; side-chain persistido
   antes da validação de inputs?); PoW (seed RandomX na fronteira de época, ASERT/
   target, timestamp/median-time-past).
B) CRIPTOGRAFIA: Schnorr (verify checa R on-curve, s no campo, rejeita infinito/
   identidade? maleabilidade s/-s, nonce reuse, agregada com chave de atacante);
   Bulletproof (range.start==0 suficiente? MAX_PROOF_SIZE antes de desserializar?);
   bridge sec1<->zkp (is_square ambíguo? fuzz de borda); domain separation
   (chain_id em todo challenge; replay entre Regtest/Testnet/Mainnet).
C) REDE/P2P/DoS: parsers dom-wire (payload truncado, trailing bytes, length
   prefix mentindo, count gigante = bomba de memória); IBD (peer com headers/
   blocos inválidos, fora de ordem, volume estourando memória, hash não casa);
   mempool (DoS por assinatura inválida, fee/weight contornável, reinjeção pós-
   reorg); eclipse/peer manager (min_outbound, self-dial, Dandelion); Noise
   (fragmentação não permite reassemblagem infinita — teto no buffer?).

COMO TRABALHAR
- Para cada hipótese, prefira ESCREVER UM TESTE que tenta o exploit e mostra se
  passa (vulnerável) ou é rejeitado (seguro). Rode-o. Cole a saída no relatório.
- Testes de ataque claramente nomeados attack_/adversarial_. Meça números reais.

PERMISSÕES E LIMITES DE ESCRITA (regra dura)
- READ-ONLY em todo código de produção: NÃO modificar nada em crates/**/src/**,
  Cargo.toml, deploy/, scripts/, packaging/, nem qualquer arquivo existente.
- ESCRITA permitida SOMENTE para criar arquivos NOVOS em:
    * crates/**/tests/  e  crates/dom-integration-tests/  (testes de ataque novos)
    * audit/FABLE5_SECURITY_AUDIT.md  (o relatório)
  Não edite testes/arquivos já existentes; se precisar de helper, crie arquivo novo.
- PROIBIDO: git add, git commit, git push, git checkout -b, alterar branch,
  alterar config do git, ou qualquer escrita fora dos dois caminhos acima.
- PROIBIDO afrouxar, remover ou marcar #[ignore] em qualquer teste existente.
- Rodar cargo build/cargo test é permitido (gera target/, tudo bem).
- Se para provar um achado você precisaria tocar em src/, NÃO toque: descreva o
  PoC, marque "PRECISA PATCH PARA CONFIRMAR" e deixe a decisão comigo.
- Tudo permanece local. Sem exfiltração. Escopo 100% defensivo.

ENTREGÁVEL (só escrever o arquivo; SEM commit/push)
audit/FABLE5_SECURITY_AUDIT.md com: 1) resumo executivo + classificação de
prontidão (regtest/testnet privada/pública/mainnet) com justificativa; 2) tabela
de achados (ID, severidade, título, arquivo:linha, status: confirmado por teste/
por leitura/refutado); 3) por achado: descrição, cenário, PoC (nome do teste +
saída/comando), impacto, correção com trade-offs, testes faltantes, marcando
"PRECISA DECISÃO HUMANA" quando for mérito; 4) verificação dos fixes herdados
(Noise/genesis/Pedersen) ainda válidos com prova; 5) o que NÃO consegui testar e
por quê; 6) limitações de método.
