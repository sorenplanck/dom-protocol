---
description: Revisão de robustez e hardening defensivo do DOM antes da testnet
---

DOM Protocol — Revisão de Robustez e Hardening Defensivo (pré-testnet)

CONTEXTO E PROPÓSITO (leia primeiro)
Este é um trabalho DEFENSIVO de garantia de qualidade no MEU PRÓPRIO repositório,
do qual sou o mantenedor (Soren Planck). O objetivo é endurecer o código antes da
testnet: encontrar e corrigir fragilidades de robustez, validação e tratamento de
entradas malformadas, para que a rede resista a uso adversarial quando estiver no
ar. NÃO há alvo externo. NÃO se trata de atacar sistemas de terceiros. Todo teste
roda localmente, contra este repositório, e serve para FECHAR fragilidades, nunca
para explorá-las fora daqui. É o equivalente a testes de estresse e validação de
robustez que qualquer projeto sério faz antes de ir para produção.

POSTURA DE TRABALHO
Trabalhe contra o CÓDIGO REAL, nunca contra relatórios ou docstrings. Não confie
em comentários — confirme na fonte e, quando possível, com um teste que executa.

PRINCÍPIOS (inquebráveis)
- Nunca mascarar falha: não afrouxar asserção, não marcar #[ignore], não inserir
  sleep para "passar". Se um teste de robustez revela um defeito, o defeito é o achado.
- Distinguir defeito real de teste flaky com EVIDÊNCIA executável.
- Decisões de mérito (mudar consenso/design/economia) NÃO são suas: documente a
  opção com trade-offs, marque "PRECISA DECISÃO HUMANA" e pare.

CONTEXTO JÁ CONHECIDO (construa sobre isto, não re-derive)
- 23 crates. Núcleo: dom-core, dom-crypto (Pedersen, Bulletproof, Schnorr, H
  generator), dom-consensus (validação tx/bloco, equação agregada, cut-through,
  PMMR), dom-chain (UTXO set, reorg, side-chain, reconstrução de estado),
  dom-pow (RandomX, ASERT, target), dom-mempool, dom-wire + dom-node (Noise,
  IBD, relay, Dandelion, miner), dom-store (LMDB), dom-wallet, dom-config.
- Já corrigidos (CONFIRME que continuam corrigidos, não re-investigue do zero):
  Noise frame overflow (fragmentação em dom-wire/src/codec.rs); genesis state
  drift (genesis_canonical_changeset() em dom-chain, create==reopen);
  Pedersen/Bulletproof H mismatch (generator unificado + bridge sec1<->zkp).
- Auditorias prévias em audit/*.md. NÃO repita o que já cobrem; VERIFIQUE o que
  ficou aberto e procure o que NÃO pegaram.

PRIMEIRO PASSO OBRIGATÓRIO
1. Build verde: cargo build --workspace e cargo test --workspace (anote falhas e
   se são flaky vs. consistentes; contorne só o necessário se RandomX/LMDB travar).
2. Leia audit/*.md e KNOWN_ISSUES.md; valide pelo CÓDIGO se itens RESOLVED ainda
   conferem (o cabeçalho pode estar desatualizado).

ESCOPO EM FASES — rode uma fase por vez, cada achado com teste que executa quando possível.

FASE 1 — INTEGRIDADE MONETÁRIA E DE CONSENSO (prioridade máxima)
Verifique se as invariantes de valor se sustentam em TODOS os caminhos: a equação
agregada de soma (saídas - entradas - taxas == recompensa) fecha sempre? coinbase
nunca paga mais que recompensa+taxas? há overflow/underflow em taxas, supply ou
target (u64/u128)? todo output confidencial, incluindo coinbase, passa pela
verificação de range proof na faixa [0, 2^52)? a mesma UTXO pode ser gasta duas
vezes no mesmo bloco? o cut-through preserva o balanço? o estado reconstruído por
create e por reopen é idêntico após N reorgs? bloco de side-chain é persistido
antes ou depois da validação contextual de entradas?

FASE 2 — ROBUSTEZ CRIPTOGRÁFICA
Schnorr: a verificação checa R on-curve, s dentro do campo, e rejeita ponto no
infinito / chave identidade? há maleabilidade (s vs -s)? reuso de nonce? soma de
chave indevida em assinatura agregada? Bulletproof: range.start==0 é suficiente?
há teto de tamanho antes de desserializar (proteção contra entrada gigante)?
bridge sec1<->zkp: o passo de is_square pode aceitar ponto ambíguo? Domain
separation: o chain_id entra em todo challenge/hash, impedindo reaproveitamento de
assinatura entre Regtest/Testnet/Mainnet?

FASE 3 — ROBUSTEZ DE REDE E TRATAMENTO DE ENTRADA
Parsers (dom-wire): como o código reage a payload truncado, bytes sobrando, prefixo
de tamanho mentindo o conteúdo, contagem enorme que pré-aloca memória demais? IBD:
o que acontece se um peer serve headers/blocos inválidos, fora de ordem, em volume
que pressiona memória, ou um bloco cujo hash não casa o pedido? Mempool: enchê-lo
de transações com assinatura inválida pressiona CPU? a política de taxa/peso é
contornável? há reinserção duplicada após reorg? Peer manager: min_outbound é
respeitado, evita self-dial, e o Dandelion não vaza origem nem trava? Noise:
confirme que a fragmentação tem teto de buffer (não permite reassemblagem infinita).

COMO TRABALHAR
- Para cada hipótese, prefira ESCREVER UM TESTE que exercita a entrada malformada e
  mostra se o código rejeita corretamente (robusto) ou aceita (defeito). Rode-o.
  Cole a saída no relatório. Testes nomeados robustness_/adversarial_. Meça números reais.

PERMISSÕES E LIMITES DE ESCRITA (regra dura)
- READ-ONLY em todo código de produção: NÃO modificar nada em crates/**/src/**,
  Cargo.toml, deploy/, scripts/, packaging/, nem qualquer arquivo existente.
- ESCRITA permitida SOMENTE para criar arquivos NOVOS em:
    * crates/**/tests/  e  crates/dom-integration-tests/
    * audit/FABLE5_SECURITY_AUDIT.md
  Não edite testes/arquivos já existentes; se precisar de helper, crie arquivo novo.
- PROIBIDO: git add, git commit, git push, git checkout -b, alterar branch/config,
  ou qualquer escrita fora dos dois caminhos acima.
- PROIBIDO afrouxar, remover ou marcar #[ignore] em teste existente.
- cargo build/cargo test são permitidos.
- Se para provar um achado você precisaria tocar em src/, NÃO toque: descreva o
  caso, marque "PRECISA PATCH PARA CONFIRMAR" e deixe a decisão comigo.
- Tudo permanece local. Sem exfiltração.

ENTREGÁVEL (só escrever o arquivo; SEM commit/push)
audit/FABLE5_SECURITY_AUDIT.md com: 1) resumo executivo + classificação de
prontidão (regtest/testnet privada/pública/mainnet) com justificativa; 2) tabela
de achados (ID, severidade, título, arquivo:linha, status: confirmado por teste/
por leitura/refutado); 3) por achado: descrição, cenário, evidência (nome do teste
+ saída/comando), impacto, correção com trade-offs, testes faltantes, marcando
"PRECISA DECISÃO HUMANA" quando for mérito; 4) verificação dos fixes herdados
(Noise/genesis/Pedersen) ainda válidos com prova; 5) o que NÃO consegui testar e
por quê; 6) limitações de método.
