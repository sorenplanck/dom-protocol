# Auditoria P2P — DOM Protocol

**Repositório:** `/root/dom-protocol` (branch `chore/fmt-fix-after-pr52`, HEAD `dc5d435`)
**Data:** 2026-06-10
**Escopo:** camada P2P de rede pública — Transporte/handshake (`dom-wire`), gerência de peers (`dom-wire/manager.rs`, `dom-node`), propagação (`dom-node`, `dom-mempool`, `dom-wire/dandelion.rs`).
**Método:** leitura do código real + grep. Achados verificados na fonte; nenhum arquivo modificado.

> NÃO auditados (fora de escopo por ordem): `/root/dom-ci-debug`, `wip/wallet-confirm-receive-request`. As cópias `dom-build-seed`/`dom-ci-debug` foram ignoradas; só `dom-protocol` foi auditado.

---

## Resumo executivo

O transporte (Noise_XX + prologue ligando `chain_id`, codec cancel-safe com nonce em lockstep, timeouts de handshake/idle, caps de frame/mensagem) está **bem feito e bem testado** — é a parte mais madura da pilha. A fraqueza estrutural está em **identidade e gerência de peers**: a identidade do peer é o `SocketAddr` (IP:porta), **a chave estática Noise autenticada nunca é lida** (`get_remote_static` não aparece em lugar nenhum), então bans/reputação/diversidade degradam todos para IP — e o ban é evadível trocando a porta de origem. Não há **diversidade de subnet nos slots outbound** (a regra `/16` só vale inbound), deixando o nó exposto a eclipse (BIP155/Erebus). No relay, **todo `DomError::Invalid` — inclusive PoW inválido — pontua só 10** (a constante `INVALID_POW = 50` é código morto), exigindo ~10 blocos inválidos para banir, cada um forçando verificação completa de PoW/assinatura/estado. E o caminho de **envio não tem timeout** (só o recv tem), abrindo slowloris-on-send que trava a task do peer indefinidamente.

**Cinco itens de maior prioridade para sobreviver a rede pública hostil:**
1. **[Alto]** `codec.send`/`write_framed` sem timeout → slowloris-on-send trava tasks de peer (custo quase-zero pro atacante).
2. **[Alto]** Sem diversidade de subnet outbound → eclipse de um único /16/AS.
3. **[Alto]** `peer_id` = IP:porta, chave Noise nunca vinculada → identidade spoofável, base de toda evasão de ban e Sybil.
4. **[Alto]** PoW/estado inválido pontua 10 em vez de 50 (`INVALID_POW` é dead code) → CPU-burn barato, ~10 blocos para banir.
5. **[Médio]** Ban keyed em IP:porta + sem limite por-IP/`/24` → evasão de ban trocando porta; nó novo depende só de DNS seeds (sem fallback IP).

---

## Camada 1 — Transporte e handshake

### Achados positivos
- **Noise_XX bem fundamentado.** Padrão `Noise_XX_25519_ChaChaPoly_BLAKE2s` (`handshake.rs:13`). XX dá forward secrecy e autentica ambas as chaves estáticas. O `chain_id` + `NETWORK_MAGIC` + `PROTOCOL_VERSION` entram no **prologue** (`handshake.rs:41-48`), então qualquer MITM que mexa nesses bytes causa falha de MAC (criptograficamente detectado). Redes diferentes têm prologue diferente — testado em `handshake.rs:248-261`. **OK.**
- **Replay/forward secrecy:** XX usa efêmeras por sessão (`-> e`, `<- e, ee`), salt/nonce gerenciados pelo `snow`. Sem chaves estáticas reusadas como sessão. **OK, validado em `handshake.rs:130-153,177-199`.**
- **Timeout de handshake existe e é duplo.** 10s embrulhando todo o handshake (`HANDSHAKE_TIMEOUT_SECS = 10`, `handshake.rs:20,115-121,162-168`) e a troca de Hello tem timeout próprio de 10s (`node.rs:1691-1700`, `HELLO_EXCHANGE_TIMEOUT_SECS` em `node.rs:207`). Reservas pendentes pré-registro são podadas como stale após `handshake_timeout_secs()*3` = 30s (`manager.rs:954-961`). Um socket meio-aberto não segura slot além de ~30s. **OK.**
- **Caps de frame e mensagem.** Frame Noise ≤ `NOISE_MAX_MSG = 65535` rejeitado antes de alocar (`handshake.rs:225-227,350-353`); a mensagem lógica é validada contra `MAX_LOGICAL_MSG_BYTES` **antes** de crescer o buffer de reassembly (`codec.rs:150-160`), e overrun é rejeitado (`codec.rs:162-170`). Frame gigante não vira OOM. **OK, testado em `codec.rs:366-384`.**
- **AEAD pós-handshake.** Cada frame é `write_message`/`read_message` (ChaChaPoly, tag de 16 bytes) — MAC por frame (`codec.rs:103-108,141-144`). **OK.**
- **Codec cancel-safe com nonce em lockstep.** Toda a reassembly vive na struct; invariante "sem `.await` entre decrypt e append" mantém o nonce de recepção em sincronia mesmo sob cancelamento de `tokio::select!` (`codec.rs:24-41,137-145`). Testado de verdade dirigindo a wire byte-a-byte com cancelamentos a cada 3ms (`recv_is_cancel_safe_across_frames`, `codec.rs:391-432`). **OK — excelente.**
- **Bytes de handshake corrompidos → erro mapeado, não pânico.** `read_message` em msg corrompida vira `DomError::Invalid` (`handshake.rs:143,184,195`), que sobe para `record_pending_peer_violation` (`node.rs:1388,1543`). Sem flap descontrolado: o connector dorme 5s/passo (`node.rs:1223`) e falhas têm backoff exponencial até 5min (`manager.rs:73-90,467-487`). **OK.**
- **Idle timeout em conexão estabelecida.** `IDLE_TIMEOUT_SECS = 60`, aplicado por frame dentro de `NoiseCodec::recv` (`codec.rs:125-135`). Peer mudo por 60s é desconectado. **OK.**

### Achados negativos

- **[Alto] Identidade do peer não é vinculada à chave criptográfica Noise**
  - Local: `handshake.rs:114,161` (retornam `TransportState` cru); ausência total de `get_remote_static`/`remote_static` em `crates/` (grep retorna **zero** ocorrências); identidade derivada de `SocketAddr` em `peer.rs:43-64` e `manager.rs:723`.
  - Descrição: o XX **autentica** a chave estática remota, mas o código nunca a lê de volta. `peer_id` é o IP:porta TCP, não a pubkey. (Detalhado na Camada 2; listado aqui porque a falha nasce no transporte que descarta o material de autenticação.)
  - Impacto adversarial: nenhum pinning de chave; um peer conhecido pode ser personificado por quem controlar aquele IP:porta; toda reputação/diversidade degrada para IP (spoofável/rotacionável). Base das fraquezas de eclipse e evasão de ban.
  - Recomendação: extrair a static pubkey remota do `snow` ao final do handshake e usá-la como `peer_id` (chavear dedup/reputação/diversidade nela).

- **[Médio] Sem timeout na escrita do handshake/transporte** (ver Camada 3 — slowloris-on-send; aparece já no handshake porque `write_framed` usa `write_all` sem timeout, `handshake.rs:202-214`).
  - Impacto adversarial: durante o próprio handshake um responder com janela TCP minúscula pode segurar o `write_message` do iniciador; mitigado pelo timeout de 10s que embrulha o handshake inteiro, mas **não** vale para o caminho de transporte pós-handshake.
  - Recomendação: embrulhar `write_framed` em `tokio::time::timeout`.

---

## Camada 2 — Gerência de peers

### Achados positivos
- **Cap global de inbound + cap por /16, contando reservas pendentes.** `can_accept_inbound` rejeita quando `inbound_count()+pending_inbound_count() >= max_inbound` (`manager.rs:372`); default 125 mainnet / 50 testnet / 8 regtest (`dom-config/src/lib.rs:157`). Cap por /16: `MAX_PEERS_SAME_SLASH_16 = 2` (`manager.rs:17,376-389`). O split reserva/registro (`reserve_inbound` → `register_peer`) fecha a corrida de "mil conexões passam no check antes de registrar" — a mensagem de log `"inbound limit or subnet limit reached"` sai em `manager.rs:411,739`. **OK, testado em `subnet_diversity_limit`/`different_subnets_allowed` (`manager.rs:1002,1016`).**
- **Cap de outbound em voo.** `max_in_flight_attempts = 8` (`manager.rs:40`), aplicado em `reserve_outbound` (`manager.rs:443-448`); dedup de reconexões concorrentes (`manager.rs:1033`). **OK, testado em `outbound_limit_bounds_concurrent_handshakes` (`manager.rs:1040`).**
- **Ban score persistido em disco e restaurado.** `persist_peer_reputation_snapshot` grava em `dom/peer_reputation_state/v1` (`node.rs:210,2236-2245`), restaurado no boot (`manager.rs:674`), limitado a `MAX_PERSISTED_PEER_REPUTATION_ENTRIES = 4096` (`manager.rs:29`). Ban sobrevive a restart — **melhor que a suspeita do briefing**. Tabelas de penalidade/falha são memory-bounded sob churn (`manager.rs:898-938`, testado `pending_penalties_are_bounded_under_address_churn`, `manager.rs:1214`). **OK.**
- **PEX com cooldown bidirecional + rate-limit de flood.** GETADDR tem cooldown de 10min tanto no envio quanto na resposta (`pex.rs:114-148`, `GETADDR_COOLDOWN_SECS = 600`). `AddrFloodTracker` tolera 4 mensagens Addr/janela e depois pontua `ADDRESS_FLOODING (+30)`, banindo na 8ª (`pex.rs:234-272`). Tabela de cooldown é bounded sob churn (`pex.rs:212-228`, testado `getaddr_tracking_is_bounded_under_rotating_peer_churn`, `pex.rs:402`). Known-set limitado por `max_peers` (`pex.rs:59`). **OK.**
- **Backoff de reconexão sem amplificação.** Sessão estável >120s limpa histórico de falha (`manager.rs:756-759`); churn curto não reseta o backoff (`short_outbound_session_does_not_reset_backoff`, `manager.rs:1398`); storms de timeout convergem sem leak (`repeated_outbound_timeout_storms_converge_without_leaks`, `manager.rs:1295`). **OK.**

### Achados negativos

- **[Alto] Sem diversidade obrigatória de subnet nos slots outbound (eclipse)**
  - Local: `manager.rs:380` (a regra `/16` filtra `!p.outbound` → vale **só inbound**); seleção outbound `outbound_candidates_in_retry_order` (`manager.rs:515-536`) ordena só por histórico de falha; `reserve_outbound`/`needs_outbound`/`target_outbound_count` (`manager.rs:431-457,361-368`) só checam contagem, nunca `to_slash16`. O docstring em `manager.rs:4` afirma "8 connections to different /16 subnets" — **falso contra o código** (comentário não é prova).
  - Descrição: os 8 slots outbound podem ser preenchidos integralmente por peers do mesmo /16/AS.
  - Impacto adversarial: um atacante que injete seus endereços no candidate-set (gossip PEX, DNS poisoning) ocupa todos os 8 slots outbound de um único /16 e **eclipsa** a vítima (controla a visão dela da cadeia → double-spend contra a vítima, censura de tx). É o vetor Erebus/BIP155 clássico.
  - Recomendação: exigir diversidade `/16` (idealmente ASN) na seleção de slot outbound + buckets "new/tried" estilo addrman.

- **[Alto] `peer_id` é IP:porta auto-anunciado, não a chave Noise (spoof trivial)**
  - Local: `peer.rs:43-64` (`PeerInfo` só tem `addr: SocketAddr`); chave do mapa = `info.addr.to_string()` (`manager.rs:723`); `get_remote_static` ausente no repo inteiro.
  - Descrição: identidade = 5-tupla TCP. O `relay/dandelion.rs:17,57` também usa a string de endereço como `peer_id`.
  - Impacto adversarial: impossível fixar (pin) um peer conhecido a uma chave; impossível construir reputação por chave; um MITM que troque a static key na reconexão é indetectável; toda defesa anti-Sybil/eclipse cai para a camada IP (fraca, ver acima e abaixo).
  - Recomendação: derivar `peer_id` da static pubkey remota do Noise e chavear reputação/dedup/diversidade nela.

- **[Médio] Ban chaveado em IP:porta + sem limite por-IP nem por-/24 (evasão de ban barata)**
  - Local: chave de ban = `SocketAddr` string (`manager.rs:399,723,1832`); dedup por IP:porta, não por IP (`manager.rs:400,724`); só existe cap `/16` (=2) e global (=125) — **não há limite por IP exato nem por /24** (`to_slash16` = 2 primeiros octetos, `manager.rs:976-987`).
  - Descrição: 1 conexão por IP **não** é imposta; o mesmo IP pode segurar 2 slots inbound (mesmo /16). E um peer banido reconectando de outra **porta de origem** começa com score 0.
  - Impacto adversarial: (a) atacante banido por PoW/malformado reconecta na hora trocando a porta de origem → ciclo ban→reconnect indefinido (compõe com identidade spoofável); (b) atacante espalhado por ~63 /16s distintos (trivial numa conta de cloud multi-região) enche os 125 slots inbound, negando capacidade a peers honestos.
  - Recomendação: chavear ban/dedup em IP (ou /16) e não em IP:porta; adicionar cap por /24.

- **[Médio] PEX aceita endereços privados/loopback/não-roteáveis sem filtro de roteabilidade**
  - Local: `pex.rs:151-164` — `process_addr_message` só valida `addr.parse::<SocketAddr>().is_ok()`. Não rejeita `127.0.0.0/8`, `10/8`, `192.168/16`, `169.254/16`, `0.0.0.0`, multicast. Os próprios testes tratam `192.168.1.1:8080` como válido (`pex.rs:489,511`).
  - Descrição: endereços inventados, desde que parseiem, viram candidatos a discagem. Uma mensagem Addr carrega até `MAX_ADDRS_PER_MESSAGE = 1000` (`message.rs:435`); com 4 msgs/janela são 4000 endereços/10min por peer.
  - Impacto adversarial: poluição da tabela de peers com lixo (desperdício de tentativas outbound em LANs/loopback) e seeding de endereços do atacante para o vetor de eclipse acima. Em cenários NAT, pode induzir a vítima a discar serviços da própria rede interna (SSRF-like fraco).
  - Recomendação: filtrar faixas não-roteáveis/privadas/loopback antes de `add_peer`.

- **[Médio] Sem rate-limit geral por tipo de mensagem**
  - Local: ausência de `rate_limit`/`token_bucket` em `manager.rs`/`node.rs` (grep vazio). Único controle de frequência: quota de relay de bloco duplicado (32/30s, +10, `manager.rs:827-856`) e o flood de Addr (`pex.rs`).
  - Impacto adversarial: peer conectado floda INV/GETDATA/GETHEADERS/TX sem throttle de transporte; a defesa depende inteiramente do ban-score (que, pelos itens acima, é evadível).
  - Recomendação: token-bucket por tipo de mensagem por conexão.

- **[Médio] Código morto de scoring dá falsa garantia**
  - Local: `peer_scoring.rs:30-193` (`PeerScorer`) só é referenciado por `pub mod peer_scoring;` em `lib.rs:12` — **nunca instanciado**; tem testes verdes (`scoring_works`, `banning_works`, `peer_scoring.rs:136-192`) que validam código sem efeito em runtime. Idem as constantes `INVALID_POW=50`, `INVALID_SIGNATURE=25`, `INVALID_TX_STRUCTURE=15` (`peer.rs:11,17,19`), nunca lidas (ver Camada 3).
  - Impacto adversarial: auditor/operador pode acreditar que existe scoring por severidade que de fato não roda.
  - Recomendação: remover `peer_scoring.rs` ou ligá-lo; ligar as constantes de severidade no mapeamento real.

- **[Médio] DNS seeds são o único bootstrap de nó novo; fallback de IPs vazio**
  - Local: `dns_seed.rs:19-21` — `MAINNET_SEED_IPS` está **vazio** ("To be filled after genesis"); `resolve_seeds` só cai no fallback se DNS retornar nada (`dns_seed.rs:53-58`).
  - Descrição: peer store vazio → nó novo depende 100% das 5 DNS seeds; sem DNSSEC e sem validação dos endereços resolvidos.
  - Impacto adversarial: um atacante com DNS poisoning (ou que comprometa/responda pelas seeds) entrega só endereços próprios → eclipse total de nós novos desde o primeiro contato, sem nenhum IP fixo de resgate.
  - Recomendação: preencher `MAINNET_SEED_IPS` com nós-âncora da fundação antes da mainnet; considerar pinning de seeds e diversidade de operadores.

- **[Baixo] Violação sub-threshold nunca encerra a sessão**
  - Local: a sessão só cai quando `banned == true` (score ≥ 100) (`node.rs:3927-3929`). Um peer pode ficar em score 99 indefinidamente emitindo violações abaixo do gatilho.
  - Recomendação: aceitável por design, mas documentar.

---

## Camada 3 — Propagação

### Achados positivos
- **Sync header-first.** `run_ibd_session` (`node.rs:2939`) pede `GetHeaders`, valida cada header (incl. PoW) em `validate_ibd_header_step` (`node.rs:2896`) **antes** de pedir corpo; corpos são buscados por hash e casados contra o hash esperado, rejeitando mismatch (`node.rs:2708,2755-2760`). `Headers` limitado a `MAX_HEADERS_PER_MSG` (`message.rs:305,324`). Atacante não força download de bloco grande inválido sem passar pela validação de header. **OK, testado `invariant_ibd_import_rejects_...economically_unbalanced_block` (`node.rs:6154`).**
- **Future-block buffer com cap rígido.** `MAX_QUEUE_SIZE = 256` (`future_block_queue.rs:23`), reject-on-full (`defer` retorna `false`, `:57-65`) + evicção por idade (`evict_expired`, `:103-111`) drenada pela task `future_block_queue_drain` (`node.rs:737`). Atacante não estoura memória com blocos de timestamp futuro. **OK, testado `full_queue_rejects` (`:294`), `evict_expired_works` (`:277`).**
- **Orphan pool bounded.** 1024 total / 32 por parent, evicção FIFO (`orphan_pool.rs:11-13,62-118`); pool único compartilhado entre peers, então o bound é global. **OK, testado `orphan_spam_is_bounded_by_total_and_parent_limits` (`orphan_pool.rs:160`).**
- **Mempool com cap de peso e evicção por fee.** `max_weight = MAX_BLOCK_WEIGHT*10` (`dom-mempool/src/lib.rs:167`); `evict_lowest_fee` recusa evictar tx com fee ≥ a entrante (`:401-404`) → flood de baixo-fee não expulsa tx legítimo de fee maior; piso `MIN_RELAY_FEE_RATE` rejeita dust (`:268-273`); loop de evicção com backstop de no-progress (`:333-341`). **OK, testado `eviction_loops_until_heavy_high_fee_tx_fits` (`:1047`), `heavy_low_fee_tx_rejected_and_pool_left_intact` (`:1084`).**
- **Missing-block requests expiram.** `next_request_batch` dropa um hash após `max_attempts = 8` rounds (`missing_block_tracker.rs:213-221`, construído em `node.rs:482`). A vítima **não** re-pede para sempre um parent que nunca chega. **OK (lado das requisições), testado `max_attempts_drops_hash_after_exhaustion` (`:366`).**
- **Stem timeout do Dandelion.** `STEM_TIMEOUT = 30s` (`dandelion.rs:38`), aplicado em `process_stem_tx` (`:107`) e drenado por task a cada 5s (`node.rs:901-915`). Tx presa em stem floda após ≤30s. **OK.**

### Achados negativos

- **[Alto] PoW/estado inválido pontua só 10 (não 50); `INVALID_POW = 50` é código morto**
  - Local: `peer_violation_score` (`node.rs:1787-1810`) mapeia **todo** `DomError::Invalid(_)` para `PROTOCOL_VIOLATION = 10` no catch-all da linha 1807. `connect_block` retorna `Invalid("proof-of-work invalid")` para PoW ruim (`dom-consensus/src/block.rs:360-363`) e `Invalid(...)` para estado/UTXO/PMMR/assinatura ruins. As constantes `INVALID_POW=50`/`INVALID_SIGNATURE=25` (`peer.rs:11,17`) **nunca são lidas** (grep confirma).
  - Descrição: com `BAN_THRESHOLD = 100` (`peer.rs:23`), são necessários ~10 blocos inválidos distintos para banir, em vez de 2.
  - Impacto adversarial: cada bloco inválido força verificação completa (PoW + range-proofs/Schnorr + transição de estado) **antes** do +10 ser registrado → CPU-burn barato. Uma única sessão TCP/Noise força 9 validações completas antes do ban; com a evasão de ban (Camada 2) o custo é efetivamente ilimitado.
  - Recomendação: rotear erros de PoW/assinatura/estrutura para suas severidades específicas (50/25/15), banindo em ≤2 blocos de PoW inválido.

- **[Alto] `codec.send`/`write_framed` sem timeout — slowloris-on-send**
  - Local: `write_framed` usa `write_all` sem timeout (`handshake.rs:202-214`); `NoiseCodec::send` herda (`codec.rs:86-111`). Todos os envios do `message_loop` são `codec.send(...).await?` inline em branches do `select!` (`node.rs:3525,3547,3575,3600,3626,...`), sem writer concorrente. Assimetria explícita: o recv tem `IDLE_TIMEOUT` por frame (`codec.rs:125-135`), o send **não tem nenhum**.
  - Descrição: um `write_all` bloqueado num leitor lento trava a task inteira do peer — ela para de processar recv, shutdown e timers de ping.
  - Impacto adversarial: atacante anuncia janela TCP minúscula (ou lê 1 byte/s), pede `GetBlockData` de blocos grandes, e com **uma** conexão prende uma task de peer indefinidamente, custo de banda ~zero. Abrindo várias (até o cap de conexões), exaure o pool de tasks de relay. Slowloris clássico, nenhum timeout dispara.
  - Recomendação: embrulhar todo `codec.send`/`write_framed` em `tokio::time::timeout` e dropar+pontuar o peer no estouro; opcionalmente uma task escritora dedicada e bounded por peer.

- **[Médio] `MissingBlockTracker.dependents` nunca é podado na exaustão de tentativas (crescimento de memória)**
  - Local: `missing_block_tracker.rs:107` (`dependents: BTreeMap`); `note_orphan` insere incondicionalmente (`:161-168`); `next_request_batch` na exaustão só remove de `missing`/`key_by_hash`, **mantendo `dependents`** — documentado nas próprias linhas `:193-195`; `dependents` só é removido em `resolve()` quando o parent chega (`:231-239`). No node, `note_orphan` é chamado **sem** gate no resultado bounded do orphan pool (`node.rs:2174-2178,3881-3885` ignoram o outcome de `insert`).
  - Descrição: o pool de órfãos é bounded, mas o `dependents`/`missing` do tracker não tem cap total.
  - Impacto adversarial: atacante envia órfãos cada um citando um **parent inexistente distinto** → entradas `(parent→child)` (64 bytes) que nunca são liberadas (parent nunca chega → nunca resolve; exaustão libera só `missing`). Crescimento monotônico pela vida do processo → vazamento lento / OOM em conjunto de conexões longevas.
  - Recomendação: cap total em `dependents`/`missing`; podar `dependents` na exaustão; gate em `note_orphan` pelo sucesso do insert no orphan pool.

- **[Médio] Dandelion: fluff forçado sob peer-único/eclipse, sem cap de hops, router duplicado morto**
  - Local: `dandelion.rs:71-73` (`route_new_tx` → `Fluff` se `available_peers` vazio); `process_stem_tx` filtra o remetente (`:113-117`) → se o atacante é o **único** peer da vítima, a lista filtrada fica vazia → fluff imediato; sem contador de hops (só `FLUFF_PROBABILITY = 0.10` por hop, `:35,77`); roteamento é re-sorteado **por tx** (`route_new_tx` independente), divergindo do Dandelion++ (que fixa o grafo de stem por época para resistir a graph-learning). `crates/dom-node/src/relay/dandelion.rs` é uma **segunda implementação divergente não usada** (dead code).
  - Impacto adversarial: um atacante peer-único ou com eclipse observa o fluff de primeiro hop e liga tx→origem (deanonimização). A duplicação de routers é risco de manutenção/drift.
  - Recomendação: cap de hops; não fluffar só porque o conjunto não-remetente está vazio quando há melhor conectividade; roteamento por época; remover o router morto. (Privacidade — abaixo de DoS/eclipse em prioridade.)

- **[Baixo] `stem_txs` do Dandelion sem cap explícito** — `dandelion.rs:52` cresce com txs distintas em stem; limpo pelo timeout de 30s, então bounded por taxa·30s. Cap explícito seria mais robusto.

- **[Baixo] Worst-case de memória do future-queue** — 256 × `MAX_BLOCK_SERIALIZED_SIZE` (16 MiB) ≈ 4 GiB residente no pior caso. Bounded e aceitável, mas vale documentar.

- **[Nota] Mempool sem fairness por-peer e sem RBF** — um peer pode encher o pool global com txs acima do piso até o cap de peso (evictando outras só se estritamente mais baratas). Memória bounded e tx de fee maior protegida; aceitável.

### Cobertura de testes (Camada 3)
- **Exercitam de verdade:** evicção/fee do mempool (`mempool/lib.rs:1047,1084,1122`), bounds do orphan pool (`orphan_pool.rs:160`), expiração de request do missing-tracker (`missing_block_tracker.rs:366`), cap+idade do future-queue (`future_block_queue.rs:277,294`), rejeição header-first de bloco desbalanceado (`node.rs:6154`).
- **Lacunas (Médio):** **nenhum** teste afirma o score real de um bloco de PoW inválido nem "envie N blocos inválidos → peer banido" end-to-end (exatamente por que o mis-mapping `INVALID_POW` passou batido); **nenhum** teste de crescimento de memória do `dependents` sob flood de parents falsos distintos; **nenhum** teste de slowloris/write-timeout (não há timeout para testar); o teste de timeout do Dandelion (`dandelion.rs:183`) admite que "não dá pra testar o timeout sem dormir" e só checa o caso vazio.

---

## Lista priorizada de PRs sugeridos

1. **[Alto] Write timeout no caminho de envio** — embrulhar `write_framed`/`codec.send` em `tokio::time::timeout`, dropar+pontuar peer no estouro. Escopo: pequeno (`handshake.rs` + sites de `codec.send` em `node.rs`), + teste de slowloris-send.
2. **[Alto] Severidade correta de bloco inválido** — rotear `Invalid(PoW/assinatura/estrutura)` para `INVALID_POW/INVALID_SIGNATURE/INVALID_TX_STRUCTURE` em `peer_violation_score` (`node.rs:1787`). Escopo: pequeno + teste "N blocos PoW-inválido → ban".
3. **[Alto] Diversidade de subnet outbound** — aplicar regra `/16` (idealmente ASN) na seleção de slot outbound (`manager.rs:431-536`); buckets new/tried. Escopo: médio + teste de diversidade outbound.
4. **[Alto] `peer_id` vinculado à chave Noise** — extrair a static pubkey remota e chavear reputação/dedup/diversidade nela (`handshake.rs` + `manager.rs` + `peer.rs`). Escopo: médio-grande (toca o keying de vários mapas).
5. **[Médio] Ban/dedup por IP (não IP:porta) + cap por /24** — `manager.rs:399,723,976`. Escopo: médio + teste de evasão por troca de porta.
6. **[Médio] Filtro de roteabilidade no PEX** — rejeitar privados/loopback/unspecified em `process_addr_message` (`pex.rs:151`). Escopo: pequeno + teste.
7. **[Médio] Cap/poda no `MissingBlockTracker`** — cap total + poda de `dependents` na exaustão + gate de `note_orphan` no insert (`missing_block_tracker.rs`, `node.rs:3881`). Escopo: pequeno-médio + teste de crescimento.
8. **[Médio] Bootstrap de nó novo** — preencher `MAINNET_SEED_IPS`; considerar pinning/diversidade de seeds (`dns_seed.rs:19`). Escopo: pequeno (decisão operacional).
9. **[Médio] Hardening do Dandelion** — cap de hops, roteamento por época, remover router duplicado morto (`dandelion.rs`, `relay/dandelion.rs`). Escopo: médio. **PRECISA DECISÃO HUMANA** (mexe em política de privacidade/propagação).
10. **[Médio] Resolver código morto de scoring** — remover ou ligar `peer_scoring.rs` e as constantes de severidade (`peer.rs:11-19`). Escopo: pequeno.
11. **[Médio] Rate-limit por tipo de mensagem** — token-bucket por conexão. Escopo: médio.

---

## Limites desta auditoria

- **Auditoria estática por IA.** NÃO substitui teste de stress em rede pública real com nós adversariais.
- **Cobertura:** leitura do código + busca por padrões, com verificação na fonte dos achados Alto/Crítico. Não exercita a rede com fuzzer, não roda nós adversário-vs-defensor, não testa contra implementações de outras blockchains. Severidades de DoS são argumentadas por leitura, não medidas com carga real.
- **Profundidade desigual:** `node.rs` (285 KB) e `manager.rs` (62 KB) foram varridos por busca dirigida + leitura de trechos, não linha-a-linha integral; trechos de consenso (`dom-consensus`, `dom-chain`) só foram tocados onde a validação de bloco/PoW alimenta o scoring. Pode haver caminhos não cobertos.
- **Vieses conhecidos:** pode confundir-se com convenções de nomes; pode reportar falsos positivos; pode perder bugs sutis em código que parece correto (falsos negativos). A afirmação "thread_rng é fraco" de uma investigação preliminar foi **corrigida**: `rand::thread_rng()` é CSPRNG — a fraqueza do Dandelion é de design de roteamento (por-tx vs por-época), não de qualidade de RNG. Leia o relatório com olho crítico e confirme cada achado antes de virar PR.
- **Não foram feitas correções nem commits** — só relatório, conforme a tarefa.
