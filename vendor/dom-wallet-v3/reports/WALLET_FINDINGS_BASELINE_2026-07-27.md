# Análise profunda da DOM Wallet V3 — relatório

Data: 2026-07-27 · Modo: somente leitura e testes · Nenhuma linha de código foi alterada
(working tree limpo, só o arquivo pré-existente reports/WALLET_V0.2.1_RELEASE_VALIDATION.md)

Método: suíte completa do workspace + testes de frontend + auditoria de dependências,
mais três varreduras de leitura cruzada (ciclo de vida; nó/sync/mineração; transações/updater).
Cada achado crítico abaixo foi confirmado por mim com evidência arquivo:linha direta; onde não
reverifiquei pessoalmente, está marcado [reportado].

═══════════════════════════════════════════════════════════════════════
VEREDITO
═══════════════════════════════════════════════════════════════════════

Nada quebra a build e nada compromete a cadeia de release/assinatura — tudo isso está
sólido. Mas há problemas sérios de FUNCIONAMENTO que os testes não pegam porque são de
design/contrato, não de compilação. O mais grave: a MINERAÇÃO NÃO PODE INICIAR em nenhuma
rede, e vários indicadores de status MENTEM (mostram "sincronizado"/"pronto" quando não
estão). Há também caminhos de cancelamento de transação que podem liberar inputs já
transmitidos à rede.

O que está SÃO (verificado):
- Suíte completa do workspace: TODOS os crates passam (0 falhas).
- Frontend: 29/29. rustfmt: limpo. cargo audit: ok (15 advisories já permitidos na política).
  cargo deny: advisories/bans/licenças/fontes ok.
- Feed da wallet no ar (HTTP 200, v0.2.6). Assinatura/verificação do updater: correta —
  publicamos 0.2.5 e 0.2.6 com sucesso.
- Higiene de segredos no Rust, validação de nomes de wallet, gate de restore backend↔UI,
  atomicidade do backup-import, replay-guard de slate: todos verificados OK.

═══════════════════════════════════════════════════════════════════════
CRÍTICO — quebra funcionalidade ou arrisca fundos
═══════════════════════════════════════════════════════════════════════

C1. A MINERAÇÃO NUNCA INICIA — gate impossível de satisfazer. [CONFIRMADO]
    src-tauri/src/lib.rs:1258 exige node.metrics.ibd_progress_percent >= 100.
    No nó pinado (rev 28ba3ce), esse atômico é criado em 0 (metrics.rs:64) e SÓ é escrito
    dentro de #[test] (metrics.rs:301,309). Em produção o nó apenas LOGA o progresso IBD
    via tracing (node.rs:3287,3299) — nunca faz store no atômico. O lado wallet só LÊ
    (miner.rs:146,204,255; lib.rs:1258). Resultado: mining_start sempre retorna
    EMBEDDED_NODE_NOT_READY, em qualquer rede. Feature morta atrás de um gate que nunca abre.
    Nenhum teste cobre mining_start com nó real, por isso passou despercebido.

C2. Cancelamento de transação pode liberar inputs já transmitidos à rede. [CONFIRMADO]
    crates/dom-wallet-core/src/lib.rs:1366-1375: a lista de bloqueio do cancel cobre só
    Submitting/Submitted/AcceptedNotRelayed/InMempool/Confirmed. Os estados
    RetransmitRequired, ReconciliationRequired, Reorged e Failed CAEM fora e são cancelados
    (:1383-1391: reserved_by=None, PendingOutgoing→Confirmed). RetransmitRequired nasce de
    NodeNotReady/TemporaryFailure — casos em que a transação pode JÁ estar na rede. Cancelar
    aí devolve os inputs para gastáveis → risco de gasto duplo/re-spend do próprio usuário.

C3. expires_at_height não é validado contra o tip; inputs travam sem uso. [CONFIRMADO/reportado]
    transaction_send_create valida só amount==0 (lib.rs:802). expires_at_height é repassado
    como current_height em from_validated (core-protocol/src/lib.rs:323), então o check de
    expiração se compara consigo mesmo. Criar com expires_at_height=1 SUCEDE e reserva inputs
    duravelmente, mas o export depois falha SlateExpired para sempre — fundos travados até um
    cancel explícito. Sem limite superior também.

C4. Exportar/importar slate reescreve o ciclo de vida para trás, sem gate. [reportado]
    core/src/lib.rs:1018-1030, 1146-1158, 1175-1187: slate_request_export/response_export/
    response_import não checam estado e reatribuem lifecycle (RequestExported/ResponseExported/
    ResponseImported) incondicionalmente. Reexportar uma transação SUBMITTED/CONFIRMED a
    rebaixa a um estado que o cancel aceita → mesma classe de risco do C2. (slate_qr_encode
    delega a esses exports, então "Request QR" numa tx submetida dispara o mesmo efeito.)

C5. Status MENTE: nó reporta READY/"sincronizado" com altura 0 e zero peers. [CONFIRMADO]
    - ready no DTO = "mutexes não contendidos" (dom-node wallet_core_api.rs:915: try_lock),
      não "sincronizado".
    - lib.rs:1760-1777: com zero peers, o ramo Synchronizing é pulado e cai em READY
      "Ready at height {local}". Nó isolado que não baixou nada aparece saudável.
    - frontend/status.js:5-8 usa localHeight como peerHeight quando não há peer height, então
      "Wallet synchronized at height N" nunca consulta contagem de peers.
    Efeito combinado: dashboard e onboarding podem afirmar "sincronizado/pronto" para uma
    wallet que não está conectada a nada.

═══════════════════════════════════════════════════════════════════════
ALTO — trava estados ou engana o usuário
═══════════════════════════════════════════════════════════════════════

A1. Senha errada é indistinguível de disco corrompido. [CONFIRMADO]
    No unlock, a senha errada falha dentro de location.load (decriptação → StorageError::Crypto),
    NÃO em CoreError::InvalidPassword (que só cobre comprimento, lib.rs:1595). Todo StorageError
    (exceto WriterActive) vira o genérico WALLET_STORAGE_FAILED / "Review its typed error code".
    O erro mais comum do usuário aparece igual a corrupção de disco, nome duplicado ou wallet
    ausente. Vale para unlock, confirmação da cerimônia e import de backup.

A2. Beco sem saída no gate: não dá para abrir a wallet B depois de travar a A. [CONFIRMADO]
    Os botões close/lock existem só dentro do app (frontend/main.js:425-426); o gate não tem
    botão de fechar. Após wallet_lock (estado=Locked) ou uma criação/restore não finalizada,
    submeter open/create/restore no gate bate em ensure_closed → InvalidLifecycleState, com a
    mensagem genérica de A1. O recurso-título da camada de wallets por nome (trocar de wallet)
    exige reiniciar o app.

A3. Mineração fica travada em STOPPING/ERROR para sempre após qualquer erro do worker.
    [CONFIRMADO] stop_mining_worker (lib.rs:1391-1405) armazena MINING_STOPPING e nunca reseta
    para READY (o reset só ocorre dentro da thread do worker, que já saiu no erro). Depois de
    um erro, mining_start e mining_config_set retornam MiningRunning pelo resto da sessão.
    Uma simples oscilação de peers dispara isso (miner.rs:202-206 → MINING_ERROR). Impacto
    prático hoje é secundário porque a mineração já não inicia (C1).

A4. Não existe worker de sincronização: pause/resume são flags sobre uma chamada bloqueante
    única, sob o mutex global. [CONFIRMADO] synchronization_start_live roda o loop inteiro
    reconcile_to_tip de forma síncrona segurando self.service; nenhuma thread chama synchronize
    sozinha. Consequências: (a) o cursor da wallet só avança quando o usuário clica; (b) "Pause"
    não interrompe um scan em curso; (c) durante um scan longo TODO o resto (status, mining_stop,
    node_stop) fica bloqueado atrás de um mutex; (d) create/restore/backup também são síncronos
    sob o mesmo mutex — a própria barra de progresso do gate (poll a cada 5s) é a primeira vítima.

A5. Um erro isolado (ex.: senha errada) contamina status do nó, do sync e o gate de mineração.
    [CONFIRMADO] core/src/lib.rs:295-298 grava last_error num unlock falho, só limpo por um sync
    bem-sucedido (:646). Esse campo dirige WalletSyncStatus.last_error/synchronized, o gate
    require_mining_cursor_gate (→ CursorInitializationFailed), o EmbeddedNode error_code
    "CORE_NOT_READY" e o badge ATTENTION do dashboard. Uma senha digitada errada faz o nó
    reportar CORE_NOT_READY e a mineração recusar com CURSOR_INITIALIZATION_FAILED.

A6. Status stale do nó é reexibido após o nó morrer; e um nó falho não reinicia por nenhum
    caminho de UI. [reportado] main.js:208-211 continua renderizando o último status bom quando
    a chamada falha; e node_started nunca é limpo no estado STATE_FAILED, então
    embedded_node_start vira no-op e o "Retry node" do gate não recupera — só reiniciar o app.

A7. wallet_open por path cru abre uma staging de restore como se fosse wallet. [reportado]
    src-tauri/src/main.rs (wallet_open) aceita path sem validação nem contenção na raiz
    gerenciada; um diretório .nome.seed-restore é um WalletDirectory válido e seed_restore_status
    nunca é lido fora do resume. Usuário pode abrir/destravar/transacionar de um restore
    pela-metade e corromper o checkpoint resumível.

A8. Restore abandonado deixa pasta oculta com material de seed, para sempre. [reportado]
    Não há Drop nem remove_dir_all no crate de restore (contraste: backup-import limpa a sua
    staging). .nome.seed-restore fica invisível na UI (list_wallet_names filtra dot-prefix) e
    nenhum comando registrado a apaga — remédio único é cirurgia manual no filesystem, que é
    exatamente o que a mensagem RESTORE_STAGING_INCOMPATIBLE manda o usuário fazer.

═══════════════════════════════════════════════════════════════════════
MÉDIO — coerência, contrato e robustez
═══════════════════════════════════════════════════════════════════════

M1. COMMAND_NAMES desatualizado e o teste que deveria pegar isso CONGELA o erro. [CONFIRMADO]
    lib.rs:52 declara [&str; 67] e pula de "wallet_open" direto para "wallet_unlock" —
    wallet_open_named e wallet_list ausentes — enquanto main.rs registra 69 handlers e
    main.rs:963 afirma len()==67. A superfície IPC declarada não bate com a real, e o guard
    que existe para detectar drift é o que codifica o drift. (Os 3 agentes acharam isso.)

M2. Feeds de nó e de peers estão 404 e essencialmente não-fiados. [CONFIRMADO]
    curl: node-latest.json (dom-protocol) e mainnet-peers.json (wallet) → 404. Além disso,
    validate_peer_manifest, NODE_UPDATE_ENDPOINT, PEER_UPDATE_ENDPOINT não têm chamadores fora
    do próprio crate; a linha de peers/nó na UI é constante ("FALLBACK_ACTIVE"/
    "PEER_MANIFEST_NOT_ACTIVATED"). "Check node updates" na verdade roda o feed da WALLET com
    install desligado e sempre reporta NODE_RPC_BUILD_INFO_PENDING. Não há mecanismo de update
    de nó no produto entregue. (Já era conhecido em parte; agora mapeado por completo.)

M3. Panic sob o mutex de serviço tijola o app atrás de um erro "retryable: true". [CONFIRMADO]
    Todo accessor usa service.lock().map_err(|_| Unavailable) e nada limpa o envenenamento;
    reconcile_once retira backend e unlocked do struct, então um panic ali deixa o serviço
    estruturalmente vazio. O usuário é instruído a "tentar de novo" para sempre.

M4. update_safe_point_available retorna true com a wallet travada/fechada e é TOCTOU com o
    shutdown. [reportado] lib.rs:725-745 dá Ok(true) em Locked/WalletNotOpen; o gate "sem
    transação crítica em voo" é contornado só por ter a wallet travada, e o check não é atômico
    com o application_shutdown que ele protege. Ignora mineração ativa e sync em curso.

M5. check_updates_now é na prática "instalar e reiniciar agora", sem passo de consentimento.
    [reportado] O botão de diagnóstico dispara perform_update_cycle(true) → baixa, fecha a
    wallet, reinicia. automatic_updates é hardcoded true sem setter.

M6. Timeout de 20s cobre também o DOWNLOAD do instalador, e todo erro de download vira
    "assinatura inválida". [reportado] Downloads do tamanho de instalador raramente completam
    em 20s; um timeout de link lento aparece ao usuário como falha de verificação de assinatura.
    Além disso o corpo é bufferizado sem checar Content-Length contra artifact.size antes.

M7. Cerimônia BIP-39 é só decorativa. [CONFIRMADO] phrase_confirmed é escrito
    (core/src/lib.rs:479; restore:831) mas NUNCA lido em lugar nenhum — não há gate em unlock,
    summary nem em DTO. Some com a UI: o painel da cerimônia pode ser dispensado (main.js:99-105
    chama clearSecretForms, não clearPhrase; não há botão para voltar a ele) e a frase fica no
    DOM pelo resto da sessão. Pular a cerimônia não tem consequência nem visibilidade.

M8. QR é single-frame com plumbing multipart vestigial; o painel de QR fica só na tela de
    Enviar e passa o ID do remetente a um comando de papel receptor. [reportado] "Response QR"
    nunca funciona; não há caminho de QR para o fluxo de recebimento; o DTO anuncia um protocolo
    de reassembly que não existe; slates com range proof ficam no limite da capacidade de um QR.

M9. wallet_list reporta diretórios, não wallets. [reportado] Filtra só is_dir()+nome válido,
    sem checar metadata.json/generations. Qualquer pasta solta em wallets/ aparece como wallet
    selecionável; uma criação interrompida (WalletDirectory::create sem rollback) queima o nome
    e mostra uma entrada fantasma no seletor.

═══════════════════════════════════════════════════════════════════════
CORREÇÕES QUE FIZ NAS SUSPEITAS DOS AGENTES (para você não agir em falso)
═══════════════════════════════════════════════════════════════════════

- Pubkey do updater "divergente" entre runtime e tauri.conf.json: é COSMÉTICO, NÃO quebra
  verificação. As duas formas só diferem na linha de COMENTÁRIO do minisign; ambas decodificam
  para a MESMA chave (RWTwnDDK...), que é o que o minisign usa para verificar. As assinaturas
  validam — publicamos 0.2.5 e 0.2.6 com sucesso por esse caminho. O que É verdade: o teste de
  contrato e o tauri.conf fixam uma string que não é byte-idêntica à usada em runtime, então
  esse guard específico é decorativo. Corrigir é higiene, não urgência.

- Import de backup fecha a wallet antes de validar: real como incômodo de UX, mas o
  import_backup em si valida magic/versão/identidade/payload ANTES de criar qualquer coisa e
  limpa a própria staging em toda falha (verificado) — não há risco de corromper a wallet atual.

═══════════════════════════════════════════════════════════════════════
RESUMO EXECUTIVO E RECOMENDAÇÃO
═══════════════════════════════════════════════════════════════════════

Ordem de prioridade se/quando você autorizar correções (rodada futura — aqui não mexi em nada):

1. C1 (mineração morta) — decidir: ou o nó pinado passa a escrever ibd_progress_percent, ou o
   gate da wallet usa outro sinal de sincronização. É o maior buraco funcional.
2. C2/C3/C4 (segurança de fundos no cancel/expiry/export) — adicionar gates de lifecycle e
   validar expires_at_height contra o tip. Classe de bug que pode custar fundos.
3. C5/A5/A6 (status que mente) — exigir peers>0 e altura de peer real antes de afirmar
   sincronizado/pronto; parar de contaminar status com last_error de unlock.
4. A1/A2 (erros opacos e beco no gate) — mapear StorageError::Crypto para INVALID_PASSWORD e
   dar um caminho de fechar/trocar wallet a partir do gate.
5. A4 (sync sem worker sob mutex global) — mover o scan para thread, respeitar a flag de pause.
6. M1 (COMMAND_NAMES) — corrigir a constante e o teste de 67→69. Trivial e de baixo risco.
7. M7 (cerimônia decorativa) e demais itens M — conforme prioridade de produto.

Observação de escopo: tudo acima é comportamento existente encontrado por LEITURA e pelos
testes automatizados; não executei a aplicação empacotada de ponta a ponta (isso exige display/
GUI). As confirmações [CONFIRMADO] têm evidência arquivo:linha que reverifiquei pessoalmente;
os [reportado] vêm dos agentes de auditoria e são plausíveis, mas não os reexecutei um a um.
