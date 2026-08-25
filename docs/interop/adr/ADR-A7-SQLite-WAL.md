# ADR A7: SQLite em modo WAL para o store autoritativo local

- **Status:** RATIFIED pelo operador em 2026-08-06
- **Escopo:** `crates/store` e o adaptador protocol-facing em `crates/dom-leg`
- **Base auditada:** `52268e1228bf85cb5be05d2929318819b91c7de0`
- **Autoridade:** ratificacao operacional A7; este ADR registra a decisao e nao
  substitui o Documento de Fundacao DOM Interop v0.2.1 nem decisoes D-xxx.

## Contexto normativo

O Documento de Fundacao exige uma sessao local autoritativa, journal append-only,
idempotency keys, cursores por chain, revisao monotona/CAS, outbox duravel,
retomada pos-crash e uma implementacao duravel do contrato `NonceVaultV1`
([secao 4.7](../normative/DOM-Interop-Documento-de-Fundacao-v0.2.1.md#47-store--persistência--princípio-decidido-tecnologia-aberta-a7)).
A ratificacao do operador fecha A7 com SQLite/WAL e mantem `dom-leg` como unica
fronteira autorizada a importar `dom-adaptor`.

## Decisao

Usar um unico banco SQLite local, sem `ATTACH`, compilado dentro do binario e em
modo WAL. Filesystems de rede e salvage automatico sao proibidos. Erro de I/O,
configuracao divergente, versao desconhecida, downgrade, migracao parcial,
corrupcao ou digest inconsistente devem falhar fechado antes de qualquer efeito
economico externo.

O banco e a infraestrutura generica de persistencia pertencem a `crates/store`.
Esse crate nao depende de `dom-adaptor`. O adaptador `NonceVaultV1` pertence a
`crates/dom-leg` e usa apenas operacoes duraveis expostas por `store`.

### Pins de dependencia

O manifesto deve usar exatamente:

```toml
rusqlite = { version = "=0.40.1", default-features = false, features = ["backup", "bundled", "limits"] }
```

`bundled` impede vinculacao acidental ao SQLite do sistema; `backup` expoe a
Online Backup API; `limits` permite impor limites antes de decodificar/alocar.
Features default e extensoes carregaveis ficam desabilitadas para reduzir a
superficie. A resolucao comprovada em 2026-08-06 foi:

```text
rusqlite 0.40.1
|-- bitflags 2.13.1
|-- fallible-iterator 0.3.0
|-- fallible-streaming-iterator 0.1.9
|-- libsqlite3-sys 0.38.1
|   `-- build: cc 1.4.0
|       |-- find-msvc-tools 0.1.9
|       `-- shlex 2.0.1
|   `-- build: pkg-config 0.3.33
|   `-- build: vcpkg 0.2.15
`-- smallvec 1.15.2
```

Pins efetivos sao confirmados pelo `Cargo.lock`; nenhuma atualizacao global e
permitida. Checksums SHA-256 dos pacotes publicados, conforme o indice crates.io:

| Pacote | SHA-256 |
|---|---|
| `rusqlite-0.40.1.crate` | `11438310b19e3109b6446c33d1ed5e889428cf2e278407bc7896bc4aaea43323` |
| `libsqlite3-sys-0.38.1.crate` | `f6c19a05435c21ac299d71b6a9c13db3e3f47c520517d58990a462a1397a61db` |
| `bitflags-2.13.1.crate` | `b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da` |
| `fallible-iterator-0.3.0.crate` | `2acce4a10f12dc2fb14a218589d4f1f62ef011b2d0cc4b3cb1bba8e94da14649` |
| `fallible-streaming-iterator-0.1.9.crate` | `7360491ce676a36bf9bb3c56c1aa791658183a54d2744120f27285738d90465a` |
| `smallvec-1.15.2.crate` | `8ed6a63f02c8539c91a8685a86f4099661ba3da017932f6ebbea6de3f0fa7c90` |
| `cc-1.4.0.crate` | `5add81bb678e6cb321aff7fa0dc7689ad82b112dbc032cea19f91d6b8e3582b9` |
| `find-msvc-tools-0.1.9.crate` | `5baebc0774151f905a1a2cc41989300b1e6fbb29aff0ceffa1064fdd3088d582` |
| `shlex-2.0.1.crate` | `f8fadd59c855ef2080decdef8ff161eb6661b86933c9d82e5ba29dc602a55aba` |
| `pkg-config-0.3.33.crate` | `19f132c84eca552bf34cab8ec81f1c1dcc229b811638f9d283dceabe58c5569e` |
| `vcpkg-0.2.15.crate` | `accd4ea62f7bb7a82fe23066fb0957d48ef677f6eeb8215f372f52e48bb32426` |

`rusqlite` e `libsqlite3-sys` sao MIT; o SQLite bundled e dominio publico.
Origens: [tag rusqlite v0.40.1](https://github.com/rusqlite/rusqlite/tree/v0.40.1),
[licenca rusqlite](https://github.com/rusqlite/rusqlite/blob/v0.40.1/LICENSE) e
[declaracao SQLite](https://sqlite.org/copyright.html).

### SQLite efetivamente compilado

`libsqlite3-sys 0.38.1` contem o amalgamation SQLite **3.53.2**:

```text
SQLITE_VERSION   = 3.53.2
SQLITE_SOURCE_ID = 2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24
SHA-256 sqlite3.c = 0a409f1633283fa31a9126b11fbfd64a1991c5d30defad07e5745d4667f5e23d
```

Um projeto isolado com a declaracao exata acima foi compilado com Rust 1.96.1 e
consultou `sqlite_version()` e `sqlite_source_id()` em runtime, retornando
exatamente esses valores. A arvore acima foi obtida com `cargo tree --locked`.
SQLite 3.51.3 corrigiu explicitamente o bug de corrupcao no WAL-reset; 3.53.2 e
posterior e incorpora essa correcao
([release 3.51.3](https://sqlite.org/releaselog/3_51_3.html)).

Na abertura, a implementacao deve recusar versao inferior a 3.51.3 e tambem
recusar qualquer versao/source-id diferente do pin resolvido. Isso detecta
vinculacao acidental a biblioteca do sistema. O pin exige a toolchain
reproduzivel Rust 1.96.1: uma compilacao de prova com Rust 1.89.0 falhou porque
`libsqlite3-sys 0.38.1` usa `cfg_select!`, indisponivel naquela toolchain.

## Configuracao obrigatoria de abertura

Cada conexao deve configurar e ler de volta os valores antes de uso:

| Configuracao | Valor exigido | Verificacao |
|---|---:|---|
| `PRAGMA journal_mode` | `wal` | retorno textual exatamente `wal` |
| `PRAGMA synchronous` | `FULL` (`2`) | read-back `2` |
| `PRAGMA foreign_keys` | `ON` (`1`) | read-back `1` |
| `PRAGMA read_uncommitted` | `OFF` (`0`) | read-back `0` |
| `PRAGMA trusted_schema` | `OFF` (`0`) | read-back `0` |
| `PRAGMA busy_timeout` | `5000` ms | read-back `5000`; sem retry infinito |
| `PRAGMA secure_delete` | `ON` (`1`) | read-back `1` |
| `PRAGMA fullfsync` | `ON` no macOS | read-back `1` |
| `PRAGMA checkpoint_fullfsync` | `ON` no macOS | read-back `1` |

`secure_delete=ON` reduz remanencia em paginas liberadas, mas nao e controle
suficiente para segredos e pode deixar copias em WAL/backups. A defesa primaria
continua sendo nunca entregar ao codec/store seed, chave privada, nonce share,
escalar secreto `t` ou representacao reversivel. Banco, WAL e backups devem ser
incluidos nos testes de secret scanning.

Pragmas desconhecidos podem ser ignorados silenciosamente pelo SQLite, logo o
read-back e obrigatorio. Referencias primarias:
[PRAGMA](https://sqlite.org/pragma.html),
[WAL](https://sqlite.org/wal.html) e
[durabilidade de `synchronous`](https://sqlite.org/pragma.html#pragma_synchronous).

O caminho deve ser absoluto/canonico e local. A abertura recusa URI, `:memory:`,
filesystem de rede conhecido e qualquer plataforma na qual o tipo do filesystem
nao possa ser determinado com seguranca. `PRAGMA database_list` deve conter
somente `main` e `temp`; qualquer schema anexado e erro fail-closed.

## Transacoes, schema e recovery

Toda mutacao inicia com `BEGIN IMMEDIATE`, valida `expected_revision` e confirma
em uma unica transacao todos os componentes da mesma decisao: contexto, journal,
outbox, cursor, revisao, idempotency key e outcome terminal. `COMMIT` precede o
submit externo; ACK e reconciliado em outra transacao. Conflito CAS nao altera
estado e nao dispara efeito. SQLite documenta que `BEGIN IMMEDIATE` inicia a
transacao de escrita e pode retornar `SQLITE_BUSY`
([transacoes](https://sqlite.org/lang_transaction.html)).

O schema usa `STRICT`, `PRIMARY KEY`, `UNIQUE`, `CHECK` e `FOREIGN KEY` para
expressar invariantes fisicas, incluindo sequencia sem fork/gap, mesma chave de
idempotencia com os mesmos bytes e `SETTLED XOR REFUNDED`. Migracoes sao
forward-only, idempotentes e transacionais. A versao de schema e registrada em
tabela propria; nao se usa `schema_version` como mecanismo aplicativo.

Na abertura e antes de recovery economico: validar pins/configuracao, schema,
migration marker, `PRAGMA quick_check`, constraints, cadeia de digests, cursores,
revisoes, outbox e outcome. Qualquer divergencia impede submit. `SQLITE_BUSY`,
disk-full e erros de permissao tem erro estruturado e retry finito apenas antes
de qualquer efeito externo.

## Backup

Backup usa exclusivamente a Online Backup API em um destino novo e local, com
controle de `BUSY/LOCKED`, conclusao verificada e integridade validada antes de
publicar o arquivo. Copiar diretamente um banco ativo, seu WAL ou SHM e proibido.
Referencia: [SQLite Online Backup API](https://sqlite.org/backup.html).

## Threat model e controles

| Ameaca | Controle obrigatorio | Falha esperada |
|---|---|---|
| power-loss/kill entre persistencia e submit | WAL + FULL, transacao atomica e outbox opaca | recovery reenvia os mesmos bytes |
| WAL-reset vulneravel | bundled 3.53.2, runtime pin e piso 3.51.3 | abertura recusada se divergente |
| dois writers/processos | `BEGIN IMMEDIATE`, busy timeout finito e CAS | exatamente um commit; perdedor recebe conflito/busy |
| ACK perdido | idempotency key unica + bytes opacos persistidos | reenvio byte-identico |
| mesmo id com bytes diferentes | constraint/digest e comparacao antes de ACK | equivocation; fail-closed |
| migracao parcial/downgrade | migration marker na mesma transacao e schema pinado | abertura recusada |
| truncamento/bit flip/digest fork | quick/integrity checks e digest chain | recovery economico bloqueado |
| estado terminal duplo | constraint fisica e CAS | segundo outcome recusado |
| filesystem remoto/locking incerto | verificacao de filesystem na abertura | abertura recusada |
| exaustao por entrada hostil | limites de tamanho/SQLite antes de alocar | erro estruturado, sem submit |
| vazamento de segredo | tipos/codec nao aceitam material proibido; redaction e scanning | dado rejeitado antes da persistencia |
| backup inconsistente | Online Backup API + validacao do destino | backup nao publicado |
| defaults mudarem | todos os pragmas relevantes configurados e lidos de volta | abertura recusada |

## Consequencias e limites

- WAL requer que todos os processos estejam no mesmo host e que locking e shared
  memory funcionem; por isso filesystems de rede sao proibidos.
- Existe um unico writer por vez. O timeout de 5 segundos e uma politica finita,
  nao promessa de progresso; contention vira erro estruturado.
- `synchronous=FULL` reduz risco de perda, mas nao corrige hardware, kernel ou
  filesystem que violem contratos de flush. No macOS, `fullfsync` e
  `checkpoint_fullfsync` sao habilitados para solicitar `F_FULLFSYNC` quando
  suportado.
- SQLite nao criptografa o banco. A conformidade depende de excluir material
  proibido na fronteira da aplicacao; permissao de arquivo e criptografia de
  volume sao defesa operacional adicional, nao substituto dessa invariavel.
- Este ADR nao prova a implementacao. PASS depende dos testes de arquivo,
  subprocesso, kill, concorrencia, corrupcao, backup, secret scanning,
  `NonceVaultV1`, G-F1 e G-F2 exigidos pela missao.

