# Resultado do congelamento técnico pré-implementação

Data: 2026-08-04
Status da missão: **CONCLUÍDO**
G1a: **NÃO APROVADO** — 19 pendências
G1b: **NÃO APROVADO** — 26 pendências

“Concluído” significa que os inputs solucionáveis foram congelados e os demais
foram bloqueados de forma rastreável; não significa que qualquer gate ou
funcionalidade esteja pronto para produção.

## Estado inicial e histórico preservado

- caminho: `/home/leonardov/dom-scriptless-dev/dom-scriptless-contracts`;
- branch: `feat/phase-1-dom-adaptor`;
- HEAD inicial: `069da06c8ba41fd99fc197bb1d12f214f95b8207`;
- working tree inicial: limpo;
- commits anteriores preservados: `069da06` (fontes normativas), `ed3f41e`
  (split G1a/G1b) e `ee91d5a` (bootstrap).

O commit desta entrega usa o assunto
`docs(scriptless): freeze phase 1 inputs and phase 3 boundaries`. Seu hash
completo é registrado no relatório externo
`/home/leonardov/dom-scriptless-dev/CODEX-BOOTSTRAP-RESULTADO.md`, pois um commit
não pode conter estavelmente o próprio hash.

## Documentos analisados

Foram lidos integralmente `NORMATIVE-SOURCES.md`, `NORMATIVE-REVIEW.md`, a
matriz anterior, GATE-G1A/G1B, ADR-0001–0008 e as três fontes importadas. O DOCX
foi extraído somente em memória/saída para inspeção; sua cópia não foi alterada.

## Backend DOM inspecionado

Baseline: `769822562565f18ef55423dc992e7aa661206b4a`. O inventário detalhado está em
[`DOM-BACKEND-INVENTORY.md`](../../phase-1a/DOM-BACKEND-INVENTORY.md). Foram
mapeados:

- secp256k1, ordem do grupo, `Scalar`, `SecretKey` e `PublicKey`;
- SEC1 comprimido e regras de rejeição;
- `blake2b_256`, `blake2b_256_tagged` e `DomHasher`;
- `schnorr_challenge`, partials, agregação, assinatura e verificação;
- `validate_kernel_signatures`, mensagem e serialização do kernel;
- nonce RFC6979 atual, comparações constant-time e zeroização;
- KAVs de hash/scalar/kernel e os oito testes SCAD0.

Decisão central: `dom-adaptor` reutiliza o backend/verificador DOM. A aritmética
necessária que hoje é privada deve ser exposta por uma extensão mínima em
`dom-crypto`; não se adicionará `k256` ou outro backend ao caminho de produção.

## Parâmetros congelados

- secp256k1 e ordem `FFFFFFFF…D0364141`;
- pontos SEC1 comprimidos 33 bytes, ambas as paridades, identidade/infinito e
  encodings alternativos rejeitados;
- scalars de protocolo/Schnorr em 32 bytes big-endian no intervalo `[1,n-1]`;
- distinção explícita do `keys::Scalar` interno little-endian;
- BLAKE2b nativo de 32 bytes, sem key/salt/personalization;
- framing `u16_le(tag_len) || tag || data` da DOM;
- challenge `DOM:kernel-sig:v1` e assinatura `R33 || s32`;
- conventions `R_hat=R+T`, `s=s_hat+t`, `t=s-s_hat`, sem fator de sinal;
- purposes v1 `Refund=01`, `ClaimAdaptor=02`, `Funding=03`; Sponsor `04`
  reservado e fora do escopo;
- payloads G1a explicitamente listados no Apêndice E, nos limites da ADR-0011.

## ADRs criadas

| ADR | Assunto | Status |
|---|---|---|
| 0009 | perfil criptográfico DOM | ACEITA |
| 0010 | scalars e pontos | ACEITA |
| 0011 | framing/transcript | ACEITA no escopo explícito; cumulativo bloqueado |
| 0012 | purposes | ACEITA |
| 0013 | dois nonces/binding | ACEITA; derivação/vetores bloqueados |
| 0014 | verificador DOM | ACEITA |
| 0015 | nomenclatura Fase 3 | ACEITA |
| 0016 | fronteiras de implementação | ACEITA |

## Parâmetros ainda bloqueados

1. derivação/KDF byte-exata de `k_i1/k_i2` com aux randomness, contexto e chave;
2. vetores independentes do esquema completo de dois nonces;
3. API pública mínima de aritmética em `dom-crypto`, sem backend paralelo;
4. hash inicial e códigos direction/phase do transcript cumulativo Fase 3-SM;
5. wire/assinatura/rotação/retention da witness e valores numéricos de budgets,
   janelas, timeouts e retries.

Nenhum desses valores foi inferido ou preenchido silenciosamente.

## Probe e vetores

O probe oficial não rastreado foi lido somente como evidência não autoritativa,
teve SHA-256 registrado e não foi importado. O test-only
`preimplementation_freeze_probe.rs` chama apenas APIs públicas DOM e compara
oito vetores determinísticos cujos digests foram calculados separadamente com
Python `hashlib`. Resultado: 3 testes aprovados. Ele não implementa adaptor,
binding, dois nonces, vault ou máquina de estados e não é vetor independente do
esquema G1a.

O relatório SCAD0 completo e o fixture compacto de consenso têm os mesmos oito
kernels, porém formatos/hashes distintos; ambos foram preservados em seus
papéis. O manifesto Scriptless valida os dois arquivos versionados desta árvore.

## Resolução da Fase 3 e fronteira do segundo agente

ADR-0015 define:

- `Fase 1/G1a`: núcleo criptográfico;
- `Fase 3-SNV/G1b`: Store e Nonce Vault da Especificação Mestra, escopo do
  segundo agente;
- `Fase 3-SM`: sessão/transporte/máquina de estados do Cronograma.

Os documentos de G1b definem responsabilidades, futura trait, reserva/uso/
consumo/aborto, atomicidade, idempotência, journal, crash/rollback/restore,
witness/receipts, modo auto-hospedado e isolamento de transações comuns. A
Wallet já oferece geração esperada, staging, lock e publicação durável úteis,
mas isso não foi confundido com vault ou proteção antirrollback.

## Validações

| Comando | Resultado |
|---|---|
| `cargo metadata --no-deps --format-version 1` | exit 0; 166.830 bytes |
| `cargo fmt --all --check` | exit 0 |
| `CARGO_BUILD_JOBS=4 cargo check -p dom-adaptor --locked` | exit 0 |
| `CARGO_BUILD_JOBS=4 cargo test -p dom-adaptor --locked` | exit 0; 3 testes aprovados |
| probe determinístico com `--locked` | exit 0; 3/3 |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | exit 0 |
| `bash -n scripts/scriptless/*.sh` | exit 0 |
| `./scripts/scriptless/preflight.sh` | `PREFLIGHT OK` |
| `./scripts/scriptless/phase1-gate.sh` | exit 1 esperado; G1a=19, G1b=26 |
| links documentais locais | 0 quebrados |
| `sha256sum --check test-vectors/scriptless/MANIFEST.sha256` | 2/2 OK |
| `git diff --check` | exit 0 após correção de EOF |
| hook pre-push | exit 1 esperado; push bloqueado |

O primeiro probe com `--locked` recusou a nova `dev-dependency` local. O
`Cargo.lock` foi atualizado uma vez com `--offline`; o diff adicionou somente
`dom-crypto` às dependências do pacote `dom-adaptor`. Todos os comandos
subsequentes passaram com `--locked`.

`verify-isolation.sh` retornou 1 porque conserva o HEAD/hash do snapshot anterior
da Wallet oficial. Durante esta missão, o operador continuou alterações já
autorizadas como definitivas e criou, às 12:42:57 -03:00, o commit descendente
`4722b95de461c1107f8511f3b9b9a4d80d08c9a6` (`fix(miner): use persistent
RandomX fast-mode VMs`) sobre `abb573…`; a branch permaneceu a mesma e o working
tree continuou evoluindo. A verificação independente de baseline do clone,
remotes, push URLs, hooks e DOM oficial passou. O estado final observado é
registrado no relatório externo, sem alterar ou mascarar o script.

## Limites e integridade

Nenhuma implementação funcional completa G1a/G1b, Nonce Vault, witness ou
máquina de estados foi iniciada. Nenhum consenso, wire ou arquivo persistido DOM
foi alterado. Nenhum DL2P foi importado. Os repositórios oficiais foram acessados
somente por comandos de leitura; as alterações concorrentes da Wallet não foram
abertas, copiadas, descartadas ou atribuídas a esta missão. Nenhum push, merge,
release ou publicação ocorreu.
