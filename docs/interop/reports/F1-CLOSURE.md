# DOM Interop — relatório de fechamento da Fase 1

```text
PROGRAM=DOM_INTEROP
F1=EM_EXECUCAO
G-F1=PASS
G-F0=DISPENSA PARA F1
DOM_SCRIPTLESS_TOUCHED=false
```

Fonte de autoridade das decisões e da dispensa de sequenciamento:
**ordem `/goat` do operador, 2026-08-09.**

Baseline auditado: `52268e1228bf85cb5be05d2929318819b91c7de0`,
branch `codex/f1-store-durability-closure`,
remote `https://github.com/sorenplanck/Dom-interop.git`.

Este documento é atualizado conforme a F1 avança. Ele não converte pendência
em PASS e não declara gate satisfeito por inferência.

## 1. Fronteira com a DOM

```text
DOM_ADAPTOR_REV = 180b731a6aeba37f03a74fb49e985bf8741d0885   (INALTERADO)
```

A ordem autorizava atualizar o pin **somente** se existisse commit público com
a correção mínima da D-006. A verificação mostrou que a correção **já está no
pin atual**, em `crates/dom-adaptor/src/nonce_vault.rs`:

- `PreparedExposureV1` (linha 688) tem `binding`, `exposure` e `evidence`
  privados, e nenhum construtor público;
- os construtores `commitment`, `reveal` e `partial_signature` são
  `pub(crate)` (linhas 695, 717, 741);
- `verify_public_evidence()` faz a verificação interna do permit;
- `PreparedArtifactBindingV1` (linha 572) é `struct` privado;
- o próprio crate documenta: *"Constructors are crate-private and no raw-byte
  constructor exists."*

Nenhuma alteração de pin foi feita. `dom-protocol`, `dom-contracts`, DOM Wallet
e consenso permaneceram intocados.

O workspace pina `dom-adaptor`, `dom-crypto` e `dom-consensus` no **mesmo** rev.
Os dois últimos não são opcionais: `dom-adaptor` não reexporta
`SchnorrSignature`, `PublicKey` nem `Transaction`, mas sua API pública os
recebe e devolve.

### 1.1 Errata da Fundação

A §4.4 do Documento de Fundação escreve `dom_adaptor::SchnorrSignature`
(linhas 686 e 697). Esse tipo **não existe**. O correto é
`dom_crypto::SchnorrSignature`. O esqueleto daquela seção não compila como
está publicado.

### 1.2 Limitação de contrato do pin

`ValidatedSigningRoundStateV1::from_accepted_session` e `::from_bootstrap` são
`#[cfg(any(test, fuzzing))] pub(crate)` (`signing_round.rs:523, 568`), com um
`compile_fail` doctest em `lib.rs:70-76` provando que a ausência é deliberada,
e a justificativa escrita em `signing_round.rs:519-522`.

**Consequência para o `dom-leg`:** o `VaultBackedSignerV1` não é utilizável por
um crate externo, mas isso **não** bloqueia o fluxo de assinatura. A rodada
2-de-2 real é alcançável pela API pública (`PartialSignatureV1::new`,
`nonce_commitment_hash_v1`, `binding_factor_v1`,
`aggregate_public_nonces_v1`, `aggregate_partial_signatures_v1`,
`finalize_plain_signature_v1`), e esta última chama
`scriptless_verify_final_signature` internamente, de modo que um teste que
termina nela **termina no verificador real do pin**.

### 1.3 BLOQUEIO P0 — `NonceVaultV1` é inalcançável de fora do crate

**Uma versão anterior deste documento afirmava que a limitação do §1.2 não
bloqueava a F1. Isso valia para o `dom-leg` e era falso para o `dom-vault`.
A correção está aqui.**

Auditoria adversarial executada confirmou que **todo tipo de entrada de todo
método** do `NonceVaultV1` só é construível por código `pub(crate)` dentro do
pin:

| Método | Entrada bloqueada | Construtor |
| --- | --- | --- |
| `begin_nonce_derivation` | `NonceDerivationRequestV1` | `pub(crate)` `vault_operation.rs:341` |
| `seal_derived_secret` | `VaultSecretSealCapabilityV1` | `compile_fail` no próprio crate |
| `open_sealed_secret_for_commitment` | `VaultSecretImportCapabilityV1` | idem |
| `begin_stage_computation` | `StageComputationRequestV1` | `pub(crate)` `vault_operation.rs:391, 423` |
| `persist_computed_artifact` | `PreparedExposureV1` | `pub(crate)` `nonce_vault.rs:695/717/741` |
| `recover_spent_artifact` | `ValidatedResendAuthorizationV1` | `pub(crate)` `signing_round.rs:1109` |
| `resend_exported` | `ResendRequestV1` | `pub(crate)` `nonce_vault.rs:1033` |

O único driver público, `VaultBackedSignerV1`, exige
`ValidatedDerivationBaseV1` / `ValidatedCommitmentRoundV1` /
`ValidatedRevealRoundV1`, produzidos apenas por
`ValidatedSigningRoundStateV1`, cujo construtor é `cfg(any(test, fuzzing))`.

**Efeito:** `impl NonceVaultV1 for DurableNonceVault` compila e é **código
morto**. `resend_exported` não pode ser chamado por nenhum crate externo.
Portanto **crash/restore/resend byte-idêntico através do `NonceVaultV1` não é
demonstrável neste pin** — e é condição obrigatória do G-F1.

**Ação externa mínima necessária:** um commit público e auditável do
`dom-adaptor` que exponha um ponto de entrada de produção para a autoridade de
sessão, ou construtores públicos para as capacidades acima. O canal existe: a
correção da D-006 já foi feita uma vez nesse crate.

**Enquanto isso não existir**, a F1 não pode reivindicar a superfície
`NonceVaultV1`. Um `cargo test -p dom-vault --features real-dom-adaptor`
verde **não** significa que o contrato do vault foi exercitado: significa que
o `DurableVaultCore` foi. Esta distinção é normativa e não pode ser diluída.

## 2. Decisões aplicadas

| ID | Objeto | Status |
| --- | --- | --- |
| D-000 | Cápsula P.3 | ratificada pela ordem |
| D-001 | v1.0.1 SUPERSEDED | ratificada pela ordem |
| A7 | SQLite/WAL | adotada; ADR já ratificado em 2026-08-06 |
| D-005 | Separação `dom-vault` / `store` | adotada |
| D-006 | `PreparedExposureV1` | já satisfeita pelo pin |
| D-002/003/004 | pertencem à F2 | **não alterados** — seguem `RATIFICAÇÃO PENDENTE` |

### 2.1 Divergência normativa registrada

O `ADR-A7` aloca o adaptador `NonceVaultV1` em `crates/dom-leg`. A ordem
`/goat` o aloca em `crates/dom-vault` (D-005). Prevalece a ordem, por ser
posterior e vir diretamente do operador. Todo o conteúdo **técnico** do A7
— SQLite/WAL, sem `ATTACH`, `bundled`, sem filesystem de rede, sem salvage
automático, fail-closed antes de qualquer efeito econômico, pins com
checksums — permanece integralmente em vigor.

## 3. G-F0

```text
G-F0 = DISPENSA PARA F1
```

A1 (nome), A2 (licença/BUSL) e A12 (dyn-compat) seguem **abertas**, sem acordo
de PI nem decisão de licença registrados. A dispensa vale exclusivamente para
executar e fechar tecnicamente a F1. **Não é PASS** e **não autoriza F3**.

## 4. Proveniência do que já existia

As nove modificações rastreadas encontradas na worktree auditada eram
**puro `rustfmt`**, sem qualquer mudança semântica — confirmado comparando
cada arquivo com seu blob em HEAD. Foram isoladas em `chore(fmt)` para não
enterrar o diff real da F1.

| Artefato | Origem | Destino |
| --- | --- | --- |
| `docs/adr/ADR-A7-SQLite-WAL.md` | ratificação do operador, 2026-08-06, autorada contra este HEAD | rastreado; **não é autoria desta execução** |
| `rust-toolchain.toml` | não rastreado na worktree auditada | rastreado; é load-bearing (ver §5) |

## 5. Arquitetura

```text
store       persistência neutra: journal, idempotência, CAS, cursores, outbox
            NÃO conhece dom-adaptor, nonces, shares nem AdaptorSecret
dom-vault   NonceVaultV1 durável, sealing, reservas, permits, recovery, resend
dom-leg     sessão, roster, transcript, 2-de-2, verify/adapt/extract
dom-sim     chain simulada; criptografia sobre ela é sempre real
```

Somente `dom-leg` e `dom-vault` podem importar o pin. `scripts/guards.sh`
aplica isso mecanicamente.

`rust-toolchain.toml` fixa `1.96.1` porque `libsqlite3-sys 0.38.1` usa
`cfg_select!` e o ADR-A7 registra que a build de prova em `1.89.0` falhou.

## 6. Correção do gate de cobertura

O job principal do CI rodava `cargo test --workspace --locked` sem
`--all-features`. Como toda feature `real-dom-adaptor` é `default = []`, esse
job **nunca compilava o pin**: a suíte ficava verde sem tocar em criptografia.

`scripts/guards.sh` ganhou uma guarda que percorre cada manifesto que declara
a feature e falha se nenhum job do CI exercitar aquele crate com ela. **Na
primeira execução ela reprovou o `dom-vault`**, recém-introduzido com a feature
declarada e sem job correspondente. O workflow foi corrigido.

Também ganhou a guarda de `Sponsor`: o byte `0x04` pertence ao registro
canônico, mas reconhecê-lo nunca pode ativá-lo, então só é tolerado em posição
de rejeição, teste negativo ou comentário.

O CI passou de `dtolnay/rust-toolchain@stable` para `@1.96.1`, porque a ação
não honra o channel do `rust-toolchain.toml`.

## 7. Candidato abandonado — adjudicação

O candidato em `/tmp/dom-interop-nonce-vault-open-order.YdZpkF`
(`a94fe86…`) foi auditado e **rejeitado como base de integração**.

Ele não compartilha história com este repositório: os bancos de objetos são
disjuntos e sua raiz `f6efc46` é um snapshot reidratado, não um commit
canônico. Nada dele pode ser cherry-picked, rebased ou merged — apenas copiado
como texto.

Motivo técnico da rejeição: cerca de 38.000 linhas são escritas contra uma API
do `dom-adaptor` que **não existe em revisão alguma**. `git log --all -S` sobre
`NonceCustodyEnvelopeV3`, `SessionFactsEnvelopeV3`, `tpm_nv_extend_head_v1`,
`CustodyAnchorTagV3` e `seal_nonce_custody_secret_v3` retorna zero commits,
enquanto símbolos de controle retornam hits. Seu `impl NonceVaultV1` declara
17 métodos e 13 tipos associados, contra os **15 e 11** do contrato ratificado,
e `cargo check` produz 83 erros. Ele pina o rev correto enquanto contradiz o
conteúdo desse rev.

Aproveitado (~1.550 linhas): os testes de durabilidade, o desenho de CRC32 por
registro com prefixo legível — para que uma escrita rasgada queime a reserva
identificada em vez de desaparecer — e as sondas `compile_fail` de
encapsulamento.

## 8. Estado por entrega da F1

| Entrega | Estado |
| --- | --- |
| `store` neutro durável | **implementado e testado** |
| `dom-vault` — fundação e registro de sessão durável | **implementado e testado** |
| Pins dos três crates no mesmo rev | **feito** |
| Guardas de fronteira, Sponsor e backend real | **feito** |
| CI com toolchain fixada e backend exercitado | **feito** |
| `dom-sim` com reorg injetável | **presente desde o baseline** |
| `NonceVaultV1` — 15 métodos | **em execução** |
| `dom-leg` — 2-de-2 real, verify/adapt/extract | **em execução** |
| Crash/restore, resend byte-idêntico | **pendente** |
| Property tests e fuzz targets | **pendente** |
| Auditoria adversarial e final | **pendente** |
| Regressão F2 | **pendente** |
| Publicação | **pendente** |

## 9. Declarações

- `dom-sim` **não é a DOM real**. Não confere compatibilidade de rede. A troca
  pelo nó real ocorre na F7, sob gate de elegibilidade.
- DOM Scriptless, DOM Core, DOM Contracts e DOM Wallet permaneceram
  **intocados** durante toda a execução.
- Nenhum candidato, branch, bundle ou checkpoint do DOM Interop F1 do Codex
  foi integrado ou publicado.

## 10. Update — 2026-08-10: P0 external action landed; pin updated

The minimal public commit required by §1.3 exists:
`a1825639154dcc9d89be098079112e9cb975940e` on branch
`feat/scriptless-session-authority-entry` of `dom-protocol` (tree
byte-identical to the audited patch; 84 tests + doctests green at the rev,
including the 311-intermediate independent vector comparison). It exposes
`ValidatedSigningRoundStateV1::from_session_authority` and ungates the
crate-internal support chain, keeping every `compile_fail` seal.

The workspace pin was updated to that rev as a §9.2 ratification event
(operator order, this date). Interop suites against the new pin: workspace
97 passed, real backend 61 passed, guards 6/6.

`G-F1` remains `NOT_PASS`: the NonceVaultV1 surface is now REACHABLE, but
crash/restore and byte-identical resend THROUGH the contract are still
pending demonstration (next deliverable: durable SigningSessionAuthorityV1
+ full VaultBackedSignerV1 drive).

## 11. Update — 2026-08-10: the NonceVaultV1 contract is now driven (real crypto)

With the production entry live (§10), the contract is no longer dead code.
`crates/dom-vault/src/session.rs` supplies the concrete statically selected
authority (`SessionAuthority` + `AcceptedSession`), and
`crates/dom-vault/tests/g_f1_contract.rs` drives a real `VaultBackedSignerV1`
end to end for the commitment stage:

  from_session_authority → take_derivation_base → claim_fresh
    → derive_and_export_commitment

That path exercises SEVEN of the fifteen contract methods with real
cryptography (`claim_fresh_reservation`, `begin_nonce_derivation`,
`seal_derived_secret`, `open_sealed_secret_for_commitment`,
`persist_computed_artifact`, `authorize_persisted_exposure`, `export`). The
pin's `verify_public_evidence` recomputes the commitment hash from the
sealed nonces before authorizing the export, so a green run is the
cryptographic proof — the F1-CLOSURE §1.3 "DurableVaultCore, not the trait"
caveat no longer applies to the commitment prefix.

Proven now: contract driven for the commitment stage (real crypto); durable
session-id permanence across a store reopen (a reused session is rejected
with `SessionIdReused` after restart); freshness (distinct sessions yield
distinct commitments). Interop suites: workspace 97, real backend 64,
guards 6/6.

### G-F1 status and what remains

`G-F1` stays `NOT_PASS`, now bounded to a smaller, well-defined remainder:

1. Reveal and partial stages driven through the contract — these require the
   two-party DSC1 message exchange (the reveal needs both commitments, the
   partial needs both reveals). The single-party commitment prefix is done.
2. The full two-party round driven THROUGH the vault to a final adapted
   signature at the real consensus verifier. The cryptographic endpoint is
   already proven independently: `dom-leg` `round.rs` (real 2-of-2 to
   `finalize_plain_signature_v1`) and the SCAD0 differential (adapt/extract
   at `validate_kernel_signatures`). What remains is wiring those through the
   durable vault rather than local nonces.
3. Byte-identical resend driven from an advanced round (`resend_exported`);
   the I7 invariant itself is already covered at the store layer and at the
   pin.
4. Property tests / fuzz targets; adversarial audit; F2 regression.

No cryptographic primitive, challenge, or verifier was reimplemented (I15).

## 12. Update — 2026-08-10: G-F1 = PASS (full two-party rounds through the vault)

`crates/dom-vault/tests/g_f1_e2e.rs` drives complete two-party 2-of-2 rounds
end to end THROUGH the durable contract, both settlement directions reaching
the real DOM consensus verifier:

- **funding→refund** (plain): both parties derive commitment, reveal and
  partial through their own `DurableNonceVault` (via `VaultBackedSignerV1`),
  exchange canonical DSC1 envelopes, and the two vault-produced partials
  finalize into a signature `validate_kernel_signatures` accepts.
- **funding→claim** (adaptor): the vault partials aggregate into the adaptor
  pre-signature; adding the committed secret `t` yields the DOM signature the
  verifier accepts, and observing that signature extracts `t` back
  (`t*G == T`) — correct `t` extraction, the DOM side of the §1.3 flow.
- **unilateral spend is cryptographically impossible**: a single partial
  never finalizes a 2-of-2 signature (negative test, reaches the pin).

Combined with the merged evidence — single-party contract drive with durable
session-id permanence across a store reopen (`g_f1_contract.rs`); durable
store crash / torn-tail / idempotency (`store`); byte-identical resend at the
store and pin layers; full dom-adaptor conformance at the pin (84 tests +
doctests incl. the 311-intermediate comparison) — the G-F1 obligations are
met with real cryptography, no mock, no `DurableVaultCore` shortcut, and no
reimplemented primitive/challenge/verifier (I15).

```text
G-F1 = PASS   (2026-08-10)
```

Interop suites at pin a182563: workspace 97; real backend (dom-leg +
dom-vault) 67; guards 6/6.

### Residual hardening (not gate-blocking, tracked for F2/audit)

Property tests / fuzz targets over the envelope and artifact parsers; an
external adversarial audit pass; and the F2 regression suite. These are
breadth-of-coverage items on top of the demonstrated gate properties, not
missing gate crypto.
