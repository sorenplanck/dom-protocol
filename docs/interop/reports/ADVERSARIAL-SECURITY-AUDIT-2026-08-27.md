# Auditoria adversarial da camada de interoperabilidade

**Data:** 2026-08-27
**Branch:** `feat/domv2-interop-absorption`
**Base auditada:** `166b55299d5642200e0f5b7e384b14cf8bcbd17f`
**Estado:** correções locais, sem commit e sem push

## Escopo e modelo de ameaça

A revisão concentrou-se nos mecanismos que podem alterar a segurança de uma
liquidação entre chains: centralidade da DOM, composição de timelocks, RFQ e
seleção, relay autenticado, intent board, adapters EVM, contratos de custódia,
persistência e recuperação. Foram considerados inputs canônicos porém hostis,
overflow nos limites numéricos, substituição de política, divergência entre
objetos relacionados, replay/equivocação, contratos/tokens hostis e cobertura
enganosa de CI.

Esta revisão não encontrou alteração no consenso da DOM nem uma forma de um
atacante remoto produzir uma assinatura válida sem a chave correspondente.
Ela encontrou falhas na camada off-chain e na capacidade de reproduzir/testar
a perna EVM, detalhadas abaixo.

## Achados corrigidos

### A-01 — ALTA — contrato de custódia EVM ausente e fora do gate

O branch continha adapters e testes que referenciavam
`contracts/src/ConditionLockV2.sol`, artefatos em `contracts/out` e
`scripts/e2e_anvil.sh`, mas nenhum desses arquivos existia. Os testes reais
eram `#[ignore]`; portanto, o CI Rust podia ficar verde sem compilar ou
executar o contrato que mantém os fundos.

**Impacto:** um release não conseguia reproduzir o bytecode implantado nem
demonstrar, a partir de um checkout limpo, claim, refund, pull payout,
recuperação e comportamento sob reorg.

**Correção:** restaurados os 20 arquivos versionados de `contracts/` e o
runner Anvil a partir da linhagem F3. O corpo funcional dos fontes é o da
linhagem de evidência `9afaea8`; não houve mudança funcional em `contracts/`
entre essa evidência e `400a6627aa32af7b5baf11117aef0a895e52b5b8`. Apenas o
header SPDX foi harmonizado com a licença MIT desta integração (A-06). Foi
adicionado ao CI um job Foundry com Solc 0.8.24, Foundry 1.7.1 e dependências
em tags exatas. O mesmo job executa o gate Anvil cross-language e exige por
nome os 12 cenários F3 e 6 F4, sem skip; o job passou a ser dependência do
release blocker.

### A-02 — ALTA — política permissiva podia ser injetada pela API pública do relay

`accept_envelope_with_policy` e `MessageTypePolicy` eram públicos em builds de
produção, embora descritos como “TEST-ONLY”. Um consumidor externo podia
implementar uma política que aceitasse qualquer par papel/tipo e chamar essa
função diretamente. O `scripts/guards.sh` citado como defesa não existia no
branch e, mesmo quando presente, só inspecionava callers dentro do próprio
repositório.

**Impacto:** uma composição incorreta ou comprometida podia contornar a
política D-019 e aceitar mensagens reservadas ou emitidas por papéis proibidos.

**Correção:** trait e seam tornaram-se privadas à crate. A política canônica
continua consultável por um método público, mas a única entrada pública que
aceita envelopes fixa internamente `CanonicalMessageTypePolicyV1`. Duas
regressões `compile_fail` impedem que qualquer uma dessas superfícies volte a
ser pública sem quebrar o CI.

### A-03 — MÉDIA-ALTA — overflow aceitava margem de timelock insuficiente

O composer verificava `up >= dn.saturating_add(margin)`. Para
`dn + margin > u64::MAX`, a soma saturava e `up == u64::MAX` era aceito mesmo
quando a distância real era menor que a margem.

**Impacto:** uma rota composta podia ser vinculada com uma janela de reação
menor que a política afirma, reduzindo a defesa de atomicidade.

**Correção:** a soma agora usa `checked_add` e recusa overflow. O oráculo do
property test também foi alterado para aritmética verificada, evitando que o
teste repita o mesmo erro da implementação.

### A-04 — MÉDIA — overflow transformava fee caps inválidos em limite máximo

A especificação F6 AD-1.2 exige explicitamente
`total_fee <= dom_max + counterparty_max` com “checked arithmetic; overflow
refuses”. A seleção RFQ e o reference solver usavam `saturating_add`.

**Impacto:** caps cuja soma não cabe em `u128` viravam `u128::MAX`, permitindo
que qualquer taxa representável passasse por uma política que deveria ser
recusada como inválida.

**Correção:** seleção e solver agora recusam overflow como
`FeeAboveLimit`. Foram adicionadas regressões independentes nos dois caminhos.

### A-05 — MÉDIA — publicação do intent board não validava o objeto

`IntentBoardV1::publish` inseria diretamente a struct recebida sem executar
`IntentV1::validate`. Era possível publicar versão desconhecida, RFQ com id
adulterado ou deadline do board divergente do deadline incorporado no RFQ.

**Impacto:** o board podia tornar-se uma segunda fonte de verdade para prazo e
aceitar estado que seu próprio decoder recusaria.

**Correção:** publicação valida antes de inserir; validação inclui integridade
do RFQ e igualdade exata entre os deadlines timestamp. Testes confirmam a
recusa e que nenhum estado residual é criado.

### A-06 — MÉDIA — contratos mantinham identificador de licença indefinido

Os fontes restaurados ainda usavam `SPDX-License-Identifier: TBD-A2`, apesar de
o repositório integrado possuir licença MIT e D-010 determinar a adoção da
licença da DOM no merge. Isso contradizia o registro normativo e inviabilizava
uma atribuição SPDX válida do artefato distribuído.

**Correção:** todos os 15 fontes Solidity usam agora `SPDX-License-Identifier:
MIT`. O job de contratos conta todos os `.sol`, exige o header MIT em cada um e
recusa `TBD-A2` ou `UNLICENSED`. Como `bytecode_hash = "none"` e comentários
não entram na lógica compilada, a mudança não altera a execução do contrato.

### A-07 — MÉDIA-ALTA — policy do harness aceitava soma impossível de margens

`TimelockPolicy::total_margin` somava as quatro margens com saturação. Uma
policy construída com `u64::MAX + 1` virava `u64::MAX`; no extremo
`now = 0, deadline = u64::MAX`, `require_actionable` aceitava a janela embora
a margem prometida não pudesse ser satisfeita. O caminho inverso de refund
também saturava `finality_margin + rpc_lag_margin` e podia declarar expiração
segura com uma policy irrepresentável.

**Impacto:** uma policy configurada com valores extremos podia autorizar ação
irreversível ou refund sob uma garantia de tempo matematicamente falsa.

**Correção:** `total_margin` agora retorna `Result` e usa apenas somas
verificadas; os gates de ação e expiração recusam overflow como
`TimelockError::Overflow`. A regressão foi executada antes da correção e
reproduziu `Ok(u64::MAX)` no caminho acionável; depois da correção, ambos os
caminhos recusam.

### A-08 — MÉDIA — RPC hostil podia prender o observer EVM na última página

O header `finalized` aceitava altura `u64::MAX`. Os loops paginados de
observação e coleta avançam com `to.saturating_add(1)`; quando `to` já era o
máximo, `from` permanecia igual e a mesma página era consultada para sempre.
Esse valor cabe no parser de quantities, portanto um endpoint hostil conseguia
provocar indisponibilidade sem fornecer JSON malformado.

**Impacto:** bloqueio persistente do worker de observação/coleta contra um RPC
comprometido ou defeituoso.

**Correção:** o trust boundary de finality recusa uma altura que não possui
sucessor representável como `FinalizedHeaderMalformed`, antes de qualquer
scan. A regressão primeiro confirmou que o header máximo retornava `Ok` e
depois passou junto com toda a suíte do adapter.

## Riscos abertos / decisões necessárias

### O-01 — ALTA — não existe composition root de produção ratificado

`route-composer`, `chain-profile`, `solver` e `intent-book` declaram
explicitamente `NOT RATIFIED`. `ChainProfileV1` não possui consumidor fora de
sua própria crate/testes; em particular, os margins derivados e a lista de
assets não são ligados ao composer ou ao `EvmAdapterConfig` por uma fronteira
de produção. Os testes demonstram peças e harnesses, não um runtime mainnet
autorizado.

**Recomendação:** manter `MAINNET = DISABLED` até existir uma composição
ratificada que derive, valide e persista profiles, assets, deployment
codehashes e floors de timelock antes de autorizar funding.

### O-02 — ALTA — identidade de ERC-20 não é ligada ao profile por endereço/codehash

O contrato documenta um resíduo inevitável para tokens maliciosos: um token
que mente dinamicamente em `balanceOf` pode criar crédito fantasma ou prender o
beneficiário. O profile contém `AssetId` abstratos e o codehash do contrato de
lock, enquanto o adapter recebe o endereço do token separadamente; não há uma
prova estrutural `AssetId -> token address -> token codehash`.

**Recomendação:** antes de habilitar ERC-20, ratificar um descritor de asset
que comprometa endereço, chain id, decimals e codehash do token; exigir esse
descritor no adapter e na composição. A lista deve ser pequena e revisada.

### O-03 — MÉDIA — `policy_version` do relay é assinado, mas não adjudicado

O envelope compromete `policy_version`, porém `RecipientContextV1` não contém
uma versão aceita e a pipeline não a compara. A documentação reconhece que não
há regra ratificada. Isso preserva autenticidade dos bytes, mas não impede
downgrade semântico entre participantes.

**Recomendação:** ratificar a regra de compatibilidade e adicionar a versão
aceita ao contexto da sessão antes de tratar esse campo como proteção de
downgrade.

### O-04 — MÉDIA — semântica de `RfqV1.quote_deadline` é ambígua no fluxo direto

A seleção exige que a própria quote não esteja expirada, mas não compara `now`
ao `rfq.quote_deadline`. O intent board possui deadline próprio e agora prova
que ele espelha o RFQ; o caminho F6 direto ainda pode selecionar depois do
deadline do RFQ se a quote tiver expiry posterior.

**Recomendação:** decidir normativamente se `quote_deadline` limita recepção,
seleção ou apenas serve de base para os offsets do solver. Se limitar o fluxo,
adicionar recusa nomeada e testes em seleção e binding.

## Evidência executada

- Reprodução negativa do overflow de timelock antes da correção: teste falhou
  porque o binding retornou `Ok`.
- Reprodução negativa do overflow do fee cap antes da correção: teste falhou
  porque a admissibilidade retornou `Ok`.
- 496 testes nas crates alteradas (`rfq`, `solver`, `intent-book`, `relay`,
  `route-composer`, `f3-harness` e `adapter-evm`): todos passaram.
- 2 regressões de privacidade `compile_fail` do relay: passaram.
- Clippy das sete crates, todos os targets, `-D warnings`: passou.
- Foundry: 184 testes, 0 falhas, 0 skips, incluindo 1024 casos por fuzz test e
  256 campanhas de invariantes com profundidade 64.
- Anvil E2E: 12 cenários F3 + 6 cenários F4, 0 falhas e nenhum skip; incluiu
  claim/refund nativo e ERC-20, payout diferido, crash recovery e reorg.
- Guards da camada, release surface e relay fault surface: passaram.
- `cargo check --workspace --all-targets --locked`: passou após as correções.
- `cargo audit`: 653 dependências verificadas contra 1226 advisories RustSec,
  sem vulnerabilidade reportada. `cargo deny check`: advisories, bans,
  licenses e sources passaram; restaram apenas warnings não bloqueantes sobre
  metadata ausente em `fuchsia-cprng 0.1.1` e uma allowance MPL-2.0 não usada.
- Um mega-run suplementar do workspace foi interrompido depois de um único
  vermelho fora do escopo em
  `dom-scriptless-store::lock_lifetime_blocks_a_second_open_instance`, durante
  dezenas de crash tests paralelos. A repetição exata, isolada e serial passou
  (`1 passed, 0 failed`); nenhum arquivo do storage foi alterado.
- `cargo fmt --all --check`, `git diff --check` e parse do YAML de CI: passaram.

## Conclusão

As correções fecham oito falhas concretas e tornam a perna EVM novamente
reproduzível e bloqueante no CI. O estado resultante é sensivelmente mais
seguro para desenvolvimento e auditoria, mas ainda não deve ser descrito como
pronto para mainnet: a composition root e a ligação de identidade dos assets
continuam decisões de segurança não ratificadas.
