# DOM v3 Mainnet hard fork

## Consensus changes

- Mainnet requires block version 3 starting at height **12,500**.
- Blocks below height 12,500 remain version 2.
- A version 3 block before height 12,500 is invalid.
- A version 2 block at or above height 12,500 is invalid, regardless of
  accumulated work.
- Rolling finality is enforced from node startup: an established local chain
  refuses reorganization depth 360 or greater. Depth 359 remains accepted.
- Fresh and short nodes remain able to synchronize from genesis.

## Network compatibility

`WIRE_PROTOCOL_VERSION` remains **2**. Updated and legacy nodes can complete the
same P2P handshake, but legacy nodes will not follow the valid Mainnet chain
after height 12,500.

## Network synchronization fixes

corrige seeds sendo banidos durante a sincronização inicial (rajada de
re-requisições após IBD longa); penalidades de peer passam a expirar de fato;
erros locais deixam de penalizar peers.

- Timers de catch-up descartam ticks perdidos em vez de reproduzi-los em rajada.
- Tráfego excedente de sincronização recebe pacing/throttle sem pontos de ban.
- Respostas a `GetBlockData` explicitamente solicitado são classificadas como
  sync, não como relay espontâneo.
- O handler serve no máximo 16 corpos por requisição.
- IPs atualmente resolvidos dos seeds configurados nunca são recusados pelo
  limiar de reputação e são atualizados após nova resolução DNS.
- O checkpoint `ibd_session/v2` migra o formato legado; checkpoint local
  inconsistente é descartado e a sincronização reinicia do tip local.
- A ferramenta offline
  `dom-peer-reputation-clear <node-data-dir>` remove reputação persistida v1/v2.

## Required release notice

> Hard fork at height 12,500; v2 nodes will not follow the chain after that
> height; rolling finality of 360 blocks.

At the decision height of approximately 10,900, the remaining 1,600 blocks at
approximately two minutes per block represented approximately 53 hours.

## Rollout order

1. Complete automated tests and at least 20 minutes of real multi-node testing.
2. Build the release, sign it with the notebook minisign key, and publish the
   tagged release with this notice.
3. Update seed1, seed2, the observer, and the notebook miner immediately.
4. Advance the wallet pin to the v3 commit only after the restore parity blocker
   is resolved, then publish the wallet.
5. Announce the activation height, remaining time, release link, and one-command
   upgrade instruction on Discord, Telegram, Bitcointalk, and GitHub. Pin the
   Discord notice and obtain explicit confirmation from the largest miners.
6. At height 12,500, monitor the observer, block cadence, and rolling-finality
   WARN events on both seeds.
