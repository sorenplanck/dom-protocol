# Modelo transacional do Store/Nonce Vault

Origem normativa: EM §§5.5, 6.6, 10 e Apêndice F. Origem de engenharia:
ADR-0003/0016.

## Invariantes

1. Uma unidade atômica contém reserva/consumo, débito de budget, journal e
   tombstone relacionados.
2. Nenhum byte público sai antes de estado local durável **e** receipt durável
   da âncora remota.
3. Aborto e falha depois da reserva são consumo; budget não volta.
4. Retry usa o mesmo `RequestId`, digest e bytes persistidos.
5. Journal é append-only, encadeado por hash/MAC e separado logicamente do
   snapshot mutável.
6. Tombstones sobrevivem a compactação e restore conforme política ainda a
   medir.
7. Escrita usa compare-and-swap lógico; conflito nunca é last-write-wins.

## Unidade de commit lógica

| Campo | Estado | Origem |
|---|---|---|
| versão/schema/época/revisão | obrigatório | EM Ap. F + ADR |
| key/session/slot IDs opacos | obrigatório | EM Ap. F |
| purpose local | obrigatório, cifrado/privado | EM §6.6; ADR-0012 |
| digest de contexto/binding | obrigatório | EM Ap. F |
| status monotônico | reservado → comprometido → autorizado → consumido/abortado | ADR de engenharia |
| secret cipher | presente apenas antes do terminal | EM Ap. F |
| bytes/digest de exposição | fixos antes do envio | EM §§5.5/10 |
| contadores de budget | debitados com reserva | G1b local |
| entrada de journal anterior/atual | encadeada | G1b local |
| receipt remoto | antes de exposição | ADR-0003/0006 |

## Base Wallet observada

`dom-wallet-storage::WalletDirectory` no clone isolado oferece writer lock,
`expected_generation`, staging completo, `sync_all`, rename e publicação da
geração/metadata. É reutilizável como infraestrutura, mas a publicação em duas
etapas e a retenção de gerações não implementam journal append-only, witness ou
antirollback. A integração futura precisa provar boundaries de crash em Windows,
Linux e macOS; não se presume que rename/fsync tenha semântica idêntica.
