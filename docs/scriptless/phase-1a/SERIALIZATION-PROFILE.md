# Perfil de serialização G1a v1

Inteiros são little-endian somente onde a tabela diz; escalares Schnorr são
big-endian. Campos fixos nunca carregam prefixo. Listas carregam `count_u32_le`.
Campos variáveis carregam `len_u32_le` e limite explícito.

## Payloads congelados por ADR-0011/0012

| Estrutura | Campo em ordem | Tamanho | Tipo/codificação | Origem | Validação |
|---|---|---:|---|---|---|
| `SigNonceCommitV1` | `purpose` | 1 | enum ADR-0012 | EM Ap. E §E.6 | `01..03` |
| | `participant_index` | 2 | `u16` LE | EM Ap. E §E.6 | único/ordenado |
| | `nonce_reveal_hash` | 32 | digest | EM Ap. E §E.6 | exato |
| **total** | | **35** | | | |
| `SigNonceRevealV1` | `purpose` | 1 | enum | EM Ap. E §E.6 | conhecido |
| | `participant_index` | 2 | `u16` LE | EM Ap. E §E.6 | único |
| | `R_i1` | 33 | SEC1 comprimido | EM Ap. E §E.6 | canônico |
| | `R_i2` | 33 | SEC1 comprimido | EM Ap. E §E.6 | canônico |
| **total** | | **69** | | | |
| `PartialSignatureV1` | `purpose` | 1 | enum | EM Ap. E §E.6 | conhecido |
| | `participant_index` | 2 | `u16` LE | EM Ap. E §E.6 | único |
| | `template_hash` | 32 | digest | EM Ap. E §E.6 | exato |
| | `partial_scalar` | 32 | scalar BE | ADR-0010 | `[1,n-1]` |
| **total** | | **67** | | | |
| `AdaptorPreSignatureV1` | `claim_template_hash` | 32 | digest | EM Ap. E §E.6 | exato |
| | `adaptor_point_T` | 33 | SEC1 comprimido | EM Ap. E §E.6 | canônico/não identidade |
| | `aggregate_nonce_hat` | 33 | SEC1 comprimido | EM Ap. E §E.6 | canônico |
| | `scalar_hat` | 32 | scalar BE | ADR-0010 | `[1,n-1]` |
| | `transcript_hash` | 32 | digest | EM Ap. E §E.6 | exato |
| **total** | | **162** | | | |

## Formato DOM reutilizado sem alteração

`TransactionKernel = features_u8 || fee_u64_le || lock_height_u64_le ||
excess_SEC1_33 || signature_65`, total 115 bytes. A assinatura é
`R_hat_SEC1_33 || s_be_32`. O codec é `DomSerialize`/`DomDeserialize`, nunca
serde/bincode.

## Ainda bloqueado

O envelope/wire completo de sessão, o valor inicial e discriminantes do
transcript, a ausência de `T` e limites de campos variáveis pertencem a decisões
posteriores. Nenhum decoder deve aceitar trailing bytes ou normalizar entradas.
