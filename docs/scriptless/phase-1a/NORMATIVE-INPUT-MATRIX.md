# Matriz de inputs normativos de G1a — freeze pré-implementação

Data: 2026-08-04. Resultado: inputs solucionáveis congelados; bloqueios não
foram preenchidos. **Esta matriz não aprova G1a.**

Estados: `CONGELADO`, `CONSISTENTE`, `AMBÍGUO`, `AUSENTE`, `CONFLITANTE` e
`EXIGE DECISÃO`. Origem: EM = Especificação Mestra; RC = Relatório Consolidado;
CR = Cronograma.

| Input | Estado | Definição/evidência rastreável | Pendência de implementação/validação |
|---|---|---|---|
| Curva | CONGELADO | secp256k1; EM §§3.1–3.2; `dom-crypto`; ADR-0009 | implementar só via backend DOM |
| Grupo/ordem | CONGELADO | `n=FFFFFFFF…D0364141`; `schnorr.rs`; KAV negativo | testes G1a |
| Codificação de pontos | CONGELADO | SEC1 comprimido 33, prefixo 02/03; `PublicKey`; ADR-0010 | mutações/fuzz |
| Identidade/infinito/subgrupo | CONGELADO | rejeitar; parser secp256k1, cofactor 1 | corpus negativo G1a |
| Representação de scalars | CONGELADO | wire Schnorr BE 32 `[1,n-1]`; `keys::Scalar` interno LE; ADR-0010 | conversões explícitas/testes |
| Hash | CONGELADO | BLAKE2b nativo 32, sem key/salt/personalization; `hash.rs` + KAV | tags G1a vetorizadas |
| Framing tagged | CONGELADO | `u16_le(tag_len)||tag||data`; `blake2b_256_tagged` | enum fechado no código futuro |
| Tags/domínios G1a | CONGELADO PARCIAL | três tags Scriptless exatas da EM; ADR-0011 | transcript cumulativo e hash→scalar bloqueados |
| Purposes | CONGELADO | Refund=01, ClaimAdaptor=02, Funding=03; ADR-0012 | enum/testes; Sponsor reservado |
| Transcript de challenge | CONGELADO | `R33||X33||chain32||message`; `schnorr_challenge` | chamar API real |
| Transcript de commitment | CONGELADO | campos/tamanhos e T condicional; EM §6.6/ADR-0013 | implementação/vetores |
| Transcript de binding | CONGELADO | body, ordem e digest BE sem redução/retry; ADR-0013 | implementação/vetores independentes |
| Transcript acumulado | EXIGE DECISÃO | fórmula EM §8.4 | hash inicial e códigos direction/phase ausentes; Fase 3-SM |
| Ordem dos campos | CONGELADO PARCIAL | layouts E.6 promovidos por ADR-0011; listas count u32 LE | wire completo de sessão fora deste freeze |
| Esquema de dois nonces | CONGELADO PARCIAL | equação e binding aceitos; EM §6.6/ADR-0013 | derivação secreta, API DOM e vetores independentes |
| Nonce binding | CONGELADO | preimage, scalar mapping e invalid handling definidos | implementação/testes |
| Challenge | CONGELADO | challenge kernel DOM, tag `DOM:kernel-sig:v1` | integração/testes |
| Equações adaptor | CONGELADO | `R_hat=R+T`, `s=s_hat+t`, `t=s-s_hat`; EM/RC/SCAD0 | implementação G1a |
| Equações dois nonces | CONSISTENTE | EM §6.6, sem conflito | validação independente pendente |
| Adaptação/extração | CONGELADO | EM §§1.1/6.3; RC §2.1; SCAD0 | vetores independentes |
| Serialização G1a | CONGELADO PARCIAL | E.6 + ADR-0010/0011; kernel DOM intacto | campos bloqueados não codificados |
| Rejeição malformada | CONGELADO | tamanhos, canonicidade e range no backend DOM | mutações/fuzz pendentes |
| Zeroização | CONSISTENTE | EM §§3.1/5.5/20; `zeroize` na DOM | cobertura de novos tipos/caminhos |
| Constant-time | CONGELADO POR ADR | `subtle` e helpers DOM são baseline; nenhuma comparação secreta comum | auditoria/testes G1a |
| Tipos secretos | CONGELADO POR ADR | opacos, sem Debug/Clone/serde; EM + ADR-0009 | implementar e auditar |
| Vetores independentes | AUSENTE | SCAD0 correlacionado disponível | dois nonces/transcript/partials independentes faltam |
| Integração verificador DOM | CONGELADO | `schnorr_verify` + `validate_kernel_signatures`; ADR-0014 | testes da implementação |
| API aritmética DOM | EXIGE DECISÃO | necessidade comprovada; operações hoje privadas | extensão estreita em `dom-crypto`, sem backend paralelo |

## Bloqueios que permanecem legítimos

1. Derivação/KDF byte-exata dos nonces secretos com aux randomness, contexto e
   chave, sem nonce fornecido pela aplicação.
2. Vetores independentes do esquema de dois nonces.
3. API pública mínima de aritmética em `dom-crypto`, a implementar sem backend
   paralelo depois da revisão da derivação.
4. Hash inicial e discriminantes do transcript da Fase 3-SM.

Os itens 1–3 bloqueiam a conclusão da implementação G1a. O item 4 bloqueia a
integração com a máquina de estados, não o núcleo criptográfico isolado.
