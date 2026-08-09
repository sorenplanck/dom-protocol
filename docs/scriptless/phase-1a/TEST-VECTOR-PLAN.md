# Plano de vetores para G1a

| Família | Evidência atual | Estado | Critério para gate |
|---|---|---|---|
| BLAKE2b/tag framing DOM | KAVs `empty`, `abc` e tags em `dom-crypto` | backend congelado | manter pinado e testar tags Scriptless |
| Scalar BE/LE | `negative_kav.rs` | backend congelado | vetor explícito de conversão e fronteiras |
| Pontos SEC1/paridade | testes `PublicKey`; SCAD0 | backend congelado | mutações de tamanho, prefixo, curva e infinito |
| SCAD0 adaptor | relatório completo importado + fixture compacto do consenso | 8 casos presentes; não fecha gate sozinho | verificar ambos hashes e os oito kernels no verificador real |
| Purposes/domínios | ADR-0012 | parâmetros congelados | vetores diferenciais dos bytes `01/02/03` |
| Transcript | parte conhecida em `CANONICAL-TRANSCRIPT.md` | parcial | resolver bloqueios e congelar bytes completos |
| Dois nonces/binding | equações, transcript e scalar mapping congelados por ADR-0013 | derivação secreta BLOQUEADA | implementação independente, partials/agregação e mutações |
| Adapt/extract | SCAD0 + teste de consenso | forte, porém laboratório correlacionado | vetores independentes e fronteiras `0,n,n-1` |
| Fuzz | inexistente | pendente | parsers/operações sem panic e com limites |

O relatório laboratorial de 181 linhas tem SHA-256
`e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b`.
O fixture compacto rastreado por consenso tem SHA-256
`4be1657e8101a036ae2b0ea8d409e284b3c8c7215ccb9d92dc7b29b9dc7dbe10`.
Eles contêm os mesmos oito kernels, mas não são byte-idênticos: o primeiro inclui
segredos, passos e sumário do probe; o segundo é o extrato mínimo executável.
Nenhum deve substituir o outro.

Vetores gerados somente pelo backend DOM sob teste serão rotulados
`AUTO-CHECK`, nunca “independentes”.
