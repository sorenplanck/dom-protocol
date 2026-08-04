# Inventário dos demais artefatos do laboratório

Todos os itens abaixo têm status **não importado**. A finalidade é preliminar, inferida de nome/caminho e inspeção segura; nenhum item é considerado implementação autoritativa.

| Caminho relativo a `dom-scriptless-lab` | Nome | Bytes | SHA-256 | Possível finalidade | Status |
|---|---|---:|---|---|---|
| `artifacts/DOM_SCAD0_PARIDADE_2026-08-03.md` | relatório de paridade | 24.484 | `037e21269c9929ab01ff50ea773fe3685de735fc0fe874b40fdcc12c1a2a1b17` | evidência SCAD0 | não importado |
| `artifacts/DOM_SCAD0_probe_raw_2026-08-03.txt` | saída bruta | 1.934.209 | `1e277a12b22700f9495c31d40b430602a4c8a600c134156a866f78b198e05ef0` | log/vetores brutos do probe | não importado |
| `artifacts/adaptor_parity_probe.rs` | código Rust | 14.421 | `e036be3b8ae8f081a214958ed47e0d311c14e91277cbc57797f7276ef8c66064` | probe de laboratório | não importado |
| `c2_hardened/Cargo.lock` | lockfile | 26.870 | `9e3ea335d72c3bc287f6c7cc57eabb96eb7109e7a8ece647ecf9f14e6c3176e9` | dependências do experimento C2 | não importado |
| `c2_hardened/Cargo.toml` | manifest | 418 | `eb2cfffe95c36aa689e1c9ca6865bf5e67be3a3c092dcccbeff9f9637574b72c` | crate experimental C2 | não importado |
| `c2_hardened/artifacts/capsules_decoy_commit_reveal_100000.bin` | binário | 9.600.000 | `368eb45aa22185a0db1f0a5cc4242827552c234b7b7a6e6959a0b89172514bed` | corpus estatístico decoy | não importado |
| `c2_hardened/artifacts/capsules_real_100000.bin` | binário | 9.600.000 | `9f8ab26027fe6fd4f6fc96530b2f58bc807ec512d2519cb3d68a270f837e329a` | corpus estatístico real | não importado |
| `c2_hardened/artifacts/corpus_statistical_pvalues.csv` | CSV | 342.875 | `6d394ec96128c6ed8dbb47a37f4b4e71fce5effb33857ed4c69ff865baed51c7` | p-values experimentais | não importado |
| `c2_hardened/artifacts/corpus_statistical_summary.json` | JSON | 569 | `97ce0610880e445ad335baaf285c3a30f8dfe42817aa522a5a3921de0997a186` | resumo estatístico | não importado |
| `c2_hardened/src/backup_gate.rs` | código Rust | 8.531 | `afd3420e9af50678080baee8089862fc3951b1aea959906d271abada419792e5` | gate experimental de backup | não importado |
| `c2_hardened/src/bin/corpus_battery.rs` | código Rust | 18.925 | `d6dc46e953b26c2f4ce5df55ebba9c900ddde4cd38db9a7bcdd19f5215fa0530` | bateria estatística | não importado |
| `c2_hardened/src/decoy.rs` | código Rust | 7.423 | `52224da0904d6bc475341f135f45c3e476bbc457168303451894880b4a5ffec4` | experimento decoy | não importado |
| `c2_hardened/src/lib.rs` | código Rust | 191 | `b1c677785628e768b2807b78ac27e0fb3299100248940c67532add12edf73ebe` | raiz do crate experimental | não importado |
| `reports/MISSAO_3_C2_SCAD0_2026-08-04.md` | relatório | 10.863 | `65282f02ed423d31be28db3d8433c6de05ecb9cd92e8d8dcb564c9e298b3aef1` | evidência C2/SCAD0 | não importado |

`c2_hardened/target/` foi classificado integralmente como cache/artefato de build: 3.023 arquivos, 980.233.319 bytes. Não foi importado nem tratado como fonte. Para identificação das saídas finais visíveis: `target/release/corpus_battery` tem 1.095.232 bytes e SHA-256 `b1bc7f72e11b3d40e1ea8fa38876ab8cf7f3508d5ed01630de73ec26a73dba10`; seu arquivo `.d` tem 1.311 bytes e SHA-256 `1f9b8feeab7ff912a8a87aa42c92a80094ecf2b28075a54c3b3362a90417dd5a`.
