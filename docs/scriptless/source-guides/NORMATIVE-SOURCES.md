# Fontes normativas registradas

Estado do registro: **três fontes fornecidas pelo operador, importadas byte a byte e verificadas localmente em 2026-08-04**.

> PROVENIÊNCIA CONFIRMADA PELO OPERADOR; INTEGRIDADE LOCAL REGISTRADA POR SHA-256

Não foram fornecidas assinaturas digitais, certificados ou hashes publicados externamente. Os hashes abaixo demonstram identidade e integridade local a partir dos arquivos entregues pelo operador; não constituem autenticação criptográfica externa da autoria.

## Hierarquia

1. [Especificação Mestra v1.0](normative/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx)
2. [Relatório Consolidado v1](normative/DOM-Scriptless-Relatorio-Consolidado-v1.md)
3. [Cronograma de Implementação v1](normative/DOM-Scriptless-Cronograma-Implementacao-v1.md)
4. Código, fixtures e testes congelados

Uma fonte inferior fornece evidência e detalhamento, mas não altera silenciosamente uma decisão explícita da fonte superior. Divergências devem ser resolvidas por errata, ADR ou novo congelamento versionado.

## Proveniência e identidade

| Ordem | Documento e versão encontrada | Origem fornecida pelo operador | Cópia controlada | Bytes | Modificação da origem | Tipo real | SHA-256 | Identidade |
|---:|---|---|---|---:|---|---|---|---|
| 1 | `DOM Scriptless Contracts` — `Especificação Mestra de Engenharia e Implementação v1.0 — Revisão R1`, 3 de agosto de 2026 | `/home/leonardov/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx` | `docs/scriptless/source-guides/normative/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx` | 99.871 | `2026-08-04 12:07:22.515508253 -0300` | Microsoft Word 2007+ / OOXML | `5ad366d6b5c01c88bc88d4e9c016b447c32f24fbc24a32fa8b6946d7ff5dd6b5` | `cmp --silent`: igual |
| 2 | `DOM Scriptless Contracts — Relatório Consolidado de Viabilidade`; versão documental não declarada no conteúdo, nome de arquivo `v1`; data 2026-08-04 | `/home/leonardov/DOM-Scriptless-Relatorio-Consolidado-v1.md` | `docs/scriptless/source-guides/normative/DOM-Scriptless-Relatorio-Consolidado-v1.md` | 15.853 | `2026-08-04 12:07:22.359508549 -0300` | texto Unicode UTF-8 | `5431ca3894c42ffbee86cd719d4bb0e70ec8ddfb21b33895e889372fa5335acb` | `cmp --silent`: igual |
| 3 | `DOM Scriptless Contracts — Cronograma de Implementação`; escopo `V1 estrito`, versão documental não declarada no conteúdo, nome de arquivo `v1`; data 2026-08-04 | `/home/leonardov/DOM-Scriptless-Cronograma-Implementacao-v1.md` | `docs/scriptless/source-guides/normative/DOM-Scriptless-Cronograma-Implementacao-v1.md` | 10.851 | `2026-08-04 12:07:22.276508707 -0300` | texto Unicode UTF-8 | `cfee44873007390f1e19ea95ec5da66e860373a882c32af51ace985fde495e48` | `cmp --silent`: igual |

As três origens são arquivos comuns, modo `0644`. Nenhum original foi modificado, movido, renomeado ou removido.

## Busca e duplicatas

A localização combinou busca direta e varredura recursiva de arquivos Markdown/DOCX em `/home/leonardov`, excluindo `.git`, `target`, `node_modules`, caches, builds e diretórios de distribuição. Apenas os três caminhos de origem acima corresponderam aos títulos/nomes normativos. Outros arquivos contendo a palavra “scriptless” eram relatórios de código ou documentação do próprio ambiente isolado, não duplicatas dessas fontes.

Não houve duplicata idêntica nem candidato divergente a selecionar. Os nomes originais já eram canônicos e foram preservados.

## Manifesto e reprodução

O manifesto está em [`normative/MANIFEST.sha256`](normative/MANIFEST.sha256). A partir da raiz do clone:

```bash
sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256
```

## Limite DL2P

A Especificação Mestra contém referências históricas e uma seção de integração opcional com DL2P. A importação integral do documento normativo preserva esses bytes, mas não importa nenhum RFC, modelo, PDF, envelope, regra ou implementação DL2P. Essas referências não são autoridade de implementação para DOM Scriptless Contracts e permanecem fora do escopo deste repositório.

Consulte a [revisão comparativa](../reports/phase-1/NORMATIVE-REVIEW.md) e a [matriz de inputs G1a](../phase-1a/NORMATIVE-INPUT-MATRIX.md).
