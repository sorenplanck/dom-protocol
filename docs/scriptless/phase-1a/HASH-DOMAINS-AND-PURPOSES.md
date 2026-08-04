# Domínios de hash e purposes de G1a

Este é o documento autoritativo para G1a sobre domínios e purposes. O registro deverá ser fechado, canônico e versionado, com separação inequívoca para Funding, Claim e Refund e uso exclusivo de `blake2b_256_tagged` da DOM.

As fontes normativas fornecidas pelo operador congelam BLAKE2b-256 com digest nativo de 32 bytes e exigem delegação ao challenge/hash autoritativo da DOM, mas a Especificação Mestra §3.4 declara que framing, personalization, salt/key, hash-to-scalar e várias tags propostas ainda dependem de freeze e vetores diferenciais. O Apêndice E também marca seus códigos e layouts como propostos para freeze. A [matriz normativa](NORMATIVE-INPUT-MATRIX.md) registra esses estados sem promover propostas a decisões.

Não é permitido inferir valores do DL2P, de modelos antigos ou do código sob teste.

Estado: **algoritmo-base consistente; framing, registro final, bytes de purpose e vetores ainda exigem decisão/congelamento; nenhum item de gate concluído**.
