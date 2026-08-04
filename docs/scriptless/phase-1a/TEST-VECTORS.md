# Vetores de teste de G1a

G1a exige fontes independentes e congelamento byte a byte. O código sob teste não pode gerar o próprio oráculo.

## SCAD0

Existe uma cópia byte-idêntica de oito vetores candidatos em [`test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt`](../../../test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt), registrada pelo [`MANIFEST.sha256`](../../../test-vectors/scriptless/MANIFEST.sha256). Sua presença não fecha o item: ainda são necessárias classificação normativa, revisão independente e evidência de origem.

## Ainda pendente

- vetores independentes do esquema de dois nonces e binding;
- transcript, partials e agregação;
- adaptação e extração;
- purposes e domínios de hash;
- scalars/pontos malformados e fronteiras;
- mutação de todos os campos críticos;
- corpus de fuzz independente.

Nenhum vetor pode ser reformado, normalizado ou regenerado silenciosamente.
