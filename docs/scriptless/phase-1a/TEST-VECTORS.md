# Vetores de teste de G1a

G1a exige fontes independentes e congelamento byte a byte. O código sob teste não pode gerar o próprio oráculo.

## SCAD0

Existe uma cópia byte-idêntica de oito vetores em [`test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt`](../../../test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt), registrada pelo [`MANIFEST.sha256`](../../../test-vectors/scriptless/MANIFEST.sha256). O Relatório Consolidado §2.1 identifica o extrato de oito vetores pelo mesmo SHA-256 abreviado (`e99ad8a3…eaa4b`); a cópia local tem SHA-256 completo `e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b`. Sua presença e correlação documental não fecham G1a: ainda faltam implementação, execução no crate isolado, vetores independentes de dois nonces e revisão formal.

## Ainda pendente

- vetores independentes do esquema de dois nonces e binding;
- transcript, partials e agregação;
- adaptação e extração;
- purposes e domínios de hash;
- scalars/pontos malformados e fronteiras;
- mutação de todos os campos críticos;
- corpus de fuzz independente.

Nenhum vetor pode ser reformado, normalizado ou regenerado silenciosamente.

## AUTO-CHECK do backend

O arquivo
[`DOM_G1A_BACKEND_FREEZE_V1.txt`](../../../test-vectors/scriptless/hash-domains/DOM_G1A_BACKEND_FREEZE_V1.txt)
adiciona somente checks determinísticos do framing, hash e challenge já
autoritativos. Os digests esperados foram calculados com Python `hashlib` e são
comparados ao `dom-crypto` pelo probe test-only. Ele não contém dois nonces,
pré-assinatura ou prova independente do esquema G1a e não fecha item do gate.

Plano completo: [`TEST-VECTOR-PLAN.md`](TEST-VECTOR-PLAN.md).
