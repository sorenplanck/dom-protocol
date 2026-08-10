# Normas do coordenador (Soren Planck) — leitura obrigatória

## Norma 1 — Nunca escrever sem ler os documentos (SEM EXCEÇÃO)

Nunca escreva código ou documento — nem decida **onde** uma mudança pertence —
sem antes consultar os documentos mestre e fonte. Isso vale para cada mudança,
não caso a caso.

Documentos normativos deste repositório:

- `docs/scriptless/source-guides/normative/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx`
  (a mestra; extraia o texto antes de usar)
- `docs/scriptless/source-guides/normative/DOM-Scriptless-Cronograma-Implementacao-v1.md`
- NARs e ADRs no mesmo diretório

Regras derivadas:

- Cite a seção (§) da spec em comentários e mensagens de commit de qualquer
  mudança normativa.
- Se a mestra e o cronograma divergirem, PARE e peça adjudicação ao
  coordenador — nunca escolha sozinho.
- Módulo escrito sem citação de spec é dívida de auditoria: os defeitos desta
  base concentraram-se exatamente nos módulos escritos por inferência.

## Norma 2 — Fronteira do projeto

- O projeto Scriptless gera o **DOM Contracts** (repo `sorenplanck/dom-contracts`),
  um toolkit/aplicação independente. **Não é a DOM Wallet.**
- A DOM Wallet vive em repositório próprio (`dom-wallet-v3`) e está FORA deste
  projeto. Nenhum código de wallet é escrito por este projeto — nem em
  `crates/dom-wallet`/`dom-wallet2` deste repo.
- A campanha §16.2/T1 (cover HEIGHT_LOCKED) é obrigação do projeto da wallet;
  este projeto entrega no máximo a interface (`dom-slate::cover_policy`) e
  depende do G-COVER como precondição externa de mainnet.
- A rede DOM já opera em mainnet. O Scriptless permanece regtest-only até os
  gates + G-COVER (`MAINNET = DISABLED`, `REAL_FUNDS = PROHIBITED`).
- G0 foi revogado pelo coordenador (decisão registrada); G2–G5 são node-side e
  rodam no ambiente do coordenador (`docs/scriptless/REGTEST-GATES.md`).

## Norma 3 — Autoria e branches

- Autor único de commits: `Soren Planck <sorenplanck@tutamail.com>`.
- Proibido: trailers de coautoria, "Generated with", IDs de modelo ou menção a
  assistentes em commits, PRs, código ou documentos.
- Nomes de branch nunca contêm "claude" ou "codex".
