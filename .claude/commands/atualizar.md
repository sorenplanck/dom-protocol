---
description: Atualiza o repo local a partir do GitHub com segurança (sem descartar trabalho)
---

Atualize este repositório a partir do remoto (GitHub), de forma SEGURA.

PASSOS (pare e me avise se algo der errado, não force nada):
1. Rode `git status` e me diga o estado: há alterações locais não commitadas?
   A branch está à frente do remoto (commits locais não enviados)?
2. Rode `git fetch origin` e mostre `git log --oneline HEAD..origin/main`
   (o que o remoto tem que eu ainda não tenho).
3. SOMENTE se NÃO houver alterações locais não commitadas E a branch NÃO estiver
   à frente do remoto: rode `git pull --ff-only` e confirme o resultado.
4. Se HOUVER alterações locais ou commits locais não enviados: NÃO faça pull,
   NÃO descarte nada, NÃO faça force. Liste exatamente o que existe de diferente
   e PARE para eu decidir.
5. No fim, confirme que CLAUDE.md e .claude/commands/ existem e mostre o último
   commit (`git log -1 --oneline`).

REGRAS:
- PROIBIDO: git reset --hard, git checkout -- <arquivo>, git clean, git push,
  ou qualquer comando que descarte ou sobrescreva trabalho local.
- Se o pull não puder ser fast-forward, PARE e me explique — não resolva sozinho.
