# DOM Protocol — Princípios de Trabalho

Este arquivo define como qualquer agente deve trabalhar neste repositório.
Vale para TODA sessão, não só auditorias.

## Autoria
- Todo commit é assinado como: Soren Planck <sorenplanck@tutamail.com>.
- Não adicionar co-autoria de assistentes de IA nos commits.
- Manter o nome de autor uniforme (sem variações de grafia ou e-mails pessoais).

## Integridade — nunca mascarar falha
- NUNCA afrouxar uma asserção, marcar #[ignore], inserir sleep, ou ajustar um
  teste só para ele "passar". Se um teste falha, ou o teste está errado (corrija
  o teste pelo motivo certo) ou o código está errado (o bug é o achado).
- Distinguir bug real de teste flaky SEMPRE com evidência, nunca por suposição.
- Trabalhar contra o CÓDIGO REAL, nunca contra relatórios, docstrings ou
  comentários. Comentário não é prova; confirme na fonte e, quando der, com teste
  que executa.
- Não reportar "concluído" sem que cargo build e cargo test estejam verdes (ou
  sem explicar exatamente o que ficou vermelho e por quê).

## Decisões de mérito ficam com o humano
- Mudanças de consenso, design, economia (supply, reward, fees) ou qualquer coisa
  que altere o comportamento do protocolo NÃO são decisão do agente.
- Diante de uma decisão de mérito: documente as opções com trade-offs, marque
  "PRECISA DECISÃO HUMANA" e pare. Não escolha sozinho.

## Git e merges
- Merge para a branch principal SEMPRE via Pull Request, nunca push direto.
- Não rodar git push, git rebase, force-push, alterar branch ou reescrever
  histórico sem autorização explícita na tarefa.
- Não commitar binários (.exe, artefatos de build) nem segredos no repositório.

## Segurança e escopo
- Todo trabalho de segurança é DEFENSIVO: hardening deste repositório.
- Tudo permanece local. Sem exfiltração de código ou dados.

## Estilo de trabalho
- Medir números reais (tamanhos, limites, thresholds), não estimar.
- Ser explícito sobre o que NÃO foi testado e por quê (limitações de método).
- Preferir provar afirmações com um teste que roda a afirmar por leitura.
