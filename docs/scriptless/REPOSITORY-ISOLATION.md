# Isolamento dos repositórios

Os dois clones foram criados com `git clone --local --no-hardlinks`, preservando histórico e copiando objetos Git de modo independente. Verificações de inode e contagem de links confirmam que os packs/objetos amostrados não compartilham hardlinks com as fontes.

Cada clone usa `source-local` para fetch da fonte local e `upstream` para a URL pública de fetch. Não existe `origin`. Todos os push URLs são `no_push://push-disabled`, `core.hooksPath` aponta para `.githooks` e o hook `pre-push` termina com erro antes de qualquer conexão.

Os repositórios oficiais nunca podem ser destino de build, formatação, branch, tag, commit ou instalação. Os scripts em `scripts/scriptless` recusam execução quando o caminho real coincide com uma fonte oficial conhecida.
