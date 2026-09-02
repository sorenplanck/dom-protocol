# Verificação da auto-atualização — DOM Wallet V3 v0.2.4

Data: 2026-07-27
Escopo: somente verificação; nada foi alterado no repositório.

## Veredicto

A auto-atualização existe no código, mas está inerte na prática — e é
intencional. A cadeia falha no primeiro elo (o feed não existe), e mesmo que
o feed existisse, o binário publicado da v0.2.4 o recusaria por não ter
chave pública embutida.

---

## 1. URL do feed e disponibilidade — FALHOU (404)

A URL está fixada em `crates/dom-wallet-updater/src/lib.rs:26` (e repetida
em `src-tauri/tauri.conf.json`):

    https://github.com/sorenplanck/dom-wallet-v3/releases/latest/download/latest.json

Retorno real da requisição (`curl -sS -i -L`):

    HTTP/2 404
    content-type: text/plain; charset=utf-8
    server: github.com
    x-github-request-id: 8EAA:18699F:1E3E2EE:208A4A5:6A675186

    Not Found

São duas causas independentes:

a) nenhum `latest.json` foi jamais publicado como asset;
b) todas as 9 releases do repositório são pre-releases, então o GitHub não
   tem "latest release" — o caminho `/releases/latest/` não resolve para
   nada, mesmo que o asset existisse na tag.

## 2. O feed aponta para a v0.2.4? — N/A (feed não existe)

Não há versão, URLs nem hashes para conferir. Os assets reais da release
`wallet-v0.2.4` (via `gh release view`):

- dom-wallet-linux-x86_64-DOM-Wallet-V3-0.2.4-1.x86_64.rpm
- dom-wallet-linux-x86_64-DOM-Wallet-V3_0.2.4_amd64.AppImage
- dom-wallet-linux-x86_64-DOM-Wallet-V3_0.2.4_amd64.deb
- dom-wallet-macos-aarch64-DOM-Wallet-V3.app.tar.gz
- dom-wallet-macos-aarch64-DOM-Wallet-V3_0.2.4_aarch64.dmg
- dom-wallet-windows-x86_64-DOM-Wallet-V3_0.2.4_x64-setup.exe
- dom-wallet-windows-x86_64-DOM-Wallet-V3_0.2.4_x64_en-US.msi
- SHA256SUMS.txt

Nenhum `latest.json`, nenhum arquivo `.sig`. O CI compila explicitamente
com `createUpdaterArtifacts: false`
(`.github/workflows/release-wallet.yml:157`), então os artefatos de updater
nem são gerados.

## 3. Assinatura do feed vs. chaves fixadas — FALHOU (dos dois lados)

Não há feed para assinar, e não há chave fixada na wallet:

- `tauri.conf.json` tem `"pubkey": ""`;
- o código usa `option_env!("DOM_UPDATE_PUBLIC_KEY")`
  (`src-tauri/src/main.rs:21`), que nenhum workflow do CI define;
- o workflow de estabilização verifica que `TAURI_SIGNING_PRIVATE_KEY` NÃO
  aparece no release workflow (`stabilize-wallet.yml:60`) — a assinatura
  foi projetada para ser offline e ainda não aconteceu.

## 4. Uma instalação da v0.2.4 encontra o feed? — FALHOU (nem tenta a rede)

Evidência no artefato publicado, não no código-fonte: baixei o `.deb` real
da release e inspecionei o binário `usr/bin/dom-wallet-tauri-shell`:

- `strings` encontra `UPDATE_SIGNATURE_KEY_UNAVAILABLE` (a string do
  caminho de erro "sem chave") — 1 ocorrência;
- ZERO chaves minisign embutidas (nenhuma string no formato `RW...` de
  chave pública).

Ou seja, o binário distribuído foi compilado sem `DOM_UPDATE_PUBLIC_KEY`.
O ciclo de update curto-circuita em `main.rs:130-132` antes de qualquer
requisição HTTP e marca o estado como `Failed` /
`UPDATE_SIGNATURE_KEY_UNAVAILABLE`. O cliente v0.2.4 nunca chega ao
endpoint — e se chegasse, receberia o 404 do item 1.

## 5. Fail-closed — OK (único item que passa)

- Sem chave embutida: recusa antes da rede (`finish_check_without_key`,
  estado `Failed`).
- Feed ausente/erro de rede: `UpdateError::CheckFailed`, estado `Failed`,
  nada instala.
- Feed sem o bloco `dom_manifest`, assinatura minisign inválida,
  `expires_at` vencido (`lib.rs:606-607`), downgrade, canal errado, host de
  download fora da allowlist (github.com, objects.githubusercontent.com,
  release-assets.githubusercontent.com, dom-protocol.org): todos retornam
  erro antes de qualquer download.
- Há cross-check entre o `dom_manifest` e os campos do feed Tauri
  (`main.rs:198-203`).
- Os 21 testes unitários do crate `dom-wallet-updater` passam.

Consistente com a política documentada em `docs/RELEASING.md`: instaladores
podem ser publicados sem feed vivo, e `latest.json` não deve ser publicado
até que todo artefato referenciado esteja assinado e verificado.

---

## O que falta publicar para a auto-atualização funcionar

1. Gerar o par de chaves offline (Tauri/minisign) e embutir a pública no
   build via `DOM_UPDATE_PUBLIC_KEY` (e/ou `pubkey` no `tauri.conf.json`).
2. Gerar artefatos de updater (`createUpdaterArtifacts: true`) e assinar
   cada um com a chave privada offline (arquivos `.sig`).
3. Autorar e publicar `latest.json` como asset, com versão, URL +
   assinatura por plataforma e o bloco `dom_manifest` assinado (com
   `expires_at` — que expira, então o feed precisa ser re-assinado a cada
   release ou periodicamente).
4. Resolver o caminho `/releases/latest/`: marcar uma release como "latest"
   (não pre-release) ou trocar o endpoint fixado por uma URL que resolva
   (vale também para `node-latest.json` e `mainnet-peers.json`, que sofrem
   do mesmo 404).

## Ponto crítico de sequenciamento

Como os binários já distribuídos da v0.2.4 não têm chave nenhuma embutida,
nada do que for publicado fará essas instalações se atualizarem sozinhas.
A primeira versão capaz de receber auto-update será a PRÓXIMA release,
compilada já com a chave — a migração v0.2.4 -> v0.2.5 ainda será manual,
obrigatoriamente.
