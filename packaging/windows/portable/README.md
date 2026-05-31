# DOM Windows portable package

This folder defines the DOM wallet portable Windows layout and update flow.
It is packaging only; it does not change wallet, node, persistence, consensus,
or network behavior.

## Layout

```text
DOM-Portable/
  README.md
  VERSION.txt
  bin/
    dom-wallet-app.exe
    dom-node.exe
    dom-test-runner.exe
  config/
    app_state.example.json
    node.env.example
  data/
    wallets/
    chain/
  logs/
  backups/
  cache/
```

Roles:

- `bin/`: executable files only.
- `config/`: local config examples and operator-edited config files.
- `data/wallets/`: wallet directories and encrypted wallet files.
- `data/chain/`: local node chain/store data.
- `logs/`: exported wallet/node logs and diagnostics.
- `backups/`: update-time backups.
- `cache/`: disposable runtime cache.

Do not store wallet passwords, seed phrases, private keys, bearer tokens, API
tokens, or other secrets in package config files or docs.

## Build a package

From the repository root on Windows PowerShell:

```powershell
packaging\windows\portable\build_portable.ps1 `
  -ReleaseDir target\release `
  -OutputDir target\DOM-Portable
```

The build script refuses to overwrite an existing output directory unless
`-Force` is supplied. A fresh package contains examples and empty data
directories; it does not contain a wallet.

## Start

Run the wallet:

```powershell
.\bin\dom-wallet-app.exe
```

Run a local node for devnet/testnet work:

```powershell
$env:DOM_DATA_DIR = "$PWD\data\chain"
$env:DOM_LOG = "info"
.\bin\dom-node.exe
```

The current node binary defaults to `Network::Testnet`. Keep mainnet usage
behind the documented readiness and genesis-finalization gates.

## Stop

Close the wallet window normally. For a node launched from PowerShell, press
`Ctrl+C` in that terminal and wait for it to exit before replacing binaries or
moving the package directory.

## Update safely

1. Stop the wallet and node.
2. Build or download the new package into a separate directory.
3. Run the update script from this repository:

```powershell
packaging\windows\portable\update_portable.ps1 `
  -InstallDir C:\DOM\DOM-Portable `
  -NewPackageDir C:\Downloads\DOM-Portable
```

The update script:

- backs up `data\wallets` before replacing binaries;
- replaces files in `bin/`;
- preserves `config/`, `data/`, `logs/`, `backups/`, and `cache/`;
- refuses to run if required directories are missing.

## Backups

Wallet backups are written under:

```text
backups/wallets-YYYYMMDD-HHMMSS/
```

Keep offline backups of wallet seed phrases separately. Do not place seed
phrases or passwords in this portable folder.

## Version metadata

`VERSION.txt` records:

- package version from `Cargo.toml`;
- git commit hash, when available;
- build timestamp;
- source release directory.

This metadata is diagnostic only and is not consensus data.

## Validation

From the repository root:

```bash
scripts/validate_windows_portable_package.sh
```

The validator checks required packaging files, required layout entries, update
backup behavior in script text, and obvious secret placeholders in package
files.
