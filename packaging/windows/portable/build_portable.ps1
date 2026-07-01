param(
    [string]$ReleaseDir = "target\release",
    # The Tauri desktop wallet builds in its own target dir (the crate is
    # excluded from the workspace). Build it first: `npm run tauri build`
    # from wallet-desktop/ (frontend assets are embedded in the exe via the
    # default custom-protocol feature).
    [string]$WalletReleaseDir = "wallet-desktop\src-tauri\target\release",
    [string]$OutputDir = "target\DOM-Portable",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Require-File($Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
}

if ((Test-Path -LiteralPath $OutputDir) -and !$Force) {
    throw "Output directory already exists: $OutputDir. Use -Force only for disposable staging output."
}

if ((Test-Path -LiteralPath $OutputDir) -and $Force) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}

$walletExe = Join-Path $WalletReleaseDir "dom-wallet-desktop.exe"
$nodeExe = Join-Path $ReleaseDir "dom-node.exe"
$runnerExe = Join-Path $ReleaseDir "dom-test-runner.exe"

Require-File $walletExe
Require-File $nodeExe
Require-File $runnerExe

$dirs = @(
    "bin",
    "config",
    "data\wallets",
    "data\chain",
    "logs",
    "backups",
    "cache"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path (Join-Path $OutputDir $dir) | Out-Null
}

Copy-Item -LiteralPath $walletExe -Destination (Join-Path $OutputDir "bin\dom-wallet-desktop.exe")
Copy-Item -LiteralPath $nodeExe -Destination (Join-Path $OutputDir "bin\dom-node.exe")
Copy-Item -LiteralPath $runnerExe -Destination (Join-Path $OutputDir "bin\dom-test-runner.exe")
Copy-Item -LiteralPath "packaging\windows\portable\README.md" -Destination (Join-Path $OutputDir "README.md")
Copy-Item -LiteralPath "packaging\windows\portable\layout.txt" -Destination (Join-Path $OutputDir "layout.txt")

$nodeEnv = @'
# Local node environment example. Do not add wallet passwords, seed phrases,
# private keys, API tokens, or bearer tokens here.
DOM_DATA_DIR=.\data\chain
DOM_LOG=info
'@
Set-Content -LiteralPath (Join-Path $OutputDir "config\node.env.example") -Value $nodeEnv -Encoding UTF8

$version = (Select-String -Path "Cargo.toml" -Pattern '^version\s*=' | Select-Object -First 1).Line
$gitHash = "unknown"
try {
    $gitHash = (git rev-parse HEAD).Trim()
} catch {
    $gitHash = "unknown"
}

$metadata = @(
    "package=DOM Windows Portable",
    "cargo_workspace_$version",
    "git_commit=$gitHash",
    "built_at_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))",
    "release_dir=$ReleaseDir"
)
Set-Content -LiteralPath (Join-Path $OutputDir "VERSION.txt") -Value $metadata -Encoding UTF8

Write-Host "Created portable package at $OutputDir"
