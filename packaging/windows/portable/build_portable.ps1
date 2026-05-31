param(
    [string]$ReleaseDir = "target\release",
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

$walletExe = Join-Path $ReleaseDir "dom-wallet-app.exe"
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

Copy-Item -LiteralPath $walletExe -Destination (Join-Path $OutputDir "bin\dom-wallet-app.exe")
Copy-Item -LiteralPath $nodeExe -Destination (Join-Path $OutputDir "bin\dom-node.exe")
Copy-Item -LiteralPath $runnerExe -Destination (Join-Path $OutputDir "bin\dom-test-runner.exe")
Copy-Item -LiteralPath "packaging\windows\portable\README.md" -Destination (Join-Path $OutputDir "README.md")
Copy-Item -LiteralPath "packaging\windows\portable\layout.txt" -Destination (Join-Path $OutputDir "layout.txt")

$appState = @'
{
  "wallet_dir": null,
  "network": null,
  "node_url": "http://127.0.0.1:33369"
}
'@
Set-Content -LiteralPath (Join-Path $OutputDir "config\app_state.example.json") -Value $appState -Encoding UTF8

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
