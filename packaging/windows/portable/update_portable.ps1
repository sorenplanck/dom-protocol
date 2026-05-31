param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$NewPackageDir
)

$ErrorActionPreference = "Stop"

function Require-Directory($Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Missing required directory: $Path"
    }
}

function Require-File($Path) {
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing required file: $Path"
    }
}

Require-Directory $InstallDir
Require-Directory $NewPackageDir
Require-Directory (Join-Path $InstallDir "bin")
Require-Directory (Join-Path $InstallDir "config")
Require-Directory (Join-Path $InstallDir "data")
Require-Directory (Join-Path $InstallDir "data\wallets")
Require-Directory (Join-Path $InstallDir "backups")
Require-Directory (Join-Path $NewPackageDir "bin")

Require-File (Join-Path $NewPackageDir "bin\dom-wallet-app.exe")
Require-File (Join-Path $NewPackageDir "bin\dom-node.exe")
Require-File (Join-Path $NewPackageDir "bin\dom-test-runner.exe")

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$walletBackup = Join-Path $InstallDir "backups\wallets-$stamp"
New-Item -ItemType Directory -Force -Path $walletBackup | Out-Null
Copy-Item -LiteralPath (Join-Path $InstallDir "data\wallets") -Destination $walletBackup -Recurse -Force

Copy-Item -LiteralPath (Join-Path $NewPackageDir "bin\dom-wallet-app.exe") -Destination (Join-Path $InstallDir "bin\dom-wallet-app.exe") -Force
Copy-Item -LiteralPath (Join-Path $NewPackageDir "bin\dom-node.exe") -Destination (Join-Path $InstallDir "bin\dom-node.exe") -Force
Copy-Item -LiteralPath (Join-Path $NewPackageDir "bin\dom-test-runner.exe") -Destination (Join-Path $InstallDir "bin\dom-test-runner.exe") -Force

if (Test-Path -LiteralPath (Join-Path $NewPackageDir "VERSION.txt")) {
    Copy-Item -LiteralPath (Join-Path $NewPackageDir "VERSION.txt") -Destination (Join-Path $InstallDir "VERSION.txt") -Force
}

Write-Host "Updated binaries in $InstallDir"
Write-Host "Wallet backup: $walletBackup"
Write-Host "Config, chain data, logs, backups, and cache were preserved."
