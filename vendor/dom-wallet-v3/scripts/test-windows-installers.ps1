param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-ProcessStarts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $process = Start-Process -FilePath $Executable -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
        if ($process.HasExited) {
            throw "$Label exited during installed-application smoke test with code $($process.ExitCode)"
        }
    }
    Stop-Process -Id $process.Id -Force
    $process.WaitForExit()
}

function Find-WalletExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $candidate = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -eq ".exe" -and
            $_.Name -match "^dom[-_ ]wallet.*\.exe$" -and
            $_.Name -notmatch "uninstall|setup|installer"
        } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $candidate) {
        throw "No installed Wallet executable was found under $Root"
    }
    return $candidate.FullName
}

$bundle = (Resolve-Path $BundleRoot).Path
$msi = Get-ChildItem -Path (Join-Path $bundle "msi") -Filter *.msi -File |
    Select-Object -First 1
if ($null -eq $msi) {
    throw "MSI bundle was not produced"
}

$msiLog = Join-Path $env:RUNNER_TEMP "dom-wallet-msi-install.log"
$msiInstall = Start-Process -FilePath "msiexec.exe" -Wait -PassThru -ArgumentList @(
    "/i",
    "`"$($msi.FullName)`"",
    "/qn",
    "/norestart",
    "/L*v",
    "`"$msiLog`""
)
if ($msiInstall.ExitCode -ne 0) {
    Get-Content $msiLog -Tail 200
    throw "MSI installation failed with code $($msiInstall.ExitCode)"
}

$programRoots = @(
    (Join-Path $env:ProgramFiles "DOM Wallet V3"),
    (Join-Path ${env:ProgramFiles(x86)} "DOM Wallet V3"),
    (Join-Path $env:LOCALAPPDATA "DOM Wallet V3")
) |
    Where-Object { $_ -and (Test-Path $_) }
$msiExecutable = $null
foreach ($root in $programRoots) {
    try {
        $msiExecutable = Find-WalletExecutable -Root $root
        break
    } catch {
        continue
    }
}
if ($null -eq $msiExecutable) {
    throw "MSI installed but its Wallet executable could not be located"
}
Assert-ProcessStarts -Executable $msiExecutable -Label "MSI-installed Wallet"

$msiUninstall = Start-Process -FilePath "msiexec.exe" -Wait -PassThru -ArgumentList @(
    "/x",
    "`"$($msi.FullName)`"",
    "/qn",
    "/norestart"
)
if ($msiUninstall.ExitCode -ne 0) {
    throw "MSI uninstall failed with code $($msiUninstall.ExitCode)"
}

$nsis = Get-ChildItem -Path (Join-Path $bundle "nsis") -Filter *.exe -File |
    Where-Object { $_.Name -notmatch "uninstall" } |
    Select-Object -First 1
if ($null -eq $nsis) {
    throw "NSIS bundle was not produced"
}

$nsisRoot = Join-Path $env:RUNNER_TEMP "dom-wallet-nsis-install"
New-Item -ItemType Directory -Path $nsisRoot -Force | Out-Null
$nsisInstall = Start-Process -FilePath $nsis.FullName -Wait -PassThru -ArgumentList @(
    "/S",
    "/D=$nsisRoot"
)
if ($nsisInstall.ExitCode -ne 0) {
    throw "NSIS installation failed with code $($nsisInstall.ExitCode)"
}
$nsisExecutable = Find-WalletExecutable -Root $nsisRoot
Assert-ProcessStarts -Executable $nsisExecutable -Label "NSIS-installed Wallet"

$uninstaller = Get-ChildItem -Path $nsisRoot -Recurse -File |
    Where-Object { $_.Name -match "uninstall.*\.exe" } |
    Select-Object -First 1
if ($null -eq $uninstaller) {
    throw "NSIS uninstaller was not installed"
}
$nsisUninstall = Start-Process -FilePath $uninstaller.FullName -Wait -PassThru -ArgumentList "/S"
if ($nsisUninstall.ExitCode -ne 0) {
    throw "NSIS uninstall failed with code $($nsisUninstall.ExitCode)"
}
