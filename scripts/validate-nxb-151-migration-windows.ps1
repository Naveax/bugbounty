[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$legacy = $null
$orphan = $null

function Invoke-NativeGate {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Gate '$Name' failed with exit code $LASTEXITCODE."
    }
}

function Set-PrivateTestAcl {
    param([Parameter(Mandatory)] [string]$Path)

    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
    & $icacls $Path /inheritance:r `
        /grant:r "*$sid`:F" `
        '*S-1-5-18:F' `
        '*S-1-5-32-544:F' `
        /remove:g '*S-1-1-0' '*S-1-5-11' '*S-1-5-32-545' `
        /q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply a private ACL to test path '$Path'."
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve an exact Git HEAD."
    }
    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw "Working tree must be clean before validation."
    }
    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith("rustc 1.97.1 ")) {
        throw "Rust 1.97.1 is required."
    }

    Invoke-NativeGate cargo_fmt cargo @("fmt", "--all", "--", "--check")
    Invoke-NativeGate cargo_check cargo @("check", "-p", "nxb-core", "--bin", "nxb", "--all-features", "--locked")
    Invoke-NativeGate cargo_clippy cargo @("clippy", "-p", "nxb-core", "--bin", "nxb", "--all-features", "--locked", "--", "-D", "warnings")
    Invoke-NativeGate cargo_test cargo @("test", "-p", "nxb-core", "--all-features", "--locked", "--", "--test-threads=1")
    Invoke-NativeGate cargo_build cargo @("build", "-p", "nxb-core", "--bin", "nxb", "--all-features", "--locked")

    $nxb = Join-Path $RepoRoot "target\debug\nxb.exe"
    $fixture = Join-Path $RepoRoot "fixtures\nxb-151\workspace-v0.json"
    foreach ($path in @($nxb, $fixture)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required migration acceptance input is missing: $path"
        }
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $legacy = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-migrate-$nonce"
    $orphan = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-orphan-$nonce"
    $fixtureBytes = [IO.File]::ReadAllBytes($fixture)

    Invoke-NativeGate workspace_init $nxb @(
        "workspace", "init", "--workspace", $legacy,
        "--name", "Legacy Migration Acceptance", "--json"
    )
    [IO.File]::WriteAllBytes((Join-Path $legacy "workspace.json"), $fixtureBytes)
    Invoke-NativeGate migration_status_before $nxb @(
        "workspace", "migrate", "status", "--workspace", $legacy, "--json"
    )
    Invoke-NativeGate migration_apply $nxb @(
        "workspace", "migrate", "apply", "--workspace", $legacy, "--json"
    )
    Invoke-NativeGate migration_status_after $nxb @(
        "workspace", "migrate", "status", "--workspace", $legacy, "--json"
    )

    $manifest = Get-Content -LiteralPath (Join-Path $legacy "workspace.json") -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.secret_storage -ne "external_provider_only") {
        throw "Schema-0 workspace did not migrate to the canonical schema-1 manifest."
    }
    $receipts = @(Get-ChildItem -LiteralPath (Join-Path $legacy "state\migrations") -File -Filter "nxb-migration-*.json")
    if ($receipts.Count -ne 1) {
        throw "Expected exactly one immutable migration receipt."
    }
    foreach ($name in @("migration-active.json", "migration-source.json", "migration-applied.json")) {
        if (Test-Path -LiteralPath (Join-Path $legacy "state\$name")) {
            throw "Transient migration file remained after commit: $name"
        }
    }

    Invoke-NativeGate workspace_init_orphan $nxb @(
        "workspace", "init", "--workspace", $orphan,
        "--name", "Orphan Recovery Acceptance", "--json"
    )
    [IO.File]::WriteAllBytes((Join-Path $orphan "workspace.json"), $fixtureBytes)
    $orphanBackup = Join-Path $orphan "state\migration-source.json"
    [IO.File]::WriteAllBytes($orphanBackup, $fixtureBytes)
    Set-PrivateTestAcl -Path $orphanBackup
    Invoke-NativeGate migration_recover_orphan $nxb @(
        "workspace", "migrate", "recover", "--workspace", $orphan, "--json"
    )
    Invoke-NativeGate migration_status_orphan $nxb @(
        "workspace", "migrate", "status", "--workspace", $orphan, "--json"
    )

    $orphanManifest = Get-Content -LiteralPath (Join-Path $orphan "workspace.json") -Raw | ConvertFrom-Json
    if ($orphanManifest.schema_version -ne 1) {
        throw "Orphan backup recovery did not publish schema 1."
    }

    $outputDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $output = Join-Path $outputDirectory "nxb-151-migration-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151-migration"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        nxb_binary_sha256 = (Get-FileHash -LiteralPath $nxb -Algorithm SHA256).Hash.ToLowerInvariant()
        gates = @(
            "fmt", "check", "clippy", "tests", "schema_0_to_1",
            "orphan_backup_recovery", "receipt_cleanup", "single_binary_dispatch"
        )
    }
    [IO.File]::WriteAllText(
        $output,
        ($evidence | ConvertTo-Json -Depth 6) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 single-binary migration Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $output"
}
finally {
    Pop-Location
    foreach ($path in @($legacy, $orphan)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
