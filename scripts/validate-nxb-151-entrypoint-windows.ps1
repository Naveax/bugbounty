[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$workspace = $null
$outputDirectory = $null

function Invoke-JsonCommand {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter()] [int]$ExpectedExitCode = 0,
        [Parameter(Mandatory)] [string]$OutputPath,
        [Parameter(Mandatory)] [string]$ErrorPath
    )

    $raw = (& $FilePath @Arguments 2>$ErrorPath | Out-String)
    $exitCode = $LASTEXITCODE
    [IO.File]::WriteAllText(
        $OutputPath,
        $raw,
        [Text.UTF8Encoding]::new($false)
    )
    if ($exitCode -ne $ExpectedExitCode) {
        $errorText = if (Test-Path -LiteralPath $ErrorPath) {
            Get-Content -LiteralPath $ErrorPath -Raw
        } else {
            ""
        }
        throw "Command '$FilePath $($Arguments -join ' ')' returned $exitCode; expected $ExpectedExitCode. $errorText"
    }
    return ($raw | ConvertFrom-Json -Depth 32)
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
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    & cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "cargo fmt failed." }
    & cargo check -p nxb-core --all-targets --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo check failed." }
    & cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed." }
    & cargo test -p nxb-core --all-features --locked -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed." }
    & cargo build -p nxb-core --bin nxb --all-features --locked
    if ($LASTEXITCODE -ne 0) { throw "cargo build --bin nxb failed." }

    $nxb = Join-Path $RepoRoot "target\debug\nxb.exe"
    if (-not (Test-Path -LiteralPath $nxb -PathType Leaf)) {
        throw "Required binary is missing: $nxb"
    }

    $metadataPath = Join-Path $RepoRoot "target\nxb-151-metadata.json"
    & cargo metadata --no-deps --format-version 1 | Set-Content -LiteralPath $metadataPath -Encoding utf8NoBOM
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed." }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json -Depth 64
    $package = @($metadata.packages | Where-Object name -eq "nxb-core")
    if ($package.Count -ne 1) { throw "Could not resolve the nxb-core package target set." }
    $binaryTargets = @(
        $package[0].targets |
        Where-Object { $_.kind -contains "bin" } |
        ForEach-Object name |
        Sort-Object
    )
    if ($binaryTargets.Count -ne 1 -or $binaryTargets[0] -ne "nxb") {
        throw "Expected exactly one nxb binary target; found '$($binaryTargets -join ',')'."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $workspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-entrypoint-$nonce"
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-entrypoint-output-$nonce"
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null

    $init = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "init", "--workspace", $workspace,
        "--name", "Unified Windows Acceptance", "--json"
    ) -OutputPath (Join-Path $outputDirectory "init.json") `
      -ErrorPath (Join-Path $outputDirectory "init.err")
    if ($init.status -ne "initialized") { throw "Unified init output is invalid." }

    $doctor = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    ) -OutputPath (Join-Path $outputDirectory "doctor.json") `
      -ErrorPath (Join-Path $outputDirectory "doctor.err")
    if ($doctor.status -ne "healthy" -or $doctor.migration.status -ne "stable") {
        throw "Unified doctor did not report a stable healthy workspace."
    }
    $migrationCheck = @($doctor.checks | Where-Object name -eq "migration_state")
    if ($migrationCheck.Count -ne 1 -or $migrationCheck[0].status -ne "pass") {
        throw "Unified doctor migration check is missing or invalid."
    }

    $workspaceStatus = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "status", "--workspace", $workspace, "--json"
    ) -OutputPath (Join-Path $outputDirectory "status.json") `
      -ErrorPath (Join-Path $outputDirectory "status.err")
    if ($workspaceStatus.status -ne "ready" -or $workspaceStatus.migration.status -ne "stable") {
        throw "Unified status output is invalid."
    }

    $migration = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "migrate", "status", "--workspace", $workspace, "--json"
    ) -OutputPath (Join-Path $outputDirectory "migration.json") `
      -ErrorPath (Join-Path $outputDirectory "migration.err")
    if ($migration.status -ne "stable") { throw "Migration status is not stable." }

    $active = Join-Path $workspace "state\migration-active.json"
    [IO.File]::WriteAllText($active, "{}`n", [Text.UTF8Encoding]::new($false))

    $pendingDoctor = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    ) -ExpectedExitCode 20 `
      -OutputPath (Join-Path $outputDirectory "doctor-pending.json") `
      -ErrorPath (Join-Path $outputDirectory "doctor-pending.err")
    if ($pendingDoctor.status -ne "unhealthy" -or
        $pendingDoctor.migration.status -ne "recovery_required") {
        throw "Pending migration was not surfaced through doctor."
    }

    $pendingStatus = Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "status", "--workspace", $workspace, "--json"
    ) -ExpectedExitCode 30 `
      -OutputPath (Join-Path $outputDirectory "status-pending.json") `
      -ErrorPath (Join-Path $outputDirectory "status-pending.err")
    if ($pendingStatus.status -ne "recovery_required" -or
        $pendingStatus.migration.status -ne "recovery_required") {
        throw "Pending migration was not surfaced through status."
    }

    Remove-Item -LiteralPath $active -Force
    [void](Invoke-JsonCommand -FilePath $nxb -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    ) -OutputPath (Join-Path $outputDirectory "doctor-restored.json") `
      -ErrorPath (Join-Path $outputDirectory "doctor-restored.err"))

    $validationDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-entrypoint-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        gate = "linked_single_binary_entrypoint"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        binary = [ordered]@{
            name = "nxb.exe"
            sha256 = (Get-FileHash -LiteralPath $nxb -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        checks = [ordered]@{
            single_cargo_binary_target = "passed"
            workspace_init = "passed"
            combined_doctor = "passed"
            combined_status = "passed"
            migration_status = "passed"
            pending_doctor_exit_20 = "passed"
            pending_status_exit_30 = "passed"
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 8) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 linked single-binary Windows validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    foreach ($path in @($workspace, $outputDirectory)) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
