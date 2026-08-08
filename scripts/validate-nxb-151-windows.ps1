[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$results = [System.Collections.Generic.List[object]]::new()
$workspace = $null
$nonEmptyWorkspace = $null
$brokenWorkspace = $null
$junctionWorkspace = $null
$junctionTarget = $null
$aclWorkspace = $null
$junctionPath = $null

function Invoke-Gate {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter()] [string[]]$Arguments = @()
    )

    $started = [DateTimeOffset]::UtcNow
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    $finished = [DateTimeOffset]::UtcNow

    $results.Add([ordered]@{
        name = $Name
        command = (($FilePath, $Arguments) -join " ")
        exit_code = $exitCode
        started_at = $started.ToString("O")
        finished_at = $finished.ToString("O")
        passed = ($exitCode -eq 0)
    })

    if ($exitCode -ne 0) {
        throw "Gate '$Name' failed with exit code $exitCode."
    }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [int]$ExpectedExitCode
    )

    $started = [DateTimeOffset]::UtcNow
    & $FilePath @Arguments 2>$null | Out-Null
    $exitCode = $LASTEXITCODE
    $finished = [DateTimeOffset]::UtcNow

    $results.Add([ordered]@{
        name = $Name
        command = (($FilePath, $Arguments) -join " ")
        exit_code = $exitCode
        expected_exit_code = $ExpectedExitCode
        started_at = $started.ToString("O")
        finished_at = $finished.ToString("O")
        passed = ($exitCode -eq $ExpectedExitCode)
    })

    if ($exitCode -ne $ExpectedExitCode) {
        throw "Gate '$Name' returned $exitCode; expected $ExpectedExitCode."
    }
}

function Assert-PrivateAcl {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name
    )

    $started = [DateTimeOffset]::UtcNow
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance is not protected for '$Path'."
    }

    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $forbiddenSids = @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
    $currentFullControl = $false

    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            $sid = $rule.IdentityReference.Value
        }
        if ($forbiddenSids -contains $sid) {
            throw "Broad allow ACE '$sid' exists on '$Path'."
        }
        if ($sid -eq $currentSid -and
            (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
             [Security.AccessControl.FileSystemRights]::FullControl)) {
            $currentFullControl = $true
        }
    }

    if (-not $currentFullControl) {
        throw "Current user full-control ACE is missing on '$Path'."
    }

    $results.Add([ordered]@{
        name = $Name
        command = "Get-Acl $Path"
        exit_code = 0
        started_at = $started.ToString("O")
        finished_at = [DateTimeOffset]::UtcNow.ToString("O")
        passed = $true
    })
}

function Remove-TestPath {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
    else {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw "Could not resolve an exact Git HEAD."
    }

    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect repository status."
    }
    if ($status) {
        throw "Working tree must be clean before validation."
    }

    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "rustc is unavailable."
    }
    if (-not $rustcVersion.StartsWith("rustc 1.97.1 ")) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    $cargoVersion = (& cargo --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo is unavailable."
    }
    $rustfmtVersion = (& rustfmt --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "rustfmt is unavailable."
    }
    $clippyVersion = (& cargo clippy --version).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Clippy is unavailable."
    }

    Invoke-Gate -Name "cargo_fmt" -FilePath "cargo" -Arguments @(
        "fmt", "--all", "--", "--check"
    )
    Invoke-Gate -Name "cargo_check" -FilePath "cargo" -Arguments @(
        "check", "-p", "nxb-core", "--all-targets", "--all-features", "--locked"
    )
    Invoke-Gate -Name "cargo_clippy" -FilePath "cargo" -Arguments @(
        "clippy", "-p", "nxb-core", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"
    )
    Invoke-Gate -Name "cargo_test" -FilePath "cargo" -Arguments @(
        "test", "-p", "nxb-core", "--all-features", "--locked", "--", "--test-threads=1"
    )
    Invoke-Gate -Name "cargo_build_nxb" -FilePath "cargo" -Arguments @(
        "build", "-p", "nxb-core", "--bin", "nxb", "--all-features", "--locked"
    )

    $binary = Join-Path $RepoRoot "target\debug\nxb.exe"
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "NXB binary was not created at '$binary'."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $temp = [IO.Path]::GetTempPath()
    $workspace = Join-Path $temp "nxb-151-$nonce"
    $nonEmptyWorkspace = Join-Path $temp "nxb-151-nonempty-$nonce"
    $brokenWorkspace = Join-Path $temp "nxb-151-broken-$nonce"
    $junctionWorkspace = Join-Path $temp "nxb-151-junction-$nonce"
    $junctionTarget = Join-Path $temp "nxb-151-junction-target-$nonce"
    $aclWorkspace = Join-Path $temp "nxb-151-acl-$nonce"

    Invoke-Gate -Name "workspace_init" -FilePath $binary -Arguments @(
        "workspace", "init", "--workspace", $workspace,
        "--name", "Windows Acceptance", "--json"
    )
    Invoke-Gate -Name "workspace_doctor" -FilePath $binary -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    )
    Invoke-Gate -Name "workspace_status" -FilePath $binary -Arguments @(
        "workspace", "status", "--workspace", $workspace, "--json"
    )

    Assert-PrivateAcl -Path $workspace -Name "acl_workspace_root"
    foreach ($directory in @("config", "targets", "sessions", "runs", "evidence", "reports", "state", "tmp")) {
        Assert-PrivateAcl -Path (Join-Path $workspace $directory) -Name "acl_directory_$directory"
    }
    Assert-PrivateAcl -Path (Join-Path $workspace "workspace.json") -Name "acl_manifest"

    New-Item -ItemType Directory -Path $nonEmptyWorkspace | Out-Null
    Set-Content -LiteralPath (Join-Path $nonEmptyWorkspace "existing.txt") -Value "occupied" -NoNewline
    Invoke-ExpectedFailure -Name "init_rejects_nonempty" -FilePath $binary -Arguments @(
        "workspace", "init", "--workspace", $nonEmptyWorkspace, "--json"
    ) -ExpectedExitCode 10

    Invoke-Gate -Name "broken_workspace_init" -FilePath $binary -Arguments @(
        "workspace", "init", "--workspace", $brokenWorkspace,
        "--name", "Broken Acceptance", "--json"
    )
    Remove-Item -LiteralPath (Join-Path $brokenWorkspace "evidence") -Recurse -Force
    Invoke-ExpectedFailure -Name "doctor_detects_missing_directory" -FilePath $binary -Arguments @(
        "workspace", "doctor", "--workspace", $brokenWorkspace, "--json"
    ) -ExpectedExitCode 20

    Invoke-Gate -Name "junction_workspace_init" -FilePath $binary -Arguments @(
        "workspace", "init", "--workspace", $junctionWorkspace,
        "--name", "Junction Acceptance", "--json"
    )
    New-Item -ItemType Directory -Path $junctionTarget | Out-Null
    $junctionPath = Join-Path $junctionWorkspace "targets"
    Remove-Item -LiteralPath $junctionPath -Recurse -Force
    New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget | Out-Null
    Invoke-ExpectedFailure -Name "doctor_rejects_junction" -FilePath $binary -Arguments @(
        "workspace", "doctor", "--workspace", $junctionWorkspace, "--json"
    ) -ExpectedExitCode 20

    Invoke-Gate -Name "acl_workspace_init" -FilePath $binary -Arguments @(
        "workspace", "init", "--workspace", $aclWorkspace,
        "--name", "ACL Acceptance", "--json"
    )
    $icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
    & $icacls $aclWorkspace /grant '*S-1-1-0:(OI)(CI)RX' /q | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not tamper the ACL fixture."
    }
    Invoke-ExpectedFailure -Name "doctor_rejects_broad_acl" -FilePath $binary -Arguments @(
        "workspace", "doctor", "--workspace", $aclWorkspace, "--json"
    ) -ExpectedExitCode 20

    $evidenceDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    $evidencePath = Join-Path $evidenceDirectory "nxb-151-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        platform = "windows"
        head_sha = $head
        generated_at = [DateTimeOffset]::UtcNow.ToString("O")
        toolchain = [ordered]@{
            rustc = $rustcVersion
            cargo = $cargoVersion
            rustfmt = $rustfmtVersion
            clippy = $clippyVersion
        }
        nxb_binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        security_checks = @(
            "protected current-user ACL on root, canonical directories and manifest",
            "junction/reparse-point rejection",
            "broad Everyone allow-ACE rejection"
        )
        results = $results
    }
    $json = $evidence | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText(
        $evidencePath,
        $json + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 single-binary Windows workspace validation passed."
    Write-Host "HEAD: $head"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    if ($junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        Remove-TestPath -Path $junctionPath
    }
    foreach ($path in @(
        $workspace,
        $nonEmptyWorkspace,
        $brokenWorkspace,
        $junctionWorkspace,
        $junctionTarget,
        $aclWorkspace
    )) {
        Remove-TestPath -Path $path
    }
}
