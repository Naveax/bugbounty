[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$workspace = $null
$outputDirectory = $null

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )

    $errorPath = Join-Path $outputDirectory "$Name.err"
    $raw = (& $FilePath @Arguments 2>$errorPath | Out-String)
    $exitCode = $LASTEXITCODE
    [IO.File]::WriteAllText(
        (Join-Path $outputDirectory "$Name.json"),
        $raw,
        [Text.UTF8Encoding]::new($false)
    )
    if ($exitCode -ne 0) {
        $errorText = if (Test-Path -LiteralPath $errorPath) {
            Get-Content -LiteralPath $errorPath -Raw
        } else {
            ""
        }
        throw "Command '$FilePath $($Arguments -join ' ')' returned $exitCode. $errorText"
    }
    return ($raw | ConvertFrom-Json -Depth 64)
}

function Assert-NativeExit {
    param(
        [Parameter(Mandatory)] [int]$Expected,
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )

    $stdoutPath = Join-Path $outputDirectory "$Name.out"
    $stderrPath = Join-Path $outputDirectory "$Name.err"
    & $FilePath @Arguments 1>$stdoutPath 2>$stderrPath
    $actual = $LASTEXITCODE
    if ($actual -ne $Expected) {
        $errorText = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw
        } else {
            ""
        }
        throw "Command '$Name' returned $actual; expected $Expected. $errorText"
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
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed." }

    $nxb = Join-Path $RepoRoot "target\debug\nxb.exe"
    if (-not (Test-Path -LiteralPath $nxb -PathType Leaf)) {
        throw "nxb.exe is missing."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $workspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-target-$nonce"
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-target-output-$nonce"
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null

    $policy = Join-Path $outputDirectory "target-policy.toml"
    $authorization = Join-Path $outputDirectory "authorization.txt"
    $policyText = @'
schema_version = 1

[program]
name = "Example Program"
platform = "hackerone"
policy_url = "https://hackerone.com/example"

[scope]
include_hosts = ["example.org"]
exclude_hosts = []
allowed_schemes = ["https"]
allowed_methods = ["GET", "HEAD", "OPTIONS"]
allow_subdomains = false

[automation]
active_testing = false
credential_bruteforce = false
destructive_testing = false
oob_callbacks = false
max_requests_per_second = 1.0
max_concurrency = 1
max_total_requests = 10

[authorization]
confirmed = true
researcher = "acceptance-researcher"
policy_snapshot_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
expires_at = 2099-01-01T00:00:00Z
'@
    [IO.File]::WriteAllText($policy, $policyText + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        $authorization,
        "Bearer secret-that-must-never-be-persisted" + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    $initialized = Invoke-NativeJson -FilePath $nxb -Name "init" -Arguments @(
        "workspace", "init", "--workspace", $workspace,
        "--name", "Target Windows Acceptance", "--json"
    )
    if ($initialized.status -ne "initialized") { throw "Workspace initialization failed." }

    $bindingArguments = @(
        "--authorization-reference", "hackerone/program/example#scope-2026",
        "--authorization-document", $authorization,
        "--policy", $policy
    )
    $createArguments = @(
        "target", "create", "--workspace", $workspace,
        "--id", "example-app", "--name", "Example App",
        "--origin", "https://example.org",
        "--include-path", "/api",
        "--exclude-path", "/api/logout"
    ) + $bindingArguments + @("--json")
    $created = Invoke-NativeJson -FilePath $nxb -Name "create" -Arguments $createArguments
    if ($created.status -ne "active" -or
        $created.origin -ne "https://example.org" -or
        $created.program.platform -ne "hackerone" -or
        $created.authorization_reference -ne "hackerone/program/example#scope-2026" -or
        $created.network_activity -ne "none") {
        throw "Created authorization-bound target output is invalid."
    }
    if (($created.allowed_methods -join ',') -ne "GET,HEAD,OPTIONS" -or
        $created.authorization_sha256.Length -ne 64 -or
        $created.policy_sha256.Length -ne 64 -or
        $created.identity_sha256.Length -ne 64) {
        throw "Created target digests or read-only methods are invalid."
    }

    $validated = Invoke-NativeJson -FilePath $nxb -Name "validate" -Arguments @(
        "target", "validate", "--workspace", $workspace,
        "--id", "example-app",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    )
    if ($validated.validation.status -ne "valid" -or
        $validated.validation.authorization_sha256 -ne $created.authorization_sha256 -or
        $validated.validation.policy_sha256 -ne $created.policy_sha256) {
        throw "Target source validation output is invalid."
    }

    $listed = Invoke-NativeJson -FilePath $nxb -Name "list" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    if ($listed.count -ne 1 -or $listed.network_activity -ne "none") {
        throw "Target list output is invalid."
    }

    $shown = Invoke-NativeJson -FilePath $nxb -Name "show" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    if ($shown.target_id -ne "example-app" -or
        ($shown.include_paths -join ',') -ne "/api" -or
        ($shown.exclude_paths -join ',') -ne "/api/logout") {
        throw "Target show output is invalid."
    }

    $profile = Join-Path $workspace "targets\example-app.json"
    $profileText = Get-Content -LiteralPath $profile -Raw
    if ($profileText.Contains("secret-that-must-never-be-persisted") -or
        $profileText.Contains($policy) -or
        $profileText.Contains($authorization)) {
        throw "Target profile persisted source secret bytes or local source paths."
    }

    $invalidOrigins = @(
        "http://example.org",
        "https://user@example.org",
        "https://127.0.0.1",
        "https://service.internal",
        "https://*.example.org"
    )
    for ($index = 0; $index -lt $invalidOrigins.Count; $index++) {
        $invalidOriginArguments = @(
            "target", "create", "--workspace", $workspace,
            "--id", "invalid-$index", "--name", "Invalid Origin",
            "--origin", $invalidOrigins[$index]
        ) + $bindingArguments + @("--json")
        Assert-NativeExit -Expected 50 -FilePath $nxb -Name "invalid-origin-$index" -Arguments $invalidOriginArguments
    }
    $invalidPathArguments = @(
        "target", "create", "--workspace", $workspace,
        "--id", "invalid-path", "--name", "Invalid Path",
        "--origin", "https://example.org",
        "--include-path", "/api%2fadmin"
    ) + $bindingArguments + @("--json")
    Assert-NativeExit -Expected 50 -FilePath $nxb -Name "invalid-path" -Arguments $invalidPathArguments
    Assert-NativeExit -Expected 50 -FilePath $nxb -Name "invalid-reference" -Arguments @(
        "target", "create", "--workspace", $workspace,
        "--id", "invalid-reference", "--name", "Invalid Reference",
        "--origin", "https://example.org",
        "--authorization-reference", "https://example.org/scope?token=secret",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    )

    $profileBackup = Join-Path $outputDirectory "profile.original"
    [IO.File]::WriteAllBytes($profileBackup, [IO.File]::ReadAllBytes($profile))
    $profileValue = Get-Content -LiteralPath $profile -Raw | ConvertFrom-Json -Depth 64
    $profileValue.name = "Tampered Target"
    [IO.File]::WriteAllText(
        $profile,
        ($profileValue | ConvertTo-Json -Depth 64) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "profile-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    [IO.File]::WriteAllBytes($profile, [IO.File]::ReadAllBytes($profileBackup))

    $authorizationBackup = Join-Path $outputDirectory "authorization.original"
    [IO.File]::WriteAllBytes($authorizationBackup, [IO.File]::ReadAllBytes($authorization))
    [IO.File]::WriteAllText(
        $authorization,
        "different authorization" + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Assert-NativeExit -Expected 54 -FilePath $nxb -Name "authorization-drift" -Arguments @(
        "target", "validate", "--workspace", $workspace,
        "--id", "example-app",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    )
    [IO.File]::WriteAllBytes($authorization, [IO.File]::ReadAllBytes($authorizationBackup))

    $disabled = Invoke-NativeJson -FilePath $nxb -Name "disable" -Arguments @(
        "target", "disable", "--workspace", $workspace,
        "--id", "example-app", "--reason", "operator-hold", "--json"
    )
    if ($disabled.status -ne "disabled" -or $disabled.disabled_reason -ne "operator_hold") {
        throw "Target disable output is invalid."
    }
    $active = Invoke-NativeJson -FilePath $nxb -Name "active" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    $all = Invoke-NativeJson -FilePath $nxb -Name "all" -Arguments @(
        "target", "list", "--workspace", $workspace,
        "--include-disabled", "--json"
    )
    if ($active.count -ne 0 -or $all.count -ne 1 -or $all.targets[0].status -ne "disabled") {
        throw "Disabled-target list behavior is invalid."
    }

    $receipt = Join-Path $workspace "targets\example-app.disabled.json"
    $receiptBackup = Join-Path $outputDirectory "receipt.original"
    [IO.File]::WriteAllBytes($receiptBackup, [IO.File]::ReadAllBytes($receipt))
    $receiptValue = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json -Depth 64
    $receiptValue.profile_sha256 = [string]::new([char]'0', 64)
    [IO.File]::WriteAllText(
        $receipt,
        ($receiptValue | ConvertTo-Json -Depth 64) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "receipt-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    [IO.File]::WriteAllBytes($receipt, [IO.File]::ReadAllBytes($receiptBackup))

    $systemRoot = [Environment]::GetEnvironmentVariable("SystemRoot")
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { throw "SystemRoot is unavailable." }
    $icacls = Join-Path $systemRoot "System32\icacls.exe"
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) { throw "icacls.exe is missing." }
    & $icacls $profile "/grant" "*S-1-1-0:(R)" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not inject broad target-profile ACL." }
    Assert-NativeExit -Expected 52 -FilePath $nxb -Name "profile-acl-tamper" -Arguments @(
        "target", "show", "--workspace", $workspace,
        "--id", "example-app", "--json"
    )
    & $icacls $profile "/remove:g" "*S-1-1-0" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not remove broad target-profile ACL." }

    $migrationActive = Join-Path $workspace "state\migration-active.json"
    [IO.File]::WriteAllText($migrationActive, "{}`n", [Text.UTF8Encoding]::new($false))
    Assert-NativeExit -Expected 51 -FilePath $nxb -Name "pending-migration" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    Remove-Item -LiteralPath $migrationActive -Force
    [void](Invoke-NativeJson -FilePath $nxb -Name "restored" -Arguments @(
        "target", "validate", "--workspace", $workspace,
        "--id", "example-app",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    ))

    $validationDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-target-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        gate = "authorization_bound_target_profiles"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        binary_sha256 = (Get-FileHash -LiteralPath $nxb -Algorithm SHA256).Hash.ToLowerInvariant()
        checks = [ordered]@{
            create_validate_list_show_disable = "passed"
            authorization_and_policy_binding = "passed"
            secret_and_source_path_non_persistence = "passed"
            origin_path_and_reference_rejection = "passed"
            identity_tamper_rejection = "passed"
            source_digest_drift_exit_54 = "passed"
            receipt_tamper_rejection = "passed"
            broad_acl_rejection = "passed"
            pending_migration_exit_51 = "passed"
            network_activity = "none"
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 authorization-bound target Windows validation passed."
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
