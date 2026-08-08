[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$workspace = $null
$outputDirectory = $null

function Invoke-NativeText {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )
    $stderr = Join-Path $outputDirectory "$Name.err"
    $text = (& $FilePath @Arguments 2>$stderr | Out-String)
    if ($LASTEXITCODE -ne 0) {
        $errorText = if (Test-Path -LiteralPath $stderr) {
            Get-Content -LiteralPath $stderr -Raw
        } else { "" }
        throw "Command '$Name' failed with exit code $LASTEXITCODE. $errorText"
    }
    [IO.File]::WriteAllText(
        (Join-Path $outputDirectory "$Name.txt"),
        $text,
        [Text.UTF8Encoding]::new($false)
    )
    return $text
}

function Invoke-NativeJson {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$Name
    )
    $text = Invoke-NativeText -FilePath $FilePath -Arguments $Arguments -Name $Name
    return ($text | ConvertFrom-Json -Depth 64)
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
    $policy = Join-Path $RepoRoot "fixtures\nxb-151\synthetic-policy.toml"
    $authorization = Join-Path $RepoRoot "fixtures\nxb-151\synthetic-authorization.txt"
    if (-not (Test-Path -LiteralPath $nxb -PathType Leaf) -or
        -not (Test-Path -LiteralPath $policy -PathType Leaf) -or
        -not (Test-Path -LiteralPath $authorization -PathType Leaf)) {
        throw "Synthetic acceptance inputs are missing."
    }

    $nonce = [Guid]::NewGuid().ToString("N")
    $workspace = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-synthetic-$nonce"
    $outputDirectory = Join-Path ([IO.Path]::GetTempPath()) "nxb-151-synthetic-output-$nonce"
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    $scanOutput = Join-Path $workspace "reports\synthetic-run"
    $demoReceipt = Join-Path $workspace "reports\demo-receipt.json"
    $now = "2026-08-05T12:00:00Z"

    $initialized = Invoke-NativeJson -FilePath $nxb -Name "init" -Arguments @(
        "workspace", "init", "--workspace", $workspace,
        "--name", "NXB Synthetic Product", "--json"
    )
    $doctorBefore = Invoke-NativeJson -FilePath $nxb -Name "doctor-before" -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    )
    $target = Invoke-NativeJson -FilePath $nxb -Name "target" -Arguments @(
        "target", "create", "--workspace", $workspace,
        "--id", "synthetic-example", "--name", "Synthetic Example",
        "--origin", "https://example.org",
        "--include-path", "/", "--exclude-path", "/logout",
        "--authorization-reference", "local_fixture/nxb-151#synthetic",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    )
    $targetValidation = Invoke-NativeJson -FilePath $nxb -Name "target-validate" -Arguments @(
        "target", "validate", "--workspace", $workspace,
        "--id", "synthetic-example",
        "--authorization-document", $authorization,
        "--policy", $policy,
        "--json"
    )
    $targetList = Invoke-NativeJson -FilePath $nxb -Name "target-list" -Arguments @(
        "target", "list", "--workspace", $workspace, "--json"
    )
    $policyText = Invoke-NativeText -FilePath $nxb -Name "policy" -Arguments @(
        "validate-policy", "--path", $policy, "--now", $now
    )
    $scanText = Invoke-NativeText -FilePath $nxb -Name "scan" -Arguments @(
        "scan", "--program", $policy,
        "--target", "https://example.org/",
        "--output-directory", $scanOutput,
        "--run-id", "synthetic-run-001",
        "--maximum-depth", "1",
        "--maximum-endpoints", "16",
        "--maximum-requests", "8",
        "--dry-run", "true",
        "--now", $now
    )
    [void](Invoke-NativeText -FilePath $nxb -Name "demo" -Arguments @(
        "demo-run", "--output", $demoReceipt
    ))
    $verifyDemoText = Invoke-NativeText -FilePath $nxb -Name "verify-demo" -Arguments @(
        "verify-demo", $demoReceipt
    )
    $doctorAfter = Invoke-NativeJson -FilePath $nxb -Name "doctor-after" -Arguments @(
        "workspace", "doctor", "--workspace", $workspace, "--json"
    )
    $workspaceStatus = Invoke-NativeJson -FilePath $nxb -Name "status" -Arguments @(
        "workspace", "status", "--workspace", $workspace, "--json"
    )
    $systemText = Invoke-NativeText -FilePath $nxb -Name "system-status" -Arguments @(
        "system-status"
    )

    $targetProfile = Join-Path $workspace "targets\synthetic-example.json"
    $planPath = Join-Path $scanOutput "scan-plan.json"
    $reportPath = Join-Path $scanOutput "report.json"
    $reportMarkdown = Join-Path $scanOutput "report.md"
    $hackerOneDraft = Join-Path $scanOutput "hackerone-draft.md"
    $manifestPath = Join-Path $scanOutput "manifest.json"
    foreach ($path in @(
        $targetProfile,
        $planPath,
        $reportPath,
        $reportMarkdown,
        $hackerOneDraft,
        $manifestPath,
        $demoReceipt
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Missing synthetic artifact: $path"
        }
    }

    $profileText = Get-Content -LiteralPath $targetProfile -Raw
    if ($profileText.Contains((Get-Content -LiteralPath $authorization -Raw)) -or
        $profileText.Contains((Get-Content -LiteralPath $policy -Raw)) -or
        $profileText.Contains($authorization) -or
        $profileText.Contains($policy)) {
        throw "Synthetic target profile persisted source bytes or local source paths."
    }

    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json -Depth 64
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 64
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -Depth 64

    if ($initialized.status -ne "initialized" -or
        $doctorBefore.status -ne "healthy" -or
        $target.status -ne "active" -or
        $target.origin -ne "https://example.org" -or
        $target.network_activity -ne "none" -or
        $target.program.platform -ne "local_fixture" -or
        $target.authorization_reference -ne "local_fixture/nxb-151#synthetic" -or
        $target.authorization_sha256.Length -ne 64 -or
        $target.policy_sha256.Length -ne 64 -or
        $target.identity_sha256.Length -ne 64 -or
        $targetValidation.validation.status -ne "valid" -or
        $targetValidation.validation.authorization_sha256 -ne $target.authorization_sha256 -or
        $targetValidation.validation.policy_sha256 -ne $target.policy_sha256 -or
        $targetList.count -ne 1 -or
        $targetList.network_activity -ne "none") {
        throw "Workspace or authorization-bound target synthetic state is invalid."
    }
    if ($plan.version -ne 1 -or
        $plan.run_id -ne "synthetic-run-001" -or
        $plan.target_url -ne "https://example.org/" -or
        -not $plan.dry_run -or
        $plan.network_activity -ne "none" -or
        $plan.scheduler.issued -ne 0) {
        throw "Networkless scan plan is invalid."
    }
    if ($report.run_id -ne "synthetic-run-001" -or
        $report.automatic_submission -ne $false -or
        @($report.findings).Count -ne 0) {
        throw "Synthetic report boundary is invalid."
    }
    $manifestNames = @($manifest.entries.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @("hackerone-draft.md", "report.json", "report.md")
    if ($manifest.version -ne 1 -or
        (Compare-Object $manifestNames $expectedNames)) {
        throw "Synthetic export manifest is invalid."
    }
    if ($doctorAfter.status -ne "healthy" -or $workspaceStatus.status -ne "ready") {
        throw "Final workspace state is not healthy and ready."
    }
    if ($policyText -notmatch '(?m)^policy: valid$' -or
        $scanText -notmatch '(?m)^network_activity: none$' -or
        $verifyDemoText -notmatch '(?m)^demo_receipt: valid$' -or
        $systemText -notmatch '(?m)^status: contract-complete$') {
        throw "Synthetic command text contract is invalid."
    }
    $draftText = Get-Content -LiteralPath $hackerOneDraft -Raw
    if ($draftText -notmatch 'NXB does not submit reports automatically' -or
        $draftText -notmatch 'No candidate findings are available for submission') {
        throw "Manual HackerOne draft boundary is invalid."
    }

    $validationDirectory = Join-Path $RepoRoot "target\nxb-validation"
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-synthetic-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 1
        milestone = "NXB-151"
        gate = "synthetic_product_flow"
        platform = "windows"
        head_sha = $head
        rustc = $rustcVersion
        binary_sha256 = (Get-FileHash -LiteralPath $nxb -Algorithm SHA256).Hash.ToLowerInvariant()
        artifacts = [ordered]@{
            target_profile_sha256 = (Get-FileHash -LiteralPath $targetProfile -Algorithm SHA256).Hash.ToLowerInvariant()
            scan_plan_sha256 = (Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
            report_sha256 = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant()
            manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
            demo_receipt_sha256 = (Get-FileHash -LiteralPath $demoReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        checks = [ordered]@{
            workspace = "passed"
            authorization_bound_target_profile = "passed"
            target_source_validation = "passed"
            policy_validation = "passed"
            networkless_scan = "passed"
            manual_report_bundle = "passed"
            demo_receipt = "passed"
            final_doctor_status = "passed"
            network_activity = "none"
            automatic_submission = $false
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "NXB-151 synthetic Windows validation passed."
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
