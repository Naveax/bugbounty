[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,

    [string]$PreviousSourceCommit = 'a8aef038449edbe1dbe1ecc6d57e160f82f44c7b'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$temporaryRoot = $null
$previousWorktree = $null
$certificate = $null
$rootStore = $null
$publisherStore = $null

function Get-OpenSslPath {
    $command = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSL-Win64\bin\openssl.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'OpenSSL-Win32\bin\openssl.exe')
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    throw 'OpenSSL with Ed25519 support is required for installer validation.'
}

function Convert-BytesToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Convert-HexToBytes {
    param([Parameter(Mandatory = $true)][string]$Hex)

    if ($Hex.Length % 2 -ne 0 -or $Hex -notmatch '^[0-9a-f]+$') {
        throw 'Hexadecimal value is invalid.'
    }
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return $bytes
}

function Assert-PowerShellScriptParses {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -ne 0) {
        $messages = ($errors | ForEach-Object { $_.Message }) -join '; '
        throw "PowerShell parser rejected $Path: $messages"
    }
}

function Invoke-InstallerJson {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $raw = (& $ScriptPath @Arguments | Out-String)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Installer script returned no JSON: $ScriptPath"
    }
    return $raw | ConvertFrom-Json
}

function Expect-InstallerFailure {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Arguments
    )

    $failed = $false
    try {
        [void](& $ScriptPath @Arguments | Out-String)
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw "Expected installer failure was not observed: $ScriptPath"
    }
}

function Open-NxbRenameBlocker {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Rename blocker target is missing: $Path"
    }
    return [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
}

function Assert-NxbInstalledRevision {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][uint64]$ExpectedSequence,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $statePath = Join-Path $Root 'install-state.json'
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "$Label state is missing: $statePath"
    }
    $state = [IO.File]::ReadAllText($statePath) | ConvertFrom-Json
    if ([uint64]$state.release_sequence -ne $ExpectedSequence -or
        $state.source_commit -ne $ExpectedCommit -or
        -not (Test-Path -LiteralPath (Join-Path $Root 'nxb.exe') -PathType Leaf)) {
        throw "$Label does not contain the expected signed revision."
    }
}

function Assert-NoInstallerResidue {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $parent = Split-Path -Parent $InstallRoot
    $leaf = Split-Path -Leaf $InstallRoot
    $patterns = @(
        "$leaf.stage.*",
        "$leaf.previous.backup.*",
        "$leaf.rollback-failed.*",
        "$leaf.rollback-restore.*",
        "$leaf.uninstall.*"
    )
    foreach ($pattern in $patterns) {
        $matches = @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like $pattern })
        if ($matches.Count -ne 0) {
            throw "Installer left transaction residue matching '$pattern'."
        }
    }
}

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$TargetDirectory,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $previousTarget = $env:CARGO_TARGET_DIR
    try {
        $env:CARGO_TARGET_DIR = $TargetDirectory
        Push-Location $WorkingDirectory
        try {
            & cargo @Arguments
            if ($LASTEXITCODE -ne 0) {
                throw "$Label failed with exit code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $env:CARGO_TARGET_DIR = $previousTarget
    }
}

function New-SignedReleasePackage {
    param(
        [Parameter(Mandatory = $true)][string]$SourceBinary,
        [Parameter(Mandatory = $true)][string]$SourceCommit,
        [Parameter(Mandatory = $true)][uint64]$ReleaseSequence,
        [Parameter(Mandatory = $true)][string]$PackageRoot,
        [Parameter(Mandatory = $true)]$Certificate,
        [Parameter(Mandatory = $true)][string]$OpenSsl,
        [Parameter(Mandatory = $true)][string]$PrivateKey,
        [Parameter(Mandatory = $true)][string]$RawPublicKeyHex
    )

    if (Test-Path -LiteralPath $PackageRoot) {
        Remove-Item -LiteralPath $PackageRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $PackageRoot | Out-Null

    $candidateBinary = Join-Path $PackageRoot 'nxb.exe'
    Copy-Item -LiteralPath $SourceBinary -Destination $candidateBinary
    $authenticode = Set-AuthenticodeSignature `
        -LiteralPath $candidateBinary `
        -Certificate $Certificate `
        -HashAlgorithm SHA256
    if ($authenticode.Status.ToString() -ne 'Valid') {
        throw "Could not create a valid Authenticode signature: $($authenticode.Status)"
    }

    $sbomPath = Join-Path $PackageRoot 'nxb.cdx.json'
    $sbom = [ordered]@{
        bomFormat = 'CycloneDX'
        specVersion = '1.6'
        components = @()
        metadata = [ordered]@{
            component = [ordered]@{
                type = 'application'
                name = 'NXBounty'
                version = '0.1.0'
                properties = @(
                    [ordered]@{ name = 'nxb:source_commit'; value = $SourceCommit },
                    [ordered]@{ name = 'nxb:release_sequence'; value = [string]$ReleaseSequence }
                )
            }
        }
    }
    [IO.File]::WriteAllText(
        $sbomPath,
        ($sbom | ConvertTo-Json -Depth 12 -Compress) + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $checksumsPath = Join-Path $PackageRoot 'SHA256SUMS'
    $binarySha = (Get-FileHash -LiteralPath $candidateBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $sbomSha = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        $checksumsPath,
        "$binarySha  nxb.exe`n$sbomSha  nxb.cdx.json`n",
        [Text.UTF8Encoding]::new($false)
    )

    $publicKeyPath = Join-Path $PackageRoot 'release-public-key.hex'
    [IO.File]::WriteAllText(
        $publicKeyPath,
        $RawPublicKeyHex + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    $manifestPath = Join-Path $PackageRoot 'nxb-release-manifest.json'
    $generatedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $sequenceText = [string]$ReleaseSequence
    & $candidateBinary release manifest-template `
        --release-id "v0.1.0-r$sequenceText-installer-validation" `
        --release-sequence $sequenceText `
        --source-commit $SourceCommit `
        --platform windows `
        --architecture x86-64 `
        --binary $candidateBinary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --generated-at $generatedAt `
        --output $manifestPath `
        --json | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Release manifest template generation failed for sequence $ReleaseSequence."
    }

    $manifest = [IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
    if ([uint64]$manifest.manifest.release_sequence -ne $ReleaseSequence -or
        $manifest.manifest.source_commit -ne $SourceCommit) {
        throw 'Generated manifest does not bind the requested revision.'
    }
    $payloadPath = Join-Path $PackageRoot 'signing-payload.bin'
    $signaturePath = Join-Path $PackageRoot 'release-signature.bin'
    [IO.File]::WriteAllBytes(
        $payloadPath,
        (Convert-HexToBytes $manifest.signing_payload_hex)
    )
    & $OpenSsl pkeyutl -sign -inkey $PrivateKey -rawin -in $payloadPath -out $signaturePath
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 signing failed.' }
    $signatureBytes = [IO.File]::ReadAllBytes($signaturePath)
    if ($signatureBytes.Length -ne 64) { throw 'Ed25519 signature length is invalid.' }

    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $manifestText = $manifestText.Replace(
        '"signature_hex": ""',
        ('"signature_hex": "' + (Convert-BytesToHex $signatureBytes) + '"')
    )
    [IO.File]::WriteAllText(
        $manifestPath,
        $manifestText,
        [Text.UTF8Encoding]::new($false)
    )
    Remove-Item -LiteralPath $payloadPath, $signaturePath -Force

    $verifiedRaw = (& $candidateBinary release verify-manifest `
        --document $manifestPath `
        --public-key $publicKeyPath `
        --binary $candidateBinary `
        --sbom $sbomPath `
        --checksums $checksumsPath `
        --json | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Pre-install signed release verification failed.' }
    $verified = $verifiedRaw | ConvertFrom-Json
    if ($verified.status -ne 'valid' -or
        [uint64]$verified.release_sequence -ne $ReleaseSequence -or
        $verified.source_commit -ne $SourceCommit) {
        throw 'Pre-install verifier returned an invalid revision binding.'
    }

    return [pscustomobject]@{
        Root = $PackageRoot
        BinarySha256 = $binarySha
        ManifestSha256 = $verified.manifest_sha256
        SourceCommit = $SourceCommit
        ReleaseSequence = $ReleaseSequence
    }
}

Push-Location $RepoRoot
try {
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve exact Git HEAD.'
    }
    $previous = (git rev-parse $PreviousSourceCommit).Trim()
    if ($LASTEXITCODE -ne 0 -or $previous -notmatch '^[0-9a-f]{40}$' -or $previous -eq $head) {
        throw 'PreviousSourceCommit must resolve to a distinct exact commit.'
    }
    git merge-base --is-ancestor $previous $head
    if ($LASTEXITCODE -ne 0) {
        throw 'PreviousSourceCommit must be an ancestor of the validation head.'
    }
    $status = git status --porcelain=v1
    if ($LASTEXITCODE -ne 0 -or $status) {
        throw 'Working tree must be clean before installer validation.'
    }

    $rustcVersion = (& rustc --version).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $rustcVersion.StartsWith('rustc 1.97.1 ')) {
        throw "Expected rustc 1.97.1, found '$rustcVersion'."
    }

    $scripts = @(
        (Join-Path $RepoRoot 'scripts\nxb-installer-common.ps1'),
        (Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\rollback-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\uninstall-nxb-windows.ps1'),
        (Join-Path $RepoRoot 'scripts\validate-nxb-151-installer-windows.ps1')
    )
    foreach ($script in $scripts) {
        Assert-PowerShellScriptParses $script
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-installer-validation-' + [Guid]::NewGuid().ToString('N'))
    $previousWorktree = Join-Path $temporaryRoot 'previous-source'
    $currentTarget = Join-Path $temporaryRoot 'current-target'
    $previousTarget = Join-Path $temporaryRoot 'previous-target'
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

    Invoke-Cargo $RepoRoot $currentTarget @('fmt', '--all', '--', '--check') 'cargo fmt'
    Invoke-Cargo $RepoRoot $currentTarget @('check', '-p', 'nxb-core', '--all-targets', '--all-features', '--locked') 'cargo check'
    Invoke-Cargo $RepoRoot $currentTarget @('clippy', '-p', 'nxb-core', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings') 'cargo clippy'
    Invoke-Cargo $RepoRoot $currentTarget @('test', '-p', 'nxb-core', '--all-features', '--locked', '--', '--test-threads=1') 'cargo test'
    Invoke-Cargo $RepoRoot $currentTarget @('build', '-p', 'nxb-core', '--bin', 'nxb', '--release', '--all-features', '--locked') 'current release build'

    git worktree add --detach $previousWorktree $previous
    if ($LASTEXITCODE -ne 0) { throw 'Could not create previous-source worktree.' }
    Invoke-Cargo $previousWorktree $previousTarget @('build', '-p', 'nxb-core', '--bin', 'nxb', '--release', '--all-features', '--locked') 'previous release build'

    $currentBinary = Join-Path $currentTarget 'release\nxb.exe'
    $previousBinary = Join-Path $previousTarget 'release\nxb.exe'
    foreach ($binary in @($currentBinary, $previousBinary)) {
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
            throw "Release binary is missing: $binary"
        }
    }

    $openssl = Get-OpenSslPath
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=NXBounty Installer Validation' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddDays(2)
    $rootStore = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $publisherStore = New-Object Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'CurrentUser')
    $rootStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $publisherStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add($certificate)
    $publisherStore.Add($certificate)

    $privateKey = Join-Path $temporaryRoot 'release-private-key.pem'
    $publicDer = Join-Path $temporaryRoot 'release-public-key.der'
    & $openssl genpkey -algorithm ED25519 -out $privateKey
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 private-key generation failed.' }
    & $openssl pkey -in $privateKey -pubout -outform DER -out $publicDer
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSL Ed25519 public-key export failed.' }
    $derBytes = [IO.File]::ReadAllBytes($publicDer)
    if ($derBytes.Length -lt 32) { throw 'Ed25519 SPKI output is too short.' }
    $rawPublicKey = New-Object byte[] 32
    [Array]::Copy($derBytes, $derBytes.Length - 32, $rawPublicKey, 0, 32)
    $rawPublicKeyHex = Convert-BytesToHex $rawPublicKey

    $previousPackage = New-SignedReleasePackage `
        $previousBinary $previous 1 `
        (Join-Path $temporaryRoot 'package-r1') `
        $certificate $openssl $privateKey $rawPublicKeyHex
    $currentPackage = New-SignedReleasePackage `
        $currentBinary $head 2 `
        (Join-Path $temporaryRoot 'package-r2') `
        $certificate $openssl $privateKey $rawPublicKeyHex
    $recoveryPackage = New-SignedReleasePackage `
        $previousBinary $previous 3 `
        (Join-Path $temporaryRoot 'package-r3-recovery') `
        $certificate $openssl $privateKey $rawPublicKeyHex

    $publisherThumbprint = $certificate.Thumbprint.ToLowerInvariant()
    $publicKeyPath = Join-Path $previousPackage.Root 'release-public-key.hex'
    $publicKeySha = (Get-FileHash -LiteralPath $publicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $installRoot = Join-Path $temporaryRoot 'install\NXBounty'
    $previousRoot = $installRoot + '.previous'
    $dataRoot = Join-Path $temporaryRoot 'data\NXBounty'
    $installScript = Join-Path $RepoRoot 'scripts\install-nxb-windows.ps1'
    $rollbackScript = Join-Path $RepoRoot 'scripts\rollback-nxb-windows.ps1'
    $baseArguments = @{
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
        AddToUserPath = $false
        CreateStartMenuShortcut = $false
    }

    $installPrevious = $baseArguments.Clone()
    $installPrevious.PackageDirectory = $previousPackage.Root
    $installed = Invoke-InstallerJson $installScript $installPrevious
    if ($installed.status -ne 'installed' -or [uint64]$installed.release_sequence -ne 1) {
        throw 'Previous revision clean installation failed.'
    }
    $idempotent = Invoke-InstallerJson $installScript $installPrevious
    if ($idempotent.status -ne 'already_installed' -or [uint64]$idempotent.release_sequence -ne 1) {
        throw 'Previous revision idempotent installation failed.'
    }

    $installCurrent = $baseArguments.Clone()
    $installCurrent.PackageDirectory = $currentPackage.Root
    $upgraded = Invoke-InstallerJson $installScript $installCurrent
    if ($upgraded.status -ne 'upgraded' -or
        [uint64]$upgraded.release_sequence -ne 2 -or
        $upgraded.rollback_available -ne $true) {
        throw 'Signed revision upgrade failed.'
    }
    Expect-InstallerFailure $installScript $installPrevious

    # Force the upgrade to fail after the existing previous slot has been backed up.
    # The state file remains readable, but its handle denies delete/rename sharing.
    $installRecovery = $baseArguments.Clone()
    $installRecovery.PackageDirectory = $recoveryPackage.Root
    $blocker = Open-NxbRenameBlocker (Join-Path $installRoot 'install-state.json')
    try {
        Expect-InstallerFailure $installScript $installRecovery
    }
    finally {
        $blocker.Dispose()
    }
    Assert-NxbInstalledRevision $installRoot 2 $head 'active release after failed upgrade'
    Assert-NxbInstalledRevision $previousRoot 1 $previous 'previous release after failed upgrade'
    Assert-NoInstallerResidue $installRoot

    # Force rollback metadata publication to fail after both release slots were swapped.
    $currentInstallState = Join-Path $dataRoot 'installer\current-install.json'
    $blocker = Open-NxbRenameBlocker $currentInstallState
    try {
        Expect-InstallerFailure $rollbackScript @{
            InstallRoot = $installRoot
            DataRoot = $dataRoot
            ExpectedPublisherThumbprint = $publisherThumbprint
            ExpectedReleasePublicKeySha256 = $publicKeySha
        }
    }
    finally {
        $blocker.Dispose()
    }
    Assert-NxbInstalledRevision $installRoot 2 $head 'active release after failed rollback'
    Assert-NxbInstalledRevision $previousRoot 1 $previous 'previous release after failed rollback'
    Assert-NoInstallerResidue $installRoot

    $rolledBack = Invoke-InstallerJson $rollbackScript @{
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
    }
    if ($rolledBack.status -ne 'rolled_back' -or
        [uint64]$rolledBack.from_release_sequence -ne 2 -or
        [uint64]$rolledBack.to_release_sequence -ne 1) {
        throw 'Signed revision rollback failed.'
    }

    $upgradedAgain = Invoke-InstallerJson $installScript $installCurrent
    if ($upgradedAgain.status -ne 'upgraded' -or [uint64]$upgradedAgain.release_sequence -ne 2) {
        throw 'Post-rollback signed revision upgrade failed.'
    }

    # Force uninstall to fail after the active root was moved to its tombstone.
    # Previous-slot validation can read this file, but the slot cannot be renamed.
    $uninstallScript = Join-Path $dataRoot 'installer\uninstall-nxb-windows.ps1'
    $blocker = Open-NxbRenameBlocker (Join-Path $previousRoot 'install-state.json')
    try {
        Expect-InstallerFailure $uninstallScript @{
            InstallRoot = $installRoot
            DataRoot = $dataRoot
            ExpectedPublisherThumbprint = $publisherThumbprint
            ExpectedReleasePublicKeySha256 = $publicKeySha
        }
    }
    finally {
        $blocker.Dispose()
    }
    Assert-NxbInstalledRevision $installRoot 2 $head 'active release after failed uninstall'
    Assert-NxbInstalledRevision $previousRoot 1 $previous 'previous release after failed uninstall'
    Assert-NoInstallerResidue $installRoot

    $tamperedPackageRoot = Join-Path $temporaryRoot 'tampered-package'
    Copy-Item -LiteralPath $currentPackage.Root -Destination $tamperedPackageRoot -Recurse
    $tamperedBinary = Join-Path $tamperedPackageRoot 'nxb.exe'
    $tamperedBytes = [IO.File]::ReadAllBytes($tamperedBinary)
    $tamperedBytes[$tamperedBytes.Length - 1] = $tamperedBytes[$tamperedBytes.Length - 1] -bxor 1
    [IO.File]::WriteAllBytes($tamperedBinary, $tamperedBytes)
    $tamperedArguments = $baseArguments.Clone()
    $tamperedArguments.PackageDirectory = $tamperedPackageRoot
    Expect-InstallerFailure $installScript $tamperedArguments

    $sentinel = Join-Path $dataRoot 'workspace-data-sentinel.txt'
    [IO.File]::WriteAllText($sentinel, 'preserve-me', [Text.UTF8Encoding]::new($false))
    $uninstalled = Invoke-InstallerJson $uninstallScript @{
        InstallRoot = $installRoot
        DataRoot = $dataRoot
        ExpectedPublisherThumbprint = $publisherThumbprint
        ExpectedReleasePublicKeySha256 = $publicKeySha
    }
    if ($uninstalled.status -ne 'uninstalled' -or
        $uninstalled.cleanup_complete -ne $true -or
        @($uninstalled.cleanup_warnings).Count -ne 0 -or
        $uninstalled.rollback_slot_deactivated -ne $true -or
        $uninstalled.data_preserved -ne $true -or
        (Test-Path -LiteralPath $installRoot) -or
        (Test-Path -LiteralPath $previousRoot) -or
        -not (Test-Path -LiteralPath $sentinel -PathType Leaf)) {
        throw 'Data-preserving uninstall result is invalid.'
    }
    Assert-NoInstallerResidue $installRoot

    $validationDirectory = Join-Path $RepoRoot 'target\nxb-validation'
    New-Item -ItemType Directory -Path $validationDirectory -Force | Out-Null
    $evidencePath = Join-Path $validationDirectory "nxb-151-installer-windows-$head.json"
    $evidence = [ordered]@{
        schema_version = 2
        milestone = 'NXB-151'
        gate = 'windows_installer_lifecycle'
        platform = 'windows'
        head_sha = $head
        previous_source_commit = $previous
        rustc = $rustcVersion
        publisher_thumbprint = $publisherThumbprint
        release_public_key_sha256 = $publicKeySha
        releases = @(
            [ordered]@{
                source_commit = $previousPackage.SourceCommit
                release_sequence = $previousPackage.ReleaseSequence
                binary_sha256 = $previousPackage.BinarySha256
                manifest_sha256 = $previousPackage.ManifestSha256
            },
            [ordered]@{
                source_commit = $currentPackage.SourceCommit
                release_sequence = $currentPackage.ReleaseSequence
                binary_sha256 = $currentPackage.BinarySha256
                manifest_sha256 = $currentPackage.ManifestSha256
            }
        )
        checks = [ordered]@{
            powershell_parser = 'passed'
            authenticode_bootstrap = 'passed'
            ed25519_manifest_v2 = 'passed'
            clean_install_sequence_1 = 'passed'
            idempotent_install = 'passed'
            upgrade_sequence_1_to_2 = 'passed'
            downgrade_replay_rejection = 'passed'
            failed_upgrade_state_restoration = 'passed'
            failed_rollback_slot_restoration = 'passed'
            rollback_sequence_2_to_1 = 'passed'
            post_rollback_upgrade = 'passed'
            failed_uninstall_deactivation_restoration = 'passed'
            tampered_binary_rejection = 'passed'
            data_preserving_uninstall = 'passed'
            transaction_residue_cleanup = 'passed'
            network_activity = 'none'
        }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 12) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host 'NXB-151 Windows installer lifecycle validation passed.'
    Write-Host "HEAD: $head"
    Write-Host "Previous source: $previous"
    Write-Host "Evidence: $evidencePath"
}
finally {
    Pop-Location
    if ($null -ne $publisherStore -and $null -ne $certificate) {
        try { $publisherStore.Remove($certificate) } catch { }
    }
    if ($null -ne $rootStore -and $null -ne $certificate) {
        try { $rootStore.Remove($certificate) } catch { }
    }
    if ($null -ne $publisherStore) { $publisherStore.Dispose() }
    if ($null -ne $rootStore) { $rootStore.Dispose() }
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath ("Cert:\CurrentUser\My\{0}" -f $certificate.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $previousWorktree -and (Test-Path -LiteralPath $previousWorktree)) {
        git -C $RepoRoot worktree remove --force $previousWorktree 2>$null
        if ($LASTEXITCODE -ne 0) {
            Remove-Item -LiteralPath $previousWorktree -Recurse -Force -ErrorAction SilentlyContinue
            git -C $RepoRoot worktree prune 2>$null
        }
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
