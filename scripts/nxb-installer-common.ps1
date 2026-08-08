Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:NxbInstallerSchemaVersion = 2
$script:NxbPackageFileNames = @(
    'nxb.exe',
    'nxb.cdx.json',
    'SHA256SUMS',
    'nxb-release-manifest.json',
    'release-public-key.hex'
)
$script:NxbInstalledFileNames = @(
    'nxb.exe',
    'nxb.cdx.json',
    'SHA256SUMS',
    'nxb-release-manifest.json',
    'release-public-key.hex',
    'install-state.json'
)

function Get-NxbCanonicalPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        $Path.Contains([string][char]0) -or
        $Path.Contains("`r") -or
        $Path.Contains("`n")) {
        throw 'Path is empty or contains forbidden control characters.'
    }
    return [IO.Path]::GetFullPath($Path)
}

function Test-NxbPathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $candidatePath = (Get-NxbCanonicalPath $Candidate).TrimEnd('\')
    $parentPath = (Get-NxbCanonicalPath $Parent).TrimEnd('\')
    return $candidatePath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith(
            $parentPath + '\',
            [StringComparison]::OrdinalIgnoreCase
        )
}

function Assert-NxbNoReparseChain {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-NxbCanonicalPath $Path
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label has no filesystem root."
    }
    $relative = $fullPath.Substring($root.Length)
    $segments = $relative.Split(
        [char[]]@('\'),
        [StringSplitOptions]::RemoveEmptyEntries
    )
    $current = $root.TrimEnd('\')
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        if (-not (Test-Path -LiteralPath $current)) {
            continue
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a symbolic link, junction or reparse point: $current"
        }
    }
}

function Assert-NxbManagedRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = Get-NxbCanonicalPath $Path
    $driveRoot = ([IO.Path]::GetPathRoot($fullPath)).TrimEnd('\')
    if ($fullPath.TrimEnd('\').Equals($driveRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must not be a drive root."
    }
    $windowsRoot = ([Environment]::GetFolderPath('Windows')).TrimEnd('\')
    if (-not [string]::IsNullOrWhiteSpace($windowsRoot) -and
        (Test-NxbPathWithin $fullPath $windowsRoot)) {
        throw "$Label must not be inside the Windows directory."
    }
    Assert-NxbNoReparseChain $fullPath $Label
    return $fullPath
}

function Assert-NxbRegularFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [long]$MaximumBytes = 536870912
    )

    Assert-NxbNoReparseChain $Path $Label
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label is missing or is not a regular file: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or
        $item.Length -gt $MaximumBytes) {
        throw "$Label size, type or indirection state is outside the supported boundary."
    }
}

function Assert-NxbExactDirectoryEntries {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-NxbNoReparseChain $Directory $Label
    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "$Label is missing: $Directory"
    }
    $entries = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($entries.Count -ne $ExpectedNames.Count) {
        throw "$Label contains an unexpected number of entries."
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not ($ExpectedNames -contains $entry.Name)) {
            throw "$Label contains an unsupported entry: $($entry.Name)"
        }
    }
}

function Get-NxbPackagePaths {
    param([Parameter(Mandatory = $true)][string]$PackageDirectory)

    $root = Get-NxbCanonicalPath $PackageDirectory
    Assert-NxbExactDirectoryEntries $root $script:NxbPackageFileNames 'package directory'
    $paths = [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'nxb.exe'
        Sbom = Join-Path $root 'nxb.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'nxb-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
    }
    Assert-NxbRegularFile $paths.Binary 'candidate nxb.exe'
    Assert-NxbRegularFile $paths.Sbom 'candidate CycloneDX SBOM' 33554432
    Assert-NxbRegularFile $paths.Checksums 'candidate checksum manifest' 1048576
    Assert-NxbRegularFile $paths.Manifest 'candidate signed release manifest' 65536
    Assert-NxbRegularFile $paths.PublicKey 'candidate release public key' 4096
    return $paths
}

function Normalize-NxbHex {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $normalized = $Value.Replace(' ', '').ToLowerInvariant()
    if ($normalized.Length -ne $Length -or $normalized -notmatch '^[0-9a-f]+$') {
        throw "$Label must contain exactly $Length hexadecimal characters."
    }
    return $normalized
}

function Assert-NxbReleaseSequence {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        $sequence = [uint64]$Value
    }
    catch {
        throw "$Label must be an unsigned integer."
    }
    if ($sequence -eq 0 -or $sequence -gt [uint64][int64]::MaxValue) {
        throw "$Label must be between 1 and 9223372036854775807."
    }
    return $sequence
}

function Assert-NxbAuthenticode {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherThumbprint
    )

    $expected = Normalize-NxbHex $ExpectedPublisherThumbprint 40 'publisher certificate thumbprint'
    $signature = Get-AuthenticodeSignature -LiteralPath $BinaryPath
    if ($signature.Status.ToString() -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $BinaryPath with status $($signature.Status)."
    }
    $actual = Normalize-NxbHex $signature.SignerCertificate.Thumbprint 40 'actual publisher certificate thumbprint'
    if ($actual -ne $expected) {
        throw 'Authenticode signer does not match the pinned publisher certificate.'
    }
    return $actual
}

function Assert-NxbReleasePublicKey {
    param(
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    $expected = Normalize-NxbHex $ExpectedSha256 64 'release public-key SHA-256'
    $actual = (Get-FileHash -LiteralPath $PublicKeyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw 'Release public key does not match the pinned SHA-256 trust anchor.'
    }
    $keyText = [IO.File]::ReadAllText($PublicKeyPath).Trim()
    [void](Normalize-NxbHex $keyText 64 'release public key')
    return $actual
}

function Invoke-NxbReleaseVerification {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$PublicKeyPath,
        [Parameter(Mandatory = $true)][string]$SbomPath,
        [Parameter(Mandatory = $true)][string]$ChecksumsPath
    )

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('nxb-verify-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Protect-NxbDirectoryAcl $temporaryRoot
    $stdoutPath = Join-Path $temporaryRoot 'stdout.json'
    $stderrPath = Join-Path $temporaryRoot 'stderr.json'
    $arguments = @(
        'release', 'verify-manifest',
        '--document', $ManifestPath,
        '--public-key', $PublicKeyPath,
        '--binary', $BinaryPath,
        '--sbom', $SbomPath,
        '--checksums', $ChecksumsPath,
        '--json'
    )
    try {
        & $BinaryPath @arguments 1>$stdoutPath 2>$stderrPath
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $errorText = if (Test-Path -LiteralPath $stderrPath) {
                [IO.File]::ReadAllText($stderrPath)
            } else {
                ''
            }
            throw "Signed release verification failed with exit code $exitCode. $errorText"
        }
        $value = [IO.File]::ReadAllText($stdoutPath) | ConvertFrom-Json
        if ($value.status -ne 'valid' -or
            $value.network_activity -ne 'none' -or
            (Assert-NxbReleaseSequence $value.release_sequence 'verified release sequence') -ne [uint64]$value.release_sequence) {
            throw 'Signed release verifier returned an invalid success document.'
        }
        return $value
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-NxbManifestDocument {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $value = [IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json
    if ($null -eq $value.manifest -or
        $value.manifest.manifest_version -ne 2 -or
        $value.manifest.product -ne 'NXBounty' -or
        $value.manifest.platform -ne 'windows' -or
        $value.manifest.architecture -ne 'x86_64' -or
        $value.manifest.binary.file_name -ne 'nxb.exe') {
        throw 'Signed release manifest is not a supported Windows x86_64 package.'
    }
    [void](Assert-NxbReleaseSequence $value.manifest.release_sequence 'manifest release sequence')
    return $value
}

function Compare-NxbVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $pattern = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
    $leftMatch = [regex]::Match($Left, $pattern)
    $rightMatch = [regex]::Match($Right, $pattern)
    if (-not $leftMatch.Success -or -not $rightMatch.Success) {
        throw 'Installer currently accepts stable three-component semantic versions only.'
    }
    for ($index = 1; $index -le 3; $index++) {
        $leftValue = [uint64]$leftMatch.Groups[$index].Value
        $rightValue = [uint64]$rightMatch.Groups[$index].Value
        if ($leftValue -lt $rightValue) { return -1 }
        if ($leftValue -gt $rightValue) { return 1 }
    }
    return 0
}

function Compare-NxbReleaseOrder {
    param(
        [Parameter(Mandatory = $true)][string]$LeftVersion,
        [Parameter(Mandatory = $true)]$LeftSequence,
        [Parameter(Mandatory = $true)][string]$RightVersion,
        [Parameter(Mandatory = $true)]$RightSequence
    )

    $versionComparison = Compare-NxbVersion $LeftVersion $RightVersion
    if ($versionComparison -ne 0) {
        return $versionComparison
    }
    $left = Assert-NxbReleaseSequence $LeftSequence 'left release sequence'
    $right = Assert-NxbReleaseSequence $RightSequence 'right release sequence'
    if ($left -lt $right) { return -1 }
    if ($left -gt $right) { return 1 }
    return 0
}

function Protect-NxbDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Cannot protect missing directory: $Path"
    }
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    if (-not (Test-Path -LiteralPath $icacls -PathType Leaf)) {
        throw 'icacls.exe is unavailable.'
    }
    & $icacls $Path '/inheritance:r' '/grant:r' `
        ('*{0}:(OI)(CI)F' -f $userSid) `
        '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not apply protected ACL to $Path"
    }
}

function Open-NxbInstallerLock {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $parent = Split-Path -Parent (Get-NxbCanonicalPath $InstallRoot)
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Assert-NxbNoReparseChain $parent 'install parent'
    return [IO.File]::Open(
        (Join-Path $parent '.nxbounty-install.lock'),
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None
    )
}

function Add-NxbUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-NxbCanonicalPath $InstallRoot).TrimEnd('\')
    $raw = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = if ([string]::IsNullOrWhiteSpace($raw)) {
        @()
    } else {
        @($raw.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    foreach ($entry in $entries) {
        if ($entry.Trim().TrimEnd('\').Equals($canonical, [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    [Environment]::SetEnvironmentVariable('Path', (@($entries + $canonical) -join ';'), 'User')
    return $true
}

function Remove-NxbUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $canonical = (Get-NxbCanonicalPath $InstallRoot).TrimEnd('\')
    $raw = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ([string]::IsNullOrWhiteSpace($raw)) { return $false }
    $entries = @($raw.Split(';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $filtered = @($entries | Where-Object {
        -not $_.Trim().TrimEnd('\').Equals($canonical, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($filtered.Count -eq $entries.Count) { return $false }
    [Environment]::SetEnvironmentVariable('Path', ($filtered -join ';'), 'User')
    return $true
}

function Set-NxbStartMenuShortcut {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'NXBounty'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $shortcutPath = Join-Path $directory 'NXBounty.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $InstallRoot 'nxb.exe'
    $shortcut.Arguments = '--help'
    $shortcut.WorkingDirectory = $InstallRoot
    $shortcut.Description = 'NXBounty command-line security research tool'
    $shortcut.Save()
    return $shortcutPath
}

function Remove-NxbStartMenuShortcut {
    $directory = Join-Path ([Environment]::GetFolderPath('Programs')) 'NXBounty'
    if (Test-Path -LiteralPath $directory) {
        Remove-Item -LiteralPath $directory -Recurse -Force
        return $true
    }
    return $false
}

function Write-NxbJsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-NxbInstalledPaths {
    param([Parameter(Mandatory = $true)][string]$InstallRoot)

    $root = Get-NxbCanonicalPath $InstallRoot
    return [pscustomobject]@{
        Root = $root
        Binary = Join-Path $root 'nxb.exe'
        Sbom = Join-Path $root 'nxb.cdx.json'
        Checksums = Join-Path $root 'SHA256SUMS'
        Manifest = Join-Path $root 'nxb-release-manifest.json'
        PublicKey = Join-Path $root 'release-public-key.hex'
        State = Join-Path $root 'install-state.json'
    }
}

function Assert-NxbInstalledRoot {
    param(
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ExpectedReleasePublicKeySha256
    )

    $paths = Get-NxbInstalledPaths $InstallRoot
    $paths.Root = Assert-NxbManagedRoot $paths.Root 'installed NXBounty root'
    Assert-NxbExactDirectoryEntries $paths.Root $script:NxbInstalledFileNames 'installed NXBounty root'
    foreach ($name in @('Binary', 'Sbom', 'Checksums', 'Manifest', 'PublicKey', 'State')) {
        Assert-NxbRegularFile $paths.$name "installed $name"
    }
    [void](Assert-NxbAuthenticode $paths.Binary $ExpectedPublisherThumbprint)
    [void](Assert-NxbReleasePublicKey $paths.PublicKey $ExpectedReleasePublicKeySha256)
    $verification = Invoke-NxbReleaseVerification `
        $paths.Binary $paths.Manifest $paths.PublicKey $paths.Sbom $paths.Checksums
    $state = [IO.File]::ReadAllText($paths.State) | ConvertFrom-Json
    if ($state.schema_version -ne $script:NxbInstallerSchemaVersion -or
        $state.product -ne 'NXBounty' -or
        $state.install_root -ne $paths.Root -or
        $state.manifest_sha256 -ne $verification.manifest_sha256 -or
        $state.source_commit -ne $verification.source_commit -or
        $state.version -ne $verification.version -or
        [uint64]$state.release_sequence -ne [uint64]$verification.release_sequence) {
        throw 'Installed state does not match the verified release package.'
    }
    [void](Assert-NxbReleaseSequence $state.release_sequence 'installed release sequence')
    return [pscustomobject]@{
        Paths = $paths
        State = $state
        Verification = $verification
    }
}
