[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\NXBounty'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'NXBounty'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256,

    [switch]$PurgeData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'nxb-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'NXBounty uninstall is supported only on Windows.'
}

function Set-NxbUninstallEntryForRestore {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][uint64]$ReleaseSequence,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    $keyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NXBounty'
    New-Item -Path $keyPath -Force | Out-Null
    $uninstaller = Join-Path $Data 'installer\uninstall-nxb-windows.ps1'
    $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{0}" -InstallRoot "{1}" -DataRoot "{2}" -ExpectedPublisherThumbprint {3} -ExpectedReleasePublicKeySha256 {4}' -f `
        $uninstaller, $Root, $Data, $PublisherThumbprint, $ReleasePublicKeySha256
    New-ItemProperty -Path $keyPath -Name DisplayName -Value 'NXBounty' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayVersion -Value $Version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name ReleaseSequence -Value ([string]$ReleaseSequence) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name Publisher -Value 'Naveax' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name InstallLocation -Value $Root -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name DisplayIcon -Value (Join-Path $Root 'nxb.exe') -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name UninstallString -Value $command -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $keyPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

function Restore-NxbUninstallIntegration {
    param(
        [Parameter(Mandatory = $true)]$Installed,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Data,
        [Parameter(Mandatory = $true)][string]$PublisherThumbprint,
        [Parameter(Mandatory = $true)][string]$ReleasePublicKeySha256
    )

    if ([bool]$Installed.State.add_to_user_path) {
        [void](Add-NxbUserPath $Root)
    } else {
        [void](Remove-NxbUserPath $Root)
    }
    if ([bool]$Installed.State.create_start_menu_shortcut) {
        [void](Set-NxbStartMenuShortcut $Root)
    } else {
        [void](Remove-NxbStartMenuShortcut)
    }
    Set-NxbUninstallEntryForRestore `
        $Root $Data $Installed.Verification.version `
        ([uint64]$Installed.Verification.release_sequence) `
        $PublisherThumbprint $ReleasePublicKeySha256
}

function Publish-NxbUninstallReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    $pending = $Path + '.pending.' + $Nonce
    $backup = $Path + '.backup.' + $Nonce
    $backedUp = $false
    $published = $false
    try {
        Write-NxbJsonFile $pending $Value
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Assert-NxbRegularFile $Path 'previous uninstall receipt' 1048576
            Move-Item -LiteralPath $Path -Destination $backup
            $backedUp = $true
        }
        Move-Item -LiteralPath $pending -Destination $Path
        $published = $true
    }
    catch {
        if ($published -and (Test-Path -LiteralPath $Path)) {
            Remove-Item -LiteralPath $Path -Force
        }
        if ($backedUp -and (Test-Path -LiteralPath $backup -PathType Leaf)) {
            Move-Item -LiteralPath $backup -Destination $Path
        }
        Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
        throw
    }
    finally {
        if ($published) {
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
    }
}

$installRootPath = Assert-NxbManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-NxbManagedRoot $DataRoot 'data root'
if ((Test-NxbPathWithin $installRootPath $dataRootPath) -or
    (Test-NxbPathWithin $dataRootPath $installRootPath)) {
    throw 'Install and data roots must be independent directories.'
}

$previousRoot = $installRootPath + '.previous'
$nonce = [Guid]::NewGuid().ToString('N')
$currentTombstone = $installRootPath + '.uninstall.' + $nonce
$previousTombstone = $previousRoot + '.uninstall.' + $nonce
$lock = Open-NxbInstallerLock $installRootPath
$current = $null
$previous = $null
$receipt = $null
$cleanupWarnings = [Collections.Generic.List[string]]::new()
try {
    try {
        $current = Assert-NxbInstalledRoot `
            $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
        if (Test-Path -LiteralPath $previousRoot) {
            $previous = Assert-NxbInstalledRoot `
                $previousRoot $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
        }

        Move-Item -LiteralPath $installRootPath -Destination $currentTombstone
        if ($null -ne $previous) {
            Move-Item -LiteralPath $previousRoot -Destination $previousTombstone
        }

        [void](Remove-NxbUserPath $installRootPath)
        [void](Remove-NxbStartMenuShortcut)
        $uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NXBounty'
        if (Test-Path -LiteralPath $uninstallKey) {
            Remove-Item -LiteralPath $uninstallKey -Recurse -Force
        }

        $receipt = [ordered]@{
            schema_version = 2
            status = 'uninstalled'
            version = $current.Verification.version
            release_sequence = [uint64]$current.Verification.release_sequence
            source_commit = $current.Verification.source_commit
            manifest_sha256 = $current.Verification.manifest_sha256
            binary_sha256 = $current.State.binary_sha256
            install_root = $installRootPath
            data_root = $dataRootPath
            data_preserved = (-not $PurgeData)
            rollback_slot_deactivated = ($null -ne $previous)
            cleanup_complete = $false
            cleanup_warnings = @()
            uninstalled_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
            network_activity = 'none'
        }
    }
    catch {
        $failure = $_
        try {
            if (Test-Path -LiteralPath $currentTombstone -PathType Container) {
                if (Test-Path -LiteralPath $installRootPath) {
                    throw 'Cannot restore active installation because its root is occupied.'
                }
                Move-Item -LiteralPath $currentTombstone -Destination $installRootPath
            }
            if (Test-Path -LiteralPath $previousTombstone -PathType Container) {
                if (Test-Path -LiteralPath $previousRoot) {
                    throw 'Cannot restore rollback slot because its root is occupied.'
                }
                Move-Item -LiteralPath $previousTombstone -Destination $previousRoot
            }
            if ($null -ne $current -and
                (Test-Path -LiteralPath $installRootPath -PathType Container)) {
                $restored = Assert-NxbInstalledRoot `
                    $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
                Restore-NxbUninstallIntegration `
                    $restored $installRootPath $dataRootPath `
                    $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
            }
        }
        catch {
            Write-Error "Uninstall restoration also failed: $($_.Exception.Message)"
        }
        throw $failure
    }

    # Active paths and Windows integrations are now gone. Cleanup failures below
    # must never recreate integrations that point to missing binaries.
    foreach ($entry in @(
        [pscustomobject]@{ Path = $currentTombstone; Label = 'active uninstall tombstone' },
        [pscustomobject]@{ Path = $previousTombstone; Label = 'rollback uninstall tombstone' }
    )) {
        if (Test-Path -LiteralPath $entry.Path) {
            try {
                Assert-NxbNoReparseChain $entry.Path $entry.Label
                Remove-Item -LiteralPath $entry.Path -Recurse -Force
            }
            catch {
                $cleanupWarnings.Add("$($entry.Label): $($_.Exception.Message)")
            }
        }
    }

    $installerStateRoot = Join-Path $dataRootPath 'installer'
    if ($PurgeData) {
        if (Test-Path -LiteralPath $dataRootPath) {
            try {
                Assert-NxbNoReparseChain $dataRootPath 'data root purge target'
                Remove-Item -LiteralPath $dataRootPath -Recurse -Force
            }
            catch {
                $cleanupWarnings.Add("data root purge: $($_.Exception.Message)")
            }
        }
    } else {
        try {
            New-Item -ItemType Directory -Path $installerStateRoot -Force | Out-Null
            Protect-NxbDirectoryAcl $installerStateRoot
            Remove-Item -LiteralPath (Join-Path $installerStateRoot 'current-install.json') `
                -Force -ErrorAction SilentlyContinue
        }
        catch {
            $cleanupWarnings.Add("installer state cleanup: $($_.Exception.Message)")
        }
    }

    $receipt.data_preserved = Test-Path -LiteralPath $dataRootPath -PathType Container
    $receipt.cleanup_complete = ($cleanupWarnings.Count -eq 0)
    $receipt.cleanup_warnings = @($cleanupWarnings)
    if (-not $receipt.cleanup_complete) {
        $receipt.status = 'uninstalled_cleanup_incomplete'
    }

    if (-not $PurgeData -and (Test-Path -LiteralPath $installerStateRoot -PathType Container)) {
        try {
            Publish-NxbUninstallReceipt `
                (Join-Path $installerStateRoot 'last-uninstall.json') $receipt $nonce
        }
        catch {
            $cleanupWarnings.Add("uninstall receipt: $($_.Exception.Message)")
            $receipt.cleanup_complete = $false
            $receipt.cleanup_warnings = @($cleanupWarnings)
            $receipt.status = 'uninstalled_cleanup_incomplete'
        }
    }

    $receipt | ConvertTo-Json -Depth 8
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
