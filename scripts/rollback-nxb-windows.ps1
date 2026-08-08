[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'Programs\NXBounty'),

    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'NXBounty'),

    [Parameter(Mandatory = $true)]
    [string]$ExpectedPublisherThumbprint,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedReleasePublicKeySha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$commonPath = Join-Path $PSScriptRoot 'nxb-installer-common.ps1'
if (-not (Test-Path -LiteralPath $commonPath -PathType Leaf)) {
    throw "Installer support library is missing: $commonPath"
}
. $commonPath

if ($env:OS -ne 'Windows_NT') {
    throw 'NXBounty rollback is supported only on Windows.'
}

function Set-NxbRollbackUninstallEntry {
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

function Restore-NxbIntegration {
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
    Set-NxbRollbackUninstallEntry `
        $Root $Data $Installed.Verification.version `
        ([uint64]$Installed.Verification.release_sequence) `
        $PublisherThumbprint $ReleasePublicKeySha256
}

function Restore-NxbRollbackSlots {
    param(
        [Parameter(Mandatory = $true)][string]$ActiveRoot,
        [Parameter(Mandatory = $true)][string]$PreviousRoot,
        [Parameter(Mandatory = $true)][string]$FailedRoot,
        [Parameter(Mandatory = $true)][string]$ScratchRoot,
        [Parameter(Mandatory = $true)][bool]$CurrentMovedToFailed,
        [Parameter(Mandatory = $true)][bool]$PreviousPublished,
        [Parameter(Mandatory = $true)][bool]$NewerMovedToPrevious
    )

    if ($NewerMovedToPrevious) {
        if (-not (Test-Path -LiteralPath $ActiveRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $PreviousRoot -PathType Container) -or
            (Test-Path -LiteralPath $FailedRoot)) {
            throw 'Completed slot swap is not in a restorable layout.'
        }
        Move-Item -LiteralPath $ActiveRoot -Destination $ScratchRoot
        Move-Item -LiteralPath $PreviousRoot -Destination $ActiveRoot
        Move-Item -LiteralPath $ScratchRoot -Destination $PreviousRoot
        return
    }
    if ($PreviousPublished) {
        if (-not (Test-Path -LiteralPath $ActiveRoot -PathType Container) -or
            -not (Test-Path -LiteralPath $FailedRoot -PathType Container) -or
            (Test-Path -LiteralPath $PreviousRoot)) {
            throw 'Published previous slot is not in a restorable layout.'
        }
        Move-Item -LiteralPath $ActiveRoot -Destination $PreviousRoot
        Move-Item -LiteralPath $FailedRoot -Destination $ActiveRoot
        return
    }
    if ($CurrentMovedToFailed) {
        if ((Test-Path -LiteralPath $ActiveRoot) -or
            -not (Test-Path -LiteralPath $FailedRoot -PathType Container)) {
            throw 'Moved active slot is not in a restorable layout.'
        }
        Move-Item -LiteralPath $FailedRoot -Destination $ActiveRoot
    }
}

function Backup-NxbFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Backup
    )

    if (Test-Path -LiteralPath $Backup) {
        throw "Backup path already exists: $Backup"
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Assert-NxbRegularFile $Path 'rollback metadata file' 1048576
        Move-Item -LiteralPath $Path -Destination $Backup
    }
}

function Restore-NxbPublishedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Backup,
        [Parameter(Mandatory = $true)][bool]$Published
    )

    if ($Published -and (Test-Path -LiteralPath $Path)) {
        Remove-Item -LiteralPath $Path -Force
    }
    if (Test-Path -LiteralPath $Backup -PathType Leaf) {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
        Move-Item -LiteralPath $Backup -Destination $Path
    }
}

$installRootPath = Assert-NxbManagedRoot $InstallRoot 'install root'
$dataRootPath = Assert-NxbManagedRoot $DataRoot 'data root'
if ((Test-NxbPathWithin $installRootPath $dataRootPath) -or
    (Test-NxbPathWithin $dataRootPath $installRootPath)) {
    throw 'Install and data roots must be independent directories.'
}

$nonce = [Guid]::NewGuid().ToString('N')
$previousRoot = $installRootPath + '.previous'
$failedRoot = $installRootPath + '.rollback-failed.' + $nonce
$restoreScratch = $installRootPath + '.rollback-restore.' + $nonce
$maintenanceRoot = Join-Path $dataRootPath 'installer'
$currentStatePath = Join-Path $maintenanceRoot 'current-install.json'
$currentStatePending = $currentStatePath + '.pending.' + $nonce
$currentStateBackup = $currentStatePath + '.backup.' + $nonce
$receiptPath = Join-Path $maintenanceRoot 'last-rollback.json'
$receiptPending = $receiptPath + '.pending.' + $nonce
$receiptBackup = $receiptPath + '.backup.' + $nonce

$lock = Open-NxbInstallerLock $installRootPath
$current = $null
$currentMovedToFailed = $false
$previousPublished = $false
$newerMovedToPrevious = $false
$currentStatePublished = $false
$receiptPublished = $false
$transactionCommitted = $false
$result = $null
try {
    $current = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    $previous = Assert-NxbInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256

    $comparison = Compare-NxbReleaseOrder `
        $previous.Verification.version $previous.Verification.release_sequence `
        $current.Verification.version $current.Verification.release_sequence
    if ($comparison -ge 0) {
        throw 'Rollback slot must contain a strictly older signed release order.'
    }
    if ($previous.Verification.manifest_sha256 -eq $current.Verification.manifest_sha256 -or
        $previous.Verification.source_commit -eq $current.Verification.source_commit) {
        throw 'Rollback slot must bind a different manifest and exact source commit.'
    }

    Move-Item -LiteralPath $installRootPath -Destination $failedRoot
    $currentMovedToFailed = $true
    Move-Item -LiteralPath $previousRoot -Destination $installRootPath
    $previousPublished = $true

    $restored = Assert-NxbInstalledRoot `
        $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    if ($restored.Verification.manifest_sha256 -ne $previous.Verification.manifest_sha256 -or
        [uint64]$restored.Verification.release_sequence -ne [uint64]$previous.Verification.release_sequence) {
        throw 'Published rollback installation does not match the validated previous slot.'
    }

    Restore-NxbIntegration `
        $restored $installRootPath $dataRootPath `
        $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    Protect-NxbDirectoryAcl $installRootPath
    Protect-NxbDirectoryAcl $failedRoot

    New-Item -ItemType Directory -Path $maintenanceRoot -Force | Out-Null
    Protect-NxbDirectoryAcl $maintenanceRoot

    $receipt = [ordered]@{
        schema_version = 2
        status = 'rolled_back'
        from_version = $current.Verification.version
        from_release_sequence = [uint64]$current.Verification.release_sequence
        from_source_commit = $current.Verification.source_commit
        from_manifest_sha256 = $current.Verification.manifest_sha256
        to_version = $restored.Verification.version
        to_release_sequence = [uint64]$restored.Verification.release_sequence
        to_source_commit = $restored.Verification.source_commit
        to_manifest_sha256 = $restored.Verification.manifest_sha256
        newer_release_preserved_in_previous_slot = $true
        install_root = $installRootPath
        data_root = $dataRootPath
        rolled_back_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        network_activity = 'none'
    }
    Write-NxbJsonFile $currentStatePending $restored.State
    Write-NxbJsonFile $receiptPending $receipt

    Move-Item -LiteralPath $failedRoot -Destination $previousRoot
    $newerMovedToPrevious = $true
    $preserved = Assert-NxbInstalledRoot `
        $previousRoot $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
    if ($preserved.Verification.manifest_sha256 -ne $current.Verification.manifest_sha256) {
        throw 'Newer release was not preserved in the previous slot.'
    }

    Backup-NxbFile $currentStatePath $currentStateBackup
    Backup-NxbFile $receiptPath $receiptBackup
    Move-Item -LiteralPath $currentStatePending -Destination $currentStatePath
    $currentStatePublished = $true
    Move-Item -LiteralPath $receiptPending -Destination $receiptPath
    $receiptPublished = $true

    $result = $receipt
    $transactionCommitted = $true
}
catch {
    $failure = $_
    if (-not $transactionCommitted) {
        try {
            Restore-NxbPublishedFile `
                $currentStatePath $currentStateBackup $currentStatePublished
            Restore-NxbPublishedFile `
                $receiptPath $receiptBackup $receiptPublished
            Remove-Item -LiteralPath $currentStatePending -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $receiptPending -Force -ErrorAction SilentlyContinue

            Restore-NxbRollbackSlots `
                $installRootPath $previousRoot $failedRoot $restoreScratch `
                $currentMovedToFailed $previousPublished $newerMovedToPrevious
            if ($null -ne $current -and
                (Test-Path -LiteralPath $installRootPath -PathType Container)) {
                $recovered = Assert-NxbInstalledRoot `
                    $installRootPath $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
                if ($recovered.Verification.manifest_sha256 -ne $current.Verification.manifest_sha256) {
                    throw 'Rollback restoration recovered the wrong active release.'
                }
                Restore-NxbIntegration `
                    $recovered $installRootPath $dataRootPath `
                    $ExpectedPublisherThumbprint $ExpectedReleasePublicKeySha256
            }
        }
        catch {
            Write-Error "Rollback restoration also failed: $($_.Exception.Message)"
        }
    }
    throw $failure
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}

if ($transactionCommitted) {
    foreach ($path in @($currentStateBackup, $receiptBackup, $restoreScratch)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $result | ConvertTo-Json -Depth 8
}
