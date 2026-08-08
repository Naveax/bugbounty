# NXB-151 Windows Installer Lifecycle

## Purpose

The Windows lifecycle installs the single `nxb.exe` product only after two independent trust checks:

1. Windows Authenticode validation against a pinned publisher certificate thumbprint.
2. NXBounty Ed25519 manifest-v2 validation against a pinned release-public-key file SHA-256.

The candidate executable is never run before its Authenticode signature and exact publisher certificate are validated. After that bootstrap check, the candidate executes its networkless `release verify-manifest` command to verify its own bytes, CycloneDX SBOM, checksum manifest, source commit, monotonic release sequence and external Ed25519 signature.

No installer operation downloads files or contacts a network service.

## Package contract

`-PackageDirectory` must contain exactly five private regular files:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
```

Nested directories, extra files, symlinks, junctions and reparse points are rejected. Installer scripts are distributed separately and are not Cargo binary targets.

## Install command

```powershell
.\scripts\install-nxb-windows.ps1 `
  -PackageDirectory C:\path\to\release `
  -ExpectedPublisherThumbprint <40-hex-cert-thumbprint> `
  -ExpectedReleasePublicKeySha256 <64-hex-file-sha256>
```

Defaults:

```text
Install root: %LOCALAPPDATA%\Programs\NXBounty
Data root:    %LOCALAPPDATA%\NXBounty
```

Optional integration:

```powershell
-AddToUserPath $true|$false
-CreateStartMenuShortcut $true|$false
```

Package, install and data roots must be independent. Equality and nesting in either direction are rejected.

## Bootstrap trust sequence

Before publication, the installer requires:

- exact five-file layout;
- no reparse point in any path component;
- valid Authenticode status for `nxb.exe`;
- exact signer-certificate thumbprint;
- exact release-public-key file SHA-256;
- 32-byte lowercase hexadecimal Ed25519 public key;
- Windows x86_64 NXBounty manifest schema `2`;
- positive bounded release sequence;
- successful networkless `verify-manifest` result.

Checksum equality alone is never sufficient.

## Signed release ordering

The installer orders releases by:

```text
(SemVer, release_sequence)
```

Rules:

- lower SemVer is denied;
- equal SemVer with lower sequence is denied as downgrade/replay;
- equal order is idempotent only for the exact same manifest SHA-256;
- equal order with different evidence is denied;
- higher order must bind a different exact source commit;
- rollback requires a strictly lower signed order and different source commit.

This permits two source revisions to remain package version `0.1.0` while receiving signed sequences `1` and `2`. The sequence is part of the Ed25519 payload, so it cannot be changed after signing.

## Transactional install and upgrade

The transaction uses an exclusive sibling lock and unique protected staging directory:

1. Validate source package.
2. Validate existing active installation and optional previous slot.
3. Snapshot the active integration policy.
4. Compare signed release order.
5. Publish a protected maintenance-script directory while preserving its previous form in a transaction backup.
6. Copy exactly five files to staging.
7. Re-run Authenticode, release-key and Ed25519 verification against staging.
8. Write schema-v2 `install-state.json` inside staging.
9. Move any existing previous slot to a unique backup rather than deleting it.
10. Move the active installation to `<InstallRoot>.previous`.
11. Atomically publish staging as the active root.
12. Apply the requested PATH, Start Menu and HKCU uninstall state.
13. Revalidate the final active installation.
14. Publish maintenance `current-install.json`.
15. Remove superseded transaction backups only after commit.

A failed upgrade restores:

- the exact active release;
- the exact pre-existing previous slot;
- PATH registration policy;
- Start Menu registration policy;
- HKCU uninstall metadata;
- maintenance scripts and receipts;
- staging and transaction residue.

An idempotent reinstall uses pending and backup files for `install-state.json`. If integration or maintenance publication fails, the original state file and original integration policy are restored.

## Installed state

The install root contains exactly:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
install-state.json
```

Unexpected entries are rejected. State schema `2` records:

- SemVer and release sequence;
- release ID and exact source commit;
- manifest, signature, document and binary SHA-256 values;
- publisher thumbprint and release-key file SHA-256;
- install/data roots and integration policy;
- UTC installation timestamp.

## Rollback

```powershell
.\scripts\rollback-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Both current and previous slots must pass complete verification. The previous slot must have a strictly lower signed release order, different manifest and different source commit.

Rollback has explicit transaction phases:

1. Move the current release to a unique failure slot.
2. Publish the verified previous release as active.
3. Revalidate the published active release.
4. Restore its exact PATH, shortcut and uninstall policy.
5. Write pending current-state and rollback-receipt files.
6. Move the newer release into the previous slot.
7. Revalidate the preserved newer release.
8. Publish metadata through backup-and-replace operations.
9. Commit and remove obsolete backups.

Recovery is phase-aware. Depending on the last completed move, it reconstructs the original active/previous layout from:

- active + previous;
- active + failure slot;
- previous + failure slot;
- active + previous after the complete slot swap.

Metadata pending files and backups are restored before the release slots. Windows integrations are then rebound to the recovered active release. A failure after the slot swap therefore cannot leave the older release active or delete the newer release silently.

The receipt records both SemVer values, release sequences, source commits and manifest SHA-256 values.

## Uninstall

```powershell
.\scripts\uninstall-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <thumbprint> `
  -ExpectedReleasePublicKeySha256 <sha256>
```

Active and rollback installations are verified before deactivation.

### Reversible deactivation phase

1. Move the active root to a unique tombstone.
2. Move the previous slot to its own tombstone.
3. Remove only the NXBounty PATH entry, shortcut and HKCU uninstall record.

Any failure in this phase restores both roots and the exact integration policy.

### Post-commit cleanup phase

Once active paths and Windows integrations are absent, uninstall is committed. Tombstone deletion, optional data purge and receipt publication are then cleanup operations. A cleanup failure never recreates an integration pointing to a missing executable.

Results are explicit:

```text
uninstalled
uninstalled_cleanup_incomplete
```

The output includes:

- `cleanup_complete`;
- bounded `cleanup_warnings`;
- whether the rollback slot was deactivated;
- whether the data root remains.

When data is preserved, `last-uninstall.json` is published through pending and backup files after the final cleanup state is known. The persisted receipt therefore matches the returned status and warnings. Explicit data deletion requires:

```powershell
-PurgeData
```

## ACL and integration boundary

Install, rollback and maintenance directories receive protected per-user ACLs granting full control only to the current user and Local System.

When enabled, integration consists of:

- one exact user PATH entry;
- one NXBounty Start Menu shortcut;
- one HKCU uninstall record including `DisplayVersion` and `ReleaseSequence`.

Uninstall removes only NXBounty-owned entries.

## Two-revision acceptance harness

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-installer-windows.ps1
```

The default previous source is:

```text
a8aef038449edbe1dbe1ecc6d57e160f82f44c7b
```

It is an ancestor containing manifest-v2 support. The harness:

1. validates the final clean exact head;
2. parses every installer PowerShell source;
3. runs pinned Rust format, check, Clippy and tests;
4. builds the final head and previous exact commit;
5. signs both binaries with one temporary trusted Authenticode certificate;
6. creates one external Ed25519 key;
7. produces signed sequence-1 and sequence-2 packages;
8. installs sequence 1 and verifies idempotent reinstall;
9. upgrades to sequence 2;
10. rejects sequence-1 replay/downgrade;
11. creates a signed sequence-3 recovery package;
12. denies active-root rename during upgrade and requires exact active/previous restoration;
13. denies rollback metadata rename after slot swap and requires exact slot restoration;
14. performs a successful sequence-2 to sequence-1 rollback;
15. upgrades to sequence 2 again;
16. denies previous-slot rename during uninstall and requires exact deactivation rollback;
17. rejects an Authenticode-tampered package;
18. uninstalls while preserving a data sentinel;
19. requires complete cleanup with no transaction residue;
20. writes exact-head, two-source, manifest and recovery evidence.

Rename-denial tests keep files readable but omit `FileShare.Delete`. Verification therefore completes, while the intended directory or metadata rename fails at the transaction boundary being tested.

The previous commit must resolve to a distinct ancestor of the final head. The same package SemVer is intentional; signed release sequence supplies the revision order.

## Validation status

Source and harness coverage are present. No successful Windows result is claimed until the harness runs on Windows with Rust 1.97.1, Authenticode support and OpenSSL Ed25519 support on one unchanged final head. PR #70 remains draft.
