# NXBounty NXB-151 Quick Start

## Current status

NXB-151 is a draft product milestone. The supported product shape is one executable:

```text
nxb.exe   # Windows
nxb       # Linux
```

The commands below describe the intended exact-head acceptance flow. They are not a release claim until pinned Rust 1.97.1, Windows, Linux and installer gates pass and PRs #68 and #70 merge.

## Safety model

Before using NXB on a real program:

- read the current program policy;
- confirm automated testing is allowed;
- preserve the exact policy bytes reviewed;
- preserve a separate authorization document or approval export;
- use only accounts, tenants and assets you are authorized to test;
- keep automatic submission disabled;
- do not place cookies, tokens, passwords or API keys in workspace JSON.

A local target profile narrows product behavior and binds source digests. It does not prove that an authorization document is genuine or sufficient.

## 1. Create a private workspace

Windows:

```powershell
.\nxb.exe workspace init `
  --workspace "$HOME\NXBounty" `
  --name "My NXBounty Workspace" `
  --json
```

Linux:

```bash
./nxb workspace init \
  --workspace "$HOME/NXBounty" \
  --name 'My NXBounty Workspace' \
  --json
```

## 2. Check workspace health

```text
nxb workspace doctor --workspace <workspace> --json
nxb workspace status --workspace <workspace> --json
```

A pending migration blocks target and later operations:

```text
nxb workspace migrate recover --workspace <workspace> --json
```

## 3. Prepare source documents

Target profiles require:

```text
<program-policy.toml>
<authorization-document>
```

The policy is compiled. The authorization document is treated as opaque bytes and represented only by SHA-256 plus a safe external reference.

```text
nxb validate-policy \
  --path <program-policy.toml> \
  --now <current-rfc3339-time>
```

Synthetic acceptance fixtures are not authorization for real systems:

```text
fixtures/nxb-151/synthetic-policy.toml
fixtures/nxb-151/synthetic-authorization.txt
```

## 4. Create and validate one target

```text
nxb target create \
  --workspace <workspace> \
  --id example-app \
  --name "Example App" \
  --origin https://example.org \
  --include-path /api \
  --exclude-path /api/logout \
  --authorization-reference <safe-reference> \
  --authorization-document <authorization-document> \
  --policy <program-policy.toml> \
  --json
```

```text
nxb target validate \
  --workspace <workspace> \
  --id example-app \
  --authorization-document <authorization-document> \
  --policy <program-policy.toml> \
  --json
```

```text
nxb target show --workspace <workspace> --id example-app --json
nxb target list --workspace <workspace> --json
```

Disable without modifying the profile:

```text
nxb target disable \
  --workspace <workspace> \
  --id example-app \
  --reason operator-hold \
  --json
```

## 5. Produce a networkless scan/report bundle

```text
nxb scan \
  --program <program-policy.toml> \
  --target https://example.org/ \
  --output-directory <workspace>/reports/synthetic-run \
  --run-id synthetic-run-001 \
  --maximum-depth 1 \
  --maximum-endpoints 16 \
  --maximum-requests 8 \
  --dry-run true \
  --now <current-rfc3339-time>
```

Expected artifacts:

```text
scan-plan.json
report.json
report.md
hackerone-draft.md
manifest.json
```

The HackerOne document is manual-review only. NXB does not submit it.

## 6. Generate and verify architecture receipt

```text
nxb demo-run --output <workspace>/reports/demo-receipt.json
nxb verify-demo <workspace>/reports/demo-receipt.json
```

## 7. Create a signed release template

Release manifest schema `2` requires a positive monotonic revision sequence:

```text
nxb release manifest-template \
  --release-id v0.1.0-r1 \
  --release-sequence 1 \
  --source-commit <exact-40-character-commit> \
  --platform <windows|linux> \
  --architecture x86-64 \
  --binary <nxb.exe|nxb> \
  --sbom <nxb.cdx.json> \
  --checksums <SHA256SUMS> \
  --generated-at <utc-rfc3339> \
  --output <nxb-release-manifest.json> \
  --json
```

Sign the exact decoded `signing_payload_hex` externally with Ed25519, insert the lowercase signature into `signature_hex`, then verify:

```text
nxb release verify-manifest \
  --document <nxb-release-manifest.json> \
  --public-key <release-public-key.hex> \
  --binary <nxb.exe|nxb> \
  --sbom <nxb.cdx.json> \
  --checksums <SHA256SUMS> \
  --json
```

Release ordering is `(SemVer, release_sequence)`. Never reuse a sequence for a different source commit or manifest.

## 8. Windows install, rollback and uninstall

```powershell
.\scripts\install-nxb-windows.ps1 `
  -PackageDirectory C:\path\to\five-file-package `
  -ExpectedPublisherThumbprint <publisher-thumbprint> `
  -ExpectedReleasePublicKeySha256 <release-key-file-sha256>
```

```powershell
.\scripts\rollback-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <publisher-thumbprint> `
  -ExpectedReleasePublicKeySha256 <release-key-file-sha256>
```

```powershell
.\scripts\uninstall-nxb-windows.ps1 `
  -ExpectedPublisherThumbprint <publisher-thumbprint> `
  -ExpectedReleasePublicKeySha256 <release-key-file-sha256>
```

Uninstall preserves workspace/data by default. Data deletion requires `-PurgeData`.

## 9. Confirm final local state

```text
nxb workspace doctor --workspace <workspace> --json
nxb workspace status --workspace <workspace> --json
nxb system-status
```

## Machine-readable failures

Commands with `--json` emit versioned diagnostic JSON on stderr and preserve operation-specific exit codes. Automation must use `code` and `exit_code`, not parse message text.

## Acceptance harnesses

```bash
bash scripts/validate-nxb-151-synthetic-linux.sh
```

```powershell
pwsh -NoProfile -File .\scripts\validate-nxb-151-synthetic-windows.ps1
pwsh -NoProfile -File .\scripts\validate-nxb-151-installer-windows.ps1
```

The installer harness builds a previous exact ancestor and the final exact head, creates signed sequences `1` and `2`, then exercises install, upgrade, replay rejection, rollback, re-upgrade, tamper rejection and data-preserving uninstall.

No successful acceptance result is claimed until evidence is generated and reviewed on the same final head.
