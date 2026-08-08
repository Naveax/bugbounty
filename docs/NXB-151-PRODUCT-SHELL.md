# NXB-151 — Single-binary product shell

## Status

Draft implementation stacked on NXB-150. Source scope is complete through workspace, migration, authorization-bound targets, machine-readable diagnostics, synthetic product flow, signed release manifest v2 and Windows installer lifecycle. Release readiness still requires pinned Rust, Linux and Windows evidence.

## Executable model

The product declares exactly one Cargo binary target:

```text
nxb -> crates/nxb-core/src/nxb.rs
```

Cargo automatic binary discovery is disabled. Workspace, migration, target and release modules are linked directly into the same Rust process. PowerShell installer files are maintenance/orchestration sources rather than additional product executables.

## Command surface

```text
nxb workspace init|doctor|status ...
nxb workspace migrate apply|recover|status ...
nxb target create|validate|list|show|disable ...
nxb release manifest-template|verify-manifest ...
nxb scan ...
```

Existing policy, event, demo, activation and feature-gated live-run commands remain available.

## Canonical workspace

```text
<workspace>/
  workspace.json
  config/
  targets/
  sessions/
  runs/
  evidence/
  reports/
  state/
    migrations/
  tmp/
```

The manifest stores no credential, cookie, token, key material or provider handle. Secret storage is external-provider-only.

## Product invariants

- one Cargo executable target;
- networkless local management by default;
- fail-closed canonical path and reparse-point checks;
- protected Windows DACLs and private Unix modes;
- crash-safe schema `0 → 1` migration;
- immutable authorization-bound target profiles;
- policy and authorization source SHA-256 bindings;
- bounded machine-readable diagnostics;
- manual report review and submission;
- externally signed release evidence;
- transactional Windows install, upgrade, rollback and uninstall.

## Stable failure classes

| Domain | Failure codes |
|---|---:|
| Workspace | `10`, `20`, `30` |
| Migration | `40`, `41`, `42` |
| Target | `50..54` |
| Release manifest | `60`, `61` |

JSON failures use structured code/domain/operation/exit fields on stderr.

## Signed release model

Manifest schema `2` binds:

- exact source commit;
- Cargo SemVer;
- positive monotonic `release_sequence`;
- platform and architecture;
- exact `nxb` or `nxb.exe` bytes;
- CycloneDX SBOM;
- checksum manifest;
- external Ed25519 signature.

Release order is:

```text
(SemVer, release_sequence)
```

Equal order is idempotent only for the same signed manifest. Lower order is denied. Higher order must bind a different source commit.

## Windows lifecycle

The fixed release payload is:

```text
nxb.exe
nxb.cdx.json
SHA256SUMS
nxb-release-manifest.json
release-public-key.hex
```

Installation requires Authenticode publisher pinning before executing the candidate, followed by release-key file pinning and Ed25519 manifest verification. Staging and final publication are revalidated. The previous release is preserved in one rollback slot.

The two-revision harness builds:

- previous exact ancestor `a8aef038449edbe1dbe1ecc6d57e160f82f44c7b` as sequence `1`;
- final validation head as sequence `2`.

It exercises clean install, idempotent reinstall, upgrade, replay rejection, rollback, re-upgrade, tamper rejection and data-preserving uninstall.

## Validation harnesses

Linux and Windows harnesses cover:

- workspace and migration;
- single entry point;
- authorization-bound targets;
- complete synthetic product flow;
- Windows signed installer lifecycle.

No compiler, Clippy, test or platform success is claimed by source presence. PR #70 remains draft until all required evidence passes on one unchanged exact head and NXB-150 is validated and merged.
