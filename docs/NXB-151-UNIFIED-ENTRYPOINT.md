# NXB-151 — Linked single-binary workspace entry point

## Status

Draft implementation. This contract remains stacked on NXB-150 and is not release-complete until the exact Rust, Windows and Linux gates pass.

## Supported user-facing surface

The supported workspace interface is rooted at the primary `nxb` executable:

```text
nxb workspace init --workspace <path> [--name <name>] [--json]
nxb workspace doctor --workspace <path> [--json]
nxb workspace status --workspace <path> [--json]
nxb workspace migrate apply --workspace <path> [--json]
nxb workspace migrate recover --workspace <path> [--json]
nxb workspace migrate status --workspace <path> [--json]
```

Workspace initialization, diagnostics, status and crash-safe migration are linked directly into this executable. No workspace helper executable is discovered, spawned or required.

Existing non-workspace commands and `live-network` feature gating retain their prior behavior.

## Binary target contract

`nxb-core` declares exactly one Cargo binary target:

```text
nxb
```

The release installation set for this slice therefore contains one executable:

```text
nxb[.exe]
```

The former `nxb-product` and `nxb-workspace-migrate` targets and sources were removed. Cargo automatic binary discovery remains disabled so support modules cannot become unintended executable targets.

## Linked module boundary

The executable links these internal modules directly:

```text
workspace/mod.rs
workspace/migration.rs
workspace/windows.rs   # Windows only
workspace_facade.rs
```

The shared workspace module owns manifest validation, canonical layout, bounded I/O, private permissions, path-indirection rejection and cleanup. The migration module owns the deterministic prepare/apply/commit/recovery lifecycle. The Windows module is the single implementation of reparse-point and DACL enforcement.

No child process, shell, CMD script or PowerShell process is used for workspace dispatch. There is no sibling executable resolution, `PATH` lookup, helper environment, helper timeout or helper output parser.

## Exit-code contract

| Operation | Failure code |
|---|---:|
| Workspace initialization | 10 |
| Workspace doctor | 20 |
| Workspace status | 30 |
| Migration apply | 40 |
| Migration recover | 41 |
| Migration status | 42 |

Legacy non-workspace commands continue to return the primary CLI failure code `1`.

## Combined doctor and status

`nxb workspace doctor` combines structural workspace diagnostics with migration state.

A stable workspace adds a passing `migration_state` check. Pending, malformed or unavailable migration state changes the doctor result to `unhealthy` and returns exit code `20`.

`nxb workspace status` includes a nested `migration` object. Pending migration state changes the top-level status to `recovery_required` and returns exit code `30`.

This prevents normal product use while a prepare/apply/commit migration transaction is incomplete.

## Acceptance harnesses

Linux:

```text
bash scripts/validate-nxb-151-entrypoint-linux.sh
```

Windows:

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
```

Each harness requires a clean exact head and Rust `1.97.1`, then runs formatting, check, Clippy with warnings denied, serial tests and a build of only `--bin nxb`.

The harnesses verify:

- Cargo metadata exposes exactly one binary target named `nxb`;
- unified initialization;
- migration-aware doctor output;
- migration-aware status output;
- migration status through the primary CLI;
- fail-closed doctor exit code `20` during pending migration;
- fail-closed status exit code `30` during pending migration;
- restoration after transient state removal;
- the single executable SHA-256;
- exact-head-bound local JSON evidence.

## Remaining NXB-151 work

- Run and repair the pinned Rust, Linux and Windows acceptance gates.
- Add the first fail-closed `target` command group.
- Add machine-readable diagnostic subcodes.
- Add full synthetic product acceptance and quick-start documentation.
- Bind the single executable into the final signed release manifest and installer flow.

No compiler, Clippy, test or platform acceptance success is claimed by this document alone.
