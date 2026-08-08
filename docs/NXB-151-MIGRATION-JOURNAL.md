# NXB-151 — Crash-safe workspace migration journal

## Status

Draft implementation on PR #70. This slice is stacked on NXB-150 and is not release evidence until the pinned Rust 1.97.1 Windows and Linux validation harnesses pass.

## Purpose

The migration layer upgrades an existing local NXBounty workspace without silently adopting unknown schemas, losing the original manifest, following path indirections or leaving an ambiguous partially migrated state.

The initial supported transition is:

```text
workspace schema 0 → workspace schema 1
```

Schema 1 adds:

```json
"secret_storage": "external_provider_only"
```

No credential, cookie, token, key material or provider handle is introduced into the manifest or journal.

## Command surface

The migration engine is linked directly into the single `nxb` executable:

```text
nxb workspace migrate status  --workspace <absolute-path> [--json]
nxb workspace migrate apply   --workspace <absolute-path> [--json]
nxb workspace migrate recover --workspace <absolute-path> [--json]
```

| Command | Failure code |
|---|---:|
| `apply` | 40 |
| `recover` | 41 |
| `status` | 42 |

No migration helper executable, child process or shell is used.

## Journal files

```text
state/
  migration-source.json
  migration-active.json
  migration-applied.json
  migrations/
    nxb-migration-0-1-<digest>.json
```

- `migration-source.json` is the exact bounded source manifest backup.
- `migration-active.json` binds source and target SHA-256 values.
- `migration-applied.json` records verified target publication.
- `migrations/<id>.json` is the immutable commit receipt.

Transient files are removed only after the receipt exists and the manifest matches the target digest.

## Deterministic identity

The target is derived only from the validated source and canonical transition. The migration ID binds the protocol domain, source SHA-256, target SHA-256 and exact `0 → 1` transition. Identical source bytes produce the same plan ID and target digest.

## Prepare → apply → commit

### Prepare

1. Validate root, state directory, permissions and every existing path component.
2. Reject symlinks, junctions and reparse points.
3. Parse the exact legacy schema with unknown fields denied.
4. Generate canonical target bytes and digests.
5. Publish the source backup with create-new semantics.
6. Publish the prepared journal with create-new semantics.

### Apply

1. Accept only a missing manifest, the exact source digest or exact target digest.
2. Reject any third digest as out-of-band tampering.
3. Publish the target through a private temporary document.
4. Flush before publication.
5. Re-read and verify digest and schema.
6. Publish the applied marker.

### Commit

1. Create an immutable digest-bound receipt.
2. Verify an existing receipt instead of replacing it.
3. Remove transient state in bounded order.
4. Retain the receipt for history and status inspection.

## Recovery matrix

| Observed state | Action |
|---|---|
| No transient files | No operation |
| Source backup only | Reconstruct deterministic journal and continue |
| Journal + source manifest | Publish target and commit |
| Journal + target manifest | Verify target and commit |
| Journal + receipt | Verify receipt and target, then clean transient files |
| Missing manifest with valid journal and backup | Re-publish target |
| Applied marker without prepared state | Fail closed |
| Backup digest mismatch | Fail closed |
| Manifest neither exact source nor target | Fail closed and preserve evidence |
| Future or unknown schema | Fail closed |

## Filesystem and permission rules

- Documents are bounded to 64 KiB.
- Journal structures reject unknown fields.
- New files use unpredictable names and create-new publication.
- Unix directories and documents enforce private modes and parent sync where supported.
- Windows uses the shared protected-DACL and reparse-point module.
- Receipt directories reject indirections and non-file entries.
- Receipt count is bounded.
- No workspace helper binary or shell is executed.

## Source tests

The linked migration module tests successful migration, immutable receipt creation, prepared-source recovery, target-published recovery, orphan-backup recovery, manifest-tamper rejection and future-schema rejection.

## Platform acceptance harnesses

```text
bash scripts/validate-nxb-151-migration-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
```

Both harnesses build only `--bin nxb` and exercise migration through `nxb workspace migrate ...`. Evidence is written below:

```text
target/nxb-validation/nxb-151-migration-<platform>-<head>.json
```

## Remaining acceptance requirements

- Actual format, check, Clippy and tests on Rust 1.97.1.
- Real Windows ACL and reparse execution.
- Real Linux permission and parent-sync execution.
- Exact-head platform acceptance evidence.

Command consolidation and doctor/status integration are complete at source level. The PR remains draft until execution gates pass.
