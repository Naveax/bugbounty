# NXB-151 Validation Procedure

NXB-151 validation is external to GitHub Actions. Repository workflows remain disabled. Evidence is accepted only when every required gate completes on one unchanged exact Git head.

## Exact-head requirement

Validation starts from a clean working tree and Rust `1.97.1` with rustfmt and Clippy.

Required package gates:

```text
cargo fmt --all -- --check
cargo check -p nxb-core --all-targets --all-features --locked
cargo clippy -p nxb-core --all-targets --all-features --locked -- -D warnings
cargo test -p nxb-core --all-features --locked -- --test-threads=1
cargo build -p nxb-core --bin nxb --all-features --locked
```

Workspace-level check, Clippy and test regressions remain mandatory before merge.

## Single-binary requirement

Cargo metadata must expose exactly:

```json
["nxb"]
```

No helper, product, migration or temporary executable target is permitted.

## Product workspace validation

```text
bash scripts/validate-nxb-151-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-windows.ps1
```

These verify initialization, doctor, status, non-empty rejection, missing-directory detection, private permissions and single-binary behavior. Windows additionally covers protected ACLs, junction/reparse rejection and broad-ACE rejection. Linux covers private modes and durable publication.

## Migration validation

```text
bash scripts/validate-nxb-151-migration-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-migration-windows.ps1
```

These invoke migration only through `nxb workspace migrate ...` and verify schema `0 → 1`, immutable receipt publication, transient cleanup and recovery.

## Linked entry-point validation

```text
bash scripts/validate-nxb-151-entrypoint-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-entrypoint-windows.ps1
```

These require exactly one Cargo binary target and migration-aware doctor/status behavior.

## Authorization-bound target validation

```text
bash scripts/validate-nxb-151-target-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-target-windows.ps1
```

Required checks include:

- create, validate, list, show and disable lifecycle;
- current policy compilation and exact host binding;
- program metadata derived from policy;
- read-only method intersection;
- authorization and policy SHA-256 bindings;
- active-profile identity tamper rejection;
- raw source bytes and source-path non-persistence;
- unsafe origin/path/reference rejection;
- pending migration rejection;
- source drift and receipt tamper rejection;
- machine-readable diagnostics;
- networkless behavior.

Linux additionally verifies private `0600` modes. Windows injects a broad Everyone allow ACE and requires rejection.

## Signed release-manifest validation

Mandatory Rust sources:

```text
crates/nxb-core/src/release_manifest.rs
crates/nxb-core/tests/release_manifest_cli.rs
```

They verify:

- canonical manifest schema `2`;
- exact source commit, package version, platform and architecture;
- positive signed `release_sequence`;
- exact binary, CycloneDX SBOM and checksum bindings;
- external Ed25519 signing and verification;
- sequence tamper and zero-sequence rejection;
- binary, signature and checksum tamper rejection;
- wrong-public-key rejection;
- single-binary filename enforcement;
- release diagnostics `60` and `61`;
- networkless verification.

The unit fixture must use valid CycloneDX JSON directly; parser failure is not accepted as a signing-path test.

## Machine-readable diagnostics

Mandatory integration tests:

```text
crates/nxb-core/tests/product_diagnostics.rs
crates/nxb-core/tests/target_cli.rs
crates/nxb-core/tests/release_manifest_cli.rs
```

They bind to structured schema, code, domain, operation and exit-code fields rather than message wording.

## Full synthetic product validation

```text
bash scripts/validate-nxb-151-synthetic-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-synthetic-windows.ps1
```

These execute a complete networkless local product flow using synthetic policy and authorization fixtures, including workspace creation, target validation, bounded dry-run planning, manual report bundle, deterministic demo receipt and exact-head evidence.

## Windows installer validation

```text
pwsh -NoProfile -File .\scripts\validate-nxb-151-installer-windows.ps1
```

Default previous source revision:

```text
a8aef038449edbe1dbe1ecc6d57e160f82f44c7b
```

The harness must verify:

- every installer script passes the PowerShell parser;
- current head passes Rust format, check, Clippy and tests;
- current head and previous exact ancestor build with locked Rust 1.97.1;
- both `nxb.exe` files receive valid Authenticode signatures from one pinned temporary publisher certificate;
- all packages use one pinned external Ed25519 release key;
- manifest schema `2` binds sequence `1` to the previous source and sequence `2` to the final head;
- exact five-file package layout;
- clean sequence-1 installation;
- atomic idempotent sequence-1 reinstall;
- signed sequence-1 → sequence-2 upgrade;
- sequence-1 downgrade/replay rejection while sequence 2 is installed;
- failed upgrade after previous-slot backup restores active sequence 2 and previous sequence 1;
- failed rollback after the complete slot swap restores active sequence 2 and previous sequence 1;
- signed sequence-2 → sequence-1 rollback;
- sequence-1 → sequence-2 upgrade after rollback;
- failed uninstall after active deactivation restores active sequence 2 and previous sequence 1;
- Authenticode-tampered package rejection before execution;
- active and rollback installation verification before uninstall;
- data-preserving uninstall;
- final `cleanup_complete=true` and empty cleanup warnings;
- no stage, backup, rollback, restore or uninstall transaction residue;
- networkless behavior and exact two-source evidence.

The three recovery tests use readable file handles without `FileShare.Delete`. Verification therefore completes, but the intended rename fails at the exact transaction boundary. Merely failing before validation does not satisfy a recovery gate.

The previous source must be a distinct ancestor of the final head and must contain manifest-v2 support. Same package SemVer is intentional; the signed release sequence provides the revision order. Merely parsing scripts or running a single package is insufficient.

## Evidence files

Successful runs create local files under:

```text
target/nxb-validation/
```

Evidence contains milestone, platform, exact final head, pinned toolchain, explicit checks and single executable hashes. Installer evidence additionally contains:

- previous exact source commit;
- sequence-1 and sequence-2 source commits;
- both binary and manifest SHA-256 values;
- publisher thumbprint;
- release-public-key file SHA-256;
- failed-upgrade state restoration;
- failed-rollback slot restoration;
- failed-uninstall deactivation restoration;
- transaction-residue cleanup.

Evidence must contain no workspace contents, credentials, tokens, source authorization bytes or private signing keys.

## Acceptance rule

NXB-151 can move out of draft only when:

- NXB-150 validates and merges;
- all Linux and Windows harnesses pass on one final head;
- Cargo metadata confirms one binary target;
- full workspace check, Clippy and tests pass;
- Windows ACL/reparse and Linux permission/fsync checks pass;
- authorization-bound target tests pass on both platforms;
- signed manifest-v2 tests pass;
- diagnostic tests pass;
- full synthetic product flow passes on both platforms;
- two-revision install, upgrade, replay rejection, rollback, re-upgrade, tamper rejection and uninstall pass on Windows;
- all three forced transaction failures restore exact active/previous/integration state;
- generated evidence is reviewed and recorded in the PR;
- no GitHub Actions workflow is added or re-enabled.

Source implementation, static inspection, failed remote-job submission, one-platform evidence or single-revision installer execution is insufficient.

## Current infrastructure limitation

The available Hugging Face Jobs integration has failed before job creation with `Tool hf_jobs not found`. The current local environment has no Rust or Windows execution path. Repository GitHub Actions remain disabled. These infrastructure failures are not compiler or platform evidence, so PR #70 remains draft.
