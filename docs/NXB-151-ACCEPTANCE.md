# NXB-151 acceptance matrix

This matrix defines the minimum evidence required before NXB-151 can be marked complete.

| Gate | Linux | Windows | Required evidence |
|---|---:|---:|---|
| Pinned Rust toolchain | Required | Required | exact `rustc`, Cargo, rustfmt and Clippy versions |
| Formatting | Required | Required | `cargo fmt --all -- --check` |
| Package check | Required | Required | `cargo check -p nxb-core --all-targets --all-features --locked` |
| Clippy | Required | Required | all targets, all features, warnings denied |
| Unit and acceptance tests | Required | Required | serial `nxb-core` test result |
| Full workspace regression | Required | Required | workspace check, Clippy and tests |
| Single binary target | Required | Required | Cargo metadata exposes exactly `nxb` |
| Single executable build | Required | Required | `cargo build -p nxb-core --bin nxb --all-features --locked` |
| No helper executable dependency | Required | Required | workspace, migration, target and release commands use only `nxb` |
| Init absent/empty path | Required | Required | canonical tree and manifest created |
| Init non-empty path | Required | Required | fail closed, pre-existing content unchanged |
| Partial-init recovery | Required | Required | no manifest or child directories remain |
| Symlink/reparse-point root | Required | Required | fail closed |
| Manifest size bound | Required | Required | files over 64 KiB rejected |
| Unknown manifest fields | Required | Required | rejected |
| Unsupported schema | Required | Required | rejected |
| Doctor write probe | Required | Required | create-new, flush and cleanup |
| Unix permissions | Required | N/A | root/directories `0700`, documents `0600` |
| Windows ACL | N/A | Required | protected DACL with approved principals only |
| Status redaction | Required | Required | no file contents, secrets or provider handles |
| Stable workspace exit codes | Required | Required | init `10`, doctor `20`, status `30` |
| Stable migration exit codes | Required | Required | apply `40`, recover `41`, status `42` |
| Schema 0 → 1 migration | Required | Required | target manifest and immutable receipt |
| Orphan-backup recovery | Required | Required | deterministic recovery and cleanup |
| Pending migration doctor/status | Required | Required | exit `20` / `30` and recovery state |
| Target create and validate | Required | Required | policy and authorization source digests verified |
| Target immutable identity | Required | Required | active profile identity SHA-256 verified |
| Target source non-persistence | Required | Required | no raw source bytes or source paths stored |
| Target origin/path boundary | Required | Required | unsafe origin, path and reference rejected |
| Target source drift | Required | Required | exit `54` |
| Target disable receipt | Required | Required | create-only receipt binds profile SHA-256 |
| Target profile/receipt tamper | Required | Required | fail closed with exit `52` |
| Target private file mode | Required | N/A | profile and receipt `0600` |
| Target broad ACL rejection | N/A | Required | injected Everyone ACE rejected |
| Stable target exit codes | Required | Required | `50..54` |
| Release manifest schema v2 | Required | Required | canonical schema `2` verified |
| Release sequence binding | Required | Required | positive signed sequence in payload and result |
| Release sequence tamper | Required | Required | signature/manifest verification fails |
| Release zero sequence | Required | Required | template rejected with exit `60` |
| Release binary/SBOM/checksum binding | Required | Required | exact bytes and SHA-256 values |
| Release wrong-key rejection | Required | Required | exit `61` |
| Stable release exit codes | Required | Required | template `60`, verify `61` |
| Diagnostic JSON schema | Required | Required | exact schema/code/domain/operation/exit mapping |
| Diagnostic message bound | Required | Required | single line, no CR/LF/NUL, max 2,048 chars |
| Synthetic authorization/policy | Required | Required | canonical fixture source hashes validate |
| Networkless scan plan | Required | Required | zero issued requests |
| Manual report bundle | Required | Required | JSON, Markdown, HackerOne draft and manifest |
| Automatic submission disabled | Required | Required | manual review preserved |
| Demo receipt | Required | Required | generated and verified |
| Final doctor/status | Required | Required | healthy and ready |
| Installer script parser | N/A | Required | all lifecycle scripts parse without errors |
| Authenticode bootstrap | N/A | Required | valid status and exact publisher thumbprint |
| Release-key bootstrap | N/A | Required | exact public-key file SHA-256 |
| Five-file package contract | N/A | Required | extras, directories and reparse points rejected |
| Clean install sequence 1 | N/A | Required | previous exact source installed |
| Idempotent reinstall | N/A | Required | same signed order returns `already_installed` |
| Signed revision upgrade | N/A | Required | sequence `1 → 2`, distinct source commits |
| Downgrade/replay rejection | N/A | Required | sequence 1 rejected while sequence 2 installed |
| Signed rollback | N/A | Required | sequence `2 → 1` and newer release preserved |
| Post-rollback re-upgrade | N/A | Required | sequence `1 → 2` succeeds again |
| Installer tamper rejection | N/A | Required | modified Authenticode binary rejected before execution |
| Installer transaction recovery | N/A | Required | files and Windows integrations restored on failure |
| Data-preserving uninstall | N/A | Required | install/rollback slots removed, data sentinel remains |
| Exact-head evidence | Required | Required | JSON evidence and artifact SHA-256 values |
| Two-source installer evidence | N/A | Required | previous ancestor and final head both recorded |
| No workflow re-enable | Required | Required | no GitHub Actions workflow added or enabled |
| No NXB-151 lock drift | Required | Required | no `Cargo.lock` modification |

NXB-151 remains draft until every required cell has immutable evidence tied to the final exact commit. Source implementation, static inspection or a single-revision installer run does not satisfy a required evidence cell.
