# NXB-151 Product Diagnostics

## Purpose

NXB-151 product commands preserve stable process exit codes and add a separate machine-readable diagnostic subcode. Automation must not parse human error prose.

The diagnostic contract currently applies to:

- `nxb workspace ...`;
- `nxb workspace migrate ...`;
- `nxb target ...`.

Legacy scan, policy, demo, activation and live-run command failures retain their previous exit-code and text behavior in this milestone.

## JSON failure envelope

When a product command is invoked with `--json` and fails after command-line parsing, stderr contains exactly one compact JSON document followed by one newline:

```json
{
  "schema_version": 1,
  "status": "error",
  "code": "NXB151-TARGET-CREATE-REJECTED",
  "domain": "target",
  "operation": "create",
  "exit_code": 50,
  "message": "target origin must be an HTTPS origin without credentials, path, query or fragment"
}
```

The process exits using the same numeric operation code. Successful JSON documents continue to use stdout. A command may emit a redacted status document to stdout before reporting an unhealthy or recovery-required condition on stderr; callers must always inspect the process exit code.

## Text failure envelope

Without `--json`, stderr uses a bounded single-line form:

```text
NXB-TARGET-50 [NXB151-TARGET-CREATE-REJECTED] domain=target operation=create: <message>
```

The bracketed diagnostic code and numeric exit code are stable. Human message wording is informational and is not a compatibility surface.

## Schema fields

| Field | Contract |
|---|---|
| `schema_version` | Integer diagnostic schema, currently `1` |
| `status` | Always `error` |
| `code` | Stable milestone-scoped diagnostic subcode |
| `domain` | Product subsystem |
| `operation` | Requested operation |
| `exit_code` | Exact process failure code |
| `message` | Bounded single-line human detail |

Messages are limited to 2,048 Unicode scalar values. CR, LF and NUL are removed. Backtraces and environment dumps are never included.

## Registered NXB-151 diagnostic codes

### Workspace

| Code | Exit | Operation |
|---|---:|---|
| `NXB151-WORKSPACE-INIT-FAILED` | 10 | `workspace init` |
| `NXB151-WORKSPACE-DOCTOR-UNHEALTHY` | 20 | `workspace doctor` |
| `NXB151-WORKSPACE-STATUS-FAILED` | 30 | `workspace status` |

### Migration

| Code | Exit | Operation |
|---|---:|---|
| `NXB151-MIGRATION-APPLY-FAILED` | 40 | `workspace migrate apply` |
| `NXB151-MIGRATION-RECOVER-FAILED` | 41 | `workspace migrate recover` |
| `NXB151-MIGRATION-STATUS-FAILED` | 42 | `workspace migrate status` |

### Target profiles

| Code | Exit | Operation |
|---|---:|---|
| `NXB151-TARGET-CREATE-REJECTED` | 50 | `target create` |
| `NXB151-TARGET-LIST-INVALID` | 51 | `target list` |
| `NXB151-TARGET-SHOW-INVALID` | 52 | `target show` |
| `NXB151-TARGET-DISABLE-REJECTED` | 53 | `target disable` |
| `NXB151-TARGET-VALIDATE-INVALID` | 54 | `target validate` |

## Stability rules

- A registered code is never reassigned to another domain or operation.
- The numeric exit code remains the coarse operation boundary.
- The diagnostic code remains the machine-readable subcode.
- New fields may only be added in a backward-compatible manner within schema version `1`.
- Removing or changing the meaning/type of a field requires a new schema version.
- Message wording may change and must not be parsed.
- Clap argument-shape errors occur before product dispatch and retain Clap's own exit behavior.

## Security boundaries

Diagnostic output must not contain:

- cookies, session tokens or authorization headers;
- raw secret/key material;
- provider handles;
- evidence bodies;
- browser or proxy state;
- process environment dumps;
- Rust backtraces.

Product errors may include an operator-supplied local path when needed for repair. They must not include file contents.

## Validation

Unit and integration tests verify:

- schema version and status;
- exact code/domain/operation/exit mapping;
- valid compact JSON on stderr;
- bounded single-line message behavior;
- target create/list/show/validate failure codes;
- workspace init/doctor/status failure codes;
- migration status failure code;
- preservation of redacted stdout status when an unhealthy state is reported.

The diagnostic contract is not considered validated until the pinned Rust 1.97.1 tests and Windows/Linux acceptance harnesses pass on the same exact NXB-151 head.
