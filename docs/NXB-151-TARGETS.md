# NXB-151 Fail-Closed Authorization-Bound Target Profiles

## Purpose

The `nxb target` command group turns one operator-approved HTTPS origin, bounded path prefixes, a validated target policy and an external authorization document into an immutable local target profile.

Target management is networkless. It performs no DNS lookup, socket creation, HTTP request, browser discovery, proxy import or credential access.

The profile does not claim that authorization is true. It records the exact SHA-256 bindings and safe reference needed to prove which local policy and authorization bytes the operator reviewed. Raw authorization bytes, policy bytes and local source paths are never persisted in the workspace target profile.

## Supported commands

```text
nxb target create \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  --name <display-name> \
  --origin <https-origin> \
  [--include-path <absolute-prefix>]... \
  [--exclude-path <absolute-prefix>]... \
  --authorization-reference <safe-reference> \
  --authorization-document <local-file> \
  --policy <target-policy.toml> \
  [--json]

nxb target validate \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  --authorization-document <local-file> \
  --policy <target-policy.toml> \
  [--json]

nxb target list \
  --workspace <absolute-workspace> \
  [--include-disabled] \
  [--json]

nxb target show \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  [--json]

nxb target disable \
  --workspace <absolute-workspace> \
  --id <lowercase-slug> \
  --reason <operator-hold|program-ended|scope-removed|authorization-expired> \
  [--json]
```

## Exit-code and diagnostic contract

| Operation | Failure code | Diagnostic code |
|---|---:|---|
| Target create | 50 | `NXB151-TARGET-CREATE-REJECTED` |
| Target list | 51 | `NXB151-TARGET-LIST-INVALID` |
| Target show | 52 | `NXB151-TARGET-SHOW-INVALID` |
| Target disable | 53 | `NXB151-TARGET-DISABLE-REJECTED` |
| Target validate | 54 | `NXB151-TARGET-VALIDATE-INVALID` |

With `--json`, failures are written only to stderr as bounded machine-readable diagnostic JSON. Text mode retains the stable `NXB-TARGET-<exit-code>` prefix.

## Immutable schema-v2 profile

Profiles and disable receipts are stored under the protected workspace `targets` directory:

```text
targets/<target-id>.json
targets/<target-id>.disabled.json
```

A schema-v2 target profile contains only:

- target ID and display name;
- canonical exact HTTPS origin;
- canonical include and exclude path prefixes;
- the read-only methods permitted by both the product and supplied policy;
- program name, platform and optional policy reference derived from the parsed policy;
- a bounded authorization reference;
- SHA-256 of the exact authorization document bytes;
- SHA-256 of the exact policy bytes;
- SHA-256 identity binding every immutable profile field;
- UTC creation timestamp.

The profile is create-only. `show` and `list` recompute and verify the profile identity SHA-256, so active-profile content tampering is rejected even before a disable receipt exists.

Disabling a target publishes a separate create-only receipt containing:

- receipt schema version;
- exact target ID;
- SHA-256 of the canonical immutable profile;
- bounded disable reason;
- UTC disable timestamp.

A repeated disable operation is idempotent only when the existing receipt validates against the exact profile. A receipt without its profile, identity/file-name mismatch, digest mismatch, unexpected file, non-file entry, symlink or Windows reparse point causes fail-closed rejection.

## Policy and authorization binding

Creation reads at most:

- 1 MiB from the target policy;
- 8 MiB from the authorization document.

Both source paths are checked for symbolic links and Windows reparse points. The policy must be UTF-8 TOML and compile successfully at the current time. Its authorization must be current, its automation limits valid, and the exact origin host must be allowed.

Program metadata is derived from the policy rather than supplied separately by the operator. The stored method set is the intersection of the product read-only boundary and the policy. At least `GET` or `HEAD` must remain permitted.

`target validate` re-reads the supplied source files and requires:

- exact policy SHA-256 equality;
- exact authorization-document SHA-256 equality;
- successful current policy compilation;
- exact program metadata equality;
- exact origin-host scope equality;
- exact read-only method equality;
- valid profile and optional disable-receipt identity chains.

The authorization reference is metadata only. It must be bounded ASCII without whitespace, query parameters or credentials. It may identify an external program/scope record but cannot contain secret material.

## Origin boundary

A target origin must be one canonical HTTPS origin:

```text
https://example.org
https://example.org:8443
```

The following are rejected:

- HTTP or any non-HTTPS scheme;
- username or password components;
- paths, queries or fragments;
- wildcard or backslash syntax;
- IPv4 or IPv6 literals;
- missing or malformed DNS labels;
- localhost and reserved/local suffixes including `.local`, `.internal`, `.invalid`, `.test`, `.example` and `.home.arpa`.

Port 443 is omitted from canonical storage. A non-default HTTPS port remains explicit. Target creation does not resolve the host.

## Path-prefix boundary

A target contains at most 64 include prefixes and 64 exclude prefixes. Each prefix is at most 512 bytes and must:

- begin with exactly one `/`;
- contain no backslash, wildcard, percent encoding, query, fragment, whitespace or control character;
- contain no `.` or `..` segment;
- omit a trailing slash unless the path is `/`.

If no include prefix is supplied, `/` is used. Duplicate rules are rejected. An excluded prefix must be strictly inside at least one included prefix and cannot remove the complete included prefix. Excluding `/` is prohibited.

## Read-only method boundary

The product maximum is:

```text
GET
HEAD
OPTIONS
```

The supplied policy may reduce this set. Target creation fails unless the resulting exact-origin set includes at least `GET` or `HEAD`. Later policy, authorization, activation, gateway and runtime layers may reduce it further but cannot expand it.

## Workspace and migration prerequisites

Every target operation requires:

- an absolute canonical workspace path;
- valid private workspace permissions or protected Windows ACLs;
- an existing protected `targets` directory;
- a workspace status of `ready`;
- a stable migration state with no pending journal, backup or applied marker.

Pending migration blocks target operations before any profile read or write.

## Bounded directory contract

The target directory supports at most 1,024 profiles and their matching disable receipts. Every entry must be a private regular file with one supported canonical name. Unknown files and nested directories are rejected rather than ignored.

## Validation sources

Unit and CLI integration tests cover:

- create, validate, list, show and disable lifecycle;
- authorization and policy digest binding;
- secret bytes and local source-path non-persistence;
- program metadata derived from policy;
- active-profile identity tamper rejection;
- policy/authorization source drift rejection;
- active-only and include-disabled views;
- unsafe origin, reference and path rejection;
- out-of-policy host rejection;
- pending migration rejection;
- disable-receipt tamper rejection;
- machine-readable target diagnostics.

Platform acceptance harnesses:

```text
bash scripts/validate-nxb-151-target-linux.sh
pwsh -NoProfile -File .\scripts\validate-nxb-151-target-windows.ps1
```

The Linux harness additionally checks private file modes. The Windows harness injects a broad Everyone allow ACE and requires fail-closed rejection. Successful harnesses bind their result to the exact Git head and single `nxb` executable SHA-256 under `target/nxb-validation/`.

## Explicit non-goals

This layer does not:

- import HackerOne or other platform scopes automatically;
- prove ownership or authorization merely because a local document exists;
- persist raw policy or authorization bytes;
- persist cookies, tokens, API keys, browser state or proxy captures;
- resolve DNS or validate destination IPs;
- start scanning or live execution;
- submit reports;
- reactivate a disabled target.

A disabled target remains disabled because its immutable receipt is never deleted or overwritten by this command group.

## Validation status

Source, unit tests, CLI integration tests, documentation and local harnesses are present on the NXB-151 draft branch. No compiler, Clippy, Windows or Linux acceptance pass is claimed until pinned Rust 1.97.1 and all platform harnesses complete on the same exact head.
