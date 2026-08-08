# NXB-151 Signed Single-Binary Release Manifest

## Purpose

The signed release manifest binds one exact `nxb` executable, CycloneDX SBOM, checksum manifest, source Git commit and monotonic release sequence into one externally signed Ed25519 document.

The product never generates, imports or stores a release private key. Signing occurs in an external trusted process. `nxb` only creates canonical signing bytes and verifies a supplied signature against an operator-selected public key.

## Commands

Create an unsigned canonical template:

```text
nxb release manifest-template \
  --release-id <lowercase-release-id> \
  --release-sequence <positive-u64> \
  --source-commit <40-character-git-sha> \
  --platform <windows|linux> \
  --architecture x86-64 \
  --binary <nxb.exe|nxb> \
  --sbom <cyclonedx-json> \
  --checksums <SHA256SUMS> \
  --generated-at <UTC-RFC3339> \
  --output <release-manifest.json> \
  [--json]
```

The generated document contains:

- canonical manifest-v2 payload;
- signing payload as lowercase hexadecimal;
- signing-payload SHA-256;
- an empty `signature_hex` field.

The external signer signs the exact decoded `signing_payload_hex` bytes with Ed25519 and writes the lowercase 64-byte signature into `signature_hex` without changing another field or the canonical formatting.

Verify the signed document and artifacts:

```text
nxb release verify-manifest \
  --document <signed-release-manifest.json> \
  --public-key <ed25519-public-key.hex> \
  --binary <nxb.exe|nxb> \
  --sbom <cyclonedx-json> \
  --checksums <SHA256SUMS> \
  [--json]
```

## Exit-code and diagnostic contract

| Operation | Failure code | Diagnostic code |
|---|---:|---|
| Manifest template | 60 | `NXB151-RELEASE-MANIFEST-TEMPLATE-FAILED` |
| Manifest verification | 61 | `NXB151-RELEASE-MANIFEST-VERIFY-FAILED` |

JSON failures are emitted only to stderr through the bounded diagnostic schema.

## Manifest-v2 binding

The manifest binds:

- manifest schema version `2`;
- canonical release ID;
- positive `release_sequence`;
- product identity `NXBounty`;
- exact Cargo package version;
- exact lowercase 40-character source commit;
- platform and architecture;
- exact single-binary file name, size and SHA-256;
- exact SBOM file name, size and SHA-256;
- exact checksum-manifest file name, size and SHA-256;
- operator-supplied UTC generation timestamp;
- self-consistent manifest SHA-256.

The Linux binary must be named exactly `nxb`. The Windows binary must be named exactly `nxb.exe`. A helper or second executable cannot be substituted.

## Release sequence

`release_sequence` is an externally governed monotonic revision number in the range:

```text
1..=9223372036854775807
```

It does not replace semantic versioning. Release ordering is the tuple:

```text
(SemVer, release_sequence)
```

This permits two correctly signed releases from distinct exact source commits to use the same package SemVer while retaining an unambiguous upgrade and rollback order. It avoids changing the workspace-wide Cargo version merely to validate installer transactions.

Security rules:

- zero and values above signed 64-bit maximum are rejected;
- the sequence is part of the Ed25519 signing payload and manifest SHA-256;
- modifying it after signing invalidates the document;
- equal order with a different manifest is a replay/conflict and is rejected;
- a higher order must bind a different exact source commit;
- an installer must reject any lower order as downgrade/replay;
- rollback is allowed only to a strictly lower signed order.

The release authority is responsible for allocating each sequence exactly once for the applicable SemVer line.

## Artifact limits

| Artifact | Maximum size |
|---|---:|
| `nxb` / `nxb.exe` | 512 MiB |
| CycloneDX SBOM | 32 MiB |
| checksum manifest | 1 MiB |
| signed release document | 64 KiB |

All input paths are checked for symbolic links and Windows reparse points. Every artifact must be one non-empty regular file.

## SBOM boundary

The SBOM must be JSON and contain:

```text
bomFormat = CycloneDX
specVersion
components array
```

The manifest binds the exact SBOM bytes rather than a normalized representation.

## Checksum boundary

The checksum manifest is canonical LF-terminated UTF-8 text. Each line uses:

```text
<lowercase-sha256><two spaces><file-name>
```

File names cannot contain directories. Duplicate names, CRLF, NUL bytes, malformed hashes and overlong lines are rejected. The manifest must bind the exact binary and SBOM hashes.

## Signature boundary

Verification requires:

- a 32-byte Ed25519 public key encoded as lowercase hexadecimal;
- a 64-byte signature encoded as lowercase hexadecimal;
- exact signing-payload hex and SHA-256 equality;
- successful Ed25519 verification over canonical manifest bytes;
- canonical pretty JSON with one trailing LF;
- exact local artifact equality.

The public key is the external trust anchor selected by the installer, release verifier or operator. The private key never enters the NXBounty process.

## Installer requirement

The Windows installer must not install or upgrade merely because a checksum matches. It must verify:

- candidate Authenticode signature and pinned publisher certificate;
- pinned release-public-key file SHA-256;
- Ed25519 manifest signature;
- exact binary, SBOM and checksum bindings;
- exact `(SemVer, release_sequence)` order;
- distinct source commit for an upgrade.

Installer, upgrade, rollback and uninstall evidence records source commit, release sequence, manifest SHA-256, signature SHA-256 and executable SHA-256.

## Tests

Unit and CLI integration tests cover:

- canonical manifest-v2 template construction;
- external Ed25519 signing round trip;
- release-sequence output;
- zero-sequence rejection;
- sequence tamper rejection;
- binary and signature tamper rejection;
- checksum-manifest mismatch rejection;
- wrong-public-key rejection;
- single-binary filename enforcement;
- diagnostics and exit codes 60/61.

## Non-goals

This layer does not:

- generate or persist release private keys;
- allocate sequence numbers automatically;
- perform Authenticode signing;
- upload releases or create tags;
- install or download software;
- access the network.

Those operations remain external and may proceed only after manifest verification succeeds.

## Validation status

Source, tests and documentation are present on the NXB-151 draft branch. No compiler, Clippy, Linux, Windows or installer pass is claimed until the pinned matrix completes on one unchanged final head.
