use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use chrono::DateTime;
use clap::{Args, Subcommand, ValueEnum};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    diagnostic::{self, DiagnosticSpec},
    workspace,
};

const RELEASE_MANIFEST_VERSION: u32 = 2;
const TEMPLATE_EXIT_CODE: u8 = 60;
const VERIFY_EXIT_CODE: u8 = 61;
const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SBOM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024 * 1024;
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;

const TEMPLATE_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-RELEASE-MANIFEST-TEMPLATE-FAILED",
    domain: "release",
    operation: "manifest_template",
    text_prefix: "NXB-RELEASE-60",
};
const VERIFY_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-RELEASE-MANIFEST-VERIFY-FAILED",
    domain: "release",
    operation: "verify_manifest",
    text_prefix: "NXB-RELEASE-61",
};

#[derive(Debug, Args)]
pub(crate) struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Build a canonical single-binary release manifest for external Ed25519 signing.
    ManifestTemplate {
        #[arg(long)]
        release_id: String,
        #[arg(long)]
        release_sequence: u64,
        #[arg(long)]
        source_commit: String,
        #[arg(long, value_enum)]
        platform: ReleasePlatform,
        #[arg(long, value_enum)]
        architecture: ReleaseArchitecture,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        checksums: PathBuf,
        #[arg(long)]
        generated_at: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a signed release manifest and all bound local artifacts.
    VerifyManifest {
        #[arg(long)]
        document: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        checksums: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ReleasePlatform {
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ReleaseArchitecture {
    X86_64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    manifest_version: u32,
    release_id: String,
    release_sequence: u64,
    product: String,
    version: String,
    source_commit: String,
    platform: ReleasePlatform,
    architecture: ReleaseArchitecture,
    binary: ArtifactBinding,
    sbom: ArtifactBinding,
    checksums: ArtifactBinding,
    generated_at: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArtifactBinding {
    file_name: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedReleaseDocument {
    manifest: ReleaseManifest,
    signing_payload_hex: String,
    signing_payload_sha256: String,
    signature_hex: String,
}

#[derive(Debug, Serialize)]
struct VerificationResult {
    status: &'static str,
    release_id: String,
    release_sequence: u64,
    version: String,
    source_commit: String,
    platform: ReleasePlatform,
    architecture: ReleaseArchitecture,
    manifest_sha256: String,
    signature_sha256: String,
    document_sha256: String,
    network_activity: &'static str,
}

pub(crate) fn run(args: ReleaseArgs) -> ExitCode {
    let (exit_code, spec, json_output, result) = match args.command {
        ReleaseCommand::ManifestTemplate {
            release_id,
            release_sequence,
            source_commit,
            platform,
            architecture,
            binary,
            sbom,
            checksums,
            generated_at,
            output,
            json,
        } => (
            TEMPLATE_EXIT_CODE,
            TEMPLATE_DIAGNOSTIC,
            json,
            manifest_template_value(
                &release_id,
                release_sequence,
                &source_commit,
                platform,
                architecture,
                &binary,
                &sbom,
                &checksums,
                &generated_at,
                &output,
            )
            .and_then(|value| emit_value(&value, json)),
        ),
        ReleaseCommand::VerifyManifest {
            document,
            public_key,
            binary,
            sbom,
            checksums,
            json,
        } => (
            VERIFY_EXIT_CODE,
            VERIFY_DIAGNOSTIC,
            json,
            verify_manifest_value(&document, &public_key, &binary, &sbom, &checksums)
                .and_then(|value| emit_value(&value, json)),
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic::emit_failure(spec, exit_code, json_output, &error);
            ExitCode::from(exit_code)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn manifest_template_value(
    release_id: &str,
    release_sequence: u64,
    source_commit: &str,
    platform: ReleasePlatform,
    architecture: ReleaseArchitecture,
    binary_path: &Path,
    sbom_path: &Path,
    checksums_path: &Path,
    generated_at: &str,
    output: &Path,
) -> Result<Value> {
    validate_release_id(release_id)?;
    validate_release_sequence(release_sequence)?;
    validate_source_commit(source_commit)?;
    validate_utc_timestamp(generated_at)?;

    let binary = artifact_binding(binary_path, "release binary", MAX_BINARY_BYTES)?;
    let sbom = artifact_binding(sbom_path, "CycloneDX SBOM", MAX_SBOM_BYTES)?;
    let checksums = artifact_binding(checksums_path, "checksum manifest", MAX_CHECKSUM_BYTES)?;
    validate_binary_name(platform, &binary.file_name)?;
    validate_sbom(&read_bounded(sbom_path, "CycloneDX SBOM", MAX_SBOM_BYTES)?)?;
    validate_checksum_manifest(
        &read_bounded(checksums_path, "checksum manifest", MAX_CHECKSUM_BYTES)?,
        &binary,
        &sbom,
    )?;

    let mut manifest = ReleaseManifest {
        manifest_version: RELEASE_MANIFEST_VERSION,
        release_id: release_id.to_owned(),
        release_sequence,
        product: "NXBounty".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: source_commit.to_owned(),
        platform,
        architecture,
        binary,
        sbom,
        checksums,
        generated_at: generated_at.to_owned(),
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest_sha256(&manifest)?;
    validate_manifest(&manifest)?;

    let signing_payload = signing_bytes(&manifest)?;
    let document = SignedReleaseDocument {
        manifest,
        signing_payload_hex: lower_hex(&signing_payload),
        signing_payload_sha256: workspace::sha256(&signing_payload),
        signature_hex: String::new(),
    };
    workspace::create_document(output, &canonical_json(&document)?)?;
    serde_json::to_value(document).context("could not serialize release manifest template")
}

fn verify_manifest_value(
    document_path: &Path,
    public_key_path: &Path,
    binary_path: &Path,
    sbom_path: &Path,
    checksums_path: &Path,
) -> Result<Value> {
    let document_bytes =
        read_bounded(document_path, "signed release manifest", MAX_DOCUMENT_BYTES)?;
    let document: SignedReleaseDocument = serde_json::from_slice(&document_bytes)
        .context("signed release manifest is invalid JSON")?;
    if document_bytes != canonical_json(&document)? {
        bail!("signed release manifest is not canonical JSON");
    }

    validate_manifest(&document.manifest)?;
    let signing_payload = signing_bytes(&document.manifest)?;
    if document.signing_payload_hex != lower_hex(&signing_payload)
        || document.signing_payload_sha256 != workspace::sha256(&signing_payload)
    {
        bail!("release signing payload does not match the manifest");
    }

    let binary = artifact_binding(binary_path, "release binary", MAX_BINARY_BYTES)?;
    let sbom = artifact_binding(sbom_path, "CycloneDX SBOM", MAX_SBOM_BYTES)?;
    let checksums = artifact_binding(checksums_path, "checksum manifest", MAX_CHECKSUM_BYTES)?;
    if binary != document.manifest.binary
        || sbom != document.manifest.sbom
        || checksums != document.manifest.checksums
    {
        bail!("release artifacts do not match the signed manifest");
    }
    validate_binary_name(document.manifest.platform, &binary.file_name)?;
    validate_sbom(&read_bounded(sbom_path, "CycloneDX SBOM", MAX_SBOM_BYTES)?)?;
    validate_checksum_manifest(
        &read_bounded(checksums_path, "checksum manifest", MAX_CHECKSUM_BYTES)?,
        &binary,
        &sbom,
    )?;

    let public_key = read_hex_file(public_key_path, "release public key", 32)?;
    let signature = decode_hex(&document.signature_hex, "release signature")?;
    if signature.len() != 64 {
        bail!("release signature must contain 64 Ed25519 bytes");
    }
    UnparsedPublicKey::new(&ED25519, &public_key)
        .verify(&signing_payload, &signature)
        .map_err(|_| anyhow::anyhow!("release Ed25519 signature verification failed"))?;

    serde_json::to_value(VerificationResult {
        status: "valid",
        release_id: document.manifest.release_id,
        release_sequence: document.manifest.release_sequence,
        version: document.manifest.version,
        source_commit: document.manifest.source_commit,
        platform: document.manifest.platform,
        architecture: document.manifest.architecture,
        manifest_sha256: document.manifest.manifest_sha256,
        signature_sha256: workspace::sha256(&signature),
        document_sha256: workspace::sha256(&document_bytes),
        network_activity: "none",
    })
    .context("could not serialize release verification result")
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<()> {
    if manifest.manifest_version != RELEASE_MANIFEST_VERSION
        || manifest.product != "NXBounty"
        || manifest.version != env!("CARGO_PKG_VERSION")
    {
        bail!("release manifest product or version contract is invalid");
    }
    validate_release_id(&manifest.release_id)?;
    validate_release_sequence(manifest.release_sequence)?;
    validate_source_commit(&manifest.source_commit)?;
    validate_utc_timestamp(&manifest.generated_at)?;
    validate_artifact(&manifest.binary, "release binary", MAX_BINARY_BYTES)?;
    validate_artifact(&manifest.sbom, "CycloneDX SBOM", MAX_SBOM_BYTES)?;
    validate_artifact(&manifest.checksums, "checksum manifest", MAX_CHECKSUM_BYTES)?;
    validate_binary_name(manifest.platform, &manifest.binary.file_name)?;
    workspace::validate_sha(&manifest.manifest_sha256, "release manifest SHA-256")?;
    if manifest.manifest_sha256 != manifest_sha256(manifest)? {
        bail!("release manifest SHA-256 does not match its content");
    }
    Ok(())
}

fn artifact_binding(path: &Path, label: &str, maximum: u64) -> Result<ArtifactBinding> {
    let bytes = read_bounded(path, label, maximum)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("{label} file name is invalid"))?
        .to_owned();
    let binding = ArtifactBinding {
        file_name,
        size_bytes: bytes.len() as u64,
        sha256: workspace::sha256(&bytes),
    };
    validate_artifact(&binding, label, maximum)?;
    Ok(binding)
}

fn validate_artifact(binding: &ArtifactBinding, label: &str, maximum: u64) -> Result<()> {
    if binding.file_name.is_empty()
        || binding.file_name.len() > 128
        || !binding.file_name.is_ascii()
        || !binding
            .file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || binding.size_bytes == 0
        || binding.size_bytes > maximum
    {
        bail!("{label} binding is invalid");
    }
    workspace::validate_sha(&binding.sha256, &format!("{label} SHA-256"))
}

fn validate_binary_name(platform: ReleasePlatform, file_name: &str) -> Result<()> {
    let expected = match platform {
        ReleasePlatform::Windows => "nxb.exe",
        ReleasePlatform::Linux => "nxb",
    };
    if file_name != expected {
        bail!("single-binary release requires artifact name {expected}");
    }
    Ok(())
}

fn validate_sbom(bytes: &[u8]) -> Result<()> {
    let value: Value = serde_json::from_slice(bytes).context("CycloneDX SBOM is invalid JSON")?;
    if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || value.get("specVersion").and_then(Value::as_str).is_none()
        || value.get("components").and_then(Value::as_array).is_none()
    {
        bail!("CycloneDX SBOM is missing required fields");
    }
    Ok(())
}

fn validate_checksum_manifest(
    bytes: &[u8],
    binary: &ArtifactBinding,
    sbom: &ArtifactBinding,
) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("checksum manifest must be UTF-8")?;
    if !text.ends_with('\n') || text.contains('\r') || text.contains('\0') {
        bail!("checksum manifest must use canonical LF-terminated text");
    }

    let mut entries = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() || line.len() > 256 {
            bail!("checksum manifest contains an invalid line");
        }
        let (sha256, file_name) = line
            .split_once("  ")
            .ok_or_else(|| anyhow::anyhow!("checksum line must use two-space separation"))?;
        workspace::validate_sha(sha256, "checksum entry SHA-256")?;
        if file_name.is_empty()
            || file_name.len() > 128
            || !file_name.is_ascii()
            || file_name.contains('/')
            || file_name.contains('\\')
            || !file_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("checksum entry file name is invalid");
        }
        if entries
            .insert(file_name.to_owned(), sha256.to_owned())
            .is_some()
        {
            bail!("checksum manifest contains a duplicate file name");
        }
    }

    if entries.len() < 2
        || entries.get(&binary.file_name) != Some(&binary.sha256)
        || entries.get(&sbom.file_name) != Some(&sbom.sha256)
    {
        bail!("checksum manifest does not bind the exact binary and SBOM");
    }
    Ok(())
}

fn signing_bytes(manifest: &ReleaseManifest) -> Result<Vec<u8>> {
    validate_manifest(manifest)?;
    serde_json::to_vec(manifest).context("could not serialize release signing payload")
}

fn manifest_sha256(manifest: &ReleaseManifest) -> Result<String> {
    let mut material = manifest.clone();
    material.manifest_sha256.clear();
    Ok(workspace::sha256(&serde_json::to_vec(&material)?))
}

fn validate_release_id(value: &str) -> Result<()> {
    if !(3..=96).contains(&value.len())
        || !value.is_ascii()
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        bail!("release_id must be a canonical lowercase release identifier");
    }
    Ok(())
}

fn validate_release_sequence(value: u64) -> Result<()> {
    if value == 0 || value > i64::MAX as u64 {
        bail!("release_sequence must be between 1 and 9223372036854775807");
    }
    Ok(())
}

fn validate_source_commit(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("source_commit must be one lowercase 40-character Git SHA");
    }
    Ok(())
}

fn validate_utc_timestamp(value: &str) -> Result<()> {
    let parsed = DateTime::parse_from_rfc3339(value).context("generated_at is invalid RFC3339")?;
    if parsed.offset().local_minus_utc() != 0 {
        bail!("generated_at must use UTC");
    }
    Ok(())
}

fn read_bounded(path: &Path, label: &str, maximum: u64) -> Result<Vec<u8>> {
    workspace::reject_path_indirections(path, label)?;
    let metadata =
        fs::metadata(path).with_context(|| format!("{label} is missing: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("{label} size or type is invalid");
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("{label} exceeds the supported size limit");
    }
    Ok(bytes)
}

fn read_hex_file(path: &Path, label: &str, expected_bytes: usize) -> Result<Vec<u8>> {
    let bytes = read_bounded(path, label, 4096)?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{label} must be UTF-8 hex"))?
        .trim();
    let decoded = decode_hex(text, label)?;
    if decoded.len() != expected_bytes {
        bail!("{label} must contain {expected_bytes} bytes");
    }
    Ok(decoded)
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must use lowercase hexadecimal encoding");
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
            let low = hex_value(pair[1]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn emit_value(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else if let Some(object) = value.as_object() {
        for (key, item) in object {
            match item {
                Value::Array(_) | Value::Object(_) => {
                    println!("{key}: {}", serde_json::to_string(item)?);
                }
                Value::String(item) => println!("{key}: {item}"),
                other => println!("{key}: {other}"),
            }
        }
    } else {
        println!("{}", serde_json::to_string(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    const SOURCE_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CYCLONEDX_FIXTURE: &[u8] =
        b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}";

    struct Fixture {
        root: PathBuf,
        binary: PathBuf,
        sbom: PathBuf,
        checksums: PathBuf,
        document: PathBuf,
        public_key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "nxb-release-manifest-{}-{}",
                std::process::id(),
                workspace::random_hex(8).unwrap()
            ));
            fs::create_dir_all(&root).unwrap();

            let binary = root.join("nxb");
            let sbom = root.join("nxb.cdx.json");
            let checksums = root.join("SHA256SUMS");
            let document = root.join("release-manifest.json");
            let public_key = root.join("release-public-key.hex");

            fs::write(&binary, b"synthetic-nxb-binary").unwrap();
            fs::write(&sbom, CYCLONEDX_FIXTURE).unwrap();

            let binary_sha = workspace::sha256(&fs::read(&binary).unwrap());
            let sbom_sha = workspace::sha256(&fs::read(&sbom).unwrap());
            fs::write(
                &checksums,
                format!("{binary_sha}  nxb\n{sbom_sha}  nxb.cdx.json\n"),
            )
            .unwrap();

            Self {
                root,
                binary,
                sbom,
                checksums,
                document,
                public_key,
            }
        }

        fn template(&self, release_sequence: u64) -> SignedReleaseDocument {
            manifest_template_value(
                "v0.1.0-test",
                release_sequence,
                SOURCE_COMMIT,
                ReleasePlatform::Linux,
                ReleaseArchitecture::X86_64,
                &self.binary,
                &self.sbom,
                &self.checksums,
                "2026-08-05T15:00:00Z",
                &self.document,
            )
            .unwrap();
            serde_json::from_slice(&fs::read(&self.document).unwrap()).unwrap()
        }

        fn sign(&self, release_sequence: u64) -> SignedReleaseDocument {
            let mut document = self.template(release_sequence);
            let key_pair = Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).unwrap();
            document.signature_hex = lower_hex(
                key_pair
                    .sign(&signing_bytes(&document.manifest).unwrap())
                    .as_ref(),
            );
            fs::write(&self.public_key, lower_hex(key_pair.public_key().as_ref())).unwrap();
            fs::write(&self.document, canonical_json(&document).unwrap()).unwrap();
            document
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn signed_release_round_trip_verifies() {
        let fixture = Fixture::new();
        let document = fixture.sign(7);
        let value = verify_manifest_value(
            &fixture.document,
            &fixture.public_key,
            &fixture.binary,
            &fixture.sbom,
            &fixture.checksums,
        )
        .unwrap();

        assert_eq!(value.get("status").and_then(Value::as_str), Some("valid"));
        assert_eq!(
            value.get("release_sequence").and_then(Value::as_u64),
            Some(7)
        );
        assert_eq!(
            value.get("manifest_sha256").and_then(Value::as_str),
            Some(document.manifest.manifest_sha256.as_str())
        );
    }

    #[test]
    fn binary_and_signature_tampering_are_rejected() {
        let fixture = Fixture::new();
        fixture.sign(1);
        fs::write(&fixture.binary, b"tampered-binary").unwrap();
        assert!(verify_manifest_value(
            &fixture.document,
            &fixture.public_key,
            &fixture.binary,
            &fixture.sbom,
            &fixture.checksums,
        )
        .is_err());

        fs::write(&fixture.binary, b"synthetic-nxb-binary").unwrap();
        let mut document: SignedReleaseDocument =
            serde_json::from_slice(&fs::read(&fixture.document).unwrap()).unwrap();
        let mut signature = decode_hex(&document.signature_hex, "signature").unwrap();
        signature[0] ^= 1;
        document.signature_hex = lower_hex(&signature);
        fs::write(&fixture.document, canonical_json(&document).unwrap()).unwrap();
        assert!(verify_manifest_value(
            &fixture.document,
            &fixture.public_key,
            &fixture.binary,
            &fixture.sbom,
            &fixture.checksums,
        )
        .is_err());
    }

    #[test]
    fn checksum_mismatch_and_zero_sequence_are_rejected() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.checksums,
            "0000000000000000000000000000000000000000000000000000000000000000  nxb\n",
        )
        .unwrap();
        assert!(manifest_template_value(
            "v0.1.0-test",
            1,
            SOURCE_COMMIT,
            ReleasePlatform::Linux,
            ReleaseArchitecture::X86_64,
            &fixture.binary,
            &fixture.sbom,
            &fixture.checksums,
            "2026-08-05T15:00:00Z",
            &fixture.document,
        )
        .is_err());

        assert!(manifest_template_value(
            "v0.1.0-test",
            0,
            SOURCE_COMMIT,
            ReleasePlatform::Linux,
            ReleaseArchitecture::X86_64,
            &fixture.binary,
            &fixture.sbom,
            &fixture.checksums,
            "2026-08-05T15:00:00Z",
            &fixture.document,
        )
        .is_err());
    }
}
