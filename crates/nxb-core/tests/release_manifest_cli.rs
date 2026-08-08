use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};

const TEMPLATE_EXIT_CODE: i32 = 60;
const VERIFY_EXIT_CODE: i32 = 61;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_directory(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb-release-cli-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(nxb())
        .args(arguments)
        .output()
        .expect("could not execute nxb")
}

fn run_json(arguments: &[&str]) -> Value {
    let output = run(arguments);
    assert!(
        output.status.success(),
        "command failed: status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("command returned invalid JSON")
}

fn assert_diagnostic(output: &Output, expected_exit: i32, expected_code: &str) {
    assert_eq!(output.status.code(), Some(expected_exit));
    assert!(output.stdout.is_empty());
    let value: Value = serde_json::from_slice(&output.stderr).expect("invalid diagnostic JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some(expected_code)
    );
    assert_eq!(value.get("domain").and_then(Value::as_str), Some("release"));
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(expected_exit))
    );
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

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let nibble = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            (nibble(pair[0]) << 4) | nibble(pair[1])
        })
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

struct Fixture {
    root: PathBuf,
    binary: PathBuf,
    sbom: PathBuf,
    checksums: PathBuf,
    public_key: PathBuf,
    document: PathBuf,
    key_pair: Ed25519KeyPair,
}

impl Fixture {
    fn new() -> Self {
        let root = temporary_directory("round-trip");
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("nxb");
        let sbom = root.join("nxb.cdx.json");
        let checksums = root.join("SHA256SUMS");
        let public_key = root.join("release-public-key.hex");
        let document = root.join("release-manifest.json");

        fs::write(&binary, b"synthetic-single-nxb-binary").unwrap();
        fs::write(
            &sbom,
            br#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}"#,
        )
        .unwrap();
        fs::write(
            &checksums,
            format!(
                "{}  nxb\n{}  nxb.cdx.json\n",
                sha256(&fs::read(&binary).unwrap()),
                sha256(&fs::read(&sbom).unwrap())
            ),
        )
        .unwrap();

        let key_pair = Ed25519KeyPair::from_seed_unchecked(&[9_u8; 32]).unwrap();
        fs::write(&public_key, lower_hex(key_pair.public_key().as_ref())).unwrap();

        Self {
            root,
            binary,
            sbom,
            checksums,
            public_key,
            document,
            key_pair,
        }
    }

    fn template(&self, release_sequence: u64) -> Value {
        let release_sequence = release_sequence.to_string();
        run_json(&[
            "release",
            "manifest-template",
            "--release-id",
            "v0.1.0-cli-test",
            "--release-sequence",
            &release_sequence,
            "--source-commit",
            "a234567890123456789012345678901234567890",
            "--platform",
            "linux",
            "--architecture",
            "x86-64",
            "--binary",
            path(&self.binary),
            "--sbom",
            path(&self.sbom),
            "--checksums",
            path(&self.checksums),
            "--generated-at",
            "2026-08-05T15:00:00Z",
            "--output",
            path(&self.document),
            "--json",
        ])
    }

    fn sign(&self, release_sequence: u64) -> Value {
        let mut document = self.template(release_sequence);
        let signing_payload = decode_hex(
            document
                .get("signing_payload_hex")
                .and_then(Value::as_str)
                .expect("signing payload is missing"),
        );
        document["signature_hex"] =
            Value::String(lower_hex(self.key_pair.sign(&signing_payload).as_ref()));
        let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
        bytes.push(b'\n');
        fs::write(&self.document, bytes).unwrap();
        document
    }

    fn verify(&self) -> Output {
        run(&[
            "release",
            "verify-manifest",
            "--document",
            path(&self.document),
            "--public-key",
            path(&self.public_key),
            "--binary",
            path(&self.binary),
            "--sbom",
            path(&self.sbom),
            "--checksums",
            path(&self.checksums),
            "--json",
        ])
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn path(value: &Path) -> &str {
    value.to_str().expect("temporary path is not UTF-8")
}

#[test]
fn release_cli_template_sign_and_verify_round_trip() {
    let fixture = Fixture::new();
    let document = fixture.sign(42);
    assert_eq!(
        document
            .pointer("/manifest/binary/file_name")
            .and_then(Value::as_str),
        Some("nxb")
    );
    assert_eq!(
        document
            .pointer("/manifest/release_sequence")
            .and_then(Value::as_u64),
        Some(42)
    );

    let output = fixture.verify();
    assert!(
        output.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value.get("status").and_then(Value::as_str), Some("valid"));
    assert_eq!(
        value.get("release_sequence").and_then(Value::as_u64),
        Some(42)
    );
    assert_eq!(
        value.get("network_activity").and_then(Value::as_str),
        Some("none")
    );
}

#[test]
fn release_cli_rejects_binary_and_sequence_tampering() {
    let fixture = Fixture::new();
    fixture.sign(1);

    fs::write(&fixture.binary, b"tampered-single-binary").unwrap();
    assert_diagnostic(
        &fixture.verify(),
        VERIFY_EXIT_CODE,
        "NXB151-RELEASE-MANIFEST-VERIFY-FAILED",
    );

    fs::write(&fixture.binary, b"synthetic-single-nxb-binary").unwrap();
    let mut document: Value =
        serde_json::from_slice(&fs::read(&fixture.document).unwrap()).unwrap();
    document["manifest"]["release_sequence"] = Value::from(2_u64);
    let mut bytes = serde_json::to_vec_pretty(&document).unwrap();
    bytes.push(b'\n');
    fs::write(&fixture.document, bytes).unwrap();
    assert_diagnostic(
        &fixture.verify(),
        VERIFY_EXIT_CODE,
        "NXB151-RELEASE-MANIFEST-VERIFY-FAILED",
    );
}

#[test]
fn release_cli_rejects_invalid_binary_name_zero_sequence_and_wrong_key() {
    let fixture = Fixture::new();
    let invalid_binary = fixture.root.join("nxb-helper");
    fs::write(&invalid_binary, b"not-the-primary-binary").unwrap();

    for (binary, sequence) in [
        (invalid_binary.as_path(), "1"),
        (fixture.binary.as_path(), "0"),
    ] {
        let output = run(&[
            "release",
            "manifest-template",
            "--release-id",
            "v0.1.0-invalid",
            "--release-sequence",
            sequence,
            "--source-commit",
            "a234567890123456789012345678901234567890",
            "--platform",
            "linux",
            "--architecture",
            "x86-64",
            "--binary",
            path(binary),
            "--sbom",
            path(&fixture.sbom),
            "--checksums",
            path(&fixture.checksums),
            "--generated-at",
            "2026-08-05T15:00:00Z",
            "--output",
            path(&fixture.document),
            "--json",
        ]);
        assert_diagnostic(
            &output,
            TEMPLATE_EXIT_CODE,
            "NXB151-RELEASE-MANIFEST-TEMPLATE-FAILED",
        );
    }

    fixture.sign(1);
    let wrong_key = fixture.root.join("wrong-public-key.hex");
    let pair = Ed25519KeyPair::from_seed_unchecked(&[10_u8; 32]).unwrap();
    fs::write(&wrong_key, lower_hex(pair.public_key().as_ref())).unwrap();

    let output = run(&[
        "release",
        "verify-manifest",
        "--document",
        path(&fixture.document),
        "--public-key",
        path(&wrong_key),
        "--binary",
        path(&fixture.binary),
        "--sbom",
        path(&fixture.sbom),
        "--checksums",
        path(&fixture.checksums),
        "--json",
    ]);
    assert_diagnostic(
        &output,
        VERIFY_EXIT_CODE,
        "NXB151-RELEASE-MANIFEST-VERIFY-FAILED",
    );
}
