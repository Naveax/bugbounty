use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

fn nxb() -> &'static str {
    env!("CARGO_BIN_EXE_nxb")
}

fn temporary_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "nxb-diagnostic-{name}-{}-{nonce}",
        std::process::id()
    ))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(nxb())
        .args(arguments)
        .output()
        .expect("could not execute nxb")
}

fn assert_diagnostic(
    output: &Output,
    expected_exit: i32,
    expected_code: &str,
    expected_domain: &str,
    expected_operation: &str,
) {
    assert_eq!(output.status.code(), Some(expected_exit));
    let value: Value =
        serde_json::from_slice(&output.stderr).expect("failure stderr is not diagnostic JSON");
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
    assert_eq!(value.get("status").and_then(Value::as_str), Some("error"));
    assert_eq!(
        value.get("code").and_then(Value::as_str),
        Some(expected_code)
    );
    assert_eq!(
        value.get("domain").and_then(Value::as_str),
        Some(expected_domain)
    );
    assert_eq!(
        value.get("operation").and_then(Value::as_str),
        Some(expected_operation)
    );
    assert_eq!(
        value.get("exit_code").and_then(Value::as_i64),
        Some(i64::from(expected_exit))
    );
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .expect("diagnostic message is missing");
    assert!(!message.is_empty());
    assert!(!message
        .chars()
        .any(|value| matches!(value, '\n' | '\r' | '\0')));
}

#[test]
fn workspace_init_and_doctor_emit_stable_json_diagnostics() {
    let occupied = temporary_path("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("unexpected.txt"), b"occupied\n").unwrap();
    let occupied_text = occupied.to_str().unwrap();
    let output = run(&[
        "workspace",
        "init",
        "--workspace",
        occupied_text,
        "--name",
        "Occupied",
        "--json",
    ]);
    assert_diagnostic(
        &output,
        10,
        "NXB151-WORKSPACE-INIT-FAILED",
        "workspace",
        "init",
    );

    let missing = temporary_path("missing");
    let missing_text = missing.to_str().unwrap();
    let output = run(&["workspace", "doctor", "--workspace", missing_text, "--json"]);
    assert_diagnostic(
        &output,
        20,
        "NXB151-WORKSPACE-DOCTOR-UNHEALTHY",
        "workspace",
        "doctor",
    );

    fs::remove_dir_all(occupied).unwrap();
}

#[test]
fn workspace_status_and_migration_status_emit_stable_json_diagnostics() {
    let root = temporary_path("pending");
    let root_text = root.to_str().unwrap();
    let initialized = run(&[
        "workspace",
        "init",
        "--workspace",
        root_text,
        "--name",
        "Pending Migration",
        "--json",
    ]);
    assert!(initialized.status.success());

    fs::write(root.join("state").join("migration-active.json"), b"{}\n").unwrap();
    let output = run(&["workspace", "status", "--workspace", root_text, "--json"]);
    assert_diagnostic(
        &output,
        30,
        "NXB151-WORKSPACE-STATUS-FAILED",
        "workspace",
        "status",
    );
    assert!(
        !output.stdout.is_empty(),
        "status must preserve its redacted state document"
    );

    let missing = temporary_path("missing-migration");
    let missing_text = missing.to_str().unwrap();
    let output = run(&[
        "workspace",
        "migrate",
        "status",
        "--workspace",
        missing_text,
        "--json",
    ]);
    assert_diagnostic(
        &output,
        42,
        "NXB151-MIGRATION-STATUS-FAILED",
        "migration",
        "status",
    );

    fs::remove_dir_all(root).unwrap();
}
