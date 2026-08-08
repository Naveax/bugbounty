use std::{
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};

use crate::{
    diagnostic::{self, DiagnosticSpec},
    workspace,
};

const INIT_EXIT_CODE: u8 = 10;
const DOCTOR_EXIT_CODE: u8 = 20;
const STATUS_EXIT_CODE: u8 = 30;
const MIGRATION_APPLY_EXIT_CODE: u8 = 40;
const MIGRATION_RECOVER_EXIT_CODE: u8 = 41;
const MIGRATION_STATUS_EXIT_CODE: u8 = 42;

const INIT_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-WORKSPACE-INIT-FAILED",
    domain: "workspace",
    operation: "init",
    text_prefix: "NXB-WORKSPACE-10",
};
const DOCTOR_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-WORKSPACE-DOCTOR-UNHEALTHY",
    domain: "workspace",
    operation: "doctor",
    text_prefix: "NXB-WORKSPACE-20",
};
const STATUS_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-WORKSPACE-STATUS-FAILED",
    domain: "workspace",
    operation: "status",
    text_prefix: "NXB-WORKSPACE-30",
};
const MIGRATION_APPLY_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-MIGRATION-APPLY-FAILED",
    domain: "migration",
    operation: "apply",
    text_prefix: "NXB-WORKSPACE-40",
};
const MIGRATION_RECOVER_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-MIGRATION-RECOVER-FAILED",
    domain: "migration",
    operation: "recover",
    text_prefix: "NXB-WORKSPACE-41",
};
const MIGRATION_STATUS_DIAGNOSTIC: DiagnosticSpec = DiagnosticSpec {
    code: "NXB151-MIGRATION-STATUS-FAILED",
    domain: "migration",
    operation: "status",
    text_prefix: "NXB-WORKSPACE-42",
};

#[derive(Debug, Args)]
pub(crate) struct WorkspaceArgs {
    #[command(subcommand)]
    command: WorkspaceCommand,
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// Initialize a private local NXBounty workspace.
    Init {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long, default_value = "Default Workspace")]
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate workspace structure, permissions and migration state.
    Doctor {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Print a redacted workspace and migration summary.
    Status {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Apply, recover or inspect crash-safe workspace schema migrations.
    Migrate {
        #[command(subcommand)]
        command: MigrationCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MigrationCommand {
    Apply {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Recover {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

pub(crate) fn run(args: WorkspaceArgs) -> ExitCode {
    let (failure_code, diagnostic_spec, json_output, result) = match args.command {
        WorkspaceCommand::Init {
            workspace,
            name,
            json,
        } => (
            INIT_EXIT_CODE,
            INIT_DIAGNOSTIC,
            json,
            workspace::initialize_value(&workspace, &name)
                .and_then(|value| emit_value(&value, json)),
        ),
        WorkspaceCommand::Doctor { workspace, json } => (
            DOCTOR_EXIT_CODE,
            DOCTOR_DIAGNOSTIC,
            json,
            run_combined_workspace_view(&workspace, json, ViewKind::Doctor),
        ),
        WorkspaceCommand::Status { workspace, json } => (
            STATUS_EXIT_CODE,
            STATUS_DIAGNOSTIC,
            json,
            run_combined_workspace_view(&workspace, json, ViewKind::Status),
        ),
        WorkspaceCommand::Migrate { command } => match command {
            MigrationCommand::Apply { workspace, json } => (
                MIGRATION_APPLY_EXIT_CODE,
                MIGRATION_APPLY_DIAGNOSTIC,
                json,
                workspace::migration::apply_value(&workspace)
                    .and_then(|value| emit_value(&value, json)),
            ),
            MigrationCommand::Recover { workspace, json } => (
                MIGRATION_RECOVER_EXIT_CODE,
                MIGRATION_RECOVER_DIAGNOSTIC,
                json,
                workspace::migration::recover_value(&workspace)
                    .and_then(|value| emit_value(&value, json)),
            ),
            MigrationCommand::Status { workspace, json } => (
                MIGRATION_STATUS_EXIT_CODE,
                MIGRATION_STATUS_DIAGNOSTIC,
                json,
                workspace::migration::status_value(&workspace)
                    .and_then(|value| emit_value(&value, json)),
            ),
        },
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic::emit_failure(diagnostic_spec, failure_code, json_output, &error);
            ExitCode::from(failure_code)
        }
    }
}

#[derive(Clone, Copy)]
enum ViewKind {
    Doctor,
    Status,
}

fn run_combined_workspace_view(
    workspace_path: &Path,
    json_output: bool,
    kind: ViewKind,
) -> Result<()> {
    let mut product_value = match kind {
        ViewKind::Doctor => workspace::doctor_value(workspace_path)?,
        ViewKind::Status => workspace::status_value(workspace_path)?,
    };

    let migration_result = workspace::migration::status_value(workspace_path);
    let (migration_value, migration_stable) = match migration_result {
        Ok(value) => {
            let stable = value
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "stable");
            (value, stable)
        }
        Err(error) if matches!(kind, ViewKind::Doctor) => (
            json!({
                "status": "unavailable",
                "schema_version": null,
                "migration_id": null,
                "recovery": "none",
                "details": {
                    "error": error.to_string()
                }
            }),
            false,
        ),
        Err(error) => return Err(error),
    };

    let object = product_value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("workspace runtime returned a non-object JSON document"))?;
    object.insert("migration".into(), migration_value.clone());

    let product_healthy = match kind {
        ViewKind::Doctor => {
            integrate_doctor_migration(object, &migration_value, migration_stable)?;
            object.get("errors").and_then(Value::as_u64) == Some(0)
        }
        ViewKind::Status => {
            if !migration_stable {
                object.insert("status".into(), Value::String("recovery_required".into()));
            }
            true
        }
    };

    emit_value(&product_value, json_output)?;
    if !product_healthy {
        bail!("workspace doctor found one or more failing checks");
    }
    if !migration_stable {
        bail!("workspace migration recovery is required before product use");
    }
    Ok(())
}

fn integrate_doctor_migration(
    object: &mut Map<String, Value>,
    migration: &Value,
    migration_stable: bool,
) -> Result<()> {
    let checks = object
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow::anyhow!("workspace doctor output is missing checks"))?;
    let detail = if migration_stable {
        format!(
            "schema={} receipts={} pending_files=0",
            migration
                .get("schema_version")
                .and_then(Value::as_u64)
                .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
            migration
                .pointer("/details/receipts")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )
    } else {
        format!(
            "status={} pending_files={} error={}",
            migration
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            migration
                .pointer("/details/pending_files")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            migration
                .pointer("/details/error")
                .and_then(Value::as_str)
                .unwrap_or("none")
        )
    };
    checks.push(json!({
        "name": "migration_state",
        "status": if migration_stable { "pass" } else { "fail" },
        "detail": detail,
    }));

    if !migration_stable {
        let errors = object.get("errors").and_then(Value::as_u64).unwrap_or(0);
        object.insert(
            "errors".into(),
            Value::from(
                errors
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("doctor error count overflow"))?,
            ),
        );
        object.insert("status".into(), Value::String("unhealthy".into()));
    }
    Ok(())
}

fn emit_value(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
        return Ok(());
    }
    emit_human_value(None, value, 0)
}

fn emit_human_value(key: Option<&str>, value: &Value, depth: usize) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(key) = key {
                println!("{}{}:", "  ".repeat(depth), key);
            }
            let next_depth = depth + usize::from(key.is_some());
            for (child_key, child_value) in object {
                emit_human_value(Some(child_key), child_value, next_depth)?;
            }
        }
        Value::Array(values) => {
            if let Some(key) = key {
                println!("{}{}:", "  ".repeat(depth), key);
            }
            let next_depth = depth + usize::from(key.is_some());
            for value in values {
                println!("{}- {}", "  ".repeat(next_depth), compact_json(value)?);
            }
        }
        _ => {
            let key = key.ok_or_else(|| anyhow::anyhow!("scalar output is missing a key"))?;
            println!("{}{}: {}", "  ".repeat(depth), key, scalar_text(value));
        }
    }
    Ok(())
}

fn compact_json(value: &Value) -> Result<String> {
    serde_json::to_string(value).context("could not serialize output value")
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_migration_integration_marks_recovery_required() {
        let mut object = Map::from_iter([
            ("status".into(), Value::String("healthy".into())),
            ("errors".into(), Value::from(0_u64)),
            ("checks".into(), Value::Array(Vec::new())),
        ]);
        let migration = json!({
            "status": "recovery_required",
            "schema_version": 1,
            "details": {"pending_files": "1", "receipts": "0"}
        });
        integrate_doctor_migration(&mut object, &migration, false).unwrap();
        assert_eq!(
            object.get("status").and_then(Value::as_str),
            Some("unhealthy")
        );
        assert_eq!(object.get("errors").and_then(Value::as_u64), Some(1));
    }
}
