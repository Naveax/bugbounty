use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    create_document, manifest_schema, now, read_document, remove_regular, replace_document,
    safe_exists, set_private_directory_permissions, sha256, validate_common, validate_identifier,
    validate_manifest_v1, validate_private_permissions, validate_sha, validate_workspace_root,
    LegacyManifestV0, ManifestV1, SecretStorageBoundary, CURRENT_SCHEMA_VERSION, MANIFEST_FILE,
};

const JOURNAL_VERSION: u32 = 1;
const RECEIPT_VERSION: u32 = 1;
const STATE_DIRECTORY: &str = "state";
const RECEIPTS_DIRECTORY: &str = "migrations";
const ACTIVE_FILE: &str = "migration-active.json";
const BACKUP_FILE: &str = "migration-source.json";
const APPLIED_FILE: &str = "migration-applied.json";
const MAX_RECEIPTS: usize = 1_024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparedJournal {
    journal_version: u32,
    migration_id: String,
    from_schema: u32,
    to_schema: u32,
    source_sha256: String,
    target_sha256: String,
    prepared_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AppliedMarker {
    journal_version: u32,
    migration_id: String,
    target_sha256: String,
    applied_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MigrationReceipt {
    receipt_version: u32,
    migration_id: String,
    from_schema: u32,
    to_schema: u32,
    source_sha256: String,
    target_sha256: String,
    committed_at: String,
}

#[derive(Debug)]
struct MigrationPlan {
    migration_id: String,
    source_sha256: String,
    target_sha256: String,
    target_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryDisposition {
    None,
    Recovered,
    Cleanup,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    status: &'static str,
    workspace: String,
    schema_version: Option<u32>,
    migration_id: Option<String>,
    recovery: &'static str,
    details: BTreeMap<String, String>,
}

#[derive(Debug)]
struct MigrationPaths {
    manifest: PathBuf,
    state: PathBuf,
    receipts: PathBuf,
    active: PathBuf,
    backup: PathBuf,
    applied: PathBuf,
}

impl MigrationPaths {
    fn receipt(&self, migration_id: &str) -> PathBuf {
        self.receipts.join(format!("{migration_id}.json"))
    }
}

pub(crate) fn apply_value(workspace: &Path) -> Result<Value> {
    serde_json::to_value(apply_result(workspace)?).context("could not serialize migration result")
}

pub(crate) fn recover_value(workspace: &Path) -> Result<Value> {
    serde_json::to_value(recover_result(workspace)?).context("could not serialize recovery result")
}

pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
    serde_json::to_value(status_result(workspace)?).context("could not serialize migration status")
}

fn apply_result(workspace: &Path) -> Result<CommandResult> {
    let root = validate_workspace_root(workspace, true)?;
    let paths = ensure_state_layout(&root)?;
    let mut recovery = recover_engine(&paths)?;
    let source = read_document(&paths.manifest, "workspace manifest")?;
    let schema = manifest_schema(&source)?;
    let mut migration_id = None;
    let status = match schema {
        CURRENT_SCHEMA_VERSION => {
            let manifest: ManifestV1 =
                serde_json::from_slice(&source).context("current manifest is invalid")?;
            validate_manifest_v1(&manifest)?;
            "current"
        }
        0 => {
            let plan = plan(&source)?;
            prepare(&paths, &plan, &source)?;
            recovery = recover_engine(&paths)?;
            migration_id = Some(plan.migration_id);
            "migrated"
        }
        newer if newer > CURRENT_SCHEMA_VERSION => {
            bail!("workspace schema {newer} is newer than this product")
        }
        other => bail!("no migration path exists from workspace schema {other}"),
    };
    let final_bytes = read_document(&paths.manifest, "workspace manifest")?;
    let final_schema = manifest_schema(&final_bytes)?;
    if final_schema != CURRENT_SCHEMA_VERSION {
        bail!("workspace did not reach the current schema");
    }
    Ok(CommandResult {
        status,
        workspace: root.display().to_string(),
        schema_version: Some(final_schema),
        migration_id,
        recovery: recovery_label(recovery),
        details: BTreeMap::new(),
    })
}

fn recover_result(workspace: &Path) -> Result<CommandResult> {
    let root = validate_workspace_root(workspace, true)?;
    let paths = ensure_state_layout(&root)?;
    let recovery = recover_engine(&paths)?;
    Ok(CommandResult {
        status: "recovered",
        workspace: root.display().to_string(),
        schema_version: optional_manifest_schema(&paths.manifest)?,
        migration_id: None,
        recovery: recovery_label(recovery),
        details: BTreeMap::new(),
    })
}

fn status_result(workspace: &Path) -> Result<CommandResult> {
    let root = validate_workspace_root(workspace, true)?;
    let paths = paths(&root);
    let pending = transient_state(&paths)?;
    let mut details = BTreeMap::new();
    details.insert("pending_files".into(), pending.to_string());
    details.insert("receipts".into(), receipt_count(&paths)?.to_string());
    Ok(CommandResult {
        status: if pending == 0 {
            "stable"
        } else {
            "recovery_required"
        },
        workspace: root.display().to_string(),
        schema_version: optional_manifest_schema(&paths.manifest)?,
        migration_id: None,
        recovery: "none",
        details,
    })
}

fn paths(root: &Path) -> MigrationPaths {
    let state = root.join(STATE_DIRECTORY);
    MigrationPaths {
        manifest: root.join(MANIFEST_FILE),
        receipts: state.join(RECEIPTS_DIRECTORY),
        active: state.join(ACTIVE_FILE),
        backup: state.join(BACKUP_FILE),
        applied: state.join(APPLIED_FILE),
        state,
    }
}

fn ensure_state_layout(root: &Path) -> Result<MigrationPaths> {
    let value = paths(root);
    validate_state_directory(&value)?;
    if !safe_exists(&value.receipts)? {
        fs::create_dir(&value.receipts).with_context(|| {
            format!(
                "could not create migration receipts directory {}",
                value.receipts.display()
            )
        })?;
        set_private_directory_permissions(&value.receipts)?;
    }
    super::reject_path_indirections(&value.receipts, "migration receipts directory")?;
    validate_private_permissions(&value.receipts, true)?;
    Ok(value)
}

fn validate_state_directory(paths: &MigrationPaths) -> Result<()> {
    super::reject_path_indirections(&paths.state, "migration state directory")?;
    let metadata = fs::metadata(&paths.state).context("migration state directory is missing")?;
    if !metadata.is_dir() {
        bail!("migration state path is not a directory");
    }
    validate_private_permissions(&paths.state, true)
}

fn transient_state(paths: &MigrationPaths) -> Result<usize> {
    validate_state_directory(paths)?;
    [
        safe_exists(&paths.active)?,
        safe_exists(&paths.backup)?,
        safe_exists(&paths.applied)?,
    ]
    .into_iter()
    .try_fold(0_usize, |count, present| {
        count
            .checked_add(usize::from(present))
            .ok_or_else(|| anyhow::anyhow!("transient count overflow"))
    })
}

fn receipt_count(paths: &MigrationPaths) -> Result<usize> {
    validate_state_directory(paths)?;
    if !safe_exists(&paths.receipts)? {
        return Ok(0);
    }
    super::reject_path_indirections(&paths.receipts, "migration receipts directory")?;
    validate_private_permissions(&paths.receipts, true)?;
    let mut count = 0_usize;
    for entry in fs::read_dir(&paths.receipts)? {
        let path = entry?.path();
        super::reject_path_indirections(&path, "migration receipt")?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            bail!("migration receipts directory contains a non-file entry");
        }
        validate_private_permissions(&path, false)?;
        count = count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("receipt count overflow"))?;
        if count > MAX_RECEIPTS {
            bail!("migration receipt count exceeds the supported limit");
        }
    }
    Ok(count)
}

fn optional_manifest_schema(path: &Path) -> Result<Option<u32>> {
    if !safe_exists(path)? {
        return Ok(None);
    }
    Ok(Some(manifest_schema(&read_document(
        path,
        "workspace manifest",
    )?)?))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    serde_json::from_slice(&read_document(path, label)?)
        .with_context(|| format!("{label} is invalid JSON"))
}

fn read_optional_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    if safe_exists(path)? {
        read_document(path, label)
    } else {
        Ok(Vec::new())
    }
}

fn create_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    create_document(path, &bytes)
}

fn cleanup(paths: &MigrationPaths) -> Result<()> {
    remove_if_exists(&paths.applied)?;
    remove_if_exists(&paths.active)?;
    remove_if_exists(&paths.backup)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    if safe_exists(path)? {
        remove_regular(path)
    } else {
        Ok(())
    }
}

fn plan(source: &[u8]) -> Result<MigrationPlan> {
    if manifest_schema(source)? != 0 {
        bail!("migration planner expected schema 0");
    }
    let legacy: LegacyManifestV0 =
        serde_json::from_slice(source).context("legacy manifest is invalid")?;
    validate_common(
        legacy.schema_version,
        &legacy.product,
        &legacy.workspace_id,
        &legacy.name,
        &legacy.created_at,
    )?;
    let target = ManifestV1 {
        schema_version: CURRENT_SCHEMA_VERSION,
        product: legacy.product,
        workspace_id: legacy.workspace_id,
        name: legacy.name,
        created_at: legacy.created_at,
        secret_storage: SecretStorageBoundary::ExternalProviderOnly,
    };
    validate_manifest_v1(&target)?;
    let mut target_bytes = serde_json::to_vec_pretty(&target)?;
    target_bytes.push(b'\n');
    let source_sha256 = sha256(source);
    let target_sha256 = sha256(&target_bytes);
    let identity = sha256(format!("nxb-migration-v1:{source_sha256}:{target_sha256}").as_bytes());
    Ok(MigrationPlan {
        migration_id: format!("nxb-migration-0-1-{}", &identity[..24]),
        source_sha256,
        target_sha256,
        target_bytes,
    })
}

fn prepare(paths: &MigrationPaths, plan: &MigrationPlan, source: &[u8]) -> Result<()> {
    if transient_state(paths)? != 0 {
        bail!("migration recovery is required first");
    }
    if sha256(source) != plan.source_sha256 {
        bail!("migration source does not match its plan");
    }
    create_document(&paths.backup, source)?;
    let journal = PreparedJournal {
        journal_version: JOURNAL_VERSION,
        migration_id: plan.migration_id.clone(),
        from_schema: 0,
        to_schema: CURRENT_SCHEMA_VERSION,
        source_sha256: plan.source_sha256.clone(),
        target_sha256: plan.target_sha256.clone(),
        prepared_at: now(),
    };
    if let Err(error) = create_json(&paths.active, &journal) {
        let _ = remove_regular(&paths.backup);
        return Err(error);
    }
    Ok(())
}

fn recover_engine(paths: &MigrationPaths) -> Result<RecoveryDisposition> {
    let active = safe_exists(&paths.active)?;
    let backup = safe_exists(&paths.backup)?;
    let applied = safe_exists(&paths.applied)?;
    if !active && !backup && !applied {
        return Ok(RecoveryDisposition::None);
    }
    if !active && !backup {
        bail!("applied marker exists without prepared state");
    }

    let (journal, source, plan) = if active {
        let journal: PreparedJournal = read_json(&paths.active, "prepared journal")?;
        validate_journal(&journal)?;
        let receipt_path = paths.receipt(&journal.migration_id);
        if safe_exists(&receipt_path)? {
            verify_committed(paths, &journal, &receipt_path)?;
            cleanup(paths)?;
            return Ok(RecoveryDisposition::Cleanup);
        }
        if !backup {
            bail!("prepared journal exists without source backup");
        }
        let source = read_document(&paths.backup, "source backup")?;
        let plan = plan(&source)?;
        validate_journal_plan(&journal, &plan)?;
        (journal, source, plan)
    } else {
        let source = read_document(&paths.backup, "orphan source backup")?;
        let plan = plan(&source)?;
        let journal = PreparedJournal {
            journal_version: JOURNAL_VERSION,
            migration_id: plan.migration_id.clone(),
            from_schema: 0,
            to_schema: CURRENT_SCHEMA_VERSION,
            source_sha256: plan.source_sha256.clone(),
            target_sha256: plan.target_sha256.clone(),
            prepared_at: now(),
        };
        create_json(&paths.active, &journal)?;
        (journal, source, plan)
    };

    if sha256(&source) != journal.source_sha256 {
        bail!("source backup digest mismatch");
    }
    let current = read_optional_document(&paths.manifest, "workspace manifest")?;
    let current_hash = sha256(&current);
    if current.is_empty() || current_hash == plan.source_sha256 {
        replace_document(&paths.manifest, &plan.target_bytes)?;
    } else if current_hash != plan.target_sha256 {
        bail!("workspace manifest changed outside the prepared migration");
    }

    let published = read_document(&paths.manifest, "published manifest")?;
    if sha256(&published) != plan.target_sha256 {
        bail!("published manifest digest mismatch");
    }
    let manifest: ManifestV1 =
        serde_json::from_slice(&published).context("published manifest is invalid")?;
    validate_manifest_v1(&manifest)?;

    if applied {
        let marker: AppliedMarker = read_json(&paths.applied, "applied marker")?;
        validate_marker(&marker, &plan)?;
    } else {
        create_json(
            &paths.applied,
            &AppliedMarker {
                journal_version: JOURNAL_VERSION,
                migration_id: plan.migration_id.clone(),
                target_sha256: plan.target_sha256.clone(),
                applied_at: now(),
            },
        )?;
    }

    let receipt = MigrationReceipt {
        receipt_version: RECEIPT_VERSION,
        migration_id: plan.migration_id.clone(),
        from_schema: 0,
        to_schema: CURRENT_SCHEMA_VERSION,
        source_sha256: plan.source_sha256,
        target_sha256: plan.target_sha256,
        committed_at: now(),
    };
    let receipt_path = paths.receipt(&receipt.migration_id);
    if safe_exists(&receipt_path)? {
        verify_receipt(&receipt_path, &receipt)?;
    } else {
        create_json(&receipt_path, &receipt)?;
    }
    cleanup(paths)?;
    Ok(RecoveryDisposition::Recovered)
}

fn validate_journal(value: &PreparedJournal) -> Result<()> {
    if value.journal_version != JOURNAL_VERSION
        || value.from_schema != 0
        || value.to_schema != CURRENT_SCHEMA_VERSION
    {
        bail!("prepared journal transition is invalid");
    }
    validate_identifier(&value.migration_id, "migration_id")?;
    validate_sha(&value.source_sha256, "source_sha256")?;
    validate_sha(&value.target_sha256, "target_sha256")?;
    validate_time(&value.prepared_at, "prepared_at")
}

fn validate_journal_plan(value: &PreparedJournal, plan: &MigrationPlan) -> Result<()> {
    if value.migration_id != plan.migration_id
        || value.source_sha256 != plan.source_sha256
        || value.target_sha256 != plan.target_sha256
    {
        bail!("prepared journal does not match the deterministic plan");
    }
    Ok(())
}

fn validate_marker(value: &AppliedMarker, plan: &MigrationPlan) -> Result<()> {
    if value.journal_version != JOURNAL_VERSION
        || value.migration_id != plan.migration_id
        || value.target_sha256 != plan.target_sha256
    {
        bail!("applied marker does not match the deterministic plan");
    }
    validate_time(&value.applied_at, "applied_at")
}

fn verify_receipt(path: &Path, expected: &MigrationReceipt) -> Result<()> {
    let actual: MigrationReceipt = read_json(path, "migration receipt")?;
    validate_receipt(&actual)?;
    if actual.migration_id != expected.migration_id
        || actual.from_schema != expected.from_schema
        || actual.to_schema != expected.to_schema
        || actual.source_sha256 != expected.source_sha256
        || actual.target_sha256 != expected.target_sha256
    {
        bail!("existing migration receipt conflicts with the completed migration");
    }
    Ok(())
}

fn verify_committed(
    paths: &MigrationPaths,
    journal: &PreparedJournal,
    receipt_path: &Path,
) -> Result<()> {
    let receipt: MigrationReceipt = read_json(receipt_path, "migration receipt")?;
    validate_receipt(&receipt)?;
    if receipt.migration_id != journal.migration_id
        || receipt.source_sha256 != journal.source_sha256
        || receipt.target_sha256 != journal.target_sha256
    {
        bail!("migration receipt does not match the prepared journal");
    }
    let current = read_document(&paths.manifest, "workspace manifest")?;
    if sha256(&current) != journal.target_sha256 {
        bail!("committed receipt exists but manifest is not the target");
    }
    Ok(())
}

fn validate_receipt(value: &MigrationReceipt) -> Result<()> {
    if value.receipt_version != RECEIPT_VERSION
        || value.from_schema != 0
        || value.to_schema != CURRENT_SCHEMA_VERSION
    {
        bail!("migration receipt transition is invalid");
    }
    validate_identifier(&value.migration_id, "migration_id")?;
    validate_sha(&value.source_sha256, "source_sha256")?;
    validate_sha(&value.target_sha256, "target_sha256")?;
    validate_time(&value.committed_at, "committed_at")
}

fn validate_time(value: &str, field: &str) -> Result<()> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{field} is invalid"))?;
    if parsed.offset().local_minus_utc() != 0 {
        bail!("{field} must use UTC");
    }
    Ok(())
}

fn recovery_label(value: RecoveryDisposition) -> &'static str {
    match value {
        RecoveryDisposition::None => "none",
        RecoveryDisposition::Recovered => "recovered_and_committed",
        RecoveryDisposition::Cleanup => "committed_cleanup",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::{random_hex, set_private_file_permissions};

    fn workspace(name: &str, schema: u32) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nxb-migration-{name}-{}-{}",
            std::process::id(),
            random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        set_private_directory_permissions(&root).unwrap();
        let state = root.join(STATE_DIRECTORY);
        fs::create_dir(&state).unwrap();
        set_private_directory_permissions(&state).unwrap();
        let bytes = if schema == 0 {
            let mut value = serde_json::to_vec_pretty(&LegacyManifestV0 {
                schema_version: 0,
                product: super::super::PRODUCT_NAME.into(),
                workspace_id: "nxb-workspace-test-0001".into(),
                name: "Migration Test".into(),
                created_at: "2026-08-05T00:00:00Z".into(),
            })
            .unwrap();
            value.push(b'\n');
            value
        } else {
            format!(
                "{{\n  \"schema_version\": {schema},\n  \"product\": \"NXBounty\",\n  \"workspace_id\": \"nxb-workspace-test-0001\",\n  \"name\": \"Migration Test\",\n  \"created_at\": \"2026-08-05T00:00:00Z\"\n}}\n"
            )
            .into_bytes()
        };
        fs::write(root.join(MANIFEST_FILE), bytes).unwrap();
        set_private_file_permissions(&root.join(MANIFEST_FILE)).unwrap();
        root
    }

    #[test]
    fn migrates_schema_zero_and_writes_receipt() {
        let root = workspace("apply", 0);
        let value = apply_value(&root).unwrap();
        assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
        let paths = paths(&root);
        assert_eq!(receipt_count(&paths).unwrap(), 1);
        assert_eq!(transient_state(&paths).unwrap(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovers_orphan_backup_before_journal() {
        let root = workspace("orphan", 0);
        let paths = ensure_state_layout(&root).unwrap();
        let source = read_document(&paths.manifest, "manifest").unwrap();
        create_document(&paths.backup, &source).unwrap();
        recover_value(&root).unwrap();
        assert_eq!(optional_manifest_schema(&paths.manifest).unwrap(), Some(1));
        assert_eq!(transient_state(&paths).unwrap(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_manifest_tamper_during_active_migration() {
        let root = workspace("tamper", 0);
        let paths = ensure_state_layout(&root).unwrap();
        let source = read_document(&paths.manifest, "manifest").unwrap();
        let migration = plan(&source).unwrap();
        prepare(&paths, &migration, &source).unwrap();
        replace_document(
            &paths.manifest,
            b"{\"schema_version\":0,\"tampered\":true}\n",
        )
        .unwrap();
        assert!(recover_value(&root)
            .unwrap_err()
            .to_string()
            .contains("changed outside"));
        assert!(paths.backup.is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_future_schema() {
        let root = workspace("future", CURRENT_SCHEMA_VERSION + 1);
        assert!(apply_value(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
