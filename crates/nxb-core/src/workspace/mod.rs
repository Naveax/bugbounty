pub(crate) mod migration;

#[cfg(windows)]
mod windows;

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const PRODUCT_NAME: &str = "NXBounty";
pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 1;
pub(crate) const MANIFEST_FILE: &str = "workspace.json";
pub(crate) const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;
const CANONICAL_DIRECTORIES: &[&str] = &[
    "config", "targets", "sessions", "runs", "evidence", "reports", "state", "tmp",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyManifestV0 {
    pub(crate) schema_version: u32,
    pub(crate) product: String,
    pub(crate) workspace_id: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestV1 {
    pub(crate) schema_version: u32,
    pub(crate) product: String,
    pub(crate) workspace_id: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
    pub(crate) secret_storage: SecretStorageBoundary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SecretStorageBoundary {
    ExternalProviderOnly,
}

#[derive(Debug, Serialize)]
struct InitResult {
    status: &'static str,
    workspace: String,
    workspace_id: String,
    schema_version: u32,
    directories_created: usize,
}

#[derive(Debug, Serialize)]
struct DoctorResult {
    status: &'static str,
    workspace: String,
    workspace_id: Option<String>,
    checks: Vec<DoctorCheck>,
    errors: usize,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: String,
    status: CheckStatus,
    detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
struct StatusResult {
    status: &'static str,
    workspace: String,
    workspace_id: String,
    name: String,
    schema_version: u32,
    created_at: String,
    records: BTreeMap<String, u64>,
}

pub(crate) fn initialize_value(workspace: &Path, name: &str) -> Result<Value> {
    serde_json::to_value(initialize_result(workspace, name)?)
        .context("could not serialize workspace initialization result")
}

pub(crate) fn doctor_value(workspace: &Path) -> Result<Value> {
    serde_json::to_value(doctor_result(workspace))
        .context("could not serialize workspace doctor result")
}

pub(crate) fn status_value(workspace: &Path) -> Result<Value> {
    serde_json::to_value(status_result(workspace)?)
        .context("could not serialize workspace status result")
}

fn initialize_result(workspace: &Path, name: &str) -> Result<InitResult> {
    validate_workspace_name(name)?;
    reject_path_indirections(workspace, "workspace root")?;

    let root_created = !workspace.exists();
    if root_created {
        fs::create_dir_all(workspace)
            .with_context(|| format!("could not create workspace {}", workspace.display()))?;
    } else {
        let metadata = fs::metadata(workspace)
            .with_context(|| format!("could not inspect workspace {}", workspace.display()))?;
        if !metadata.is_dir() {
            bail!("workspace root is not a directory: {}", workspace.display());
        }
        let mut entries = fs::read_dir(workspace)
            .with_context(|| format!("could not inspect workspace {}", workspace.display()))?;
        if entries.next().transpose()?.is_some() {
            bail!("workspace directory is not empty: {}", workspace.display());
        }
    }

    let result = initialize_inner(workspace, name);
    if result.is_err() {
        cleanup_partial_workspace(workspace, root_created);
    }
    result
}

fn initialize_inner(workspace: &Path, name: &str) -> Result<InitResult> {
    reject_path_indirections(workspace, "workspace root")?;
    let canonical_root = fs::canonicalize(workspace)
        .with_context(|| format!("could not canonicalize workspace {}", workspace.display()))?;
    reject_path_indirections(&canonical_root, "canonical workspace root")?;
    set_private_directory_permissions(&canonical_root)?;

    for directory in CANONICAL_DIRECTORIES {
        let path = canonical_root.join(directory);
        fs::create_dir(&path)
            .with_context(|| format!("could not create workspace directory {}", path.display()))?;
        set_private_directory_permissions(&path)?;
    }

    let manifest = ManifestV1 {
        schema_version: CURRENT_SCHEMA_VERSION,
        product: PRODUCT_NAME.into(),
        workspace_id: generate_workspace_id(&canonical_root)?,
        name: name.into(),
        created_at: now(),
        secret_storage: SecretStorageBoundary::ExternalProviderOnly,
    };
    validate_manifest_v1(&manifest)?;
    create_json(&canonical_root.join(MANIFEST_FILE), &manifest)?;

    Ok(InitResult {
        status: "initialized",
        workspace: canonical_root.display().to_string(),
        workspace_id: manifest.workspace_id,
        schema_version: manifest.schema_version,
        directories_created: CANONICAL_DIRECTORIES.len(),
    })
}

fn doctor_result(workspace: &Path) -> DoctorResult {
    let mut checks = Vec::new();
    let canonical_root = match validate_workspace_root(workspace, false) {
        Ok(root) => {
            checks.push(pass_check(
                "workspace_root",
                format!("canonical root: {}", root.display()),
            ));
            Some(root)
        }
        Err(error) => {
            checks.push(fail_check("workspace_root", error.to_string()));
            None
        }
    };

    let mut workspace_id = None;
    if let Some(root) = &canonical_root {
        match read_manifest(root) {
            Ok(manifest) => {
                workspace_id = Some(manifest.workspace_id.clone());
                checks.push(pass_check(
                    "manifest",
                    format!(
                        "schema={} secret_storage=external_provider_only",
                        manifest.schema_version
                    ),
                ));
            }
            Err(error) => checks.push(fail_check("manifest", error.to_string())),
        }

        for directory in CANONICAL_DIRECTORIES {
            let path = root.join(directory);
            match validate_private_directory(&path) {
                Ok(()) => checks.push(pass_check(
                    format!("directory_{directory}"),
                    path.display().to_string(),
                )),
                Err(error) => checks.push(fail_check(
                    format!("directory_{directory}"),
                    error.to_string(),
                )),
            }
        }

        match write_probe(root) {
            Ok(()) => checks.push(pass_check(
                "atomic_write_probe",
                "create-new, private-permissions, sync and cleanup succeeded",
            )),
            Err(error) => checks.push(fail_check("atomic_write_probe", error.to_string())),
        }
    }

    let errors = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .count();
    DoctorResult {
        status: if errors == 0 { "healthy" } else { "unhealthy" },
        workspace: workspace.display().to_string(),
        workspace_id,
        checks,
        errors,
    }
}

fn status_result(workspace: &Path) -> Result<StatusResult> {
    let canonical_root = validate_workspace_root(workspace, false)?;
    let manifest = read_manifest(&canonical_root)?;
    let mut records = BTreeMap::new();
    for directory in ["targets", "sessions", "runs", "evidence", "reports"] {
        records.insert(
            directory.to_string(),
            count_regular_files(&canonical_root.join(directory))?,
        );
    }
    Ok(StatusResult {
        status: "ready",
        workspace: canonical_root.display().to_string(),
        workspace_id: manifest.workspace_id,
        name: manifest.name,
        schema_version: manifest.schema_version,
        created_at: manifest.created_at,
        records,
    })
}

pub(crate) fn validate_workspace_root(workspace: &Path, require_absolute: bool) -> Result<PathBuf> {
    if require_absolute && !workspace.is_absolute() {
        bail!("workspace path must be absolute");
    }
    reject_path_indirections(workspace, "workspace root")?;
    let metadata = fs::metadata(workspace)
        .with_context(|| format!("workspace does not exist: {}", workspace.display()))?;
    if !metadata.is_dir() {
        bail!("workspace root is not a directory: {}", workspace.display());
    }
    validate_private_permissions(workspace, true)?;
    let canonical = fs::canonicalize(workspace)
        .with_context(|| format!("could not canonicalize workspace {}", workspace.display()))?;
    reject_path_indirections(&canonical, "canonical workspace root")?;
    Ok(canonical)
}

fn read_manifest(workspace: &Path) -> Result<ManifestV1> {
    let path = workspace.join(MANIFEST_FILE);
    let bytes = read_document(&path, "workspace manifest")?;
    let manifest: ManifestV1 = serde_json::from_slice(&bytes)
        .with_context(|| format!("workspace manifest is invalid: {}", path.display()))?;
    validate_manifest_v1(&manifest)?;
    Ok(manifest)
}

pub(crate) fn manifest_schema(bytes: &[u8]) -> Result<u32> {
    let value: Value = serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
    let raw = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("manifest schema_version is missing or invalid"))?;
    u32::try_from(raw).context("manifest schema_version is too large")
}

pub(crate) fn validate_manifest_v1(manifest: &ManifestV1) -> Result<()> {
    validate_common(
        manifest.schema_version,
        &manifest.product,
        &manifest.workspace_id,
        &manifest.name,
        &manifest.created_at,
    )?;
    if manifest.schema_version != CURRENT_SCHEMA_VERSION {
        bail!("current manifest schema is invalid");
    }
    if manifest.secret_storage != SecretStorageBoundary::ExternalProviderOnly {
        bail!("unsupported secret-storage boundary");
    }
    Ok(())
}

pub(crate) fn validate_common(
    schema: u32,
    product: &str,
    id: &str,
    name: &str,
    created_at: &str,
) -> Result<()> {
    if schema > CURRENT_SCHEMA_VERSION {
        bail!("workspace schema is newer than this product");
    }
    if product != PRODUCT_NAME {
        bail!("workspace product identity does not match");
    }
    validate_identifier(id, "workspace_id")?;
    validate_workspace_name(name)?;
    let parsed = chrono::DateTime::parse_from_rfc3339(created_at)
        .context("workspace created_at is not valid RFC3339 time")?;
    if parsed.offset().local_minus_utc() != 0 {
        bail!("workspace created_at must use UTC");
    }
    Ok(())
}

fn validate_private_directory(path: &Path) -> Result<()> {
    reject_path_indirections(path, "workspace directory")?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("workspace directory is missing: {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("workspace path is not a directory: {}", path.display());
    }
    validate_private_permissions(path, true)
}

pub(crate) fn reject_path_indirections(path: &Path, label: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("could not resolve current directory")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => bail!("{label} must not contain parent traversal"),
            Component::Normal(value) => current.push(value),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata_is_indirection(&metadata) => {
                bail!("{label} contains a path indirection: {}", current.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("could not inspect {}", current.display()))
            }
        }
    }
    Ok(())
}

fn metadata_is_indirection(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        windows::is_reparse_point(metadata)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn generate_workspace_id(workspace: &Path) -> Result<String> {
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    let mut digest = Sha256::new();
    digest.update(b"nxb-product-workspace-v1");
    digest.update(random);
    digest.update(workspace.as_os_str().to_string_lossy().as_bytes());
    digest.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_le_bytes(),
    );
    random.fill(0);
    Ok(format!("nxb-workspace-{}", &hex(&digest.finalize())[..32]))
}

fn create_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    create_document(path, &bytes)
}

pub(crate) fn create_document(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        bail!("output document size is invalid");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output path has no parent"))?;
    reject_path_indirections(parent, "output parent")?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("output file name is invalid"))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("could not create temporary file {}", temporary.display()))?;
        set_private_file_permissions(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        if safe_exists(path)? {
            bail!("create-new destination already exists: {}", path.display());
        }
        fs::rename(&temporary, path).with_context(|| {
            format!(
                "could not publish {} as {}",
                temporary.display(),
                path.display()
            )
        })?;
        set_private_file_permissions(path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn replace_document(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        bail!("replacement document size is invalid");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("document has no parent"))?;
    reject_path_indirections(parent, "document parent")?;
    reject_path_indirections(path, "workspace document")?;
    let temporary = parent.join(format!(".workspace.migrate.{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_file_permissions(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        replace_file(&temporary, path)?;
        set_private_file_permissions(path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn read_document(path: &Path, label: &str) -> Result<Vec<u8>> {
    reject_path_indirections(path, label)?;
    let metadata =
        fs::metadata(path).with_context(|| format!("{label} is missing: {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_DOCUMENT_BYTES {
        bail!("{label} size or type is invalid");
    }
    validate_private_permissions(path, false)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        bail!("{label} exceeds the supported size limit");
    }
    Ok(bytes)
}

fn write_probe(workspace: &Path) -> Result<()> {
    let path = workspace
        .join("tmp")
        .join(format!("doctor-write-probe-{}.tmp", random_hex(12)?));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("could not create write probe {}", path.display()))?;
        set_private_file_permissions(&path)?;
        output.write_all(b"nxb-doctor-probe\n")?;
        output.sync_all()?;
        drop(output);
        validate_private_permissions(&path, false)?;
        fs::remove_file(&path)
            .with_context(|| format!("could not remove write probe {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&path);
    }
    result
}

fn count_regular_files(path: &Path) -> Result<u64> {
    validate_private_directory(path)?;
    let mut count = 0_u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        if metadata_is_indirection(&metadata) {
            bail!(
                "record directory contains a symbolic link or reparse point: {}",
                entry_path.display()
            );
        }
        if metadata.is_file() {
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("record count overflow"))?;
        }
    }
    Ok(count)
}

fn cleanup_partial_workspace(workspace: &Path, root_created: bool) {
    remove_path_without_following(&workspace.join(MANIFEST_FILE));
    if let Ok(entries) = fs::read_dir(workspace) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if file_name.to_string_lossy().starts_with(".workspace.json.") {
                remove_path_without_following(&entry.path());
            }
        }
    }
    for directory in CANONICAL_DIRECTORIES.iter().rev() {
        remove_path_without_following(&workspace.join(directory));
    }
    if root_created {
        let _ = fs::remove_dir(workspace);
    }
}

fn remove_path_without_following(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata_is_indirection(&metadata) {
        if metadata.is_dir() {
            let _ = fs::remove_dir(path);
        } else {
            let _ = fs::remove_file(path);
        }
    } else if metadata.is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn validate_workspace_name(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed != value
        || trimmed.is_empty()
        || trimmed.len() > 96
        || trimmed.chars().any(char::is_control)
    {
        bail!("workspace name must contain 1-96 printable characters without edge whitespace");
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 192
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("invalid {field}");
    }
    Ok(())
}

pub(crate) fn validate_sha(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid {field}");
    }
    Ok(())
}

pub(crate) fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut value)
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    let encoded = hex(&value);
    value.fill(0);
    Ok(encoded)
}

fn pass_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: CheckStatus::Pass,
        detail: detail.into(),
    }
}

fn fail_check(name: impl Into<String>, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status: CheckStatus::Fail,
        detail: detail.into(),
    }
}

pub(crate) fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn safe_exists(path: &Path) -> Result<bool> {
    reject_path_indirections(path, "workspace path")?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata_is_indirection(&metadata) {
                bail!("path indirection is not allowed: {}", path.display());
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn remove_regular(path: &Path) -> Result<()> {
    reject_path_indirections(path, "workspace transient file")?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("workspace transient path is not a regular file");
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn set_private_directory_permissions(path: &Path) -> Result<()> {
    windows::set_private_directory_permissions(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn set_private_file_permissions(path: &Path) -> Result<()> {
    windows::set_private_file_permissions(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "workspace path permissions are too broad: {}",
            path.display()
        );
    }
    let required = if directory { 0o700 } else { 0o600 };
    if mode & required != required {
        bail!(
            "workspace path permissions are incomplete: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    windows::validate_private_permissions(path, directory)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn validate_private_permissions(_path: &Path, _directory: bool) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(not(unix))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        remove_regular(destination)?;
    }
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path(test_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nxb-workspace-{test_name}-{}-{}",
            std::process::id(),
            random_hex(8).unwrap()
        ))
    }

    #[test]
    fn initializes_and_reads_canonical_workspace() {
        let path = temporary_path("init");
        let value = initialize_value(&path, "Test Workspace").unwrap();
        assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(1));
        let root = validate_workspace_root(&path, false).unwrap();
        let manifest = read_manifest(&root).unwrap();
        assert_eq!(manifest.schema_version, CURRENT_SCHEMA_VERSION);
        for directory in CANONICAL_DIRECTORIES {
            assert!(root.join(directory).is_dir());
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn refuses_non_empty_workspace() {
        let path = temporary_path("non-empty");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("existing.txt"), b"occupied").unwrap();
        let error = initialize_value(&path, "Test Workspace").unwrap_err();
        assert!(error.to_string().contains("not empty"));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn doctor_detects_missing_canonical_directory() {
        let path = temporary_path("doctor");
        initialize_value(&path, "Test Workspace").unwrap();
        fs::remove_dir(path.join("evidence")).unwrap();
        let value = doctor_value(&path).unwrap();
        assert_eq!(
            value.get("status").and_then(Value::as_str),
            Some("unhealthy")
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn status_counts_only_regular_records() {
        let path = temporary_path("status");
        initialize_value(&path, "Test Workspace").unwrap();
        fs::write(path.join("targets").join("one.json"), b"{}\n").unwrap();
        set_private_file_permissions(&path.join("targets").join("one.json")).unwrap();
        fs::create_dir(path.join("targets").join("nested")).unwrap();
        set_private_directory_permissions(&path.join("targets").join("nested")).unwrap();
        let value = status_value(&path).unwrap();
        assert_eq!(
            value.pointer("/records/targets").and_then(Value::as_u64),
            Some(1)
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_workspace_component() {
        use std::os::unix::fs::symlink;

        let root = temporary_path("symlink-root");
        let target = temporary_path("symlink-target");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, root.join("linked")).unwrap();
        let error =
            reject_path_indirections(&root.join("linked").join("workspace"), "test").unwrap_err();
        assert!(error.to_string().contains("path indirection"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(target).unwrap();
    }
}
