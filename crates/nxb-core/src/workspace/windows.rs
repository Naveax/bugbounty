use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use anyhow::{bail, Context, Result};

use super::{random_hex, reject_path_indirections};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const WINDOWS_SYSTEM_SID: &str = "S-1-5-18";
const WINDOWS_ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const WINDOWS_FORBIDDEN_ALLOW_SIDS: &[&str] = &["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];
const WINDOWS_FORBIDDEN_ALLOW_ALIASES: &[&str] = &["WD", "AU", "BU"];
const MAX_WINDOWS_ACL_EXPORT_BYTES: u64 = 128 * 1024;

pub(super) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(super) fn set_private_directory_permissions(path: &Path) -> Result<()> {
    harden_windows_acl(path, true)
}

pub(super) fn set_private_file_permissions(path: &Path) -> Result<()> {
    harden_windows_acl(path, false)
}

pub(super) fn validate_private_permissions(path: &Path, directory: bool) -> Result<()> {
    let current_sid = current_windows_user_sid()?;
    validate_windows_acl_with_sid(path, directory, &current_sid)
}

fn harden_windows_acl(path: &Path, directory: bool) -> Result<()> {
    reject_path_indirections(path, "Windows ACL target")?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("Windows ACL target is missing: {}", path.display()))?;
    if directory != metadata.is_dir() {
        bail!("Windows ACL target type does not match: {}", path.display());
    }

    let current_sid = current_windows_user_sid()?;
    let rights = if directory { "(OI)(CI)F" } else { "F" };
    let mut arguments = vec![
        OsString::from("/inheritance:r"),
        OsString::from("/grant:r"),
        OsString::from(format!("*{current_sid}:{rights}")),
        OsString::from(format!("*{WINDOWS_SYSTEM_SID}:{rights}")),
        OsString::from(format!("*{WINDOWS_ADMINISTRATORS_SID}:{rights}")),
        OsString::from("/remove:g"),
    ];
    arguments.extend(
        WINDOWS_FORBIDDEN_ALLOW_SIDS
            .iter()
            .map(|sid| OsString::from(format!("*{sid}"))),
    );
    arguments.push(OsString::from("/q"));
    run_icacls(path, &arguments)?;
    validate_windows_acl_with_sid(path, directory, &current_sid)
}

fn validate_windows_acl_with_sid(path: &Path, directory: bool, current_sid: &str) -> Result<()> {
    reject_path_indirections(path, "Windows ACL target")?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("Windows ACL target is missing: {}", path.display()))?;
    if directory != metadata.is_dir() {
        bail!("Windows ACL target type does not match: {}", path.display());
    }

    run_icacls(path, &[OsString::from("/verify"), OsString::from("/q")])?;
    let sddl = export_windows_acl_sddl(path)?;
    if !sddl.contains("D:P") {
        bail!(
            "Windows ACL inheritance is not protected: {}",
            path.display()
        );
    }
    if !sddl_has_full_control(&sddl, current_sid)
        || !(sddl_has_full_control(&sddl, WINDOWS_SYSTEM_SID) || sddl_has_full_control(&sddl, "SY"))
        || !(sddl_has_full_control(&sddl, WINDOWS_ADMINISTRATORS_SID)
            || sddl_has_full_control(&sddl, "BA"))
    {
        bail!(
            "Windows ACL required full-control entries are missing: {}",
            path.display()
        );
    }
    for principal in WINDOWS_FORBIDDEN_ALLOW_SIDS
        .iter()
        .chain(WINDOWS_FORBIDDEN_ALLOW_ALIASES.iter())
    {
        if sddl_has_allow_ace(&sddl, principal) {
            bail!(
                "Windows ACL contains a broad allow entry for {principal}: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn current_windows_user_sid() -> Result<String> {
    let output = run_windows_system_tool(
        "whoami.exe",
        &[
            OsString::from("/user"),
            OsString::from("/fo"),
            OsString::from("csv"),
            OsString::from("/nh"),
        ],
    )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let sid = text
        .trim()
        .rsplit(',')
        .next()
        .map(|value| value.trim().trim_matches('"'))
        .ok_or_else(|| anyhow::anyhow!("whoami did not return a user SID"))?;
    if !valid_windows_sid(sid) {
        bail!("whoami returned an invalid user SID");
    }
    Ok(sid.to_string())
}

fn valid_windows_sid(value: &str) -> bool {
    let Some(remainder) = value.strip_prefix("S-") else {
        return false;
    };
    !remainder.is_empty()
        && value.len() <= 184
        && remainder
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
}

fn run_icacls(path: &Path, arguments: &[OsString]) -> Result<Output> {
    let mut complete = Vec::with_capacity(arguments.len() + 1);
    complete.push(windows_cli_path(path));
    complete.extend_from_slice(arguments);
    run_windows_system_tool("icacls.exe", &complete)
}

fn run_windows_system_tool(name: &str, arguments: &[OsString]) -> Result<Output> {
    if !name.ends_with(".exe")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("Windows system tool name is invalid");
    }
    let root = windows_system_root()?;
    let tool = root.join("System32").join(name);
    if !tool.is_absolute() {
        bail!("Windows system tool path is not absolute");
    }
    reject_path_indirections(&tool, "Windows system tool")?;
    let metadata = fs::metadata(&tool)
        .with_context(|| format!("Windows system tool is missing: {}", tool.display()))?;
    if !metadata.is_file() {
        bail!(
            "Windows system tool is not a regular file: {}",
            tool.display()
        );
    }

    let output = Command::new(&tool)
        .args(arguments)
        .stdin(Stdio::null())
        .env_clear()
        .env("SystemRoot", &root)
        .env("WINDIR", &root)
        .output()
        .with_context(|| format!("could not execute Windows system tool {}", tool.display()))?;
    if !output.status.success() {
        let detail = bounded_process_detail(&output.stderr);
        bail!(
            "Windows system tool {} failed with status {}: {}",
            tool.display(),
            output.status,
            detail
        );
    }
    Ok(output)
}

fn windows_system_root() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("Windows system root is unavailable"))?;
    if !root.is_absolute() {
        bail!("Windows system root is not absolute");
    }
    reject_path_indirections(&root, "Windows system root")?;
    fs::canonicalize(&root).with_context(|| {
        format!(
            "could not canonicalize Windows system root {}",
            root.display()
        )
    })
}

fn windows_cli_path(path: &Path) -> OsString {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    const VERBATIM_PREFIX: &[u16] = &[92, 92, 63, 92];
    const VERBATIM_UNC_PREFIX: &[u16] = &[92, 92, 63, 92, 85, 78, 67, 92];
    const UNC_PREFIX: &[u16] = &[92, 92];

    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.starts_with(VERBATIM_UNC_PREFIX) {
        let mut normal = Vec::with_capacity(encoded.len() - VERBATIM_UNC_PREFIX.len() + 2);
        normal.extend_from_slice(UNC_PREFIX);
        normal.extend_from_slice(&encoded[VERBATIM_UNC_PREFIX.len()..]);
        return OsString::from_wide(&normal);
    }
    if encoded.starts_with(VERBATIM_PREFIX) {
        return OsString::from_wide(&encoded[VERBATIM_PREFIX.len()..]);
    }
    OsStr::new(path.as_os_str()).to_os_string()
}

fn bounded_process_detail(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(512).collect()
}

fn export_windows_acl_sddl(path: &Path) -> Result<String> {
    let export = std::env::temp_dir().join(format!("nxb-acl-{}.txt", random_hex(16)?));
    reject_path_indirections(
        export
            .parent()
            .ok_or_else(|| anyhow::anyhow!("ACL export has no parent"))?,
        "ACL export parent",
    )?;
    let result = (|| {
        run_icacls(
            path,
            &[
                OsString::from("/save"),
                windows_cli_path(&export),
                OsString::from("/q"),
            ],
        )?;
        let metadata = fs::metadata(&export)
            .with_context(|| format!("ACL export is missing: {}", export.display()))?;
        if metadata.len() == 0 || metadata.len() > MAX_WINDOWS_ACL_EXPORT_BYTES {
            bail!("ACL export size is invalid");
        }
        let bytes = fs::read(&export)
            .with_context(|| format!("could not read ACL export {}", export.display()))?;
        decode_windows_text(&bytes)
    })();
    let _ = fs::remove_file(&export);
    result
}

fn decode_windows_text(bytes: &[u8]) -> Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        if !(bytes.len() - 2).is_multiple_of(2) {
            bail!("UTF-16 ACL export has an invalid byte length");
        }
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return String::from_utf16(&units).context("ACL export is not valid UTF-16");
    }
    String::from_utf8(bytes.to_vec()).context("ACL export is not valid UTF-8")
}

fn sddl_has_full_control(sddl: &str, principal: &str) -> bool {
    sddl_aces(sddl)
        .any(|ace| ace.ace_type == "A" && ace.rights.contains("FA") && ace.principal == principal)
}

fn sddl_has_allow_ace(sddl: &str, principal: &str) -> bool {
    sddl_aces(sddl).any(|ace| ace.ace_type == "A" && ace.principal == principal)
}

struct SddlAce<'a> {
    ace_type: &'a str,
    rights: &'a str,
    principal: &'a str,
}

fn sddl_aces(sddl: &str) -> impl Iterator<Item = SddlAce<'_>> {
    sddl.split('(').filter_map(|segment| {
        let ace = segment.split_once(')')?.0;
        let mut fields = ace.split(';');
        let ace_type = fields.next()?;
        let _flags = fields.next()?;
        let rights = fields.next()?;
        let _object_guid = fields.next()?;
        let _inherit_object_guid = fields.next()?;
        let principal = fields.next()?;
        Some(SddlAce {
            ace_type,
            rights,
            principal,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_windows_sid_shape() {
        assert!(valid_windows_sid("S-1-5-21-100-200-300-1001"));
        assert!(!valid_windows_sid("1-5-21-100"));
        assert!(!valid_windows_sid("S-1-invalid"));
    }

    #[test]
    fn normalizes_verbatim_windows_paths_for_system_tools() {
        let input = Path::new(r"\\?\C:\NXBounty\workspace.json");
        assert_eq!(
            windows_cli_path(input),
            OsString::from(r"C:\NXBounty\workspace.json")
        );
        let unc = Path::new(r"\\?\UNC\server\share\workspace.json");
        assert_eq!(
            windows_cli_path(unc),
            OsString::from(r"\\server\share\workspace.json")
        );
    }

    #[test]
    fn parses_required_and_forbidden_sddl_entries() {
        let sid = "S-1-5-21-100-200-300-1001";
        let sddl =
            format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RX;;;WD)");
        assert!(sddl_has_full_control(&sddl, sid));
        assert!(sddl_has_full_control(&sddl, "SY"));
        assert!(sddl_has_allow_ace(&sddl, "WD"));
        assert!(!sddl_has_allow_ace(&sddl, "AU"));
    }
}
