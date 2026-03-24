use std::path::Path;

use serde::Serialize;
use serde::ser::SerializeSeq;

use omne_fs::ops::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse, ListDirEntry,
    ListDirEntryKind, ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse,
    MovePathRequest, MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse,
    ScanLimitReason, StatRequest, StatResponse, WriteFileRequest, WriteFileResponse,
};

use crate::error::CliError;
use crate::input::load_text_limited;
use crate::{Cli, Command};

pub(crate) fn run_with_policy(cli: Cli, policy: omne_fs::SandboxPolicy) -> Result<(), CliError> {
    let max_patch_bytes = effective_max_patch_bytes(&cli, &policy);
    let max_write_bytes = policy.limits.max_write_bytes;
    let ctx = Context::new(policy)?;
    let Cli {
        confirm_mutating_ops,
        command,
        pretty,
        ..
    } = cli;
    ensure_mutating_confirmation(&command, confirm_mutating_ops)?;

    let out = execute_command_json(&ctx, command, max_patch_bytes, max_write_bytes, pretty)?;
    crate::write_stdout_line(&out)?;
    Ok(())
}

const MUTATING_CONFIRMATION_MESSAGE: &str =
    "mutating operation requires explicit confirmation (--confirm-mutating-ops)";

fn command_requires_mutation_confirmation(command: &Command) -> bool {
    matches!(
        command,
        Command::Edit { .. }
            | Command::Patch { .. }
            | Command::Mkdir { .. }
            | Command::Write { .. }
            | Command::Delete { .. }
            | Command::Move { .. }
            | Command::CopyFile { .. }
    )
}

fn ensure_mutating_confirmation(command: &Command, confirmed: bool) -> Result<(), CliError> {
    if command_requires_mutation_confirmation(command) && !confirmed {
        return Err(omne_fs::Error::NotPermitted(MUTATING_CONFIRMATION_MESSAGE.to_string()).into());
    }
    Ok(())
}

fn effective_max_patch_bytes(cli: &Cli, policy: &omne_fs::SandboxPolicy) -> u64 {
    let policy_patch_limit = policy
        .limits
        .max_patch_bytes
        .unwrap_or(policy.limits.max_read_bytes);
    cli.max_patch_bytes
        .map_or(policy_patch_limit, |bytes| bytes.min(policy_patch_limit))
}

#[derive(Debug, Clone, Copy)]
struct LossyPath<'a>(&'a Path);

impl Serialize for LossyPath<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string_lossy())
    }
}

fn scan_limit_reason_str(reason: ScanLimitReason) -> &'static str {
    match reason {
        ScanLimitReason::Entries => "entries",
        ScanLimitReason::Files => "files",
        ScanLimitReason::Time => "time",
        ScanLimitReason::Results => "results",
        ScanLimitReason::ResponseBytes => "response_bytes",
        _ => "unknown",
    }
}

#[derive(Debug, Serialize)]
struct JsonReadResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    truncated: bool,
    bytes_read: u64,
    content: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u64>,
}

impl<'a> From<&'a ReadResponse> for JsonReadResponse<'a> {
    fn from(response: &'a ReadResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            truncated: response.truncated,
            bytes_read: response.bytes_read,
            content: response.content.as_str(),
            start_line: response.start_line,
            end_line: response.end_line,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonListDirResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    entries: JsonListDirEntries<'a>,
    truncated: bool,
    skipped_io_errors: u64,
}

impl<'a> From<&'a ListDirResponse> for JsonListDirResponse<'a> {
    fn from(response: &'a ListDirResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            entries: JsonListDirEntries(response.entries.as_slice()),
            truncated: response.truncated,
            skipped_io_errors: response.skipped_io_errors,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct JsonListDirEntries<'a>(&'a [ListDirEntry]);

impl Serialize for JsonListDirEntries<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            seq.serialize_element(&JsonListDirEntry::from(entry))?;
        }
        seq.end()
    }
}

#[derive(Debug, Serialize)]
struct JsonListDirEntry<'a> {
    path: LossyPath<'a>,
    name: &'a str,
    #[serde(rename = "type")]
    kind: ListDirEntryKind,
    size_bytes: u64,
}

impl<'a> From<&'a ListDirEntry> for JsonListDirEntry<'a> {
    fn from(entry: &'a ListDirEntry) -> Self {
        Self {
            path: LossyPath(&entry.path),
            name: entry.name.as_str(),
            kind: entry.kind,
            size_bytes: entry.size_bytes,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonGlobResponse<'a> {
    matches: LossyPaths<'a>,
    truncated: bool,
    scanned_files: u64,
    scan_limit_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_limit_reason: Option<&'static str>,
    elapsed_ms: u64,
    scanned_entries: u64,
    skipped_walk_errors: u64,
    skipped_io_errors: u64,
    skipped_dangling_symlink_targets: u64,
}

impl<'a> From<&'a GlobResponse> for JsonGlobResponse<'a> {
    fn from(response: &'a GlobResponse) -> Self {
        Self {
            matches: LossyPaths(response.matches.as_slice()),
            truncated: response.truncated,
            scanned_files: response.scanned_files,
            scan_limit_reached: response.scan_limit_reached,
            scan_limit_reason: response.scan_limit_reason.map(scan_limit_reason_str),
            elapsed_ms: response.elapsed_ms,
            scanned_entries: response.scanned_entries,
            skipped_walk_errors: response.skipped_walk_errors,
            skipped_io_errors: response.skipped_io_errors,
            skipped_dangling_symlink_targets: response.skipped_dangling_symlink_targets,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LossyPaths<'a>(&'a [std::path::PathBuf]);

impl Serialize for LossyPaths<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for path in self.0 {
            seq.serialize_element(&LossyPath(path.as_path()))?;
        }
        seq.end()
    }
}

#[derive(Debug, Serialize)]
struct JsonGrepResponse<'a> {
    matches: JsonGrepMatches<'a>,
    truncated: bool,
    skipped_too_large_files: u64,
    skipped_non_utf8_files: u64,
    scanned_files: u64,
    scan_limit_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_limit_reason: Option<&'static str>,
    elapsed_ms: u64,
    scanned_entries: u64,
    skipped_walk_errors: u64,
    skipped_io_errors: u64,
    skipped_dangling_symlink_targets: u64,
}

impl<'a> From<&'a GrepResponse> for JsonGrepResponse<'a> {
    fn from(response: &'a GrepResponse) -> Self {
        Self {
            matches: JsonGrepMatches(response.matches.as_slice()),
            truncated: response.truncated,
            skipped_too_large_files: response.skipped_too_large_files,
            skipped_non_utf8_files: response.skipped_non_utf8_files,
            scanned_files: response.scanned_files,
            scan_limit_reached: response.scan_limit_reached,
            scan_limit_reason: response.scan_limit_reason.map(scan_limit_reason_str),
            elapsed_ms: response.elapsed_ms,
            scanned_entries: response.scanned_entries,
            skipped_walk_errors: response.skipped_walk_errors,
            skipped_io_errors: response.skipped_io_errors,
            skipped_dangling_symlink_targets: response.skipped_dangling_symlink_targets,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct JsonGrepMatches<'a>(&'a [omne_fs::ops::GrepMatch]);

impl Serialize for JsonGrepMatches<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for m in self.0 {
            seq.serialize_element(&JsonGrepMatch::from(m))?;
        }
        seq.end()
    }
}

#[derive(Debug, Serialize)]
struct JsonGrepMatch<'a> {
    path: LossyPath<'a>,
    line: u64,
    text: &'a str,
    line_truncated: bool,
}

impl<'a> From<&'a omne_fs::ops::GrepMatch> for JsonGrepMatch<'a> {
    fn from(m: &'a omne_fs::ops::GrepMatch) -> Self {
        Self {
            path: LossyPath(&m.path),
            line: m.line,
            text: m.text.as_str(),
            line_truncated: m.line_truncated,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonStatResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    #[serde(rename = "type")]
    kind: omne_fs::ops::StatKind,
    size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accessed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_ms: Option<u64>,
    readonly: bool,
}

impl<'a> From<&'a StatResponse> for JsonStatResponse<'a> {
    fn from(response: &'a StatResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            kind: response.kind,
            size_bytes: response.size_bytes,
            modified_ms: response.modified_ms,
            accessed_ms: response.accessed_ms,
            created_ms: response.created_ms,
            readonly: response.readonly,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonEditResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    bytes_written: u64,
}

impl<'a> From<&'a EditResponse> for JsonEditResponse<'a> {
    fn from(response: &'a EditResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            bytes_written: response.bytes_written,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonPatchResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    bytes_written: u64,
}

impl<'a> From<&'a PatchResponse> for JsonPatchResponse<'a> {
    fn from(response: &'a PatchResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            bytes_written: response.bytes_written,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonMkdirResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    created: bool,
}

impl<'a> From<&'a MkdirResponse> for JsonMkdirResponse<'a> {
    fn from(response: &'a MkdirResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            created: response.created,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonWriteFileResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    bytes_written: u64,
    created: bool,
}

impl<'a> From<&'a WriteFileResponse> for JsonWriteFileResponse<'a> {
    fn from(response: &'a WriteFileResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            bytes_written: response.bytes_written,
            created: response.created,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonDeleteResponse<'a> {
    path: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_path: Option<LossyPath<'a>>,
    deleted: bool,
    #[serde(rename = "type")]
    kind: omne_fs::ops::DeleteKind,
}

impl<'a> From<&'a DeleteResponse> for JsonDeleteResponse<'a> {
    fn from(response: &'a DeleteResponse) -> Self {
        Self {
            path: LossyPath(&response.path),
            requested_path: response.requested_path.as_deref().map(LossyPath),
            deleted: response.deleted,
            kind: response.kind,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonMovePathResponse<'a> {
    from: LossyPath<'a>,
    to: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_from: Option<LossyPath<'a>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_to: Option<LossyPath<'a>>,
    moved: bool,
    #[serde(rename = "type")]
    kind: &'a str,
}

impl<'a> From<&'a MovePathResponse> for JsonMovePathResponse<'a> {
    fn from(response: &'a MovePathResponse) -> Self {
        Self {
            from: LossyPath(&response.from),
            to: LossyPath(&response.to),
            requested_from: response.requested_from.as_deref().map(LossyPath),
            requested_to: response.requested_to.as_deref().map(LossyPath),
            moved: response.moved,
            kind: response.kind.as_str(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonCopyFileResponse<'a> {
    from: LossyPath<'a>,
    to: LossyPath<'a>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_from: Option<LossyPath<'a>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_to: Option<LossyPath<'a>>,
    copied: bool,
    bytes: u64,
}

impl<'a> From<&'a CopyFileResponse> for JsonCopyFileResponse<'a> {
    fn from(response: &'a CopyFileResponse) -> Self {
        Self {
            from: LossyPath(&response.from),
            to: LossyPath(&response.to),
            requested_from: response.requested_from.as_deref().map(LossyPath),
            requested_to: response.requested_to.as_deref().map(LossyPath),
            copied: response.copied,
            bytes: response.bytes,
        }
    }
}

fn execute_command_json(
    ctx: &Context,
    command: Command,
    max_patch_bytes: u64,
    max_write_bytes: u64,
    pretty: bool,
) -> Result<String, CliError> {
    match command {
        Command::Read {
            root,
            path,
            start_line,
            end_line,
        } => {
            let response = omne_fs::ops::read_file(
                ctx,
                ReadRequest {
                    root_id: root,
                    path,
                    start_line,
                    end_line,
                },
            )?;
            crate::serialize_json(&JsonReadResponse::from(&response), pretty)
        }
        Command::ListDir {
            root,
            max_entries,
            path,
        } => {
            let response = omne_fs::ops::list_dir(
                ctx,
                ListDirRequest {
                    root_id: root,
                    path,
                    max_entries,
                },
            )?;
            crate::serialize_json(&JsonListDirResponse::from(&response), pretty)
        }
        Command::Glob { root, pattern } => {
            let response = omne_fs::ops::glob_paths(
                ctx,
                GlobRequest {
                    root_id: root,
                    pattern,
                },
            )?;
            crate::serialize_json(&JsonGlobResponse::from(&response), pretty)
        }
        Command::Grep {
            root,
            query,
            regex,
            glob,
        } => {
            let response = omne_fs::ops::grep(
                ctx,
                GrepRequest {
                    root_id: root,
                    query,
                    regex,
                    glob,
                },
            )?;
            crate::serialize_json(&JsonGrepResponse::from(&response), pretty)
        }
        Command::Stat { root, path } => {
            let response = omne_fs::ops::stat(
                ctx,
                StatRequest {
                    root_id: root,
                    path,
                },
            )?;
            crate::serialize_json(&JsonStatResponse::from(&response), pretty)
        }
        Command::Edit {
            root,
            path,
            start_line,
            end_line,
            replacement,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.edit,
                "edit is disabled by policy",
                "edit",
            )?;
            let response = omne_fs::ops::edit_range(
                ctx,
                EditRequest {
                    root_id: root,
                    path,
                    start_line,
                    end_line,
                    replacement,
                },
            )?;
            crate::serialize_json(&JsonEditResponse::from(&response), pretty)
        }
        Command::Patch {
            root,
            path,
            patch_file,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.patch,
                "patch is disabled by policy",
                "patch",
            )?;
            let response = omne_fs::ops::apply_unified_patch(
                ctx,
                PatchRequest {
                    root_id: root,
                    path,
                    patch: load_text_limited(&patch_file, max_patch_bytes)?,
                },
            )?;
            crate::serialize_json(&JsonPatchResponse::from(&response), pretty)
        }
        Command::Mkdir {
            root,
            path,
            create_parents,
            ignore_existing,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.mkdir,
                "mkdir is disabled by policy",
                "mkdir",
            )?;
            let response = omne_fs::ops::mkdir(
                ctx,
                MkdirRequest {
                    root_id: root,
                    path,
                    create_parents,
                    ignore_existing,
                },
            )?;
            crate::serialize_json(&JsonMkdirResponse::from(&response), pretty)
        }
        Command::Write {
            root,
            path,
            content_file,
            overwrite,
            create_parents,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.write,
                "write is disabled by policy",
                "write",
            )?;
            let response = omne_fs::ops::write_file(
                ctx,
                WriteFileRequest {
                    root_id: root,
                    path,
                    content: load_text_limited(&content_file, max_write_bytes)?,
                    overwrite,
                    create_parents,
                },
            )?;
            crate::serialize_json(&JsonWriteFileResponse::from(&response), pretty)
        }
        Command::Delete {
            root,
            path,
            recursive,
            ignore_missing,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.delete,
                "delete is disabled by policy",
                "delete",
            )?;
            let response = omne_fs::ops::delete(
                ctx,
                DeleteRequest {
                    root_id: root,
                    path,
                    recursive,
                    ignore_missing,
                },
            )?;
            crate::serialize_json(&JsonDeleteResponse::from(&response), pretty)
        }
        Command::Move {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.move_path,
                "move is disabled by policy",
                "move",
            )?;
            let response = omne_fs::ops::move_path(
                ctx,
                MovePathRequest {
                    root_id: root,
                    from,
                    to,
                    overwrite,
                    create_parents,
                },
            )?;
            crate::serialize_json(&JsonMovePathResponse::from(&response), pretty)
        }
        Command::CopyFile {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => {
            preflight_mutating_target(
                ctx,
                root.as_str(),
                ctx.policy().permissions.copy_file,
                "copy_file is disabled by policy",
                "copy_file",
            )?;
            let response = omne_fs::ops::copy_file(
                ctx,
                CopyFileRequest {
                    root_id: root,
                    from,
                    to,
                    overwrite,
                    create_parents,
                },
            )?;
            crate::serialize_json(&JsonCopyFileResponse::from(&response), pretty)
        }
    }
}

fn preflight_mutating_target(
    ctx: &Context,
    root_id: &str,
    operation_enabled: bool,
    disabled_message: &'static str,
    operation_name: &'static str,
) -> Result<(), CliError> {
    if !operation_enabled {
        return Err(omne_fs::Error::NotPermitted(disabled_message.to_string()).into());
    }

    let root = ctx.policy().root(root_id)?;
    if !matches!(
        root.mode,
        omne_fs::RootMode::WorkspaceWrite | omne_fs::RootMode::FullAccess
    ) {
        return Err(omne_fs::Error::NotPermitted(format!(
            "{operation_name} is not allowed: root {root_id} is read_only"
        ))
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Command;
    use crate::error::CliError;
    use std::path::PathBuf;

    use omne_fs::ops::ScanLimitReason;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::{
        JsonGlobResponse, JsonGrepResponse, JsonListDirResponse,
        command_requires_mutation_confirmation, ensure_mutating_confirmation,
        scan_limit_reason_str,
    };

    #[cfg(unix)]
    fn non_utf8_path() -> PathBuf {
        PathBuf::from(std::ffi::OsString::from_vec(vec![b'f', b'o', 0x80]))
    }

    #[cfg(unix)]
    #[test]
    fn list_dir_json_uses_lossy_paths_for_non_utf8_entries() {
        let path = non_utf8_path();
        let response = omne_fs::ops::ListDirResponse {
            path: PathBuf::from("."),
            requested_path: Some(PathBuf::from(".")),
            entries: vec![omne_fs::ops::ListDirEntry {
                path: path.clone(),
                name: "x".to_string(),
                kind: omne_fs::ops::ListDirEntryKind::File,
                size_bytes: 1,
            }],
            truncated: false,
            skipped_io_errors: 0,
        };
        let value = serde_json::to_value(JsonListDirResponse::from(&response)).expect("to_value");

        assert_eq!(
            value["entries"][0]["path"].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn glob_json_uses_lossy_paths_for_non_utf8_matches() {
        let path = non_utf8_path();
        let response = omne_fs::ops::GlobResponse {
            matches: vec![path.clone()],
            truncated: false,
            scanned_files: 1,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 0,
            scanned_entries: 1,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        };
        let value = serde_json::to_value(JsonGlobResponse::from(&response)).expect("to_value");

        assert_eq!(
            value["matches"][0].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn grep_json_uses_lossy_paths_for_non_utf8_matches() {
        let path = non_utf8_path();
        let response = omne_fs::ops::GrepResponse {
            matches: vec![omne_fs::ops::GrepMatch {
                path: path.clone(),
                line: 1,
                text: "hit".to_string(),
                line_truncated: false,
            }],
            truncated: false,
            skipped_too_large_files: 0,
            skipped_non_utf8_files: 0,
            scanned_files: 1,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 0,
            scanned_entries: 1,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        };
        let value = serde_json::to_value(JsonGrepResponse::from(&response)).expect("to_value");

        assert_eq!(
            value["matches"][0]["path"].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn scan_limit_reason_json_matches_public_contract() {
        assert_eq!(scan_limit_reason_str(ScanLimitReason::Entries), "entries");
        assert_eq!(scan_limit_reason_str(ScanLimitReason::Files), "files");
        assert_eq!(scan_limit_reason_str(ScanLimitReason::Time), "time");
        assert_eq!(scan_limit_reason_str(ScanLimitReason::Results), "results");
        assert_eq!(
            scan_limit_reason_str(ScanLimitReason::ResponseBytes),
            "response_bytes"
        );
    }

    #[test]
    fn mutation_confirmation_classifies_commands_correctly() {
        assert!(!command_requires_mutation_confirmation(&Command::Read {
            root: "root".to_string(),
            path: PathBuf::from("a.txt"),
            start_line: None,
            end_line: None,
        }));
        assert!(!command_requires_mutation_confirmation(&Command::Stat {
            root: "root".to_string(),
            path: PathBuf::from("a.txt"),
        }));
        assert!(command_requires_mutation_confirmation(&Command::Write {
            root: "root".to_string(),
            path: PathBuf::from("a.txt"),
            content_file: PathBuf::from("content.txt"),
            overwrite: false,
            create_parents: false,
        }));
        assert!(command_requires_mutation_confirmation(&Command::Delete {
            root: "root".to_string(),
            path: PathBuf::from("a.txt"),
            recursive: false,
            ignore_missing: false,
        }));
    }

    #[test]
    fn mutation_confirmation_rejects_mutating_commands_when_not_confirmed() {
        let err = ensure_mutating_confirmation(
            &Command::Write {
                root: "root".to_string(),
                path: PathBuf::from("a.txt"),
                content_file: PathBuf::from("content.txt"),
                overwrite: false,
                create_parents: false,
            },
            false,
        )
        .expect_err("mutating command should require confirmation");

        match err {
            CliError::Tool(omne_fs::Error::NotPermitted(message)) => {
                assert!(
                    message.contains("--confirm-mutating-ops"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
