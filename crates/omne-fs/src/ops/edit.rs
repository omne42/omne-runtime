use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub start_line: u64,
    pub end_line: u64,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    pub bytes_written: u64,
}

pub fn edit_range(ctx: &Context, request: EditRequest) -> Result<EditResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.edit, "edit")?;
    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    if request.start_line == 0 || request.end_line == 0 || request.start_line > request.end_line {
        return Err(invalid_edit_range(format!(
            "invalid line range: {}..{}",
            request.start_line, request.end_line
        )));
    }

    let (mut content, identity) = super::io::read_string_limited_with_identity(
        &path,
        &relative,
        ctx.policy.limits.max_read_bytes,
    )?;
    let offsets =
        locate_edit_range_offsets(&content, request.start_line, request.end_line, &relative)?;
    let removed_bytes = usize_to_u64(
        offsets.end_offset.saturating_sub(offsets.start_offset),
        &relative,
        "removed range size",
    )?;

    let newline = offsets.end_line_ending;

    let mut replacement = normalize_replacement_line_endings(&request.replacement, newline);

    if !replacement.is_empty() && !newline.is_empty() && !replacement.ends_with(newline) {
        replacement.to_mut().push_str(newline);
    }

    let content_bytes = usize_to_u64(content.len(), &relative, "file size")?;
    let replacement_bytes = usize_to_u64(replacement.len(), &relative, "replacement size")?;
    let output_bytes = content_bytes
        .checked_sub(removed_bytes)
        .and_then(|remaining| remaining.checked_add(replacement_bytes))
        .ok_or_else(|| {
            Error::InvalidPath(format!(
                "{}: output byte count overflow",
                relative.display()
            ))
        })?;
    if output_bytes > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative,
            size_bytes: output_bytes,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let replaced = &content[offsets.start_offset..offsets.end_offset];
    if replacement.as_ref() != replaced {
        // Apply edits in-place to avoid rebuilding the full output string.
        content.replace_range(
            offsets.start_offset..offsets.end_offset,
            replacement.as_ref(),
        );
        super::io::write_bytes_atomic_checked(
            &path,
            &relative,
            content.as_bytes(),
            identity,
            ctx.policy.limits.preserve_unix_xattrs,
        )?;

        let output_len = usize_to_u64(content.len(), &relative, "output size")?;
        return Ok(EditResponse {
            path: relative,
            requested_path,
            bytes_written: output_len,
        });
    }

    Ok(EditResponse {
        path: relative,
        requested_path,
        bytes_written: 0,
    })
}

fn normalize_replacement_line_endings<'a>(replacement: &'a str, newline: &str) -> Cow<'a, str> {
    if newline.is_empty() {
        return Cow::Borrowed(replacement);
    }
    if newline == "\n" && !replacement.contains('\r') {
        return Cow::Borrowed(replacement);
    }

    let mut out = String::with_capacity(replacement.len());
    let mut chars = replacement.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                out.push_str(newline);
            }
            '\n' => out.push_str(newline),
            _ => out.push(ch),
        }
    }

    Cow::Owned(out)
}

#[cfg(test)]
fn split_lines_preserving_endings(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }

    let bytes = content.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0_usize;
    let mut idx = 0_usize;

    while idx < bytes.len() {
        let end = match bytes[idx] {
            b'\n' => Some(idx + 1),
            b'\r' if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' => Some(idx + 2),
            b'\r' => Some(idx + 1),
            _ => None,
        };

        if let Some(line_end) = end {
            lines.push(&content[start..line_end]);
            start = line_end;
            idx = line_end;
        } else {
            idx += 1;
        }
    }

    if start < bytes.len() {
        lines.push(&content[start..]);
    }

    lines
}

fn line_ending(line: &str) -> &'static str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else if line.ends_with('\r') {
        "\r"
    } else {
        ""
    }
}

struct EditRangeOffsets {
    start_offset: usize,
    end_offset: usize,
    end_line_ending: &'static str,
}

fn locate_edit_range_offsets(
    content: &str,
    start_line: u64,
    end_line: u64,
    relative: &Path,
) -> Result<EditRangeOffsets> {
    let bytes = content.as_bytes();
    let mut idx = 0usize;
    let mut line_start = 0usize;
    let mut line_no = 0u64;
    let mut start_offset = None::<usize>;
    let mut end_offset = None::<usize>;
    let mut end_line_ending = "";

    while idx < bytes.len() {
        let line_end = match bytes[idx] {
            b'\n' => Some(idx + 1),
            b'\r' if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' => Some(idx + 2),
            b'\r' => Some(idx + 1),
            _ => None,
        };
        if let Some(line_end) = line_end {
            line_no = line_no.checked_add(1).ok_or_else(|| {
                Error::InvalidPath(format!("{}: line count overflow", relative.display()))
            })?;
            if line_no == start_line {
                start_offset = Some(line_start);
            }
            if line_no == end_line {
                end_offset = Some(line_end);
                end_line_ending = line_ending(&content[line_start..line_end]);
            }
            line_start = line_end;
            idx = line_end;
        } else {
            idx += 1;
        }
    }

    if line_start < bytes.len() {
        line_no = line_no.checked_add(1).ok_or_else(|| {
            Error::InvalidPath(format!("{}: line count overflow", relative.display()))
        })?;
        if line_no == start_line {
            start_offset = Some(line_start);
        }
        if line_no == end_line {
            end_offset = Some(bytes.len());
            end_line_ending = "";
        }
    }

    let Some(start_offset) = start_offset else {
        return Err(invalid_edit_range(format!(
            "invalid line range: {}..{} out of bounds (file has {} lines)",
            start_line, end_line, line_no
        )));
    };
    let Some(end_offset) = end_offset else {
        return Err(invalid_edit_range(format!(
            "invalid line range: {}..{} out of bounds (file has {} lines)",
            start_line, end_line, line_no
        )));
    };

    Ok(EditRangeOffsets {
        start_offset,
        end_offset,
        end_line_ending,
    })
}

fn invalid_edit_range(message: String) -> Error {
    Error::Patch(format!("invalid edit range: {message}"))
}

fn usize_to_u64(value: usize, path: &Path, context: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        Error::InvalidPath(format!(
            "{}: {context} exceeds supported size",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{line_ending, normalize_replacement_line_endings, split_lines_preserving_endings};
    use std::borrow::Cow;

    #[test]
    fn normalize_replacement_converts_bare_cr() {
        assert_eq!(
            normalize_replacement_line_endings("one\rtwo\r", "\n"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn normalize_replacement_converts_crlf() {
        assert_eq!(
            normalize_replacement_line_endings("one\r\ntwo\r\n", "\n"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn normalize_replacement_converts_mixed_line_endings() {
        assert_eq!(
            normalize_replacement_line_endings("one\rtwo\r\nthree\nfour", "\r\n"),
            "one\r\ntwo\r\nthree\r\nfour"
        );
    }

    #[test]
    fn normalize_replacement_borrows_when_no_conversion_needed() {
        let normalized = normalize_replacement_line_endings("one\ntwo\n", "\n");
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized, "one\ntwo\n");
    }

    #[test]
    fn normalize_replacement_borrows_when_target_has_no_line_ending() {
        let normalized = normalize_replacement_line_endings("one\rtwo", "");
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized, "one\rtwo");
    }

    #[test]
    fn split_lines_supports_bare_cr() {
        assert_eq!(
            split_lines_preserving_endings("one\rtwo\rthree\r"),
            vec!["one\r", "two\r", "three\r"]
        );
    }

    #[test]
    fn line_ending_detects_bare_cr() {
        assert_eq!(line_ending("value\r"), "\r");
    }
}
