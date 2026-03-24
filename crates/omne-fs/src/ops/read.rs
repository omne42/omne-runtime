use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::redaction::RedactionOutcome;

use super::Context;

#[derive(Debug, Clone, Copy)]
enum ReadMode {
    Full,
    LineRange { start_line: u64, end_line: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub root_id: String,
    /// Keep `PathBuf` at the request boundary:
    /// this preserves owned/serializable API ergonomics and avoids propagating
    /// lifetimes through request structs. Runtime path resolution borrows
    /// `&request.path`, so this does not add an extra clone in the hot path.
    pub path: PathBuf,
    #[serde(default)]
    pub start_line: Option<u64>,
    #[serde(default)]
    pub end_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    /// Always `false`: `read` fails instead of truncating.
    pub truncated: bool,
    /// Number of bytes scanned from disk before returning.
    pub bytes_read: u64,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
}

pub fn read_file(ctx: &Context, request: ReadRequest) -> Result<ReadResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.read, "read")?;

    let mode = parse_read_mode(request.start_line, request.end_line)?;

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;
    if is_sensitive_env_file_for_read(&relative) {
        return Err(Error::NotPermitted(format!(
            "read is disabled by policy: refusing to read {} (use an env-specific tool)",
            relative.display()
        )));
    }

    let (bytes_read, content) = match mode {
        ReadMode::Full => read_full(&path, &relative, ctx)?,
        ReadMode::LineRange {
            start_line,
            end_line,
        } => read_line_range(&path, &relative, ctx, start_line, end_line)?,
    };

    let content = if !ctx.redactor.has_redact_regexes() {
        content
    } else {
        match ctx.redactor.redact_text_outcome(&content) {
            RedactionOutcome::Text(std::borrow::Cow::Borrowed(_)) => content,
            RedactionOutcome::Text(std::borrow::Cow::Owned(redacted)) => redacted,
            RedactionOutcome::OutputLimitExceeded => {
                return Err(Error::io_path(
                    "redact",
                    &relative,
                    std::io::Error::other("redacted output exceeded hard safety limit"),
                ));
            }
        }
    };

    Ok(ReadResponse {
        path: relative,
        requested_path: Some(requested_path),
        truncated: false,
        bytes_read,
        content,
        start_line: request.start_line,
        end_line: request.end_line,
    })
}

fn is_sensitive_env_file_for_read(relative_path: &Path) -> bool {
    let Some(file_name) = relative_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    if !file_name.starts_with(".env") {
        return false;
    }

    let suffix = &file_name[".env".len()..];
    if !suffix.is_empty()
        && !suffix.starts_with('.')
        && !suffix.starts_with('_')
        && !suffix.starts_with('-')
    {
        return false;
    }

    !(file_name.contains("example") || file_name.contains("template"))
}

fn parse_read_mode(start_line: Option<u64>, end_line: Option<u64>) -> Result<ReadMode> {
    match (start_line, end_line) {
        (None, None) => Ok(ReadMode::Full),
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(invalid_line_range(format!(
                    "invalid line range: {}..{}",
                    start_line, end_line
                )));
            }
            Ok(ReadMode::LineRange {
                start_line,
                end_line,
            })
        }
        _ => Err(invalid_line_range(
            "invalid line range: start_line and end_line must be provided together".to_string(),
        )),
    }
}

fn read_full(path: &std::path::Path, relative: &Path, ctx: &Context) -> Result<(u64, String)> {
    let bytes = super::io::read_bytes_limited(path, relative, ctx.policy.limits.max_read_bytes)?;
    let bytes_read = usize_to_u64(bytes.len(), relative, "file size")?;
    let content =
        String::from_utf8(bytes).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))?;
    Ok((bytes_read, content))
}

fn read_line_range(
    path: &std::path::Path,
    relative: &Path,
    ctx: &Context,
    start_line: u64,
    end_line: u64,
) -> Result<(u64, String)> {
    let (file, meta) = super::io::open_regular_file_for_read(path, relative)?;
    let file_size_bytes = meta.len();
    let limit = ctx.policy.limits.max_read_bytes.saturating_add(1);
    let mut reader = std::io::BufReader::with_capacity(
        initial_line_range_reader_capacity(ctx.policy.limits.max_read_bytes),
        file.take(limit),
    );
    // Line-range reads often pull a narrow subset; start small and grow on demand.
    let mut out = Vec::<u8>::with_capacity(initial_line_range_capacity(
        file_size_bytes,
        ctx.policy.limits.max_read_bytes,
    ));
    let mut utf8_pending = [0_u8; 3];
    let mut utf8_pending_len = 0_usize;
    let mut utf8_error = None::<std::str::Utf8Error>;

    let mut scanned_bytes: u64 = 0;
    let mut current_line: u64 = 0;
    let start_line_index = start_line.saturating_sub(1);

    loop {
        let should_discard = current_line < start_line_index;
        let n = if should_discard {
            read_line_discarding_bytes_validating_utf8(
                &mut reader,
                &mut utf8_pending,
                &mut utf8_pending_len,
                &mut utf8_error,
            )
            .map_err(|err| Error::io_path("read", relative, err))?
        } else {
            read_line_appending_bytes(&mut reader, &mut out)
                .map_err(|err| Error::io_path("read", relative, err))?
        };
        if let Some(err) = utf8_error.take() {
            return Err(Error::invalid_utf8(relative.to_path_buf(), err));
        }
        if n == 0 {
            break;
        }

        let line_bytes = usize_to_u64(n, relative, "line length")?;
        scanned_bytes = scanned_bytes.saturating_add(line_bytes);
        if scanned_bytes > ctx.policy.limits.max_read_bytes {
            let size_bytes = file_size_bytes.max(scanned_bytes);
            return Err(Error::FileTooLarge {
                path: relative.to_path_buf(),
                size_bytes,
                max_bytes: ctx.policy.limits.max_read_bytes,
            });
        }

        current_line = checked_next_line(current_line, relative)?;
        if current_line == end_line {
            break;
        }
    }

    if current_line < end_line {
        return Err(invalid_line_range(format!(
            "invalid line range: {}..{} out of bounds (file has {} lines)",
            start_line, end_line, current_line
        )));
    }

    let bytes_read = scanned_bytes;
    let content =
        String::from_utf8(out).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))?;
    Ok((bytes_read, content))
}

fn initial_line_range_capacity(file_size_bytes: u64, max_read_bytes: u64) -> usize {
    const DEFAULT_CAPACITY: usize = 8 * 1024;
    const MAX_INITIAL_CAPACITY: usize = 64 * 1024;
    let bounded = file_size_bytes.min(max_read_bytes);
    usize::try_from(bounded)
        .ok()
        .map_or(DEFAULT_CAPACITY, |max| max.min(MAX_INITIAL_CAPACITY))
}

fn initial_line_range_reader_capacity(max_read_bytes: u64) -> usize {
    const DEFAULT_CAPACITY: usize = 8 * 1024;
    const MAX_INITIAL_CAPACITY: usize = 64 * 1024;
    usize::try_from(max_read_bytes)
        .ok()
        .map_or(DEFAULT_CAPACITY, |max| {
            max.clamp(DEFAULT_CAPACITY, MAX_INITIAL_CAPACITY)
        })
}

fn utf8_error_for_incomplete_sequence(bytes: &[u8]) -> std::str::Utf8Error {
    std::str::from_utf8(bytes).expect_err("incomplete UTF-8 sequence must be invalid")
}

fn update_utf8_validation_state(
    pending: &mut [u8; 3],
    pending_len: &mut usize,
    utf8_error: &mut Option<std::str::Utf8Error>,
    mut chunk: &[u8],
) {
    if utf8_error.is_some() {
        return;
    }

    while *pending_len > 0 {
        if chunk.is_empty() {
            return;
        }
        let needed = 4usize.saturating_sub(*pending_len);
        let take = needed.min(chunk.len());
        let mut combined = [0_u8; 4];
        combined[..*pending_len].copy_from_slice(&pending[..*pending_len]);
        combined[*pending_len..*pending_len + take].copy_from_slice(&chunk[..take]);
        match std::str::from_utf8(&combined[..*pending_len + take]) {
            Ok(_) => {
                *pending_len = 0;
                chunk = &chunk[take..];
            }
            Err(err) => {
                if err.error_len().is_some() {
                    *utf8_error = Some(err);
                    *pending_len = 0;
                    return;
                }
                let trailing = &combined[err.valid_up_to()..*pending_len + take];
                if trailing.len() > pending.len() {
                    *utf8_error = Some(err);
                    *pending_len = 0;
                    return;
                }
                pending[..trailing.len()].copy_from_slice(trailing);
                *pending_len = trailing.len();
                chunk = &chunk[take..];
            }
        }
    }

    match std::str::from_utf8(chunk) {
        Ok(_) => {}
        Err(err) => {
            if err.error_len().is_some() {
                *utf8_error = Some(err);
                *pending_len = 0;
                return;
            }
            let trailing = &chunk[err.valid_up_to()..];
            if trailing.len() > pending.len() {
                *utf8_error = Some(err);
                *pending_len = 0;
                return;
            }
            pending[..trailing.len()].copy_from_slice(trailing);
            *pending_len = trailing.len();
        }
    }
}

fn read_line_discarding_bytes_validating_utf8<R: BufRead>(
    reader: &mut R,
    utf8_pending: &mut [u8; 3],
    utf8_pending_len: &mut usize,
    utf8_error: &mut Option<std::str::Utf8Error>,
) -> std::io::Result<usize> {
    *utf8_pending_len = 0;
    *utf8_error = None;
    let n = consume_next_line_bytes(reader, |chunk| {
        update_utf8_validation_state(utf8_pending, utf8_pending_len, utf8_error, chunk);
    })?;
    if utf8_error.is_none() && *utf8_pending_len > 0 {
        *utf8_error = Some(utf8_error_for_incomplete_sequence(
            &utf8_pending[..*utf8_pending_len],
        ));
        *utf8_pending_len = 0;
    }
    Ok(n)
}

fn read_line_appending_bytes<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> std::io::Result<usize> {
    consume_next_line_bytes(reader, |chunk| out.extend_from_slice(chunk))
}

fn consume_next_line_bytes<R: BufRead, F: FnMut(&[u8])>(
    reader: &mut R,
    mut on_chunk: F,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(total);
        }

        let line_end = memchr::memchr2(b'\n', b'\r', available);
        let (to_consume, reached_line_end, ended_with_cr) = match line_end {
            Some(idx) => (idx.saturating_add(1), true, available[idx] == b'\r'),
            None => (available.len(), false, false),
        };

        on_chunk(&available[..to_consume]);
        reader.consume(to_consume);
        total = total
            .checked_add(to_consume)
            .ok_or_else(|| std::io::Error::other("line length overflowed usize"))?;

        if reached_line_end && ended_with_cr {
            let has_trailing_lf = {
                let next = reader.fill_buf()?;
                !next.is_empty() && next[0] == b'\n'
            };
            if has_trailing_lf {
                on_chunk(b"\n");
                reader.consume(1);
                total = total
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("line length overflowed usize"))?;
            }
        }

        if reached_line_end {
            return Ok(total);
        }
    }
}

fn invalid_line_range(message: String) -> Error {
    Error::InvalidPath(format!("invalid argument: {message}"))
}

fn checked_next_line(current_line: u64, path: &Path) -> Result<u64> {
    current_line
        .checked_add(1)
        .ok_or_else(|| Error::InvalidPath(format!("{}: line count overflow", path.display())))
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
    use std::path::Path;

    use crate::error::Error;

    use super::{
        checked_next_line, initial_line_range_capacity, initial_line_range_reader_capacity,
        is_sensitive_env_file_for_read,
    };

    #[test]
    fn line_range_output_capacity_stays_bounded() {
        assert_eq!(initial_line_range_capacity(1024, 4096), 1024);
        assert_eq!(
            initial_line_range_capacity(64 * 1024 * 1024, 64 * 1024 * 1024),
            64 * 1024
        );
    }

    #[test]
    fn line_range_reader_capacity_clamps_between_bounds() {
        assert_eq!(initial_line_range_reader_capacity(1024), 8 * 1024);
        assert_eq!(initial_line_range_reader_capacity(16 * 1024), 16 * 1024);
        assert_eq!(
            initial_line_range_reader_capacity(64 * 1024 * 1024),
            64 * 1024
        );
    }

    #[test]
    fn checked_next_line_reports_overflow() {
        let err =
            checked_next_line(u64::MAX, Path::new("file.txt")).expect_err("must reject overflow");
        match err {
            Error::InvalidPath(message) => assert!(message.contains("line count overflow")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sensitive_env_read_blocking_allows_example_and_template_variants() {
        assert!(is_sensitive_env_file_for_read(Path::new(".env")));
        assert!(is_sensitive_env_file_for_read(Path::new(".env.local")));
        assert!(is_sensitive_env_file_for_read(Path::new(".env.production")));
        assert!(!is_sensitive_env_file_for_read(Path::new(".env.example")));
        assert!(!is_sensitive_env_file_for_read(Path::new(".env.template")));
        assert!(!is_sensitive_env_file_for_read(Path::new(".env-example")));
        assert!(!is_sensitive_env_file_for_read(Path::new(".environment")));
        assert!(!is_sensitive_env_file_for_read(Path::new("config.env")));
    }
}
