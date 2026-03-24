use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

use globset::{GlobSet, GlobSetBuilder};
use regex::Regex;

use crate::error::{Error, Result};
use crate::policy::SecretRules;

const MAX_DENY_GLOBS: usize = 512;
const MAX_GLOB_PATTERN_BYTES: usize = 4 * 1024;
const MAX_REDACT_REGEXES: usize = 128;
const MAX_REDACT_REGEX_BYTES: usize = 8 * 1024;
const MAX_RULE_PATTERNS_TOTAL_BYTES: usize = 64 * 1024;
const MAX_REPLACEMENT_BYTES: usize = 1024;
const MAX_REDACTED_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const REDACTION_OUTPUT_LIMIT_MARKER: &str = "[REDACTION_OUTPUT_LIMIT_EXCEEDED]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionOutcome<'a> {
    Text(Cow<'a, str>),
    OutputLimitExceeded,
}

#[derive(Debug)]
pub struct SecretRedactor {
    deny: GlobSet,
    deny_delete_scan: Vec<DenyDeleteScanPattern>,
    redact: Vec<Regex>,
    replacement: String,
}

#[derive(Debug)]
enum DenyDeleteScanPattern {
    Literal(PathBuf),
    Prefix(PathBuf),
    AlwaysScan,
}

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        if rules.deny_globs.len() > MAX_DENY_GLOBS {
            return Err(Error::InvalidPolicy(format!(
                "invalid secrets.deny_globs: too many patterns ({} > {MAX_DENY_GLOBS})",
                rules.deny_globs.len()
            )));
        }
        if rules.redact_regexes.len() > MAX_REDACT_REGEXES {
            return Err(Error::InvalidPolicy(format!(
                "invalid secrets.redact_regexes: too many patterns ({} > {MAX_REDACT_REGEXES})",
                rules.redact_regexes.len()
            )));
        }
        if rules.replacement.len() > MAX_REPLACEMENT_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "invalid secrets.replacement: too long ({} bytes > {MAX_REPLACEMENT_BYTES} bytes)",
                rules.replacement.len()
            )));
        }

        let mut deny_builder = GlobSetBuilder::new();
        let mut total_pattern_bytes = 0usize;
        let mut deny_delete_scan =
            Vec::<DenyDeleteScanPattern>::with_capacity(rules.deny_globs.len());
        for (idx, pattern) in rules.deny_globs.iter().enumerate() {
            if pattern.trim().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "invalid secrets.deny_globs glob {pattern:?}: glob pattern must not be empty"
                )));
            }
            if pattern.len() > MAX_GLOB_PATTERN_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "invalid secrets.deny_globs[{idx}]: glob pattern too long ({} bytes > {MAX_GLOB_PATTERN_BYTES} bytes)",
                    pattern.len()
                )));
            }
            accumulate_pattern_bytes(&mut total_pattern_bytes, pattern.len())?;

            let normalized =
                crate::path_utils_internal::normalize_glob_pattern_for_matching(pattern);
            compile_and_add_deny_glob(&mut deny_builder, pattern, &normalized)?;
            deny_delete_scan.push(compile_delete_scan_pattern(&normalized));

            // Ensure `foo/**` also denies direct access to `foo` itself.
            if let Some(directory_root) = normalized
                .strip_suffix("/**")
                .filter(|root| !root.is_empty())
            {
                accumulate_pattern_bytes(&mut total_pattern_bytes, directory_root.len())?;
                compile_and_add_deny_glob(&mut deny_builder, pattern, directory_root)?;
            }
        }
        let deny = deny_builder
            .build()
            .map_err(|err| Error::InvalidPolicy(format!("invalid deny globs: {err}")))?;

        let mut redact = Vec::<Regex>::with_capacity(rules.redact_regexes.len());
        for (idx, pattern) in rules.redact_regexes.iter().enumerate() {
            if pattern.is_empty() {
                return Err(Error::InvalidPolicy(
                    "invalid secrets.redact_regexes regex \"\": empty patterns are not allowed"
                        .to_string(),
                ));
            }
            if pattern.len() > MAX_REDACT_REGEX_BYTES {
                return Err(Error::InvalidPolicy(format!(
                    "invalid secrets.redact_regexes[{idx}]: regex pattern too long ({} bytes > {MAX_REDACT_REGEX_BYTES} bytes)",
                    pattern.len()
                )));
            }
            accumulate_pattern_bytes(&mut total_pattern_bytes, pattern.len())?;
            let regex = Regex::new(pattern).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "invalid secrets.redact_regexes regex {pattern:?}: {err}"
                ))
            })?;
            redact.push(regex);
        }
        Ok(Self {
            deny,
            deny_delete_scan,
            redact,
            replacement: rules.replacement.clone(),
        })
    }

    /// Returns `true` if a **root-relative** path is denied by `secrets.deny_globs`.
    ///
    /// Non-root-relative paths are denied defensively to avoid silent allow-on-mismatch behavior.
    pub fn is_path_denied(&self, relative: &Path) -> bool {
        if !is_root_relative(relative) {
            return true;
        }
        match normalize_path_for_glob(relative) {
            Some(path) => self.deny.is_match(path.as_ref()),
            None => true,
        }
    }

    pub(crate) fn requires_recursive_delete_descendant_scan(&self, target_relative: &Path) -> bool {
        let normalized_target = crate::path_utils::normalized_for_boundary(target_relative);
        for pattern in &self.deny_delete_scan {
            match pattern {
                DenyDeleteScanPattern::Literal(literal) => {
                    if crate::path_utils::starts_with_case_insensitive_normalized(
                        literal,
                        normalized_target.as_ref(),
                    ) {
                        return true;
                    }
                }
                DenyDeleteScanPattern::Prefix(prefix) => {
                    if overlaps_by_boundary_prefix_normalized(prefix, normalized_target.as_ref()) {
                        return true;
                    }
                }
                DenyDeleteScanPattern::AlwaysScan => return true,
            }
        }
        false
    }

    /// Compatibility helper: returns a marker string when output hits the hard limit.
    /// Use `redact_text_outcome` when callers must distinguish state from content.
    pub fn redact_text(&self, input: &str) -> String {
        match self.redact_text_outcome(input) {
            RedactionOutcome::Text(text) => text.into_owned(),
            RedactionOutcome::OutputLimitExceeded => REDACTION_OUTPUT_LIMIT_MARKER.to_string(),
        }
    }

    /// Compatibility helper: returns a marker when output hits the hard limit.
    /// Use `redact_text_outcome` when callers must distinguish state from content.
    pub fn redact_text_cow<'a>(&self, input: &'a str) -> Cow<'a, str> {
        match self.redact_text_outcome(input) {
            RedactionOutcome::Text(text) => text,
            RedactionOutcome::OutputLimitExceeded => Cow::Borrowed(REDACTION_OUTPUT_LIMIT_MARKER),
        }
    }

    pub fn redact_text_outcome<'a>(&self, input: &'a str) -> RedactionOutcome<'a> {
        if self.redact.is_empty() || input.is_empty() {
            return RedactionOutcome::Text(Cow::Borrowed(input));
        }

        // Reuse two owned buffers across regex passes to avoid per-regex reallocation churn.
        let mut buffers = [String::new(), String::new()];
        let mut active_buffer: Option<ActiveBuffer> = None;
        for regex in &self.redact {
            let result = match active_buffer {
                None => {
                    if input.is_empty() {
                        break;
                    }
                    replace_regex_with_limit(
                        input,
                        regex,
                        self.replacement.as_str(),
                        &mut buffers[0],
                    )
                    .map_replaced_to(ActiveBuffer::First)
                }
                Some(ActiveBuffer::First) => {
                    let (left, right) = buffers.split_at_mut(1);
                    let source = left[0].as_str();
                    if source.is_empty() {
                        break;
                    }
                    replace_regex_with_limit(
                        source,
                        regex,
                        self.replacement.as_str(),
                        &mut right[0],
                    )
                    .map_replaced_to(ActiveBuffer::Second)
                }
                Some(ActiveBuffer::Second) => {
                    let (left, right) = buffers.split_at_mut(1);
                    let source = right[0].as_str();
                    if source.is_empty() {
                        break;
                    }
                    replace_regex_with_limit(source, regex, self.replacement.as_str(), &mut left[0])
                        .map_replaced_to(ActiveBuffer::First)
                }
            };
            match result {
                RegexReplaceOutcome::NoMatch => {}
                RegexReplaceOutcome::Replaced(next_buffer) => active_buffer = Some(next_buffer),
                RegexReplaceOutcome::OutputLimitExceeded => {
                    return RedactionOutcome::OutputLimitExceeded;
                }
            }
        }
        match active_buffer {
            Some(ActiveBuffer::First) => {
                RedactionOutcome::Text(Cow::Owned(std::mem::take(&mut buffers[0])))
            }
            Some(ActiveBuffer::Second) => {
                RedactionOutcome::Text(Cow::Owned(std::mem::take(&mut buffers[1])))
            }
            None => RedactionOutcome::Text(Cow::Borrowed(input)),
        }
    }

    #[inline]
    pub(crate) fn has_redact_regexes(&self) -> bool {
        !self.redact.is_empty()
    }
}

fn compile_and_add_deny_glob(
    deny_builder: &mut GlobSetBuilder,
    source_pattern: &str,
    normalized_pattern: &str,
) -> Result<()> {
    crate::path_utils_internal::validate_root_relative_glob_pattern(normalized_pattern).map_err(
        |msg| Error::InvalidPolicy(format!("invalid deny glob {source_pattern:?}: {msg}")),
    )?;
    let glob = crate::path_utils_internal::build_glob_from_normalized(normalized_pattern).map_err(
        |err| Error::InvalidPolicy(format!("invalid deny glob {source_pattern:?}: {err}")),
    )?;
    deny_builder.add(glob);
    Ok(())
}

fn compile_delete_scan_pattern(normalized_pattern: &str) -> DenyDeleteScanPattern {
    if !glob_pattern_has_meta(normalized_pattern) {
        let literal = crate::path_utils::normalized_for_boundary(Path::new(normalized_pattern));
        return DenyDeleteScanPattern::Literal(literal.into_owned());
    }
    let Some(prefix) = leading_literal_glob_prefix(normalized_pattern) else {
        return DenyDeleteScanPattern::AlwaysScan;
    };
    let prefix = crate::path_utils::normalized_for_boundary(&prefix);
    DenyDeleteScanPattern::Prefix(prefix.into_owned())
}

fn glob_pattern_has_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
}

fn glob_component_has_meta(component: &std::ffi::OsStr) -> bool {
    component
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
}

fn leading_literal_glob_prefix(pattern: &str) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    for component in Path::new(pattern).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => {
                if glob_component_has_meta(segment) {
                    break;
                }
                prefix.push(segment);
            }
            _ => break,
        }
    }
    if prefix.as_os_str().is_empty() {
        None
    } else {
        Some(prefix)
    }
}

#[inline]
fn overlaps_by_boundary_prefix_normalized(a: &Path, b: &Path) -> bool {
    crate::path_utils::starts_with_case_insensitive_normalized(a, b)
        || crate::path_utils::starts_with_case_insensitive_normalized(b, a)
}

fn accumulate_pattern_bytes(total: &mut usize, pattern_bytes: usize) -> Result<()> {
    *total = total.checked_add(pattern_bytes).ok_or_else(|| {
        Error::InvalidPolicy(
            "invalid secrets: total deny/redact pattern bytes overflowed usize".to_string(),
        )
    })?;
    if *total > MAX_RULE_PATTERNS_TOTAL_BYTES {
        return Err(Error::InvalidPolicy(format!(
            "invalid secrets: total deny/redact pattern bytes too large ({} > {MAX_RULE_PATTERNS_TOTAL_BYTES})",
            *total
        )));
    }
    Ok(())
}

enum RegexReplaceResult {
    NoMatch,
    Replaced,
    OutputLimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveBuffer {
    First,
    Second,
}

enum RegexReplaceOutcome {
    NoMatch,
    Replaced(ActiveBuffer),
    OutputLimitExceeded,
}

impl RegexReplaceResult {
    fn map_replaced_to(self, buffer: ActiveBuffer) -> RegexReplaceOutcome {
        match self {
            Self::NoMatch => RegexReplaceOutcome::NoMatch,
            Self::Replaced => RegexReplaceOutcome::Replaced(buffer),
            Self::OutputLimitExceeded => RegexReplaceOutcome::OutputLimitExceeded,
        }
    }
}

fn append_segment_with_limit(output: &mut String, segment: &str) -> bool {
    match output.len().checked_add(segment.len()) {
        Some(next_len) if next_len <= MAX_REDACTED_OUTPUT_BYTES => {
            output.push_str(segment);
            true
        }
        _ => false,
    }
}

#[inline]
fn reserve_replace_output_capacity(output: &mut String, target_capacity: usize) {
    if output.capacity() < target_capacity {
        // `String::reserve` uses `len + additional`; with a cleared reusable buffer,
        // reserve the full target instead of a capacity delta.
        output.reserve(target_capacity.saturating_sub(output.len()));
    }
}

fn replace_regex_with_limit(
    input: &str,
    regex: &Regex,
    replacement: &str,
    output: &mut String,
) -> RegexReplaceResult {
    let mut matches = regex.find_iter(input);
    let Some(first_match) = matches.next() else {
        return RegexReplaceResult::NoMatch;
    };

    output.clear();
    let target_capacity = input.len().min(MAX_REDACTED_OUTPUT_BYTES);
    reserve_replace_output_capacity(output, target_capacity);
    let mut last = 0usize;

    for found in std::iter::once(first_match).chain(matches) {
        if !append_segment_with_limit(output, &input[last..found.start()]) {
            return RegexReplaceResult::OutputLimitExceeded;
        }
        if !append_segment_with_limit(output, replacement) {
            return RegexReplaceResult::OutputLimitExceeded;
        }
        last = found.end();
    }

    if !append_segment_with_limit(output, &input[last..]) {
        return RegexReplaceResult::OutputLimitExceeded;
    }
    RegexReplaceResult::Replaced
}

fn is_root_relative(path: &Path) -> bool {
    for component in path.components() {
        if matches!(component, Component::RootDir | Component::ParentDir) {
            return false;
        }
        #[cfg(windows)]
        if matches!(component, Component::Prefix(_)) {
            return false;
        }
    }
    true
}

fn normalize_relative_path(path: &Path) -> Cow<'_, Path> {
    if path.is_absolute() {
        return Cow::Borrowed(path);
    }

    let mut needs_normalization = false;
    for comp in path.components() {
        if matches!(comp, Component::CurDir | Component::ParentDir) {
            needs_normalization = true;
            break;
        }
    }

    if !needs_normalization {
        return Cow::Borrowed(path);
    }
    Cow::Owned(crate::path_utils_internal::normalize_path_lexical(path))
}

fn normalize_path_for_glob_common(path: &Path) -> Cow<'_, Path> {
    debug_assert!(is_root_relative(path));
    normalize_relative_path(path)
}

#[cfg(windows)]
fn normalize_path_for_glob(path: &Path) -> Option<Cow<'_, Path>> {
    let path = normalize_path_for_glob_common(path);
    // Fail closed on non-Unicode Windows paths: lossy conversion would change bytes and
    // could cause silent allow-on-mismatch behavior for glob checks.
    let raw = path.to_string_lossy();
    if matches!(raw, Cow::Owned(_)) {
        return None;
    }
    if !raw.contains('\\') {
        return Some(path);
    }
    Some(Cow::Owned(std::path::PathBuf::from(raw.replace('\\', "/"))))
}

#[cfg(not(windows))]
fn normalize_path_for_glob(path: &Path) -> Option<Cow<'_, Path>> {
    Some(normalize_path_for_glob_common(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretRules;

    #[test]
    fn normalize_relative_path_preserves_leading_parent_dirs() {
        assert_eq!(
            normalize_relative_path(Path::new("../..")).as_ref(),
            Path::new("../..")
        );
        assert_eq!(
            normalize_relative_path(Path::new("../../a/../b")).as_ref(),
            Path::new("../../b")
        );
        assert_eq!(
            normalize_relative_path(Path::new("a/../../b")).as_ref(),
            Path::new("../b")
        );
    }

    #[test]
    fn absolute_paths_are_denied_defensively() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        #[cfg(unix)]
        let absolute = Path::new("/tmp/.git/config");
        #[cfg(windows)]
        let absolute = Path::new(r"C:\tmp\.git\config");

        assert!(redactor.is_path_denied(absolute));
    }

    #[test]
    fn parent_relative_paths_are_denied_defensively() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        assert!(redactor.is_path_denied(Path::new("../.git/config")));
    }

    #[test]
    fn empty_redaction_regex_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["".to_string()],
            replacement: "***".to_string(),
        })
        .expect_err("empty redact regex should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("empty patterns are not allowed")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_deny_glob_is_rejected() {
        for pattern in ["", "   "] {
            let err = SecretRedactor::from_rules(&SecretRules {
                deny_globs: vec![pattern.to_string()],
                redact_regexes: Vec::new(),
                replacement: "***".to_string(),
            })
            .expect_err("empty deny glob should be rejected");

            match err {
                Error::InvalidPolicy(msg) => {
                    assert!(
                        msg.contains("secrets.deny_globs"),
                        "unexpected message: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn deny_glob_directory_itself_is_denied() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        assert!(redactor.is_path_denied(Path::new(".git")));
        assert!(redactor.is_path_denied(Path::new(".git/config")));
        assert!(!redactor.is_path_denied(Path::new("src")));
    }

    #[test]
    fn redact_text_cow_returns_borrowed_when_no_regex_configured() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let input = "no secrets here";
        let redacted = redactor.redact_text_cow(input);
        assert!(matches!(&redacted, Cow::Borrowed(_)));
        assert_eq!(redacted.as_ref(), input);
    }

    #[test]
    fn redact_text_cow_returns_borrowed_when_regex_configured_but_no_match() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["token".to_string()],
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let input = "no secrets here";
        let redacted = redactor.redact_text_cow(input);
        assert!(matches!(&redacted, Cow::Borrowed(_)));
        assert_eq!(redacted.as_ref(), input);
    }

    #[test]
    fn redact_text_cow_returns_borrowed_for_empty_input_with_regexes() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["token".to_string(), "secret".to_string()],
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let redacted = redactor.redact_text_cow("");
        assert!(matches!(&redacted, Cow::Borrowed(_)));
        assert_eq!(redacted.as_ref(), "");
    }

    #[test]
    fn redact_text_short_circuits_after_becoming_empty() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["foo".to_string(), ".".to_string()],
            replacement: "".to_string(),
        })
        .expect("redactor");

        let redacted = redactor.redact_text_cow("foo");
        assert_eq!(redacted.as_ref(), "");
    }

    #[test]
    fn redact_text_cow_applies_regexes_in_order() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["ab".to_string(), "b.".to_string()],
            replacement: "X".to_string(),
        })
        .expect("redactor");

        let redacted = redactor.redact_text_cow("abc");
        assert_eq!(redacted.as_ref(), "Xc");
    }

    #[test]
    fn redact_text_applies_later_regex_after_earlier_replacement() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["foo".to_string(), "^X".to_string()],
            replacement: "XY".to_string(),
        })
        .expect("redactor");

        let redacted = redactor.redact_text_cow("foo");
        assert_eq!(redacted.as_ref(), "XYY");
    }

    #[test]
    fn reserve_replace_output_capacity_grows_reused_buffer_to_target() {
        let mut output = String::with_capacity(32);
        output.push_str("seed");
        output.clear();

        reserve_replace_output_capacity(&mut output, 128);
        assert!(output.capacity() >= 128);
    }

    #[test]
    fn too_many_redact_regexes_are_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: (0..=MAX_REDACT_REGEXES)
                .map(|idx| format!("token{idx}"))
                .collect(),
            replacement: "***".to_string(),
        })
        .expect_err("too many redact regexes should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("too many patterns")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn too_many_deny_globs_are_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: (0..=MAX_DENY_GLOBS)
                .map(|idx| format!("secret-dir-{idx}/**"))
                .collect(),
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect_err("too many deny globs should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("too many patterns")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn oversized_deny_glob_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec!["x".repeat(MAX_GLOB_PATTERN_BYTES + 1)],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect_err("oversized deny glob should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("secrets.deny_globs")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn oversized_redact_regex_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["a".repeat(MAX_REDACT_REGEX_BYTES + 1)],
            replacement: "***".to_string(),
        })
        .expect_err("oversized redact regex should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("secrets.redact_regexes")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn total_pattern_budget_is_enforced() {
        let deny_count = (MAX_RULE_PATTERNS_TOTAL_BYTES / MAX_GLOB_PATTERN_BYTES) + 1;
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec!["a".repeat(MAX_GLOB_PATTERN_BYTES); deny_count],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect_err("total pattern budget should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("total deny/redact pattern bytes")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn implicit_directory_root_counts_toward_pattern_budget() {
        let pattern = format!("{}{}", "a".repeat(MAX_GLOB_PATTERN_BYTES - 3), "/**");
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![pattern; 9],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect_err("total pattern budget should include implicit directory root patterns");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("total deny/redact pattern bytes")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn oversized_replacement_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec![".".to_string()],
            replacement: "X".repeat(MAX_REPLACEMENT_BYTES + 1),
        })
        .expect_err("oversized replacement should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("secrets.replacement")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn redaction_output_is_capped() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec![".".to_string()],
            replacement: "X".repeat(MAX_REPLACEMENT_BYTES),
        })
        .expect("redactor");

        let input = "a".repeat((MAX_REDACTED_OUTPUT_BYTES / MAX_REPLACEMENT_BYTES) + 1);
        let redacted = redactor.redact_text_cow(&input);
        assert_eq!(redacted.as_ref(), REDACTION_OUTPUT_LIMIT_MARKER);
    }

    #[test]
    fn redact_text_outcome_reports_output_limit_exceeded() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec![".".to_string()],
            replacement: "X".repeat(MAX_REPLACEMENT_BYTES),
        })
        .expect("redactor");

        let input = "a".repeat((MAX_REDACTED_OUTPUT_BYTES / MAX_REPLACEMENT_BYTES) + 1);
        let outcome = redactor.redact_text_outcome(&input);
        assert!(matches!(outcome, RedactionOutcome::OutputLimitExceeded));
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_windows_path_is_denied_fail_closed() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::PathBuf;

        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let path = PathBuf::from(OsString::from_wide(&[0xD800, b'a' as u16]));
        assert!(is_root_relative(&path));
        assert!(normalize_path_for_glob(&path).is_none());
        assert!(redactor.is_path_denied(&path));
    }
}
