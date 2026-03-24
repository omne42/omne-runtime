#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;

mod command_exec;
mod error;
mod input;

use error::{
    CLI_ERROR_CODE_INVALID_CLI_ARGS, CliError, PathRedaction, tool_error_details,
    tool_error_details_with, tool_public_message,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ErrorFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "omne-fs")]
#[command(
    about = "Safe filesystem tools (read/glob/grep/edit/patch/delete) with explicit sandbox policy."
)]
struct Cli {
    #[arg(long)]
    policy: PathBuf,

    /// Pretty-print JSON responses (stdout and stderr).
    #[arg(long)]
    pretty: bool,

    #[arg(long, value_enum, default_value_t = ErrorFormat::Text)]
    error_format: ErrorFormat,

    /// Redact file paths in JSON errors (best-effort).
    ///
    /// Useful when stderr is exposed to untrusted users; avoids leaking absolute paths.
    #[arg(long)]
    redact_paths: bool,

    /// Strict path redaction in JSON errors.
    ///
    /// Hides file names for absolute paths that are outside configured roots. This implies
    /// `--redact-paths` and is intended for scenarios where even file names are sensitive.
    #[arg(long)]
    redact_paths_strict: bool,

    /// Max bytes for patch input (stdin or file).
    ///
    /// Defaults to `policy.limits.max_patch_bytes` if set, otherwise `policy.limits.max_read_bytes`.
    #[arg(long)]
    #[arg(value_parser = clap::value_parser!(u64).range(1..))]
    max_patch_bytes: Option<u64>,

    /// Require explicit confirmation before executing mutating operations.
    ///
    /// Mutating commands: `edit`, `patch`, `mkdir`, `write`, `delete`, `move`, `copy-file`.
    #[arg(long, default_value_t = false)]
    confirm_mutating_ops: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Read {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        start_line: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        end_line: Option<u64>,
    },
    ListDir {
        #[arg(long)]
        root: String,
        #[arg(long)]
        max_entries: Option<usize>,
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Glob {
        #[arg(long)]
        root: String,
        pattern: String,
    },
    Grep {
        #[arg(long)]
        root: String,
        query: String,
        #[arg(long, default_value_t = false)]
        regex: bool,
        #[arg(long)]
        glob: Option<String>,
    },
    Stat {
        #[arg(long)]
        root: String,
        path: PathBuf,
    },
    Edit {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        start_line: u64,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        end_line: u64,
        replacement: String,
    },
    Patch {
        #[arg(long)]
        root: String,
        path: PathBuf,
        patch_file: PathBuf,
    },
    Mkdir {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
        #[arg(long, default_value_t = false)]
        ignore_existing: bool,
    },
    Write {
        #[arg(long)]
        root: String,
        path: PathBuf,
        content_file: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
    Delete {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        recursive: bool,
        #[arg(long, default_value_t = false)]
        ignore_missing: bool,
    },
    Move {
        #[arg(long)]
        root: String,
        from: PathBuf,
        to: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
    CopyFile {
        #[arg(long)]
        root: String,
        from: PathBuf,
        to: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
}

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => return handle_parse_error(err),
    };
    let error_format = cli.error_format;
    let pretty = cli.pretty;
    let redact_paths = cli.redact_paths || cli.redact_paths_strict;
    let strict_redact_paths = cli.redact_paths_strict;
    if let Err(err) = validate_error_render_mode(error_format, redact_paths) {
        emit_error(
            &err,
            ErrorRenderCfg {
                format: error_format,
                pretty: cli.pretty,
                redact_paths,
                strict_redact_paths,
                redaction: None,
            },
        );
        return ExitCode::FAILURE;
    }
    let mut redaction = None::<PathRedaction>;

    let result = match omne_fs::policy_io::load_policy(&cli.policy) {
        Ok(policy) => {
            redaction = build_redaction(&policy, error_format, redact_paths);
            command_exec::run_with_policy(cli, policy)
        }
        Err(err) => Err(CliError::Tool(err)),
    };

    if let Err(err) = result {
        emit_error(
            &err,
            ErrorRenderCfg {
                format: error_format,
                pretty,
                redact_paths,
                strict_redact_paths,
                redaction: redaction.as_ref(),
            },
        );
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn handle_parse_error(err: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;

    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        return print_clap_message(err);
    }

    let cfg = parse_error_render_cfg_from_env();
    let render_mode_err = validate_error_render_mode(cfg.format, cfg.redact_paths).err();
    emit_parse_error(&err, cfg, render_mode_err.as_ref());
    ExitCode::FAILURE
}

fn print_clap_message(err: clap::Error) -> ExitCode {
    let message = err.to_string();
    let trimmed = message.trim_end_matches('\n');
    let write_result = if err.use_stderr() {
        write_stderr_line(trimmed)
    } else {
        write_stdout_line(trimmed)
    };
    if write_result.is_err() {
        write_stderr_fallback();
    }
    if err.exit_code() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_error_render_cfg_from_env() -> ErrorRenderCfg<'static> {
    parse_error_render_cfg_from_args(std::env::args_os())
}

fn parse_error_render_cfg_from_args<I, T>(args: I) -> ErrorRenderCfg<'static>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let matches = match Cli::command()
        .ignore_errors(true)
        .try_get_matches_from(args)
    {
        Ok(matches) => matches,
        Err(_) => {
            return ErrorRenderCfg {
                format: ErrorFormat::Text,
                pretty: false,
                redact_paths: false,
                strict_redact_paths: false,
                redaction: None,
            };
        }
    };

    let format = matches
        .get_one::<ErrorFormat>("error_format")
        .copied()
        .unwrap_or(ErrorFormat::Text);
    let pretty = matches.get_flag("pretty");
    let strict_redact_paths = matches.get_flag("redact_paths_strict");
    let redact_paths = matches.get_flag("redact_paths") || strict_redact_paths;

    ErrorRenderCfg {
        format,
        pretty,
        redact_paths,
        strict_redact_paths,
        redaction: None,
    }
}

fn emit_parse_error(
    err: &clap::Error,
    cfg: ErrorRenderCfg<'_>,
    render_mode_err: Option<&CliError>,
) {
    let rendered = render_parse_error(err, cfg, render_mode_err);
    if write_stderr_line(&rendered).is_err() {
        write_stderr_fallback();
    }
}

fn render_parse_error(
    err: &clap::Error,
    cfg: ErrorRenderCfg<'_>,
    render_mode_err: Option<&CliError>,
) -> String {
    let message = err.to_string();
    let message = message.trim_end_matches('\n');
    let public_message = if cfg.redact_paths {
        "invalid cli arguments".to_string()
    } else {
        message.to_string()
    };
    let render_mode_message = render_mode_err.map(|mode_err| match mode_err {
        CliError::Tool(tool) => {
            tool_public_message(tool, None, cfg.redact_paths, cfg.strict_redact_paths)
        }
        CliError::Json(_) => mode_err.to_string(),
        CliError::ArgsValidation(_) => mode_err.to_string(),
    });

    match cfg.format {
        ErrorFormat::Text => {
            if let Some(render_mode_message) = render_mode_message {
                format!("{public_message}\nnote: {render_mode_message}")
            } else {
                public_message
            }
        }
        ErrorFormat::Json => {
            let mut details = serde_json::Map::new();
            details.insert(
                "kind".to_string(),
                serde_json::Value::String("clap_error".to_string()),
            );
            details.insert(
                "clap_kind".to_string(),
                serde_json::Value::String(format!("{:?}", err.kind())),
            );
            if let Some(render_mode_message) = render_mode_message {
                details.insert(
                    "render_mode".to_string(),
                    serde_json::json!({
                        "message": render_mode_message,
                    }),
                );
            }

            let out = serde_json::json!({
                "error": {
                    "code": CLI_ERROR_CODE_INVALID_CLI_ARGS,
                    "message": public_message,
                    "details": details,
                }
            });
            match serialize_json(&out, cfg.pretty) {
                Ok(text) => text,
                Err(_) => fallback_json_error(),
            }
        }
    }
}

fn validate_error_render_mode(
    error_format: ErrorFormat,
    redact_paths: bool,
) -> Result<(), CliError> {
    if redact_paths && !matches!(error_format, ErrorFormat::Json) {
        return Err(CliError::ArgsValidation(
            "--redact-paths/--redact-paths-strict require --error-format json".to_string(),
        ));
    }
    Ok(())
}

fn emit_error(err: &CliError, cfg: ErrorRenderCfg<'_>) {
    let rendered = render_error(err, cfg);
    if write_stderr_line(&rendered).is_err() {
        write_stderr_fallback();
    }
}

fn build_redaction(
    policy: &omne_fs::policy::SandboxPolicy,
    error_format: ErrorFormat,
    redact_paths: bool,
) -> Option<PathRedaction> {
    if matches!(error_format, ErrorFormat::Json) && redact_paths {
        Some(PathRedaction::from_policy(policy))
    } else {
        None
    }
}

struct ErrorRenderCfg<'a> {
    format: ErrorFormat,
    pretty: bool,
    redact_paths: bool,
    strict_redact_paths: bool,
    redaction: Option<&'a PathRedaction>,
}

fn render_error(err: &CliError, cfg: ErrorRenderCfg<'_>) -> String {
    match cfg.format {
        ErrorFormat::Text => err.to_string(),
        ErrorFormat::Json => render_json_error(err, cfg),
    }
}

fn render_json_error(err: &CliError, cfg: ErrorRenderCfg<'_>) -> String {
    let mut error = serde_json::Map::new();
    error.insert(
        "code".to_string(),
        serde_json::Value::String(err.code().to_string()),
    );
    error.insert(
        "message".to_string(),
        serde_json::Value::String(match err {
            CliError::Tool(tool) => tool_public_message(
                tool,
                cfg.redaction,
                cfg.redact_paths,
                cfg.strict_redact_paths,
            ),
            CliError::Json(_) => err.to_string(),
            CliError::ArgsValidation(message) => message.clone(),
        }),
    );

    if let CliError::Tool(tool) = err {
        let details = if cfg.redact_paths {
            tool_error_details_with(tool, cfg.redaction, true, cfg.strict_redact_paths)
        } else {
            tool_error_details(tool)
        };
        error.insert("details".to_string(), details);
    }

    let out = serde_json::json!({ "error": error });
    match serialize_json(&out, cfg.pretty) {
        Ok(text) => text,
        Err(_) => fallback_json_error(),
    }
}

fn fallback_json_error() -> String {
    const FALLBACK: &str =
        r#"{"error":{"code":"json","message":"failed to serialize json error output"}}"#;
    let fallback = serde_json::json!({
        "error": {
            "code": "json",
            "message": "failed to serialize json error output",
        }
    });
    match serde_json::to_string(&fallback) {
        Ok(text) => text,
        Err(_) => FALLBACK.to_string(),
    }
}

fn serialize_json<T: Serialize>(value: &T, pretty: bool) -> Result<String, CliError> {
    if pretty {
        Ok(serde_json::to_string_pretty(value)?)
    } else {
        Ok(serde_json::to_string(value)?)
    }
}

fn map_broken_pipe(result: std::io::Result<()>) -> Result<(), CliError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(CliError::Tool(omne_fs::Error::Io(err))),
    }
}

fn write_stdout_line(line: &str) -> Result<(), CliError> {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    map_broken_pipe(stdout.write_all(line.as_bytes()))?;
    map_broken_pipe(stdout.write_all(b"\n"))?;
    map_broken_pipe(stdout.flush())
}

fn write_stderr_line(line: &str) -> Result<(), CliError> {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    map_broken_pipe(stderr.write_all(line.as_bytes()))?;
    map_broken_pipe(stderr.write_all(b"\n"))?;
    map_broken_pipe(stderr.flush())
}

fn write_stderr_fallback() {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(b"omne-fs: failed to write error output to stderr\n");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod parse_error_tests {
    use super::*;

    fn parse_cfg(args: &[&str]) -> ErrorRenderCfg<'static> {
        let args = std::iter::once("omne-fs")
            .chain(args.iter().copied())
            .collect::<Vec<_>>();
        parse_error_render_cfg_from_args(args)
    }

    #[test]
    fn parse_error_cfg_does_not_swallow_flag_after_missing_error_format_value() {
        let cfg = parse_cfg(&["--error-format", "--pretty", "--redact-paths"]);
        assert!(matches!(cfg.format, ErrorFormat::Text));
        assert!(cfg.pretty);
        assert!(cfg.redact_paths);
        assert!(!cfg.strict_redact_paths);
    }

    #[test]
    fn parse_error_cfg_ignores_tokens_after_double_dash() {
        let cfg = parse_cfg(&["--pretty", "--", "--error-format=json", "--redact-paths"]);
        assert!(cfg.pretty);
        assert!(matches!(cfg.format, ErrorFormat::Text));
        assert!(!cfg.redact_paths);
        assert!(!cfg.strict_redact_paths);
    }

    #[test]
    fn parse_error_json_code_is_invalid_cli_args() {
        let err =
            Cli::try_parse_from(["omne-fs", "--policy", "policy.toml", "--definitely-unknown"])
                .expect_err("expected clap parse error");

        let rendered = render_parse_error(
            &err,
            ErrorRenderCfg {
                format: ErrorFormat::Json,
                pretty: false,
                redact_paths: false,
                strict_redact_paths: false,
                redaction: None,
            },
            None,
        );

        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["error"]["code"], CLI_ERROR_CODE_INVALID_CLI_ARGS);
    }

    #[test]
    fn parse_error_keeps_primary_error_when_render_mode_is_invalid() {
        let err =
            Cli::try_parse_from(["omne-fs", "--policy", "policy.toml", "--definitely-unknown"])
                .expect_err("expected clap parse error");

        let rendered = render_parse_error(
            &err,
            ErrorRenderCfg {
                format: ErrorFormat::Json,
                pretty: false,
                redact_paths: true,
                strict_redact_paths: false,
                redaction: None,
            },
            Some(&CliError::ArgsValidation(
                "--redact-paths/--redact-paths-strict require --error-format json".to_string(),
            )),
        );

        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
        assert_eq!(parsed["error"]["code"], CLI_ERROR_CODE_INVALID_CLI_ARGS);
        assert_eq!(parsed["error"]["message"], "invalid cli arguments");
        assert_eq!(
            parsed["error"]["details"]["render_mode"]["message"],
            "--redact-paths/--redact-paths-strict require --error-format json"
        );
    }
}
