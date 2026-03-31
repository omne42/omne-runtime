#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use omne_execution_gateway::{ExecGateway, GatewayPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityArgs {
    json: bool,
    policy_path: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    let gateway = match load_gateway(&args) {
        Ok(gateway) => gateway,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let report = gateway.capability_report();
    if args.json {
        match serde_json::to_string(&report) {
            Ok(rendered) => println!("{rendered}"),
            Err(err) => {
                eprintln!("failed to serialize capability output: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("supported_isolation={:?}", report.supported_isolation);
    }

    ExitCode::SUCCESS
}

fn parse_args() -> Result<CapabilityArgs, String> {
    parse_args_from(std::env::args())
}

fn parse_args_from<I, S>(args: I) -> Result<CapabilityArgs, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = CapabilityArgs {
        json: false,
        policy_path: None,
    };
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "--json" => parsed.json = true,
            "--policy" => {
                let path = args.next().ok_or_else(|| {
                    "missing value for --policy. usage: capability [--json] [--policy <policy.json>]".to_string()
                })?;
                parsed.policy_path = Some(PathBuf::from(path.as_ref()));
            }
            other => {
                return Err(format!(
                    "unknown argument: {other}. usage: capability [--json] [--policy <policy.json>]"
                ));
            }
        }
    }
    Ok(parsed)
}

fn load_gateway(args: &CapabilityArgs) -> Result<ExecGateway, String> {
    match &args.policy_path {
        Some(path) => GatewayPolicy::load_json(path)
            .map(ExecGateway::with_policy)
            .map_err(|err| format!("failed to load policy {}: {err}", path.display())),
        None => Ok(ExecGateway::new()),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use omne_execution_gateway::CapabilityReport;
    use policy_meta::ExecutionIsolation;
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn canonical_temp_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .expect("canonicalize tempdir root")
    }

    #[test]
    fn parse_args_accepts_json_flag() {
        assert_eq!(
            parse_args_from(["capability", "--json"]).expect("parse args"),
            CapabilityArgs {
                json: true,
                policy_path: None,
            }
        );
    }

    #[test]
    fn parse_args_accepts_policy_path() {
        assert_eq!(
            parse_args_from(["capability", "--policy", "/tmp/policy.json"]).expect("parse args"),
            CapabilityArgs {
                json: false,
                policy_path: Some(PathBuf::from("/tmp/policy.json")),
            }
        );
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args_from(["capability", "--yaml"]).expect_err("reject unknown flag");
        assert!(err.contains("usage: capability [--json] [--policy <policy.json>]"));
    }

    #[test]
    fn parse_args_rejects_missing_policy_value() {
        let err = parse_args_from(["capability", "--policy"]).expect_err("missing policy");
        assert!(err.contains("missing value for --policy"));
    }

    #[test]
    fn capability_output_serializes_report_fields_only() {
        let report = CapabilityReport {
            supported_isolation: ExecutionIsolation::BestEffort,
            policy_default_isolation: ExecutionIsolation::BestEffort,
        };
        let value = serde_json::to_value(report).expect("serialize output");

        assert_eq!(value["supported_isolation"], "best_effort");
        assert_eq!(value["policy_default_isolation"], "best_effort");
        assert_eq!(
            value,
            json!({
                "supported_isolation": "best_effort",
                "policy_default_isolation": "best_effort"
            })
        );
    }

    #[test]
    fn load_gateway_without_policy_uses_none_default_for_none_only_hosts() {
        let gateway = load_gateway(&CapabilityArgs {
            json: true,
            policy_path: None,
        })
        .expect("load default gateway");

        assert_eq!(
            gateway.capability_report(),
            CapabilityReport {
                supported_isolation: ExecutionIsolation::None,
                policy_default_isolation: ExecutionIsolation::None,
            }
        );
    }

    #[test]
    fn load_gateway_uses_policy_file_defaults() {
        let dir = tempdir().expect("tempdir");
        let path = canonical_temp_root(&dir).join("policy.json");
        fs::write(
            &path,
            r#"{
  "allow_isolation_none": false,
  "enforce_allowlisted_program_for_mutation": true,
  "mutating_program_allowlist": ["/usr/local/bin/omne-fs"],
  "default_isolation": "strict",
  "audit_log_path": null
}"#,
        )
        .expect("write policy");

        let gateway = load_gateway(&CapabilityArgs {
            json: true,
            policy_path: Some(path),
        })
        .expect("load gateway");

        assert_eq!(
            gateway.capability_report().policy_default_isolation,
            ExecutionIsolation::Strict
        );
    }
}
