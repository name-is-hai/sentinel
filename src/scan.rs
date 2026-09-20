use clap::Args;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::{File, metadata},
    path::{Path, PathBuf},
    process::Stdio,
};

use crate::{
    config,
    models::{Decision, Finding, ScanError, SecurityPolicy, Severity},
};

#[derive(Args, Debug)]
pub struct ScanArgs {
    pub path: PathBuf,

    #[arg(long = "allow-id", action = clap::ArgAction::Append)]
    pub allowed_ids: Vec<String>,

    #[arg(long, default_value = ".sentinel.yaml")]
    pub config: PathBuf,

    #[arg(long, default_value = "./report")]
    pub output: String,
}

#[derive(Args, Debug)]
pub struct SbomArgs {
    pub path: PathBuf,

    #[arg(long, default_value = "./report")]
    pub output: String,
}

pub struct ScanTarget<'target> {
    pub path: &'target PathBuf,
}

#[derive(Debug, Deserialize)]
struct GrypeReport {
    matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVulnerability,
}

#[derive(Debug, Deserialize)]
struct GrypeVulnerability {
    id: String,
    description: String,

    #[serde(default = "Severity::unknown")]
    severity: Severity,
}

pub fn run_doctor() {
    println!("Checking tools...");
    check_tool("syft");
    check_tool("grype");
}

fn check_tool(name: &str) {
    match std::process::Command::new(name).arg("--version").output() {
        Ok(output) if output.status.success() => println!("{}: OK", name),
        _ => println!("{}: MISSING", name),
    }
}

pub fn run_scan(
    target: &ScanTarget,
    allowed_ids: &Vec<String>,
    config_path: &PathBuf,
    output: &str,
) -> Result<Decision, ScanError> {
    println!("Target: {}", target.path.display());
    println!("Starting security scan...");

    let syft_path = run_sbom(target, output)?;
    let grype_path = run_grype(&syft_path, output)?;

    println!("Raw Grype report: {}", grype_path.display());

    let config = config::load_config(Some(config_path));
    let mut allowed_ids = allowed_ids.clone();
    allowed_ids.append(&mut config.security.vulnerabilities.allow.clone());
    allowed_ids.dedup();

    let policy = SecurityPolicy {
        block_critical: config.security.vulnerabilities.block.critical,
        block_high: config.security.vulnerabilities.block.high,
        block_medium: config.security.vulnerabilities.block.medium,
        block_low: config.security.vulnerabilities.block.low,
        block_info: config.security.vulnerabilities.block.info,
        block_unknown: config.security.vulnerabilities.block.unknown,
        allowed_ids: allowed_ids,
    };

    let report = run_grype_report(&grype_path)?;
    let findings = run_normalize_grype(&report);
    let decision = evaluate_policy(&findings, &policy);

    println!("Grype matches: {}", report.matches.len());
    println!("Policy: {:?}", decision);
    println!("Allowed IDs: {:?}", policy.allowed_ids);
    print_policy_reason(&findings, &policy, &decision);
    // print_findings_by_severity(&findings, &policy);

    return Ok(decision);
}

fn run_normalize_grype(report: &GrypeReport) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for vul in report.matches.iter() {
        findings.push(Finding {
            id: vul.vulnerability.id.clone(),
            severity: vul.vulnerability.severity,
            scanner: "grype".to_string(),
            message: vul.vulnerability.description.clone(),
        });
    }

    findings
}

fn run_grype_report(path: &PathBuf) -> Result<GrypeReport, ScanError> {
    let grype_file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Err(ScanError::OutputFileError),
    };

    match serde_json::from_reader(grype_file) {
        Ok(report) => Ok(report),
        Err(_) => Err(ScanError::ToolFailed),
    }
}

fn run_grype(sbom_path: &PathBuf, output: &str) -> Result<PathBuf, ScanError> {
    if !sbom_path.exists() {
        return Err(ScanError::InvalidTarget);
    }
    println!("Output Grype directory: {}", output);

    match std::fs::create_dir_all(output) {
        Ok(()) => {}
        Err(_) => return Err(ScanError::OutputDirectoryError),
    }

    let grype_path = Path::new(output).join("grype.json");

    let file = match File::create(&grype_path) {
        Ok(f) => f,
        _ => return Err(ScanError::OutputFileError),
    };

    match std::process::Command::new("grype")
        .arg(sbom_path)
        .arg("--output")
        .arg("json")
        .stdout(Stdio::from(file))
        .status()
    {
        Ok(result) if result.success() => {
            println!("Grype written to {}", grype_path.display());
            println!("Grype generated successfully");
            Ok(grype_path)
        }
        _ => return Err(ScanError::ToolFailed),
    }
}

pub fn run_sbom(target: &ScanTarget, output: &str) -> Result<PathBuf, ScanError> {
    if !target.path.exists() {
        return Err(ScanError::InvalidTarget);
    }
    println!("Generating SBOM for {}", target.path.display());
    println!("Output directory: {}", output);

    match std::fs::create_dir_all(output) {
        Ok(()) => {}
        Err(_) => return Err(ScanError::OutputDirectoryError),
    }

    let sbom_path = Path::new(output).join("sbom.cdx.json");

    let file = match File::create(&sbom_path) {
        Ok(f) => f,
        _ => return Err(ScanError::OutputFileError),
    };

    match std::process::Command::new("syft")
        .arg("scan")
        .arg(target.path)
        .arg("--output")
        .arg("cyclonedx-json")
        .stdout(Stdio::from(file))
        .status()
    {
        Ok(result) if result.success() => {
            println!("SBOM written to {}", sbom_path.display());
            println!("SBOM generated successfully");
        }
        _ => return Err(ScanError::ToolFailed),
    };

    match metadata(&sbom_path) {
        Ok(metadata) => {
            println!("SBOM size: {} bytes", metadata.len());
            Ok(sbom_path)
        }
        _ => Err(ScanError::OutputFileError),
    }
}

fn print_policy_reason(findings: &[Finding], policy: &SecurityPolicy, decision: &Decision) {
    println!("Decision: {:?}", decision);
    println!("Reason:");
    let findings = findings
        .iter()
        .filter(|finding| !policy.allowed_ids.contains(&finding.id))
        .collect::<Vec<_>>();

    if findings.is_empty() {
        println!("No active findings matched blocking severities");
        return;
    }

    let findings_by_severity = findings.iter().fold(HashMap::new(), |mut acc, finding| {
        acc.entry(finding.severity)
            .or_insert_with(Vec::new)
            .push(finding);
        acc
    });

    let mut severity_order = Vec::new();

    for severity in findings_by_severity.keys() {
        if !policy.block_critical && *severity == Severity::Critical {
            continue;
        }
        if !policy.block_high && *severity == Severity::High {
            continue;
        }
        if !policy.block_medium && *severity == Severity::Medium {
            continue;
        }
        if !policy.block_low && *severity == Severity::Low {
            continue;
        }
        if !policy.block_info && *severity == Severity::Info {
            continue;
        }
        if !policy.block_unknown && *severity == Severity::Unknown {
            continue;
        }
        severity_order.push(*severity);
    }

    severity_order.sort();

    for severity in &severity_order {
        if let Some(findings) = findings_by_severity.get(severity) {
            println!(
                "{:?} {} active {}",
                severity,
                findings.len(),
                if findings.len() > 1 {
                    "findings"
                } else {
                    "finding"
                }
            );
        }
    }
}

// fn print_findings_by_severity(findings: &[Finding], policy: &SecurityPolicy) {
//     println!("Findings by severity:");
//     let findings_by_severity = findings.iter().fold(HashMap::new(), |mut acc, finding| {
//         acc.entry(finding.severity)
//             .or_insert_with(Vec::new)
//             .push(finding);
//         acc
//     });
//     let severity_order = [
//         Severity::Critical,
//         Severity::High,
//         Severity::Medium,
//         Severity::Low,
//         Severity::Info,
//         Severity::Unknown,
//     ];

//     for severity in &severity_order {
//         if let Some(findings) = findings_by_severity.get(severity) {
//             println!("Severity: {:?}, Count: {}", severity, findings.len());
//         }
//     }

//     for severity in &severity_order {
//         if let Some(findings) = findings_by_severity.get(severity) {
//             println!("Severity: {:?}", severity);
//             for (index, finding) in findings.iter().enumerate() {
//                 println!("{}. Finding ID: {}", index + 1, finding.id);
//                 println!("    Scanner: {}", finding.scanner);
//                 println!("    Severity: {:?}", finding.severity);
//                 println!("    Message: {}", finding.message);
//                 let status = if policy.allowed_ids.contains(&finding.id) {
//                     "Allowed".to_string()
//                 } else {
//                     "Active".to_string()
//                 };
//                 println!("    Status: {}", status);
//             }
//         }
//     }
// }

fn evaluate_policy(findings: &[Finding], policy: &SecurityPolicy) -> Decision {
    for finding in findings {
        let is_allowed = policy.allowed_ids.contains(&finding.id);

        if is_allowed {
            continue;
        }
        let should_block = match finding.severity {
            Severity::Critical => policy.block_critical,
            Severity::High => policy.block_high,
            Severity::Medium => policy.block_medium,
            Severity::Low => policy.block_low,
            Severity::Info => policy.block_info,
            Severity::Unknown => policy.block_unknown,
        };
        if should_block {
            return Decision::Block;
        }
    }
    return Decision::Allow;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(block_critical: bool, allowed_ids: Vec<String>) -> SecurityPolicy {
        SecurityPolicy {
            block_critical,
            block_high: false,
            block_medium: false,
            block_low: false,
            block_info: false,
            block_unknown: false,
            allowed_ids,
        }
    }

    #[test]
    fn blocks_when_critical_finding_exists() {
        let findings = vec![Finding {
            id: "test1".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        }];

        let policy = test_policy(true, vec!["test".into()]);

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Block);
    }

    #[test]
    fn allows_when_critical_finding_is_allowed() {
        let findings = vec![Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        }];

        let policy = test_policy(true, vec!["test".into()]);

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn allows_when_no_critical_finding_exists() {
        let findings = vec![Finding {
            id: "test2".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::High,
        }];

        let policy = test_policy(true, vec!["test".into()]);

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn allows_critical_when_block_critical_is_false() {
        let findings = vec![Finding {
            id: "test2".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        }];

        let policy = test_policy(false, vec!["test".into()]);

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn blocks_when_one_critical_is_not_allowed() {
        let findings = vec![
            Finding {
                id: "allowed-cve".into(),
                message: "accepted risk".into(),
                scanner: "trivy".into(),
                severity: Severity::Critical,
            },
            Finding {
                id: "new-cve".into(),
                message: "new critical issue".into(),
                scanner: "trivy".into(),
                severity: Severity::Critical,
            },
        ];

        let policy = test_policy(true, vec!["allowed-cve".into()]);

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Block);
    }

    #[test]
    fn blocks_when_high_policy_is_enabled() {
        let findings = vec![Finding {
            id: "high-1".into(),
            message: "high issue".into(),
            scanner: "grype".into(),
            severity: Severity::High,
        }];

        let policy = SecurityPolicy {
            block_critical: false,
            block_high: true,
            block_medium: false,
            block_low: false,
            block_info: false,
            block_unknown: false,
            allowed_ids: vec![],
        };

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Block);
    }
}
