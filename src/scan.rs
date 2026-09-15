use std::collections::HashMap;

use crate::models::{Decision, Finding, ScanError, ScanReport, SecurityPolicy, Severity};
use clap::Args;

#[derive(Args, Debug)]
pub struct ScanArgs {
    pub path: std::path::PathBuf,

    #[arg(long, default_value = "./report")]
    pub output: String,
}

pub struct ScanTarget<'target> {
    pub path: &'target std::path::PathBuf,
}

pub fn run_scan(target: &ScanTarget) -> Result<Decision, ScanError> {
    println!("Target: {}", target.path.display());
    println!("Starting security scan...");

    let policy = SecurityPolicy {
        block_critical: true,
        allowed_ids: vec!["test1".into()],
    };

    let findings = fake_scan(target)?;
    let decision = evaluate_policy(&findings, &policy);

    let report = ScanReport { decision, findings };

    println!("Policy: {:?}", report.decision);
    print_findings_by_severity(&report.findings, &policy);

    return Ok(report.decision);
}

fn print_findings_by_severity(findings: &[Finding], policy: &SecurityPolicy) {
    println!("Findings by severity:");
    let findings_by_severity = findings.iter().fold(HashMap::new(), |mut acc, finding| {
        acc.entry(finding.severity)
            .or_insert_with(Vec::new)
            .push(finding);
        acc
    });
    let severity_order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
        Severity::Unknown,
    ];

    for severity in &severity_order {
        if let Some(findings) = findings_by_severity.get(severity) {
            println!("Severity: {:?}, Count: {}", severity, findings.len());
        }
    }

    for severity in &severity_order {
        if let Some(findings) = findings_by_severity.get(severity) {
            println!("Severity: {:?}", severity);
            for (index, finding) in findings.iter().enumerate() {
                println!("{}. Finding ID: {}", index + 1, finding.id);
                println!("    Scanner: {}", finding.scanner);
                println!("    Message: {}", finding.message);
                let status = if policy.allowed_ids.contains(&finding.id) {
                    "Allowed".to_string()
                } else {
                    "Active".to_string()
                };
                println!("    Status: {}", status);
            }
        }
    }
}

fn evaluate_policy(findings: &[Finding], policy: &SecurityPolicy) -> Decision {
    for finding in findings {
        let is_allowed = policy.allowed_ids.contains(&finding.id);

        if is_allowed {
            continue;
        }

        if policy.block_critical && finding.severity == Severity::Critical {
            return Decision::Block;
        }
    }
    return Decision::Allow;
}

fn fake_scan(target: &ScanTarget) -> Result<Vec<Finding>, ScanError> {
    if !target.path.exists() {
        return Err(ScanError::InvalidTarget);
    }
    Ok(fake_findings())
}

fn fake_findings() -> Vec<Finding> {
    vec![
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        },
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        },
        Finding {
            id: "test2".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::High,
        },
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Medium,
        },
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Info,
        },
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Low,
        },
        Finding {
            id: "test".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Unknown,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_when_critical_finding_exists() {
        let findings = vec![Finding {
            id: "test1".into(),
            message: "messages".into(),
            scanner: "trivy".into(),
            severity: Severity::Critical,
        }];

        let policy = SecurityPolicy {
            block_critical: true,
            allowed_ids: vec!["test".into()],
        };

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

        let policy = SecurityPolicy {
            block_critical: true,
            allowed_ids: vec!["test".into()],
        };

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

        let policy = SecurityPolicy {
            block_critical: true,
            allowed_ids: vec!["test".into()],
        };

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

        let policy = SecurityPolicy {
            block_critical: false,
            allowed_ids: vec!["test".into()],
        };

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

        let policy = SecurityPolicy {
            block_critical: true,
            allowed_ids: vec!["allowed-cve".into()],
        };

        let decision = evaluate_policy(&findings, &policy);

        assert_eq!(decision, Decision::Block);
    }
}
