use std::collections::HashMap;

use crate::models::{Decision, Finding, JsonReport, SecurityPolicy, Severity, SeverityReport};

pub fn evaluate_policy(findings: &[Finding], policy: &SecurityPolicy) -> Decision {
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

pub fn policy_report(
    findings: &[Finding],
    policy: &SecurityPolicy,
    decision: &Decision,
) -> JsonReport {
    let findings = findings
        .iter()
        .filter(|finding| !policy.allowed_ids.contains(&finding.id))
        .collect::<Vec<_>>();

    if findings.is_empty() {
        println!("No active findings matched blocking severities");
        return JsonReport {
            decision: Decision::Allow,
            severity_reports: Vec::new(),
        };
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

    let mut severity_reports = Vec::new();

    for severity in &severity_order {
        if let Some(findings) = findings_by_severity.get(severity) {
            severity_reports.push(SeverityReport {
                severity: *severity,
                count: findings.len(),
            });
        }
    }

    JsonReport {
        decision: *decision,
        severity_reports,
    }
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
