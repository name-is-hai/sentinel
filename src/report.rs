use std::{fs::File, path::Path};

use crate::models::{JsonReport, ScanError};

pub fn write_report(report: &JsonReport, output: &str) -> Result<(), ScanError> {
    let report_path = Path::new(output).join("report.json");
    let mut file = match File::create(report_path) {
        Ok(file) => file,
        _ => return Err(ScanError::ToolFailed),
    };
    match serde_json::to_writer_pretty(&mut file, report) {
        Ok(_) => Ok(()),
        _ => return Err(ScanError::ToolFailed),
    }
}

pub fn print_severity(report: &JsonReport) {
    println!("Decision: {:?}", report.decision);
    println!("Reason:");
    if report.severity_reports.is_empty() {
        println!("No active findings matched blocking severities");
        return;
    }

    for severity in &report.severity_reports {
        println!(
            "{:?} {} active {}",
            severity.severity,
            severity.count,
            if severity.count > 1 {
                "findings"
            } else {
                "finding"
            }
        );
    }
}
