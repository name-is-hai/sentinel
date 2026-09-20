use serde::Deserialize;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Stdio,
};

use crate::models::{Finding, ScanError, Severity};

#[derive(Debug, Deserialize)]
pub struct GrypeReport {
    pub matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
pub struct GrypeMatch {
    pub vulnerability: GrypeVulnerability,
}

#[derive(Debug, Deserialize)]
pub struct GrypeVulnerability {
    pub id: String,
    pub description: String,

    #[serde(default = "Severity::unknown")]
    pub severity: Severity,
}

pub fn run_grype(sbom_path: &PathBuf, output: &str) -> Result<PathBuf, ScanError> {
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

pub fn run_grype_report(path: &PathBuf) -> Result<GrypeReport, ScanError> {
    let grype_file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Err(ScanError::OutputFileError),
    };

    match serde_json::from_reader(grype_file) {
        Ok(report) => Ok(report),
        Err(_) => Err(ScanError::ToolFailed),
    }
}

pub fn run_normalize_grype(report: &GrypeReport) -> Vec<Finding> {
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
