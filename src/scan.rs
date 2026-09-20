use clap::Args;
use std::path::PathBuf;

use crate::{
    config,
    models::{Decision, ScanError, ScanTarget, SecurityPolicy},
    policy, report, scanner,
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

    let syft_path = scanner::syft::run_sbom(target, output)?;
    let grype_path = scanner::grype::run_grype(&syft_path, output)?;

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

    let report = scanner::grype::run_grype_report(&grype_path)?;
    let findings = scanner::grype::run_normalize_grype(&report);
    let decision = policy::evaluate_policy(&findings, &policy);

    println!("Grype matches: {}", report.matches.len());
    println!("Policy: {:?}", decision);
    println!("Allowed IDs: {:?}", policy.allowed_ids);

    let report = policy::policy_report(&findings, &policy, &decision);
    report::print_severity(&report);
    report::write_report(&report, &output)?;

    return Ok(decision);
}
