use std::{
    fs::{File, metadata},
    path::{Path, PathBuf},
    process::Stdio,
};

use crate::{models::ScanError, models::ScanTarget};

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
