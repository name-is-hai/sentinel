use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy, Ord, PartialOrd)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}
impl Severity {
    pub fn unknown() -> Self {
        Severity::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub scanner: String,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub block_critical: bool,
    pub block_high: bool,
    pub block_medium: bool,
    pub block_low: bool,
    pub block_info: bool,
    pub block_unknown: bool,
    pub allowed_ids: Vec<String>,
}

// #[derive(Debug, PartialEq, Eq)]
// pub struct ScanReport {
//     pub findings: Vec<Finding>,
//     pub decision: Decision,
// }

#[derive(Debug, PartialEq, Eq)]
pub enum ScanError {
    InvalidTarget,
    OutputDirectoryError,
    OutputFileError,
    ToolFailed,
}
