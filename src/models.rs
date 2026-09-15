#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
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
    pub allowed_ids: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub decision: Decision,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanError {
    InvalidTarget,
}
