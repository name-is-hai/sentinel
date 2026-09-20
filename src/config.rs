use std::{path::PathBuf, str::FromStr};

use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub security: SecurityConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct SecurityConfig {
    pub vulnerabilities: VulnerabilityConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct VulnerabilityConfig {
    pub block: BlockPolicy,
    pub allow: Vec<String>,
}
impl Default for VulnerabilityConfig {
    fn default() -> Self {
        Self {
            block: Default::default(),
            allow: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct BlockPolicy {
    pub critical: bool,
    pub high: bool,
    pub medium: bool,
    pub low: bool,
    pub info: bool,
    pub unknown: bool,
}
impl Default for BlockPolicy {
    fn default() -> Self {
        Self {
            critical: true,
            high: false,
            medium: false,
            low: false,
            info: false,
            unknown: false,
        }
    }
}

pub fn load_config(config_path: Option<&PathBuf>) -> Config {
    let default_config_path = PathBuf::from_str(".sentinel.yaml").unwrap();
    let config_path = config_path.unwrap_or(&default_config_path);

    let contents = match std::fs::read_to_string(config_path) {
        Ok(contents) => contents,
        Err(_) => return Config::default(),
    };

    let config: Config = serde_yaml::from_str(&contents).unwrap_or_default();

    return config;
}
