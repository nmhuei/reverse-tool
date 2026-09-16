use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    Auto,
    Manual,
    #[default]
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_unknown")]
    pub unknown: String, // "wan"
    #[serde(default = "default_lab_failure")]
    pub lab_failure: String, // "drop"
    #[serde(default = "default_true")]
    pub auto_failback: bool,
    #[serde(default = "default_table_id")]
    pub table_id: u32,
    #[serde(default = "default_rule_priority")]
    pub rule_priority: u32,
}

fn default_unknown() -> String {
    "wan".to_string()
}
fn default_lab_failure() -> String {
    "drop".to_string()
}
fn default_true() -> bool {
    true
}
fn default_table_id() -> u32 {
    52000
}
fn default_rule_priority() -> u32 {
    12000
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            unknown: default_unknown(),
            lab_failure: default_lab_failure(),
            auto_failback: true,
            table_id: default_table_id(),
            rule_priority: default_rule_priority(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WanConfig {
    #[serde(default)]
    pub interfaces: Vec<String>, // e.g. ["auto"] or ["wlan0"]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    #[serde(default = "default_lan_role")]
    pub role: String, // "lan"
    #[serde(default)]
    pub interfaces: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_subnets: bool,
    #[serde(default)]
    pub preferred: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub dns: Vec<IpAddr>,
}

fn default_lan_role() -> String {
    "lan".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub name: String,
    pub cidr: String, // e.g. "192.168.56.0/24" or "victim.lab"
    #[serde(default)]
    pub via: Vec<String>,
    #[serde(default = "default_lab_failure")]
    pub fallback: String, // "drop" or "wan"
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfileConfig {
    pub networks: Vec<NetworkConfig>,
    pub targets: Vec<TargetConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mode: OperatingMode,
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub wan: WanConfig,
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: OperatingMode::Hybrid,
            defaults: DefaultsConfig::default(),
            wan: WanConfig {
                interfaces: vec!["auto".to_string()],
            },
            networks: vec![],
            targets: vec![],
            profiles: HashMap::new(),
        }
    }
}

impl Config {
    pub fn from_toml_str(content: &str) -> Result<Self, CoreError> {
        toml::from_str(content).map_err(|e| CoreError::Config(e.to_string()))
    }

    pub fn to_toml_string(&self) -> Result<String, CoreError> {
        toml::to_string_pretty(self).map_err(|e| CoreError::Config(e.to_string()))
    }

    /// Merges targets and interface mappings from a .env file content
    pub fn apply_env_str(&mut self, env_content: &str) {
        let mut target_ips = Vec::new();
        let mut target_subnets = Vec::new();
        let mut target_iface: Option<String> = None;
        let mut wan_iface: Option<String> = None;
        let mut fallback = "drop".to_string();

        for line in env_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"').trim_matches('\'').trim();

                match key.to_uppercase().as_str() {
                    "TARGET_IPS" | "TARGET_IP" => {
                        for ip in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            target_ips.push(ip.to_string());
                        }
                    }
                    "TARGET_SUBNETS" | "TARGET_SUBNET" | "TARGET_CIDRS" | "TARGET_CIDR" => {
                        for sub in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            target_subnets.push(sub.to_string());
                        }
                    }
                    "TARGET_INTERFACE" | "TARGET_IFACE" | "VIA_INTERFACE" | "VIA" => {
                        target_iface = Some(val.to_string());
                    }
                    "WAN_INTERFACE" | "WAN_IFACE" | "WAN" => {
                        wan_iface = Some(val.to_string());
                    }
                    "FALLBACK" => {
                        fallback = val.to_string();
                    }
                    _ => {}
                }
            }
        }

        if let Some(wan) = wan_iface {
            self.wan.interfaces = vec![wan];
        }

        let via = if let Some(iface) = target_iface {
            vec![iface]
        } else {
            vec![]
        };

        for ip in target_ips {
            let cidr = if ip.contains('/') {
                ip.clone()
            } else if ip.contains(':') {
                format!("{}/128", ip)
            } else {
                format!("{}/32", ip)
            };

            let name = format!("env-{}", ip.replace(['.', ':', '/'], "-"));
            if !self.targets.iter().any(|t| t.cidr == cidr) {
                self.targets.push(TargetConfig {
                    name,
                    cidr,
                    via: via.clone(),
                    fallback: fallback.clone(),
                });
            }
        }

        for sub in target_subnets {
            let name = format!("env-{}", sub.replace(['.', ':', '/'], "-"));
            if !self.targets.iter().any(|t| t.cidr == sub) {
                self.targets.push(TargetConfig {
                    name,
                    cidr: sub,
                    via: via.clone(),
                    fallback: fallback.clone(),
                });
            }
        }
    }

    /// Reads and merges a .env file if it exists at the given path
    pub fn merge_env_file<P: AsRef<std::path::Path>>(&mut self, path: P) {
        if let Ok(content) = std::fs::read_to_string(path) {
            self.apply_env_str(&content);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sample_config() {
        let sample = r#"
mode = "hybrid"

[defaults]
unknown = "wan"
lab_failure = "drop"
auto_failback = true
table_id = 52000
rule_priority = 12000

[wan]
interfaces = ["auto"]

[[networks]]
name = "malware-lab"
role = "lan"
interfaces = ["wlan1", "eth1"]
auto_subnets = true
preferred = ["wlan1", "eth1"]
domains = ["~malware.lab"]
dns = ["192.168.56.1"]

[[targets]]
name = "victim"
cidr = "192.168.56.0/24"
via = ["wlan1", "eth1"]
fallback = "drop"
"#;

        let cfg = Config::from_toml_str(sample).unwrap();
        assert_eq!(cfg.mode, OperatingMode::Hybrid);
        assert_eq!(cfg.defaults.table_id, 52000);
        assert_eq!(cfg.networks.len(), 1);
        assert_eq!(cfg.networks[0].name, "malware-lab");
        assert_eq!(cfg.targets.len(), 1);
        assert_eq!(cfg.targets[0].fallback, "drop");
    }

    #[test]
    fn test_env_parsing() {
        let env_data = r#"
# Manual target configuration in .env
TARGET_IPS="10.0.0.100, 192.168.1.50"
TARGET_SUBNETS=10.0.0.0/24
TARGET_INTERFACE=wlan1
WAN_INTERFACE=wlan0
FALLBACK=drop
"#;
        let mut cfg = Config::default();
        cfg.apply_env_str(env_data);

        assert_eq!(cfg.wan.interfaces, vec!["wlan0"]);
        assert_eq!(cfg.targets.len(), 3);
        assert!(cfg.targets.iter().any(|t| t.cidr == "10.0.0.100/32" && t.via == vec!["wlan1"]));
        assert!(cfg.targets.iter().any(|t| t.cidr == "192.168.1.50/32" && t.via == vec!["wlan1"]));
        assert!(cfg.targets.iter().any(|t| t.cidr == "10.0.0.0/24" && t.via == vec!["wlan1"]));
    }
}
