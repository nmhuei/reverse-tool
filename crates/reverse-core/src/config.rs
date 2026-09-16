use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    Auto,
    #[default]
    Manual,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_unknown")]
    pub unknown: String, // "wan"
    #[serde(default = "default_lab_failure")]
    pub lab_failure: String, // "wan"
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
    "wan".to_string()
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
    pub cidr: String, // e.g. "192.168.56.0/24" or "10.0.0.10/32"
    #[serde(default)]
    pub port: Option<u16>, // e.g. Some(999) for 10.0.0.10:999 or URL port
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
            mode: OperatingMode::Manual,
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

    /// Merges targets and interface mappings from a .env file content.
    /// Supports host:port (e.g. 10.0.0.10:999), URLs (e.g. http://10.0.0.10:8080/api),
    /// single IPs (10.0.0.10), and CIDR subnets (10.0.0.0/24).
    pub fn apply_env_str(&mut self, env_content: &str) {
        let mut target_specs: Vec<(String, Option<u16>)> = Vec::new();
        let mut target_iface: Option<String> = None;
        let mut wan_iface: Option<String> = None;
        let mut fallback = "wan".to_string();

        for line in env_content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, val)) = line.split_once('=') {
                let key = key.trim();
                let val = val.trim().trim_matches('"').trim_matches('\'').trim();

                match key.to_uppercase().as_str() {
                    "TARGETS" | "TARGET_IPS" | "TARGET_IP" | "TARGET_SERVER" | "TARGET_SERVERS"
                    | "SERVERS" | "SERVER" => {
                        for item in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            if let Some(spec) = parse_target_spec(item) {
                                target_specs.push(spec);
                            }
                        }
                    }
                    "TARGET_SUBNETS" | "TARGET_SUBNET" | "TARGET_CIDRS" | "TARGET_CIDR" => {
                        for sub in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            if let Some(spec) = parse_target_spec(sub) {
                                target_specs.push(spec);
                            }
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

        for (cidr, port) in target_specs {
            let port_suffix = port.map(|p| format!("-port-{}", p)).unwrap_or_default();
            let name = format!("env-{}{}", cidr.replace(['.', ':', '/'], "-"), port_suffix);
            if !self
                .targets
                .iter()
                .any(|t| t.cidr == cidr && t.port == port)
            {
                self.targets.push(TargetConfig {
                    name,
                    cidr,
                    port,
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

/// Parses a target string which can be a URL (http://... or https://...),
/// a host:port pair (10.0.0.10:999), a single IP (10.0.0.10), or a CIDR subnet (10.0.0.0/24).
/// Returns (canonical_cidr_or_ip, optional_port).
pub fn parse_target_spec(raw: &str) -> Option<(String, Option<u16>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // 1. Check if it's a URL with explicit HTTP(S) scheme
    let (without_scheme, default_port, is_url_scheme) =
        if let Some(stripped) = raw.strip_prefix("http://") {
            (stripped, Some(80), true)
        } else if let Some(stripped) = raw.strip_prefix("https://") {
            (stripped, Some(443), true)
        } else {
            (raw, None, false)
        };

    // If it is not a URL scheme and is a valid CIDR network (e.g. 10.0.0.0/24), return it directly
    if !is_url_scheme && without_scheme.contains('/') {
        if let Ok(net) = without_scheme.parse::<ipnet::IpNet>() {
            return Some((net.to_string(), None));
        }
    }

    // Strip any URL path/query/fragment: e.g. "10.0.0.10:999/api" -> "10.0.0.10:999"
    let host_port_part = without_scheme
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or(without_scheme)
        .trim();

    // Check if IPv6 with brackets: [::1]:999 or [::1]
    if host_port_part.starts_with('[') {
        if let Some(close_bracket) = host_port_part.find(']') {
            let ip_str = &host_port_part[1..close_bracket];
            let port_part = &host_port_part[close_bracket + 1..];
            let port = if let Some(colon) = port_part.strip_prefix(':') {
                colon.parse::<u16>().ok()
            } else {
                default_port
            };
            return Some((format!("{}/128", ip_str), port));
        }
    }

    // Check if host:port (e.g. 10.0.0.10:999)
    if let Some((host, port_str)) = host_port_part.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                let cidr = if host.contains('/') {
                    host.to_string()
                } else {
                    format!("{}/32", host)
                };
                return Some((cidr, Some(port)));
            }
        }
    }

    // Single IP or CIDR (no explicit port)
    let cidr = if host_port_part.contains('/') {
        host_port_part.to_string()
    } else if host_port_part.contains(':') {
        format!("{}/128", host_port_part)
    } else {
        format!("{}/32", host_port_part)
    };

    Some((cidr, default_port))
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
        assert!(cfg
            .targets
            .iter()
            .any(|t| t.cidr == "10.0.0.100/32" && t.via == vec!["wlan1"]));
        assert!(cfg
            .targets
            .iter()
            .any(|t| t.cidr == "192.168.1.50/32" && t.via == vec!["wlan1"]));
        assert!(cfg
            .targets
            .iter()
            .any(|t| t.cidr == "10.0.0.0/24" && t.via == vec!["wlan1"]));
    }

    #[test]
    fn test_parse_target_spec_formats() {
        // host:port
        let (cidr, port) = parse_target_spec("10.0.0.10:999").unwrap();
        assert_eq!(cidr, "10.0.0.10/32");
        assert_eq!(port, Some(999));

        // HTTP URL with custom port
        let (cidr, port) = parse_target_spec("http://10.0.0.20:8080/api/v1?token=123").unwrap();
        assert_eq!(cidr, "10.0.0.20/32");
        assert_eq!(port, Some(8080));

        // Default HTTP port
        let (cidr, port) = parse_target_spec("http://10.0.0.25/login").unwrap();
        assert_eq!(cidr, "10.0.0.25/32");
        assert_eq!(port, Some(80));

        // Default HTTPS port
        let (cidr, port) = parse_target_spec("https://10.0.0.30/admin").unwrap();
        assert_eq!(cidr, "10.0.0.30/32");
        assert_eq!(port, Some(443));

        // Plain IP (no port)
        let (cidr, port) = parse_target_spec("192.168.56.5").unwrap();
        assert_eq!(cidr, "192.168.56.5/32");
        assert_eq!(port, None);

        // CIDR subnet
        let (cidr, port) = parse_target_spec("192.168.56.0/24").unwrap();
        assert_eq!(cidr, "192.168.56.0/24");
        assert_eq!(port, None);
    }

    #[test]
    fn test_target_server_env_host_port() {
        let env_data = r#"
TARGET_SERVER=10.0.0.10:999
TARGET_INTERFACE=wlan1
WAN_INTERFACE=wlan0
"#;
        let mut cfg = Config::default();
        cfg.apply_env_str(env_data);

        assert_eq!(cfg.mode, OperatingMode::Manual);
        assert_eq!(cfg.wan.interfaces, vec!["wlan0"]);
        assert_eq!(cfg.targets.len(), 1);
        let t = &cfg.targets[0];
        assert_eq!(t.cidr, "10.0.0.10/32");
        assert_eq!(t.port, Some(999));
        assert_eq!(t.via, vec!["wlan1"]);
    }
}
