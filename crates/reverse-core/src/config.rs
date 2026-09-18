use crate::error::CoreError;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    /// Addresses that must never egress through a configured target interface.
    #[serde(default)]
    pub blacklist: Vec<IpNet>,
    /// Static authoritative records used by policy decisions before system DNS.
    #[serde(default)]
    pub local_dns: BTreeMap<String, Vec<IpAddr>>,
    /// Host names that are authorized to resolve through the LAN DNS server.
    #[serde(default)]
    pub lan_domains: Vec<String>,
    /// Explicit DNS resolvers used only for `lan_domains`.
    #[serde(default)]
    pub lan_dns_servers: Vec<IpAddr>,
    /// Interfaces permitted to carry configured LAN destinations and LAN DNS.
    #[serde(default)]
    pub lan_interfaces: Vec<String>,
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
            blacklist: vec![],
            local_dns: BTreeMap::new(),
            lan_domains: vec![],
            lan_dns_servers: vec![],
            lan_interfaces: vec![],
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

    /// Resolve a domain from the static local map. Matching is case-insensitive
    /// and accepts the trailing dot form emitted by DNS clients.
    pub fn resolve_local_domain(&self, name: &str) -> Option<&[IpAddr]> {
        let key = canonical_domain(name);
        self.local_dns.get(&key).map(Vec::as_slice)
    }

    /// Whether a host name is explicitly allowed to use the LAN DNS path.
    pub fn is_lan_domain(&self, name: &str) -> bool {
        let name = canonical_domain(name);
        self.lan_domains.iter().any(|domain| domain == &name)
    }

    /// Merges targets and interface mappings from a .env file content.
    /// Supports host:port (e.g. 10.0.0.10:999), URLs (e.g. http://10.0.0.10:8080/api),
    /// single IPs (10.0.0.10), and CIDR subnets (10.0.0.0/24).
    pub fn apply_env_str(&mut self, env_content: &str) {
        let mut target_specs: Vec<(String, Option<u16>)> = Vec::new();
        let mut pending_domains: Vec<(String, Option<u16>)> = Vec::new();
        let mut target_iface: Option<String> = None;
        let mut wan_iface: Option<String> = None;
        // A configured LAN target must never silently become general Internet
        // traffic when its LAN path fails. Unknown destinations use the WLAN
        // main route; configured LAN destinations fail closed.
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
                    "TARGETS" | "TARGET_IPS" | "TARGET_IP" | "TARGET_SERVER" | "TARGET_SERVERS"
                    | "SERVERS" | "SERVER" | "LAN_IPS" | "LAN_IP" => {
                        for item in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            if let Some(spec) = parse_target_spec(item) {
                                if spec.0.parse::<IpNet>().is_ok() {
                                    target_specs.push(spec);
                                } else if let Some(domain) = extract_target_domain(item) {
                                    pending_domains.push((domain, spec.1));
                                }
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
                    "TARGET_INTERFACE" | "TARGET_IFACE" | "LAN_INTERFACE" | "LAN_IFACE"
                    | "VIA_INTERFACE" | "VIA" => {
                        target_iface = Some(val.to_string());
                    }
                    "WAN_INTERFACE" | "WAN_IFACE" | "WAN" => {
                        wan_iface = Some(val.to_string());
                    }
                    "FALLBACK" => {
                        fallback = val.to_string();
                    }
                    "BLACKLIST_IPS" | "BLACKLIST_IP" | "BLACKLIST_CIDRS" => {
                        for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if let Some(net) = parse_ip_net(item) {
                                if !self.blacklist.contains(&net) {
                                    self.blacklist.push(net);
                                }
                            }
                        }
                    }
                    "LOCAL_DNS_RECORDS" | "LOCAL_DNS" => {
                        for record in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                            let Some((domain, addresses)) = record.split_once('=') else {
                                continue;
                            };
                            let key = canonical_domain(domain);
                            if key.is_empty() {
                                continue;
                            }
                            let entry = self.local_dns.entry(key).or_default();
                            for raw_ip in addresses.split(',').map(str::trim) {
                                if let Ok(ip) = raw_ip.parse::<IpAddr>() {
                                    if !entry.contains(&ip) {
                                        entry.push(ip);
                                    }
                                }
                            }
                        }
                    }
                    "LAN_DOMAINS" | "LAN_DOMAIN" => {
                        for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if let Some(domain) = extract_target_domain(item) {
                                push_lan_domain(&mut self.lan_domains, domain);
                            }
                        }
                    }
                    "LAN_DNS_SERVERS" | "LAN_DNS_SERVER" => {
                        for item in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                            if let Ok(server) = item.parse::<IpAddr>() {
                                if !self.lan_dns_servers.contains(&server) {
                                    self.lan_dns_servers.push(server);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(wan) = wan_iface {
            self.wan.interfaces = vec![wan];
        }

        let via: Vec<String> = if let Some(ifaces) = target_iface {
            ifaces
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            vec![]
        };

        if !via.is_empty() {
            self.lan_interfaces = via.clone();
        }

        for (domain, port) in pending_domains {
            push_lan_domain(&mut self.lan_domains, domain.clone());
            if let Some(ips) = self.resolve_local_domain(&domain).map(|ips| ips.to_vec()) {
                for ip in ips {
                    let prefix = if ip.is_ipv4() { 32 } else { 128 };
                    target_specs.push((format!("{}/{}", ip, prefix), port));
                }
            }
        }

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

    /// Validates the deliberately narrow production profile used by this
    /// tool: manual LAN allowlists and a WLAN default path.  This validation
    /// runs before reconciliation so malformed or overlapping configuration
    /// can never reach the kernel routing table.
    pub fn validate_strict_lan_policy(&self) -> Result<(), CoreError> {
        if self.mode != OperatingMode::Manual {
            return Err(CoreError::Config(
                "only mode=manual is permitted by the strict LAN/WLAN policy".into(),
            ));
        }

        if !self.defaults.unknown.eq_ignore_ascii_case("wan") {
            return Err(CoreError::Config(
                "defaults.unknown must be 'wan' so non-allowlisted traffic uses WLAN".into(),
            ));
        }
        if !self.defaults.lab_failure.eq_ignore_ascii_case("drop") {
            return Err(CoreError::Config(
                "defaults.lab_failure must be 'drop' (LAN targets may not fall back to WLAN)"
                    .into(),
            ));
        }
        if self.wan.interfaces.len() != 1
            || self.wan.interfaces[0].trim().is_empty()
            || self.wan.interfaces[0] == "auto"
        {
            return Err(CoreError::Config(
                "exactly one explicit WAN_INTERFACE is required; auto detection is disabled".into(),
            ));
        }

        if self.networks.iter().any(|network| network.auto_subnets) {
            return Err(CoreError::Config(
                "networks.auto_subnets is not allowed in manual-only mode".into(),
            ));
        }

        if (!self.targets.is_empty() || !self.lan_domains.is_empty())
            && self.lan_interfaces.is_empty()
        {
            return Err(CoreError::Config(
                "LAN targets/domains require an explicit LAN_INTERFACE".into(),
            ));
        }

        for target in &self.targets {
            if !target.fallback.eq_ignore_ascii_case("drop") {
                return Err(CoreError::Config(format!(
                    "target '{}' uses fallback='{}'; only drop is permitted",
                    target.name, target.fallback
                )));
            }
            if target.via.is_empty() {
                return Err(CoreError::Config(format!(
                    "target '{}' has no explicit LAN interface",
                    target.name
                )));
            }
            if target
                .via
                .iter()
                .any(|iface| !self.lan_interfaces.contains(iface))
            {
                return Err(CoreError::Config(format!(
                    "target '{}' uses an interface outside LAN_INTERFACE",
                    target.name
                )));
            }

            let target_net = parse_ip_net(&target.cidr).ok_or_else(|| {
                CoreError::Config(format!(
                    "target '{}' must be an explicit IP address or CIDR",
                    target.name
                ))
            })?;
            if let Some(blocked) = self
                .blacklist
                .iter()
                .find(|blocked| nets_overlap(**blocked, target_net))
            {
                return Err(CoreError::Config(format!(
                    "target '{}' ({}) overlaps blacklist {}; refusing ambiguous LAN route",
                    target.name, target_net, blocked
                )));
            }
        }

        for domain in &self.lan_domains {
            let addresses = self.resolve_local_domain(domain).ok_or_else(|| {
                CoreError::Config(format!(
                    "LAN domain '{}' has no LOCAL_DNS_RECORDS. Dynamic LAN DNS is disabled until a restricted DNS proxy is configured",
                    domain
                ))
            })?;
            if let Some((address, blocked)) = addresses.iter().find_map(|address| {
                self.blacklist
                    .iter()
                    .find(|blocked| blocked.contains(address))
                    .map(|blocked| (address, blocked))
            }) {
                return Err(CoreError::Config(format!(
                    "LAN domain '{}' resolves to blacklisted address {} ({})",
                    domain, address, blocked
                )));
            }
        }

        Ok(())
    }
}

fn nets_overlap(a: IpNet, b: IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

fn canonical_domain(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn push_lan_domain(domains: &mut Vec<String>, domain: String) {
    let domain = canonical_domain(&domain);
    if !domain.is_empty() && !domains.iter().any(|existing| existing == &domain) {
        domains.push(domain);
    }
}

fn parse_ip_net(raw: &str) -> Option<IpNet> {
    if let Ok(net) = raw.parse::<IpNet>() {
        return Some(net);
    }
    let ip = raw.parse::<IpAddr>().ok()?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    IpNet::new(ip, prefix).ok()
}

fn extract_target_domain(raw: &str) -> Option<String> {
    let without_scheme = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
        .unwrap_or(raw);
    let host_port = without_scheme.split(&['/', '?', '#'][..]).next()?.trim();
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    if host.parse::<IpAddr>().is_ok() || host.is_empty() {
        None
    } else {
        Some(canonical_domain(host))
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
    fn test_env_blacklist_and_local_dns() {
        let mut cfg = Config::default();
        cfg.apply_env_str(
            "BLACKLIST_IPS=192.0.2.10,2001:db8::10,198.51.100.0/24\nLOCAL_DNS_RECORDS=Server.LAN.=192.0.2.20,2001:db8::20;other.lan=198.51.100.20",
        );

        assert!(cfg.blacklist.contains(&"192.0.2.10/32".parse().unwrap()));
        assert!(cfg.blacklist.contains(&"2001:db8::10/128".parse().unwrap()));
        assert!(cfg.blacklist.contains(&"198.51.100.0/24".parse().unwrap()));
        assert_eq!(
            cfg.resolve_local_domain("server.lan.").unwrap(),
            &[
                "192.0.2.20".parse::<IpAddr>().unwrap(),
                "2001:db8::20".parse::<IpAddr>().unwrap(),
            ]
        );
        assert!(cfg.resolve_local_domain("missing.lan").is_none());
    }

    #[test]
    fn test_env_lan_domains_and_dns_servers_are_canonicalized() {
        let mut cfg = Config::default();
        cfg.apply_env_str(
            "LAN_DOMAINS=https://Server.LAN/api,server.lan.,api.lab\nLAN_DNS_SERVERS=10.0.0.53,2001:db8::53,10.0.0.53",
        );

        assert_eq!(cfg.lan_domains, vec!["server.lan", "api.lab"]);
        assert_eq!(
            cfg.lan_dns_servers,
            vec![
                "10.0.0.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn test_lan_ips_alias_creates_destination_only_target() {
        let mut cfg = Config::default();
        cfg.apply_env_str("LAN_IPS=10.0.0.1\nLAN_INTERFACE=eth0");

        assert!(cfg
            .targets
            .iter()
            .any(|target| target.cidr == "10.0.0.1/32" && target.via == ["eth0"]));
    }

    #[test]
    fn test_url_target_is_lan_domain_not_a_port_limited_target() {
        let mut cfg = Config::default();
        cfg.apply_env_str(
            "TARGET_SERVER=https://server.lab:8443/api\nTARGET_INTERFACE=eth0\nLAN_DNS_SERVER=10.0.0.53",
        );

        assert_eq!(cfg.lan_domains, vec!["server.lab"]);
        assert!(cfg.targets.is_empty());
        assert_eq!(
            cfg.lan_dns_servers,
            vec!["10.0.0.53".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(cfg.lan_interfaces, vec!["eth0"]);
    }

    #[test]
    fn test_toml_defaults_new_fields() {
        let cfg = Config::from_toml_str("mode = \"manual\"\n").unwrap();
        assert!(cfg.blacklist.is_empty());
        assert!(cfg.local_dns.is_empty());
    }

    #[test]
    fn test_url_target_uses_local_dns_without_external_resolution() {
        let mut cfg = Config::default();
        cfg.apply_env_str(
            "TARGET_SERVER=https://server.lab\nTARGET_INTERFACE=eth0\nLOCAL_DNS_RECORDS=server.lab=192.0.2.55",
        );
        assert!(cfg
            .targets
            .iter()
            .any(|t| t.cidr == "192.0.2.55/32" && t.port == Some(443)));
    }

    #[test]
    #[ignore]
    fn debug_actual_env() {
        let mut cfg = Config::default();
        cfg.merge_env_file(".env");
        println!(
            "blacklist={} dns={:?} targets={:?}",
            cfg.blacklist.len(),
            cfg.local_dns,
            cfg.targets
        );
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

    #[test]
    fn strict_policy_rejects_auto_and_wan_fallback() {
        let mut cfg = Config {
            mode: OperatingMode::Hybrid,
            ..Default::default()
        };
        assert!(cfg.validate_strict_lan_policy().is_err());

        cfg.mode = OperatingMode::Manual;
        cfg.wan.interfaces = vec!["wlan1".into()];
        cfg.defaults.lab_failure = "wan".into();
        assert!(cfg.validate_strict_lan_policy().is_err());
    }

    #[test]
    fn strict_policy_rejects_blacklist_lan_overlap_even_when_prefixes_differ() {
        let mut cfg = Config::default();
        cfg.wan.interfaces = vec!["wlan1".into()];
        cfg.lan_interfaces = vec!["eth0".into()];
        cfg.blacklist = vec!["10.0.0.0/24".parse().unwrap()];
        cfg.targets.push(TargetConfig {
            name: "overlap".into(),
            cidr: "10.0.0.99/32".into(),
            port: None,
            via: vec!["eth0".into()],
            fallback: "drop".into(),
        });

        let error = cfg.validate_strict_lan_policy().unwrap_err().to_string();
        assert!(error.contains("overlaps blacklist"));
    }

    #[test]
    fn strict_policy_rejects_dynamic_lan_dns_instead_of_opening_port_53() {
        let mut cfg = Config::default();
        cfg.wan.interfaces = vec!["wlan1".into()];
        cfg.lan_interfaces = vec!["eth0".into()];
        cfg.lan_domains = vec!["only.example".into()];
        cfg.lan_dns_servers = vec!["10.0.0.53".parse().unwrap()];

        let error = cfg.validate_strict_lan_policy().unwrap_err().to_string();
        assert!(error.contains("Dynamic LAN DNS is disabled"));
    }
}
