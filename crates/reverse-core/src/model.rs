use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceRole {
    Wan,
    Lan,
    Vpn,
    Virtual,
    Loopback,
    Unknown,
}

impl std::fmt::Display for InterfaceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wan => write!(f, "WAN"),
            Self::Lan => write!(f, "LAN"),
            Self::Vpn => write!(f, "VPN"),
            Self::Virtual => write!(f, "Virtual"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub is_up: bool,
    pub has_carrier: bool,
    pub is_loopback: bool,
    pub mtu: u32,
    pub mac: Option<String>,
    pub ip_addrs: Vec<IpNet>,
    pub gateway: Option<IpAddr>,
    pub role: InterfaceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetMatcher {
    HostIp(IpAddr),
    Cidr(IpNet),
    Domain(String),
    DomainSuffix(String),
}

impl std::fmt::Display for TargetMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostIp(ip) => write!(f, "{}", ip),
            Self::Cidr(cidr) => write!(f, "{}", cidr),
            Self::Domain(domain) => write!(f, "{}", domain),
            Self::DomainSuffix(suffix) => write!(f, "*{}", suffix),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RuleSource {
    ManualExact = 1,
    ManualDomain = 2,
    ManualCidr = 3,
    ManualSuffix = 4,
    AutoDiscovered = 5,
    WanDefault = 6,
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManualExact => write!(f, "manual exact IP"),
            Self::ManualDomain => write!(f, "manual domain"),
            Self::ManualCidr => write!(f, "manual CIDR"),
            Self::ManualSuffix => write!(f, "manual domain suffix"),
            Self::AutoDiscovered => write!(f, "auto-discovered LAN"),
            Self::WanDefault => write!(f, "default WAN"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthState {
    Unknown,
    Healthy,
    Degraded,
    Down,
    Recovering,
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Down => write!(f, "DOWN"),
            Self::Recovering => write!(f, "RECOVERING"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHealth {
    pub state: HealthState,
    pub link_up: bool,
    pub gateway_reachable: bool,
    pub target_reachable: bool,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check_epoch_secs: u64,
}

impl Default for PathHealth {
    fn default() -> Self {
        Self {
            state: HealthState::Unknown,
            link_up: false,
            gateway_reachable: false,
            target_reachable: false,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check_epoch_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FallbackAction {
    Drop,
    Wan,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Route {
    pub destination: IpNet,
    pub output_interface: String,
    pub gateway: Option<IpAddr>,
    pub table: u32,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RpdbRule {
    pub priority: u32,
    pub table: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub destination: String,
    pub resolved_ip: Option<IpAddr>,
    pub matched_rule: Option<String>,
    pub rule_source: RuleSource,
    pub selected_interface: Option<String>,
    pub candidate_interfaces: Vec<String>,
    pub health_state: HealthState,
    pub routing_table: u32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub interfaces: Vec<Interface>,
    pub default_wan_interface: Option<String>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DesiredState {
    pub routes: Vec<Route>,
    pub rules: Vec<RpdbRule>,
    pub dns_split_domains: Vec<(String, IpAddr)>, // (domain, dns_server)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ActualState {
    pub routes: Vec<Route>,
    pub rules: Vec<RpdbRule>,
    pub allocated_table: u32,
    pub rule_priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StateDiff {
    pub routes_to_add: Vec<Route>,
    pub routes_to_remove: Vec<Route>,
    pub rules_to_add: Vec<RpdbRule>,
    pub rules_to_remove: Vec<RpdbRule>,
}

impl StateDiff {
    pub fn is_empty(&self) -> bool {
        self.routes_to_add.is_empty()
            && self.routes_to_remove.is_empty()
            && self.rules_to_add.is_empty()
            && self.rules_to_remove.is_empty()
    }
}
