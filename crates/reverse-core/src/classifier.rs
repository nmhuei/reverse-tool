use crate::error::CoreError;
use crate::model::{Interface, InterfaceRole, TargetMatcher};
use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

pub struct InterfaceClassifier;

impl InterfaceClassifier {
    pub fn classify(
        iface: &Interface,
        default_wan_iface: Option<&str>,
        explicit_wan_names: &[String],
    ) -> InterfaceRole {
        let name = iface.name.as_str();

        if iface.is_loopback || name == "lo" {
            return InterfaceRole::Loopback;
        }

        // Virtual interfaces
        if name.starts_with("docker")
            || name.starts_with("br-")
            || name.starts_with("veth")
            || name.starts_with("virbr")
            || name.starts_with("cni")
            || name.starts_with("flannel")
        {
            return InterfaceRole::Virtual;
        }

        // VPN interfaces
        if name.starts_with("tun")
            || name.starts_with("tap")
            || name.starts_with("wg")
            || name.starts_with("ppp")
        {
            return InterfaceRole::Vpn;
        }

        // WAN detection
        if explicit_wan_names.iter().any(|w| w == name) {
            return InterfaceRole::Wan;
        }

        if let Some(wan_name) = default_wan_iface {
            if wan_name == name {
                return InterfaceRole::Wan;
            }
        }

        // LAN candidate: has carrier, is up, has IP, not virtual/wan/loopback
        if iface.is_up && iface.has_carrier && !iface.ip_addrs.is_empty() {
            return InterfaceRole::Lan;
        }

        InterfaceRole::Unknown
    }
}

pub struct TargetClassifier;

impl TargetClassifier {
    pub fn parse(target_str: &str) -> Result<TargetMatcher, CoreError> {
        let trimmed = target_str.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidTarget("Target cannot be empty".into()));
        }

        // Check if single IP
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            return Ok(TargetMatcher::HostIp(ip));
        }

        // Check if CIDR
        if trimmed.contains('/') {
            if let Ok(net) = IpNet::from_str(trimmed) {
                if (net.addr().is_ipv4() && net.prefix_len() == 32)
                    || (net.addr().is_ipv6() && net.prefix_len() == 128)
                {
                    return Ok(TargetMatcher::HostIp(net.addr()));
                }
                return Ok(TargetMatcher::Cidr(net));
            } else {
                return Err(CoreError::InvalidTarget(format!(
                    "Malformed CIDR: {}",
                    trimmed
                )));
            }
        }

        // Check if wildcard or routing domain suffix (*.lab, ~lab, .lab)
        if trimmed.starts_with("*.") {
            let suffix = &trimmed[1..]; // e.g. ".lab"
            return Ok(TargetMatcher::DomainSuffix(suffix.to_lowercase()));
        }

        if trimmed.starts_with('~') {
            let without_tilde = trimmed.trim_start_matches('~');
            let suffix = if without_tilde.starts_with('.') {
                without_tilde.to_string()
            } else {
                format!(".{}", without_tilde)
            };
            return Ok(TargetMatcher::DomainSuffix(suffix.to_lowercase()));
        }

        if trimmed.starts_with('.') {
            return Ok(TargetMatcher::DomainSuffix(trimmed.to_lowercase()));
        }

        // Regular domain
        Ok(TargetMatcher::Domain(trimmed.to_lowercase()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_interfaces() {
        let lo = Interface {
            index: 1,
            name: "lo".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: true,
            mtu: 65536,
            mac: None,
            ip_addrs: vec![],
            gateway: None,
            role: InterfaceRole::Unknown,
        };
        assert_eq!(
            InterfaceClassifier::classify(&lo, None, &[]),
            InterfaceRole::Loopback
        );

        let docker = Interface {
            index: 5,
            name: "docker0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["172.17.0.1/16".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Unknown,
        };
        assert_eq!(
            InterfaceClassifier::classify(&docker, None, &[]),
            InterfaceRole::Virtual
        );

        let wlan0 = Interface {
            index: 3,
            name: "wlan0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["192.168.1.50/24".parse().unwrap()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            role: InterfaceRole::Unknown,
        };
        assert_eq!(
            InterfaceClassifier::classify(&wlan0, Some("wlan0"), &[]),
            InterfaceRole::Wan
        );

        let eth1 = Interface {
            index: 2,
            name: "eth1".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["192.168.56.10/24".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Unknown,
        };
        assert_eq!(
            InterfaceClassifier::classify(&eth1, Some("wlan0"), &[]),
            InterfaceRole::Lan
        );
    }

    #[test]
    fn test_classify_targets() {
        assert_eq!(
            TargetClassifier::parse("192.168.56.20").unwrap(),
            TargetMatcher::HostIp("192.168.56.20".parse().unwrap())
        );

        assert_eq!(
            TargetClassifier::parse("192.168.56.0/24").unwrap(),
            TargetMatcher::Cidr("192.168.56.0/24".parse().unwrap())
        );

        assert_eq!(
            TargetClassifier::parse("*.malware.lab").unwrap(),
            TargetMatcher::DomainSuffix(".malware.lab".into())
        );

        assert_eq!(
            TargetClassifier::parse("~malware.lab").unwrap(),
            TargetMatcher::DomainSuffix(".malware.lab".into())
        );

        assert_eq!(
            TargetClassifier::parse("victim.lab").unwrap(),
            TargetMatcher::Domain("victim.lab".into())
        );
    }
}
