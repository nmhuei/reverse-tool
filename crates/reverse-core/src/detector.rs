use crate::config::{Config, NetworkConfig, TargetConfig};
use crate::model::{Interface, InterfaceRole};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct DetectedLanProfile {
    pub networks: Vec<NetworkConfig>,
    pub targets: Vec<TargetConfig>,
}

pub struct LanDetector;

impl LanDetector {
    /// Detects LAN subnets and server targets from discovered interfaces, gateways, and ARP neighbors
    pub fn detect(
        interfaces: &[Interface],
        gateways: &HashMap<String, IpAddr>,
        neighbors: &HashMap<String, Vec<IpAddr>>,
    ) -> DetectedLanProfile {
        let mut networks = Vec::new();
        let mut targets: Vec<TargetConfig> = Vec::new();

        for iface in interfaces {
            // Consider LAN candidates (or any physical interface with carrier & IP that is not WAN/Loopback/Virtual)
            if iface.role != InterfaceRole::Lan {
                continue;
            }

            let mut dns = Vec::new();
            if let Some(&gw) = gateways.get(&iface.name) {
                dns.push(gw);
            }

            networks.push(NetworkConfig {
                name: format!("lan-{}", iface.name),
                role: "lan".into(),
                interfaces: vec![iface.name.clone()],
                auto_subnets: true,
                preferred: vec![iface.name.clone()],
                domains: vec![],
                dns,
            });

            // 1. Add subnet CIDR targets
            for net in &iface.ip_addrs {
                if net.addr().is_loopback() {
                    continue;
                }
                if let IpAddr::V6(v6) = net.addr() {
                    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                        continue; // skip IPv6 link-local
                    }
                }

                let cidr_str = net.trunc().to_string();
                if !targets
                    .iter()
                    .any(|t| t.cidr == cidr_str && t.via == vec![iface.name.clone()])
                {
                    targets.push(TargetConfig {
                        name: format!("{}-subnet", iface.name),
                        cidr: cidr_str,
                        port: None,
                        via: vec![iface.name.clone()],
                        fallback: "drop".into(),
                    });
                }
            }

            // 2. Add gateway target if discovered (often the LAN server/router)
            if let Some(&gw) = gateways.get(&iface.name) {
                if !gw.is_loopback() {
                    if let IpAddr::V6(v6) = gw {
                        if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                            // skip link-local gateway
                        } else {
                            let prefix = 128;
                            targets.push(TargetConfig {
                                name: format!("{}-gateway", iface.name),
                                cidr: format!("{}/{}", gw, prefix),
                                port: None,
                                via: vec![iface.name.clone()],
                                fallback: "drop".into(),
                            });
                        }
                    } else {
                        let prefix = 32;
                        targets.push(TargetConfig {
                            name: format!("{}-gateway", iface.name),
                            cidr: format!("{}/{}", gw, prefix),
                            port: None,
                            via: vec![iface.name.clone()],
                            fallback: "drop".into(),
                        });
                    }
                }
            }

            // 3. Add discovered neighbor servers on this interface
            if let Some(neigh_list) = neighbors.get(&iface.name) {
                for &neigh_ip in neigh_list {
                    if neigh_ip.is_loopback() {
                        continue;
                    }
                    if let IpAddr::V6(v6) = neigh_ip {
                        if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                            continue; // skip link-local neighbor
                        }
                    }
                    // Avoid duplicating gateway
                    if Some(&neigh_ip) == gateways.get(&iface.name) {
                        continue;
                    }
                    let prefix = match neigh_ip {
                        IpAddr::V4(_) => 32,
                        IpAddr::V6(_) => 128,
                    };
                    targets.push(TargetConfig {
                        name: format!("{}-host-{}", iface.name, neigh_ip),
                        cidr: format!("{}/{}", neigh_ip, prefix),
                        port: None,
                        via: vec![iface.name.clone()],
                        fallback: "drop".into(),
                    });
                }
            }
        }

        DetectedLanProfile { networks, targets }
    }

    /// Merges detected LAN profile into an existing Config without overwriting manual custom entries
    pub fn merge_into_config(config: &mut Config, detected: DetectedLanProfile) {
        for net in detected.networks {
            if !config.networks.iter().any(|n| n.name == net.name) {
                config.networks.push(net);
            }
        }

        for target in detected.targets {
            if !config.targets.iter().any(|t| t.cidr == target.cidr) {
                config.targets.push(target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lan_detection() {
        let interfaces = vec![
            Interface {
                index: 1,
                name: "eth1".into(),
                is_up: true,
                has_carrier: true,
                is_loopback: false,
                mtu: 1500,
                mac: None,
                ip_addrs: vec!["192.168.56.10/24".parse().unwrap()],
                gateway: None,
                role: InterfaceRole::Lan,
            },
            Interface {
                index: 2,
                name: "wlan0".into(),
                is_up: true,
                has_carrier: true,
                is_loopback: false,
                mtu: 1500,
                mac: None,
                ip_addrs: vec!["10.0.0.5/24".parse().unwrap()],
                gateway: None,
                role: InterfaceRole::Wan,
            },
        ];

        let mut gateways = HashMap::new();
        gateways.insert("eth1".into(), "192.168.56.1".parse().unwrap());

        let mut neighbors = HashMap::new();
        neighbors.insert(
            "eth1".into(),
            vec![
                "192.168.56.1".parse().unwrap(),
                "192.168.56.20".parse().unwrap(),
            ],
        );

        let detected = LanDetector::detect(&interfaces, &gateways, &neighbors);
        assert_eq!(detected.networks.len(), 1);
        assert_eq!(detected.networks[0].name, "lan-eth1");

        // Should have subnet, gateway, and host .20
        assert_eq!(detected.targets.len(), 3);
        assert!(detected.targets.iter().any(|t| t.cidr == "192.168.56.0/24"));
        assert!(detected.targets.iter().any(|t| t.cidr == "192.168.56.1/32"));
        assert!(detected
            .targets
            .iter()
            .any(|t| t.cidr == "192.168.56.20/32"));

        let mut cfg = Config::default();
        LanDetector::merge_into_config(&mut cfg, detected);
        assert_eq!(cfg.networks.len(), 1);
        assert_eq!(cfg.targets.len(), 3);
    }
}
