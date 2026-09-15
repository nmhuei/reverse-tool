use crate::classifier::TargetClassifier;
use crate::config::{Config, OperatingMode};
use crate::health::HealthStateMachine;
use crate::model::{
    Decision, FallbackAction, HealthState, Interface, InterfaceRole, PathHealth, Route, RuleSource,
    TargetMatcher,
};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub matcher: TargetMatcher,
    pub source: RuleSource,
    pub candidate_interfaces: Vec<String>,
    pub fallback: FallbackAction,
}

pub struct PolicyEngine {
    pub mode: OperatingMode,
    pub table_id: u32,
    pub rules: Vec<PolicyRule>,
    pub default_wan_iface: Option<String>,
}

impl PolicyEngine {
    pub fn from_config(
        config: &Config,
        interfaces: &[Interface],
        default_wan: Option<String>,
    ) -> Self {
        let mut rules = Vec::new();

        // 1. Manual Targets from config
        for target in &config.targets {
            if let Ok(matcher) = TargetClassifier::parse(&target.cidr) {
                let source = match &matcher {
                    TargetMatcher::HostIp(_) => RuleSource::ManualExact,
                    TargetMatcher::Domain(_) => RuleSource::ManualDomain,
                    TargetMatcher::Cidr(_) => RuleSource::ManualCidr,
                    TargetMatcher::DomainSuffix(_) => RuleSource::ManualSuffix,
                };
                let fallback = if target.fallback.to_lowercase() == "wan" {
                    FallbackAction::Wan
                } else {
                    FallbackAction::Drop
                };

                rules.push(PolicyRule {
                    name: target.name.clone(),
                    matcher,
                    source,
                    candidate_interfaces: target.via.clone(),
                    fallback,
                });
            }
        }

        // 2. Manual Networks from config (domains, specific lab interfaces)
        for net in &config.networks {
            for domain in &net.domains {
                if let Ok(matcher) = TargetClassifier::parse(domain) {
                    let source = match &matcher {
                        TargetMatcher::DomainSuffix(_) => RuleSource::ManualSuffix,
                        _ => RuleSource::ManualDomain,
                    };
                    rules.push(PolicyRule {
                        name: format!("{}:{}", net.name, domain),
                        matcher,
                        source,
                        candidate_interfaces: if !net.preferred.is_empty() {
                            net.preferred.clone()
                        } else {
                            net.interfaces.clone()
                        },
                        fallback: FallbackAction::Drop,
                    });
                }
            }
        }

        // 3. Auto-discovered LAN interfaces (if Auto or Hybrid)
        if config.mode != OperatingMode::Manual {
            for iface in interfaces {
                if iface.role == InterfaceRole::Lan {
                    for ip_net in &iface.ip_addrs {
                        rules.push(PolicyRule {
                            name: format!("auto-lan:{}", iface.name),
                            matcher: TargetMatcher::Cidr(*ip_net),
                            source: RuleSource::AutoDiscovered,
                            candidate_interfaces: vec![iface.name.clone()],
                            fallback: FallbackAction::Drop,
                        });
                    }
                }
            }
        }

        // Sort rules by priority: ManualExact < ManualDomain < ManualCidr < ManualSuffix < AutoDiscovered
        rules.sort_by_key(|r| r.source);

        Self {
            mode: config.mode,
            table_id: config.defaults.table_id,
            rules,
            default_wan_iface: default_wan,
        }
    }

    pub fn decide(
        &self,
        target_str: &str,
        health_map: &HashMap<String, PathHealth>,
        health_sm: &HealthStateMachine,
    ) -> Decision {
        let parsed_target = TargetClassifier::parse(target_str);
        let maybe_ip = if let Ok(TargetMatcher::HostIp(ip)) = parsed_target {
            Some(ip)
        } else {
            IpAddr::from_str(target_str).ok()
        };

        // Match rules according to precedence
        for rule in &self.rules {
            let matches = match (&rule.matcher, &parsed_target, maybe_ip) {
                (TargetMatcher::HostIp(target_ip), _, Some(ip)) => *target_ip == ip,
                (TargetMatcher::Cidr(cidr), _, Some(ip)) => cidr.contains(&ip),
                (TargetMatcher::Cidr(cidr), Ok(TargetMatcher::Cidr(req_cidr)), _) => {
                    cidr.contains(&req_cidr.network())
                }
                (TargetMatcher::Domain(target_domain), _, _) => {
                    target_domain.eq_ignore_ascii_case(target_str.trim())
                }
                (TargetMatcher::DomainSuffix(suffix), _, _) => {
                    let d = target_str.trim().to_lowercase();
                    d.ends_with(suffix)
                }
                _ => false,
            };

            if matches {
                // Rule matched! Select candidate interface based on health
                let mut selected: Option<String> = None;
                let mut last_health = HealthState::Unknown;
                let mut failure_reason = String::new();

                for candidate in &rule.candidate_interfaces {
                    let health = health_map
                        .get(candidate)
                        .cloned()
                        .unwrap_or_else(PathHealth::default);
                    last_health = health.state;

                    if health_sm.is_available(&health) {
                        selected = Some(candidate.clone());
                        break;
                    } else {
                        if !failure_reason.is_empty() {
                            failure_reason.push_str(", ");
                        }
                        failure_reason.push_str(&format!("{}: {}", candidate, health.state));
                    }
                }

                if let Some(iface) = selected {
                    return Decision {
                        destination: target_str.to_string(),
                        resolved_ip: maybe_ip,
                        matched_rule: Some(rule.name.clone()),
                        rule_source: rule.source,
                        selected_interface: Some(iface.clone()),
                        candidate_interfaces: rule.candidate_interfaces.clone(),
                        health_state: HealthState::Healthy,
                        routing_table: self.table_id,
                        reason: format!("Matched {} -> selected healthy {}", rule.source, iface),
                    };
                } else {
                    // All candidates failed! Check fallback
                    let (table, iface, reason) = match rule.fallback {
                        FallbackAction::Drop => (
                            self.table_id,
                            None,
                            format!(
                                "All candidates failed ({}); lab target blocked (DROP)",
                                failure_reason
                            ),
                        ),
                        FallbackAction::Wan => (
                            254,
                            self.default_wan_iface.clone(),
                            format!(
                                "All candidates failed ({}); fallback to WAN",
                                failure_reason
                            ),
                        ),
                        FallbackAction::Unreachable => (
                            self.table_id,
                            None,
                            format!("Target unreachable ({})", failure_reason),
                        ),
                    };

                    return Decision {
                        destination: target_str.to_string(),
                        resolved_ip: maybe_ip,
                        matched_rule: Some(rule.name.clone()),
                        rule_source: rule.source,
                        selected_interface: iface,
                        candidate_interfaces: rule.candidate_interfaces.clone(),
                        health_state: last_health,
                        routing_table: table,
                        reason,
                    };
                }
            }
        }

        // No lab rule matched: route to WAN default table (table 254/main)
        Decision {
            destination: target_str.to_string(),
            resolved_ip: maybe_ip,
            matched_rule: None,
            rule_source: RuleSource::WanDefault,
            selected_interface: self.default_wan_iface.clone(),
            candidate_interfaces: self.default_wan_iface.clone().into_iter().collect(),
            health_state: HealthState::Healthy,
            routing_table: 254,
            reason: "No lab policy matched; normal WAN routing in main table".into(),
        }
    }

    pub fn generate_desired_routes(
        &self,
        health_map: &HashMap<String, PathHealth>,
        health_sm: &HealthStateMachine,
    ) -> Vec<Route> {
        let mut routes = Vec::new();

        for rule in &self.rules {
            // Find healthy interface
            let mut chosen_iface: Option<String> = None;
            for candidate in &rule.candidate_interfaces {
                let health = health_map
                    .get(candidate)
                    .cloned()
                    .unwrap_or_else(PathHealth::default);
                if health_sm.is_available(&health) {
                    chosen_iface = Some(candidate.clone());
                    break;
                }
            }

            if let Some(iface) = chosen_iface {
                match &rule.matcher {
                    TargetMatcher::Cidr(cidr) => {
                        routes.push(Route {
                            destination: *cidr,
                            output_interface: iface,
                            gateway: None,
                            table: self.table_id,
                            metric: Some(100),
                        });
                    }
                    TargetMatcher::HostIp(ip) => {
                        let prefix = match ip {
                            IpAddr::V4(_) => 32,
                            IpAddr::V6(_) => 128,
                        };
                        if let Ok(net) = IpNet::new(*ip, prefix) {
                            routes.push(Route {
                                destination: net,
                                output_interface: iface,
                                gateway: None,
                                table: self.table_id,
                                metric: Some(50),
                            });
                        }
                    }
                    _ => {} // Domain rules handled via split DNS
                }
            }
        }

        routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthConfig;

    fn make_test_setup() -> (
        PolicyEngine,
        HashMap<String, PathHealth>,
        HealthStateMachine,
    ) {
        let mut health_map = HashMap::new();
        let health_sm = HealthStateMachine::new(HealthConfig::default());

        let mut eth1_health = PathHealth::default();
        health_sm.record_success(&mut eth1_health, 100);
        health_map.insert("eth1".to_string(), eth1_health);

        let mut wlan1_health = PathHealth::default();
        health_sm.record_success(&mut wlan1_health, 100);
        health_map.insert("wlan1".to_string(), wlan1_health);

        let mut cfg = Config::default();
        cfg.targets.push(crate::config::TargetConfig {
            name: "victim".into(),
            cidr: "192.168.56.0/24".into(),
            via: vec!["wlan1".into(), "eth1".into()],
            fallback: "drop".into(),
        });
        cfg.targets.push(crate::config::TargetConfig {
            name: "specific-host".into(),
            cidr: "192.168.56.20".into(),
            via: vec!["eth1".into()],
            fallback: "drop".into(),
        });

        let interfaces = vec![Interface {
            index: 2,
            name: "eth1".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["10.200.2.2/24".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Lan,
        }];

        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));
        (engine, health_map, health_sm)
    }

    #[test]
    fn test_precedence_exact_ip_over_cidr() {
        let (engine, health_map, health_sm) = make_test_setup();

        // 192.168.56.20 matches specific-host (via eth1) and victim CIDR (via wlan1).
        // Specific host (ManualExact) MUST win!
        let dec = engine.decide("192.168.56.20", &health_map, &health_sm);
        assert_eq!(dec.rule_source, RuleSource::ManualExact);
        assert_eq!(dec.selected_interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn test_cidr_matches() {
        let (engine, health_map, health_sm) = make_test_setup();
        let dec = engine.decide("192.168.56.55", &health_map, &health_sm);
        assert_eq!(dec.rule_source, RuleSource::ManualCidr);
        assert_eq!(dec.selected_interface.as_deref(), Some("wlan1"));
    }

    #[test]
    fn test_unknown_goes_to_wan() {
        let (engine, health_map, health_sm) = make_test_setup();
        let dec = engine.decide("8.8.8.8", &health_map, &health_sm);
        assert_eq!(dec.rule_source, RuleSource::WanDefault);
        assert_eq!(dec.routing_table, 254);
        assert_eq!(dec.selected_interface.as_deref(), Some("wlan0"));
    }

    #[test]
    fn test_lab_target_never_leaks_to_wan_on_failure() {
        let (engine, mut health_map, health_sm) = make_test_setup();

        // Kill both wlan1 and eth1
        let down_wlan1 = PathHealth {
            state: HealthState::Down,
            ..Default::default()
        };
        health_map.insert("wlan1".into(), down_wlan1);

        let down_eth1 = PathHealth {
            state: HealthState::Down,
            ..Default::default()
        };
        health_map.insert("eth1".into(), down_eth1);

        let dec = engine.decide("192.168.56.55", &health_map, &health_sm);
        // Crucial safety check: Selected interface must be NONE (DROP), NOT wlan0!
        assert_eq!(dec.selected_interface, None);
        assert!(dec.reason.contains("DROP"));
    }
}
