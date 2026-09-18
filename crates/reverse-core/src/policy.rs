use crate::classifier::TargetClassifier;
use crate::config::{Config, OperatingMode};
use crate::health::HealthStateMachine;
use crate::model::{
    Decision, FallbackAction, HealthState, Interface, InterfaceRole, PathHealth, Route, RouteType,
    RuleSource, TargetMatcher,
};
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
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
    pub local_dns: BTreeMap<String, Vec<IpAddr>>,
    pub blacklist: Vec<IpNet>,
    pub lan_interfaces: Vec<String>,
    pub lan_dns_servers: Vec<IpAddr>,
    pub wan_gateway: Option<IpAddr>,
    /// IPv6 gateway for the WAN path. Kept separate because a single
    /// interface may have different IPv4/IPv6 default gateways.
    pub wan_ipv6_gateway: Option<IpAddr>,
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

        // Explicit LAN domains are separate from raw IP targets. Their DNS
        // transport is configured by the application layer, while any known
        // answer is routed through the configured LAN interface here.
        for domain in &config.lan_domains {
            if let Ok(matcher) = TargetClassifier::parse(domain) {
                rules.push(PolicyRule {
                    name: format!("lan-domain:{}", domain),
                    matcher,
                    source: RuleSource::ManualDomain,
                    candidate_interfaces: config.lan_interfaces.clone(),
                    fallback: FallbackAction::Drop,
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
                        if ip_net.addr().is_loopback() {
                            continue;
                        }
                        if let IpAddr::V6(v6) = ip_net.addr() {
                            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                                continue; // skip IPv6 link-local
                            }
                        }
                        let trunc_net = ip_net.trunc();
                        if !rules
                            .iter()
                            .any(|r| r.matcher == TargetMatcher::Cidr(trunc_net))
                        {
                            rules.push(PolicyRule {
                                name: format!("auto-lan:{}", iface.name),
                                matcher: TargetMatcher::Cidr(trunc_net),
                                source: RuleSource::AutoDiscovered,
                                candidate_interfaces: vec![iface.name.clone()],
                                fallback: FallbackAction::Drop,
                            });
                        }
                    }
                }
            }
        }

        // Sort rules by priority: ManualExact < ManualDomain < ManualCidr < ManualSuffix < AutoDiscovered
        rules.sort_by_key(|r| r.source);

        let wan_gateway = default_wan.as_ref().and_then(|wan| {
            interfaces
                .iter()
                .find(|iface| &iface.name == wan)
                .and_then(|iface| iface.gateway)
        });

        Self {
            mode: config.mode,
            table_id: config.defaults.table_id,
            rules,
            default_wan_iface: default_wan,
            local_dns: config.local_dns.clone(),
            blacklist: config.blacklist.clone(),
            lan_interfaces: config.lan_interfaces.clone(),
            lan_dns_servers: config.lan_dns_servers.clone(),
            wan_gateway,
            wan_ipv6_gateway: None,
        }
    }

    /// Supply the IPv6 gateway discovered by the platform backend.
    /// This is intentionally a setter so existing callers/tests that only
    /// know the IPv4 gateway remain source-compatible.
    pub fn set_wan_ipv6_gateway(&mut self, gateway: Option<IpAddr>) {
        self.wan_ipv6_gateway = gateway;
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
            IpAddr::from_str(target_str).ok().or_else(|| {
                self.local_dns
                    .get(&canonical_domain(target_str))
                    .and_then(|ips| ips.first().copied())
            })
        };

        // A blacklist is an explicit WLAN-only override. It is checked before
        // every manual LAN rule so an overlapping target configuration cannot
        // accidentally send an agent endpoint to the LAN interface.
        if let Some(ip) = maybe_ip {
            if self.blacklist.iter().any(|network| network.contains(&ip)) {
                return Decision {
                    destination: target_str.to_string(),
                    resolved_ip: Some(ip),
                    matched_rule: None,
                    rule_source: RuleSource::WanDefault,
                    selected_interface: self.default_wan_iface.clone(),
                    candidate_interfaces: self.default_wan_iface.clone().into_iter().collect(),
                    health_state: HealthState::Healthy,
                    routing_table: 254,
                    reason: "Destination matches blacklist; forced to WLAN and denied on LAN"
                        .into(),
                };
            }
        }

        // Match rules according to precedence
        for rule in &self.rules {
            let matches = match (&rule.matcher, &parsed_target, maybe_ip) {
                (TargetMatcher::HostIp(target_ip), _, Some(ip)) => *target_ip == ip,
                (TargetMatcher::Cidr(cidr), _, Some(ip)) => cidr.contains(&ip),
                (TargetMatcher::Cidr(cidr), Ok(TargetMatcher::Cidr(req_cidr)), _) => {
                    cidr.contains(&req_cidr.network())
                }
                (TargetMatcher::Domain(target_domain), _, _) => {
                    canonical_domain(target_domain) == canonical_domain(target_str)
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

        // Do not create routes to LAN DNS servers here. A route/firewall rule
        // can identify only an IP and port, not the DNS QNAME, so it would
        // let any process query arbitrary domains through LAN. Static
        // LOCAL_DNS_RECORDS below produce exact destination routes; dynamic
        // LAN DNS is rejected by Config::validate_strict_lan_policy until a
        // restricted resolver proxy is available.

        // Blacklist entries are pinned to the normal WAN path. This prevents
        // an AI endpoint from falling through to the target/server interface
        // when the main table prefers that interface.
        if let Some(wan) = &self.default_wan_iface {
            for net in &self.blacklist {
                let gateway = match net.addr() {
                    IpAddr::V4(_) => self.wan_gateway,
                    IpAddr::V6(_) => self.wan_ipv6_gateway,
                };
                routes.push(Route {
                    destination: *net,
                    output_interface: wan.clone(),
                    gateway,
                    table: self.table_id,
                    metric: Some(1),
                    route_type: RouteType::Unicast,
                });
            }
        }

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
                            route_type: RouteType::Unicast,
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
                                route_type: RouteType::Unicast,
                            });
                        }
                    }
                    TargetMatcher::Domain(domain) => {
                        if let Some(ips) = self.local_dns.get(&canonical_domain(domain)) {
                            for ip in ips {
                                if let Some(net) = host_net(*ip) {
                                    routes.push(Route {
                                        destination: net,
                                        output_interface: iface.clone(),
                                        gateway: None,
                                        table: self.table_id,
                                        metric: Some(50),
                                        route_type: RouteType::Unicast,
                                    });
                                }
                            }
                        }
                    }
                    TargetMatcher::DomainSuffix(suffix) => {
                        let suffix = canonical_domain(suffix);
                        for (domain, ips) in &self.local_dns {
                            if domain == &suffix || domain.ends_with(&format!(".{}", suffix)) {
                                for ip in ips {
                                    if let Some(net) = host_net(*ip) {
                                        routes.push(Route {
                                            destination: net,
                                            output_interface: iface.clone(),
                                            gateway: None,
                                            table: self.table_id,
                                            metric: Some(50),
                                            route_type: RouteType::Unicast,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // When candidate interface is down or unavailable:
                match rule.fallback {
                    FallbackAction::Drop | FallbackAction::Unreachable => {
                        // Crucial P0 security fix: Never leave a FIB vacuum in isolated table 52000!
                        // Install an UNREACHABLE route in table 52000 so kernel immediately rejects
                        // traffic and NEVER falls through to table main (default WAN / Internet route).
                        match &rule.matcher {
                            TargetMatcher::Cidr(cidr) => {
                                routes.push(Route {
                                    destination: *cidr,
                                    output_interface: String::new(),
                                    gateway: None,
                                    table: self.table_id,
                                    metric: Some(100),
                                    route_type: RouteType::Unreachable,
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
                                        output_interface: String::new(),
                                        gateway: None,
                                        table: self.table_id,
                                        metric: Some(50),
                                        route_type: RouteType::Unreachable,
                                    });
                                }
                            }
                            TargetMatcher::Domain(domain) => {
                                if let Some(ips) = self.local_dns.get(&canonical_domain(domain)) {
                                    for ip in ips {
                                        if let Some(net) = host_net(*ip) {
                                            routes.push(Route {
                                                destination: net,
                                                output_interface: String::new(),
                                                gateway: None,
                                                table: self.table_id,
                                                metric: Some(50),
                                                route_type: RouteType::Unreachable,
                                            });
                                        }
                                    }
                                }
                            }
                            TargetMatcher::DomainSuffix(suffix) => {
                                let suffix = canonical_domain(suffix);
                                for (domain, ips) in &self.local_dns {
                                    if domain == &suffix
                                        || domain.ends_with(&format!(".{}", suffix))
                                    {
                                        for ip in ips {
                                            if let Some(net) = host_net(*ip) {
                                                routes.push(Route {
                                                    destination: net,
                                                    output_interface: String::new(),
                                                    gateway: None,
                                                    table: self.table_id,
                                                    metric: Some(50),
                                                    route_type: RouteType::Unreachable,
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    FallbackAction::Wan => {
                        // WAN fallback: By not adding a route to table 52000,
                        // RPDB lookup falls through to table main (WAN default route).
                    }
                }
            }
        }

        let mut seen = HashSet::new();
        routes.retain(|route| seen.insert(route.clone()));
        routes
    }
}

fn canonical_domain(name: &str) -> String {
    name.trim()
        .trim_start_matches('~')
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn host_net(ip: IpAddr) -> Option<IpNet> {
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    IpNet::new(ip, prefix).ok()
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
            port: None,
            via: vec!["wlan1".into(), "eth1".into()],
            fallback: "drop".into(),
        });
        cfg.targets.push(crate::config::TargetConfig {
            name: "specific-host".into(),
            cidr: "192.168.56.20".into(),
            port: None,
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
    fn test_local_dns_domain_resolves_without_system_lookup() {
        let (mut engine, health_map, health_sm) = make_test_setup();
        engine
            .local_dns
            .insert("server.lab".into(), vec!["10.0.0.77".parse().unwrap()]);
        engine.rules.push(PolicyRule {
            name: "server.lab".into(),
            matcher: TargetMatcher::Domain("server.lab".into()),
            source: RuleSource::ManualDomain,
            candidate_interfaces: vec!["eth1".into()],
            fallback: FallbackAction::Drop,
        });
        let decision = engine.decide("SERVER.LAB.", &health_map, &health_sm);
        assert_eq!(decision.resolved_ip, Some("10.0.0.77".parse().unwrap()));
        assert_eq!(decision.selected_interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn test_local_dns_domain_generates_host_route() {
        let (mut engine, health_map, health_sm) = make_test_setup();
        engine
            .local_dns
            .insert("server.lab".into(), vec!["2001:db8::77".parse().unwrap()]);
        engine.rules.push(PolicyRule {
            name: "server.lab".into(),
            matcher: TargetMatcher::Domain("server.lab".into()),
            source: RuleSource::ManualDomain,
            candidate_interfaces: vec!["eth1".into()],
            fallback: FallbackAction::Drop,
        });
        let routes = engine.generate_desired_routes(&health_map, &health_sm);
        assert!(routes
            .iter()
            .any(|r| r.destination == "2001:db8::77/128".parse().unwrap()));
    }

    #[test]
    fn test_configured_lan_domain_uses_lan_interface_and_static_answer() {
        let cfg = Config {
            lan_domains: vec!["server.lab".into()],
            lan_interfaces: vec!["eth0".into()],
            local_dns: BTreeMap::from([("server.lab".into(), vec!["10.0.0.77".parse().unwrap()])]),
            ..Default::default()
        };
        let interfaces = vec![Interface {
            index: 2,
            name: "eth0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["10.0.0.2/24".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Lan,
        }];
        let health_sm = HealthStateMachine::with_default_config();
        let mut health = PathHealth::default();
        health_sm.record_success(&mut health, 1);
        let health_map = HashMap::from([("eth0".into(), health)]);
        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));

        let decision = engine.decide("server.lab", &health_map, &health_sm);
        assert_eq!(decision.selected_interface.as_deref(), Some("eth0"));
        assert_eq!(decision.resolved_ip, Some("10.0.0.77".parse().unwrap()));
        assert!(engine
            .generate_desired_routes(&health_map, &health_sm)
            .iter()
            .any(|route| {
                route.destination == "10.0.0.77/32".parse().unwrap()
                    && route.output_interface == "eth0"
            }));
    }

    #[test]
    fn test_lan_dns_server_never_gets_a_generic_lan_route() {
        let cfg = Config {
            lan_interfaces: vec!["eth0".into()],
            lan_dns_servers: vec!["10.0.0.53".parse().unwrap()],
            ..Default::default()
        };
        let interfaces = vec![Interface {
            index: 2,
            name: "eth0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["10.0.0.2/24".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Lan,
        }];
        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));
        let routes = engine
            .generate_desired_routes(&HashMap::new(), &HealthStateMachine::with_default_config());

        assert!(!routes.iter().any(|route| {
            route.destination == "10.0.0.53/32".parse().unwrap() && route.output_interface == "eth0"
        }));
    }

    #[test]
    fn duplicate_static_and_domain_routes_are_emitted_once() {
        let mut cfg = Config {
            lan_domains: vec!["server.lab".into()],
            lan_interfaces: vec!["eth0".into()],
            local_dns: BTreeMap::from([("server.lab".into(), vec!["10.0.0.77".parse().unwrap()])]),
            ..Default::default()
        };
        cfg.targets.push(crate::config::TargetConfig {
            name: "explicit".into(),
            cidr: "10.0.0.77/32".into(),
            port: None,
            via: vec!["eth0".into()],
            fallback: "drop".into(),
        });
        let interfaces = vec![Interface {
            index: 2,
            name: "eth0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["10.0.0.2/24".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Lan,
        }];
        let health_sm = HealthStateMachine::with_default_config();
        let mut health = PathHealth::default();
        health_sm.record_success(&mut health, 1);
        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));
        let routes =
            engine.generate_desired_routes(&HashMap::from([("eth0".into(), health)]), &health_sm);

        assert_eq!(
            routes
                .iter()
                .filter(|route| route.destination == "10.0.0.77/32".parse().unwrap())
                .count(),
            1
        );
    }

    #[test]
    fn test_blacklist_destinations_are_pinned_to_wan() {
        let cfg = Config {
            blacklist: vec!["203.0.113.10/32".parse().unwrap()],
            ..Default::default()
        };
        let interfaces = vec![Interface {
            index: 3,
            name: "wlan0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["192.168.1.104/24".parse().unwrap()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            role: InterfaceRole::Wan,
        }];
        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));
        let routes = engine
            .generate_desired_routes(&HashMap::new(), &HealthStateMachine::with_default_config());
        assert!(routes.iter().any(|route| {
            route.destination == "203.0.113.10/32".parse().unwrap()
                && route.output_interface == "wlan0"
                && route.gateway == Some("192.168.1.1".parse().unwrap())
        }));
    }

    #[test]
    fn test_blacklist_wins_over_configured_lan_ip() {
        let mut cfg = Config::default();
        cfg.targets.push(crate::config::TargetConfig {
            name: "lan-server".into(),
            cidr: "10.0.0.1/32".into(),
            port: None,
            via: vec!["eth0".into()],
            fallback: "drop".into(),
        });
        cfg.blacklist = vec!["10.0.0.1/32".parse().unwrap()];
        let interfaces = vec![
            Interface {
                index: 2,
                name: "eth0".into(),
                is_up: true,
                has_carrier: true,
                is_loopback: false,
                mtu: 1500,
                mac: None,
                ip_addrs: vec!["10.0.0.2/24".parse().unwrap()],
                gateway: None,
                role: InterfaceRole::Lan,
            },
            Interface {
                index: 3,
                name: "wlan0".into(),
                is_up: true,
                has_carrier: true,
                is_loopback: false,
                mtu: 1500,
                mac: None,
                ip_addrs: vec!["192.0.2.2/24".parse().unwrap()],
                gateway: Some("192.0.2.1".parse().unwrap()),
                role: InterfaceRole::Wan,
            },
        ];
        let engine = PolicyEngine::from_config(&cfg, &interfaces, Some("wlan0".into()));
        let health_sm = HealthStateMachine::with_default_config();
        let decision = engine.decide("10.0.0.1", &HashMap::new(), &health_sm);

        assert_eq!(decision.selected_interface.as_deref(), Some("wlan0"));
        assert_eq!(decision.rule_source, RuleSource::WanDefault);
        assert!(decision.reason.contains("blacklist"));
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

        // Crucial kernel route check: Route in table 52000 MUST be Unreachable so kernel drops
        let routes = engine.generate_desired_routes(&health_map, &health_sm);
        assert!(!routes.is_empty());
        for r in &routes {
            assert_eq!(r.route_type, RouteType::Unreachable);
            assert_eq!(r.table, 52000);
        }
    }
}
