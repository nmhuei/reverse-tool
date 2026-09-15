use reverse_core::{
    Config, HealthConfig, HealthStateMachine, Interface, InterfaceRole, PathHealth, PolicyEngine,
    Route, RoutePlanner, RuleSource, TargetConfig,
};
use std::collections::HashMap;

#[test]
fn test_end_to_end_policy_flow() {
    let mut config = Config::default();

    config.targets.push(TargetConfig {
        name: "lab-exact".into(),
        cidr: "192.168.56.100".into(),
        via: vec!["eth1".into()],
        fallback: "drop".into(),
    });

    config.targets.push(TargetConfig {
        name: "lab-subnet".into(),
        cidr: "192.168.56.0/24".into(),
        via: vec!["wlan1".into(), "eth1".into()],
        fallback: "drop".into(),
    });

    config.networks.push(reverse_core::NetworkConfig {
        name: "malware-lab".into(),
        role: "lan".into(),
        interfaces: vec!["eth1".into()],
        auto_subnets: true,
        preferred: vec!["eth1".into()],
        domains: vec!["~malware.lab".into()],
        dns: vec!["192.168.56.1".parse().unwrap()],
    });

    let interfaces = vec![
        Interface {
            index: 1,
            name: "lo".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: true,
            mtu: 65536,
            mac: None,
            ip_addrs: vec!["127.0.0.1/8".parse().unwrap()],
            gateway: None,
            role: InterfaceRole::Loopback,
        },
        Interface {
            index: 2,
            name: "wlan0".into(),
            is_up: true,
            has_carrier: true,
            is_loopback: false,
            mtu: 1500,
            mac: None,
            ip_addrs: vec!["192.168.1.10/24".parse().unwrap()],
            gateway: Some("192.168.1.1".parse().unwrap()),
            role: InterfaceRole::Wan,
        },
        Interface {
            index: 3,
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
    ];

    let engine = PolicyEngine::from_config(&config, &interfaces, Some("wlan0".into()));
    let health_sm = HealthStateMachine::new(HealthConfig::default());
    let mut health_map = HashMap::new();

    let mut eth1_health = PathHealth::default();
    health_sm.record_success(&mut eth1_health, 100);
    health_map.insert("eth1".into(), eth1_health);

    let mut wlan1_health = PathHealth::default();
    health_sm.record_success(&mut wlan1_health, 100);
    health_map.insert("wlan1".into(), wlan1_health);

    // 1. Exact manual IP matches
    let d1 = engine.decide("192.168.56.100", &health_map, &health_sm);
    assert_eq!(d1.rule_source, RuleSource::ManualExact);
    assert_eq!(d1.selected_interface.as_deref(), Some("eth1"));
    assert_eq!(d1.routing_table, 52000);

    // 2. Subnet CIDR matches
    let d2 = engine.decide("192.168.56.50", &health_map, &health_sm);
    assert_eq!(d2.rule_source, RuleSource::ManualCidr);
    assert_eq!(d2.selected_interface.as_deref(), Some("wlan1"));
    assert_eq!(d2.routing_table, 52000);

    // 3. Domain suffix matches
    let d3 = engine.decide("victim.malware.lab", &health_map, &health_sm);
    assert_eq!(d3.rule_source, RuleSource::ManualSuffix);
    assert_eq!(d3.selected_interface.as_deref(), Some("eth1"));
    assert_eq!(d3.routing_table, 52000);

    // 4. Normal Internet destination falls through to main table WAN
    let d4 = engine.decide("github.com", &health_map, &health_sm);
    assert_eq!(d4.rule_source, RuleSource::WanDefault);
    assert_eq!(d4.selected_interface.as_deref(), Some("wlan0"));
    assert_eq!(d4.routing_table, 254);

    // 5. Failover test: If eth1 dies, fallback candidate is used
    let dead_eth1 = PathHealth {
        state: reverse_core::HealthState::Down,
        ..Default::default()
    };
    health_map.insert("eth1".into(), dead_eth1);

    // lab-exact only had eth1 -> now dropped!
    let d5 = engine.decide("192.168.56.100", &health_map, &health_sm);
    assert_eq!(d5.selected_interface, None);
    assert!(d5.reason.contains("DROP"));
}

#[test]
fn test_planner_safety_invariants() {
    let desired = reverse_core::DesiredState {
        routes: vec![Route {
            destination: "0.0.0.0/0".parse().unwrap(),
            output_interface: "eth1".into(),
            gateway: None,
            table: 52000,
            metric: None,
        }],
        rules: vec![],
        dns_split_domains: vec![],
    };

    let res = RoutePlanner::validate_desired_state(&desired);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Safety violation"));
}
