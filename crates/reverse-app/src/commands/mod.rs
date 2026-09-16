pub mod autoconfig;
pub mod daemon;
pub mod doctor;

use crate::client::DaemonClient;
use crate::rpc::{DaemonRequest, DaemonResponse};
use crate::state::StateManager;
use reverse_core::{
    Config, HealthConfig, HealthStateMachine, InterfaceClassifier, PolicyEngine, RoutePlanner,
    TargetConfig,
};
use reverse_linux::NetlinkController;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub async fn handle_doctor() {
    let report = doctor::run_doctor();
    println!("\n=== reverse-tool Diagnostics ===");
    for (name, passed, msg) in report.checks {
        let tag = if passed {
            "\x1b[1;32m[OK]\x1b[0m"
        } else {
            "\x1b[1;33m[WARN]\x1b[0m"
        };
        println!("{} {}: {}", tag, name, msg);
    }
    println!();
}

pub async fn handle_scan(client: &DaemonClient) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Scan(rep)) = client.send(&DaemonRequest::Scan).await {
            print_interfaces(&rep.interfaces, rep.default_wan.as_deref());
            return;
        }
    }

    // Direct local scan
    let cfg = load_config_or_default(None);
    let netlink = NetlinkController::new();
    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
    let explicit_wan = cfg.wan.interfaces.first().filter(|w| *w != "auto").cloned();
    let default_wan = explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

    for iface in &mut ifaces {
        iface.role =
            InterfaceClassifier::classify(iface, default_wan.as_deref(), &cfg.wan.interfaces);
    }

    print_interfaces(&ifaces, default_wan.as_deref());
}

fn print_interfaces(ifaces: &[reverse_core::Interface], default_wan: Option<&str>) {
    println!("\n=== Network Interface Discovery ===");
    if let Some(wan) = default_wan {
        println!("Default WAN Interface: \x1b[1;32m{}\x1b[0m", wan);
    }
    println!(
        "{:<6} {:<12} {:<10} {:<10} {:<8} {:<24}",
        "IDX", "INTERFACE", "ROLE", "OPERSTATE", "CARRIER", "IP ADDRESSES"
    );
    println!("{:-<75}", "");

    for i in ifaces {
        let ips: Vec<String> = i.ip_addrs.iter().map(|n| n.to_string()).collect();
        let ips_str = if ips.is_empty() {
            "-".to_string()
        } else {
            ips.join(", ")
        };

        let role_colored = match i.role {
            reverse_core::InterfaceRole::Wan => format!("\x1b[1;34m{}\x1b[0m", i.role),
            reverse_core::InterfaceRole::Lan => format!("\x1b[1;32m{}\x1b[0m", i.role),
            reverse_core::InterfaceRole::Vpn => format!("\x1b[1;35m{}\x1b[0m", i.role),
            _ => format!("{}", i.role),
        };

        println!(
            "{:<6} {:<12} {:<10} {:<10} {:<8} {:<24}",
            i.index,
            i.name,
            role_colored,
            if i.is_up { "UP" } else { "DOWN" },
            if i.has_carrier { "YES" } else { "NO" },
            ips_str
        );
    }
    println!();
}

pub async fn handle_status(client: &DaemonClient) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Status(s)) = client.send(&DaemonRequest::Status).await {
            println!("\n=== reverse-tool Daemon Status ===");
            println!("Daemon Status: \x1b[1;32mACTIVE\x1b[0m");
            println!("Allocated Table: {}", s.allocated_table);
            println!("Rule Priority:   {}", s.rule_priority);
            println!("Monitored Interfaces: {}", s.interface_count);
            println!("Active Lab Routes:    {}", s.active_routes.len());
            for r in s.active_routes {
                println!("  -> {} via {}", r.destination, r.output_interface);
            }
            println!();
            return;
        }
    }

    let state_mgr = StateManager::new();
    let state = state_mgr.load().unwrap_or_default();
    println!("\n=== reverse-tool Local Status ===");
    println!("Daemon Status: \x1b[1;33mOFFLINE\x1b[0m (showing local saved state)");
    println!("Allocated Table: {}", state.allocated_table);
    println!("Rule Priority:   {}", state.rule_priority);
    println!("Saved Routes:    {}", state.routes_owned.len());
    for r in state.routes_owned {
        println!("  -> {} via {}", r.destination, r.output_interface);
    }
    println!();
}

pub async fn handle_explain(client: &DaemonClient, target: &str, config_path: Option<&Path>) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Explain(dec)) = client
            .send(&DaemonRequest::Explain {
                target: target.to_string(),
            })
            .await
        {
            print_decision(&dec);
            return;
        }
    }

    // Direct local explain
    let cfg = load_config_or_default(config_path);
    let netlink = NetlinkController::new();
    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
    let explicit_wan = cfg.wan.interfaces.first().filter(|w| *w != "auto").cloned();
    let wan = explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

    for iface in &mut ifaces {
        iface.role = InterfaceClassifier::classify(iface, wan.as_deref(), &cfg.wan.interfaces);
    }

    let engine = PolicyEngine::from_config(&cfg, &ifaces, wan);
    let health_sm = HealthStateMachine::new(HealthConfig::default());
    let mut health_map = HashMap::new();

    for iface in &ifaces {
        let mut h = reverse_core::PathHealth::default();
        if iface.is_up && iface.has_carrier {
            health_sm.record_success(&mut h, 0);
        } else {
            health_sm.record_failure(&mut h, 0);
        }
        health_map.insert(iface.name.clone(), h);
    }

    let decision = engine.decide(target, &health_map, &health_sm);
    print_decision(&decision);
}

fn print_decision(dec: &reverse_core::Decision) {
    println!("\n=== Policy Decision Explanation ===");
    println!("Destination:        \x1b[1m{}\x1b[0m", dec.destination);
    if let Some(ip) = dec.resolved_ip {
        println!("Resolved IP:        {}", ip);
    }
    println!("Rule Source:        {}", dec.rule_source);
    if let Some(ref r) = dec.matched_rule {
        println!("Matched Rule:       {}", r);
    }
    println!(
        "Candidates:         {}",
        if dec.candidate_interfaces.is_empty() {
            "none".to_string()
        } else {
            dec.candidate_interfaces.join(", ")
        }
    );
    let sel = match &dec.selected_interface {
        Some(iface) => format!("\x1b[1;32m{}\x1b[0m", iface),
        None => "\x1b[1;31mDROP\x1b[0m".to_string(),
    };
    println!("Selected Interface: {}", sel);
    println!("Routing Table:      {}", dec.routing_table);
    println!("Reason:             {}", dec.reason);
    println!();
}

pub async fn handle_apply(client: &DaemonClient, dry_run: bool, config_path: Option<&Path>) {
    let cfg = load_config_or_default(config_path);
    let toml_str = cfg.to_toml_string().ok();

    if client.is_alive().await {
        match client
            .send(&DaemonRequest::Apply {
                dry_run,
                config_toml: toml_str,
            })
            .await
        {
            Ok(DaemonResponse::Apply(rep)) => {
                print_apply_report(&rep);
                return;
            }
            Ok(DaemonResponse::Error(e)) => {
                eprintln!("\x1b[1;31mApply Error: {}\x1b[0m", e);
                return;
            }
            _ => {}
        }
    }

    // Direct apply if daemon not running
    println!("\x1b[1;33m[!] Daemon is offline; executing direct reconciliation\x1b[0m");
    let netlink = NetlinkController::new();
    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
    let explicit_wan = cfg.wan.interfaces.first().filter(|w| *w != "auto").cloned();
    let wan = explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

    for iface in &mut ifaces {
        iface.role = InterfaceClassifier::classify(iface, wan.as_deref(), &cfg.wan.interfaces);
    }

    let engine = PolicyEngine::from_config(&cfg, &ifaces, wan);
    let health_sm = HealthStateMachine::new(HealthConfig::default());
    let mut health_map = HashMap::new();

    for iface in &ifaces {
        let mut h = reverse_core::PathHealth::default();
        if iface.is_up && iface.has_carrier {
            health_sm.record_success(&mut h, 0);
        }
        health_map.insert(iface.name.clone(), h);
    }

    let routes = engine.generate_desired_routes(&health_map, &health_sm);
    let desired = RoutePlanner::generate_desired_state(
        cfg.defaults.table_id,
        cfg.defaults.rule_priority,
        routes,
        vec![],
    );

    let reconciler = crate::reconcile::Reconciler::new(StateManager::new());
    match reconciler.reconcile(&desired, dry_run) {
        Ok(rep) => print_apply_report(&rep),
        Err(e) => eprintln!("\x1b[1;31mApply failed: {}\x1b[0m", e),
    }
}

fn print_apply_report(rep: &crate::reconcile::ReconcileReport) {
    println!("\n=== Reconcile Plan / Results ===");
    if rep.dry_run {
        println!("Mode: \x1b[1;33mDRY-RUN (No changes applied)\x1b[0m");
    } else {
        println!("Mode: \x1b[1;32mLIVE APPLY\x1b[0m");
    }

    println!("Routes to Add:    {}", rep.diff.routes_to_add.len());
    for r in &rep.diff.routes_to_add {
        println!(
            "  + {} dev {} table {}",
            r.destination, r.output_interface, r.table
        );
    }
    println!("Routes to Remove: {}", rep.diff.routes_to_remove.len());
    for r in &rep.diff.routes_to_remove {
        println!(
            "  - {} dev {} table {}",
            r.destination, r.output_interface, r.table
        );
    }
    println!("Rules to Add:     {}", rep.diff.rules_to_add.len());
    for rule in &rep.diff.rules_to_add {
        println!("  + pref {} lookup {}", rule.priority, rule.table);
    }

    if let Some(ref err) = rep.error {
        println!("\x1b[1;31mError: {}\x1b[0m", err);
    } else if rep.applied {
        println!("\x1b[1;32m[+] Successfully applied and verified!\x1b[0m");
    }
    println!();
}

pub async fn handle_reset(client: &DaemonClient) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Ok(msg)) = client.send(&DaemonRequest::Reset).await {
            println!("\x1b[1;32m[+] {}\x1b[0m", msg);
            return;
        }
    }

    let reconciler = crate::reconcile::Reconciler::new(StateManager::new());
    match reconciler.reset() {
        Ok(()) => println!("\x1b[1;32m[+] Custom routes and rules cleared successfully\x1b[0m"),
        Err(e) => eprintln!("\x1b[1;31mReset error: {}\x1b[0m", e),
    }
}

pub async fn handle_target_add(
    client: &DaemonClient,
    name: &str,
    cidr: &str,
    via: Vec<String>,
    fallback: &str,
) {
    let target = TargetConfig {
        name: name.to_string(),
        cidr: cidr.to_string(),
        via,
        fallback: fallback.to_string(),
    };

    if client.is_alive().await {
        if let Ok(DaemonResponse::Ok(m)) = client.send(&DaemonRequest::AddTarget(target)).await {
            println!("\x1b[1;32m[+] {}\x1b[0m", m);
            return;
        }
    }
    println!(
        "\x1b[1;32m[+] Target defined: {} -> {} (start reversed daemon to enforce)\x1b[0m",
        name, cidr
    );
}

pub async fn handle_target_list(client: &DaemonClient) {
    if client.is_alive().await {
        if let Ok(DaemonResponse::Targets(targets)) = client.send(&DaemonRequest::ListTargets).await
        {
            println!("\n=== Configured Targets ===");
            for t in targets {
                println!(
                    "{:<15} {:<20} via [{}] fallback: {}",
                    t.name,
                    t.cidr,
                    t.via.join(", "),
                    t.fallback
                );
            }
            println!();
            return;
        }
    }
    println!("Daemon offline. View configured targets in config file.");
}

pub fn load_config_or_default(config_path: Option<&Path>) -> Config {
    let mut config = if let Some(path) = config_path {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(cfg) = Config::from_toml_str(&content) {
                cfg
            } else {
                Config::default()
            }
        } else {
            Config::default()
        }
    } else {
        let default_paths = [
            Path::new("/etc/reverse-tool/config.toml"),
            Path::new("config.toml"),
            Path::new("config/example.toml"),
        ];

        let mut loaded = None;
        for p in &default_paths {
            if let Ok(content) = fs::read_to_string(p) {
                if let Ok(cfg) = Config::from_toml_str(&content) {
                    loaded = Some(cfg);
                    break;
                }
            }
        }
        loaded.unwrap_or_default()
    };

    // Automatically merge .env if present
    if Path::new(".env").exists() {
        config.merge_env_file(".env");
    } else if Path::new("/etc/reverse-tool/.env").exists() {
        config.merge_env_file("/etc/reverse-tool/.env");
    }

    config
}
