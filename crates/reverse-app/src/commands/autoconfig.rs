use crate::client::DaemonClient;
use crate::commands::{handle_apply, load_config_or_default};
use reverse_core::{InterfaceClassifier, InterfaceRole, LanDetector};
use reverse_linux::NetlinkController;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub async fn handle_autoconfig(
    client: &DaemonClient,
    save: bool,
    apply: bool,
    config_path: Option<&Path>,
) {
    println!("\n=== Auto-Detecting LAN Subnets & Servers ===");
    let cfg = load_config_or_default(config_path);
    let netlink = NetlinkController::new();
    let mut ifaces = netlink.get_interfaces().unwrap_or_default();
    let explicit_wan = cfg.wan.interfaces.first().filter(|w| *w != "auto").cloned();
    let default_wan = explicit_wan.or_else(|| netlink.get_default_wan_interface().unwrap_or(None));

    for iface in &mut ifaces {
        iface.role =
            InterfaceClassifier::classify(iface, default_wan.as_deref(), &cfg.wan.interfaces);
    }

    let mut gateways = HashMap::new();
    let mut neighbors = HashMap::new();

    let mut lan_found = false;
    for iface in &ifaces {
        if iface.role == InterfaceRole::Lan {
            lan_found = true;
            if let Some(gw) = netlink.get_interface_gateway(&iface.name) {
                gateways.insert(iface.name.clone(), gw);
            }
            let neighs = netlink.get_interface_neighbors(&iface.name);
            if !neighs.is_empty() {
                neighbors.insert(iface.name.clone(), neighs);
            }
        }
    }

    if !lan_found {
        println!("\x1b[1;33m[!] No active LAN interfaces with carrier and IP detected.\x1b[0m");
        println!("    Check if the Ethernet cable is connected or check 'reverse-tool scan'.\n");
        return;
    }

    let detected = LanDetector::detect(&ifaces, &gateways, &neighbors);

    println!(
        "Detected \x1b[1;32m{}\x1b[0m LAN Network(s):",
        detected.networks.len()
    );
    for net in &detected.networks {
        let dns_str = if net.dns.is_empty() {
            "none".to_string()
        } else {
            net.dns
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "  • Network: \x1b[1m{}\x1b[0m (interfaces: {:?}, dns/gw: {})",
            net.name, net.interfaces, dns_str
        );
    }

    println!(
        "\nDetected \x1b[1;32m{}\x1b[0m Target IP Range(s) & Server(s):",
        detected.targets.len()
    );
    for target in &detected.targets {
        println!(
            "  • {:<25} CIDR: \x1b[1;36m{:<20}\x1b[0m via {:?}",
            target.name, target.cidr, target.via
        );
    }
    println!();

    let target_save_path = config_path.map(PathBuf::from).unwrap_or_else(|| {
        if Path::new("/etc/reverse-tool").exists() && unsafe { libc::geteuid() == 0 } {
            PathBuf::from("/etc/reverse-tool/config.toml")
        } else {
            PathBuf::from("config.toml")
        }
    });

    if save {
        let mut cfg = load_config_or_default(Some(&target_save_path));
        LanDetector::merge_into_config(&mut cfg, detected);

        if let Some(parent) = target_save_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match cfg.to_toml_string() {
            Ok(toml_str) => {
                if let Err(e) = fs::write(&target_save_path, toml_str) {
                    eprintln!(
                        "\x1b[1;31mFailed to save config to {:?}: {}\x1b[0m",
                        target_save_path, e
                    );
                } else {
                    println!(
                        "\x1b[1;32m[+] Successfully merged and saved configuration to {:?}\x1b[0m",
                        target_save_path
                    );
                }
            }
            Err(e) => eprintln!("\x1b[1;31mFailed to serialize config: {}\x1b[0m", e),
        }
    } else {
        println!(
            "(Tip: Run with \x1b[1m--save\x1b[0m to persist these ranges into your config file)"
        );
    }

    if apply {
        println!("\x1b[1;34m[*] Applying detected configuration...\x1b[0m");
        if let Err(error) = handle_apply(client, false, Some(&target_save_path)).await {
            eprintln!("\x1b[1;31mApply failed: {}\x1b[0m", error);
        }
    }
}
