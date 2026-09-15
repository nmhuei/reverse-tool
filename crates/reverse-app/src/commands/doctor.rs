use reverse_core::InterfaceClassifier;
use reverse_linux::{detect_best_dns_backend, CapabilityChecker, NetlinkController};

pub struct DoctorReport {
    pub checks: Vec<(String, bool, String)>, // (name, passed, message)
}

pub fn run_doctor() -> DoctorReport {
    let mut checks = Vec::new();

    // 1. Check CAP_NET_ADMIN / root
    let has_caps = CapabilityChecker::has_cap_net_admin();
    checks.push((
        "Privileges (CAP_NET_ADMIN)".into(),
        has_caps,
        if has_caps {
            "Process has network administrative capabilities".into()
        } else {
            "Lacks CAP_NET_ADMIN. Daemon must be run as root or with setcap cap_net_admin+ep".into()
        },
    ));

    // 2. Check Netlink access & interface listing
    let netlink = NetlinkController::new();
    match netlink.get_interfaces() {
        Ok(ifaces) => {
            checks.push((
                "Netlink interface access".into(),
                true,
                format!("Discovered {} network interfaces", ifaces.len()),
            ));

            // Check default route
            let wan = netlink.get_default_wan_interface().unwrap_or(None);
            checks.push((
                "Default WAN route".into(),
                wan.is_some(),
                if let Some(ref w) = wan {
                    format!("Found default WAN interface: {}", w)
                } else {
                    "No default route found. Internet access might be down".into()
                },
            ));

            // Check LAN candidates
            let mut lan_count = 0;
            for iface in &ifaces {
                let role = InterfaceClassifier::classify(iface, wan.as_deref(), &[]);
                if role == reverse_core::InterfaceRole::Lan {
                    lan_count += 1;
                }
            }
            checks.push((
                "LAN interface candidates".into(),
                lan_count > 0,
                format!("Detected {} potential LAN interface(s)", lan_count),
            ));
        }
        Err(e) => {
            checks.push((
                "Netlink interface access".into(),
                false,
                format!("Failed to query interfaces: {}", e),
            ));
        }
    }

    // 3. Check table 52000 allocation
    match netlink.allocate_table(52000, 52099) {
        Ok(table) => {
            checks.push((
                "Routing table allocation".into(),
                true,
                format!("Table {} is free and available", table),
            ));
        }
        Err(e) => {
            checks.push((
                "Routing table allocation".into(),
                false,
                format!("Failed to allocate routing table: {}", e),
            ));
        }
    }

    // 4. Check DNS backend
    let dns_backend = detect_best_dns_backend();
    checks.push((
        "DNS Backend".into(),
        dns_backend.is_available() && dns_backend.name() != "Disabled",
        format!("Active backend: {}", dns_backend.name()),
    ));

    DoctorReport { checks }
}
